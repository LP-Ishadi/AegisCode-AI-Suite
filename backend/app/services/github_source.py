"""GitHub App authentication and bounded immutable diff acquisition."""

import asyncio
import base64
import json
import re
import time
from pathlib import PurePosixPath

import httpx
import jwt

from app.core.config import Settings, get_settings
from app.database.supabase_client import get_service_client
from app.models.dispatch import RepositoryRef, ScanMetadata, SourceBundle
from app.models.schemas import Finding, Severity
from app.services.adapter_errors import AdapterError
from app.services.redaction import contains_secret, redact


class SourceUnavailable(AdapterError):
    def __init__(self):
        super().__init__("adapter_unavailable")


def authorize_source(metadata: ScanMetadata) -> None:
    rows = (
        get_service_client()
        .table("repositories")
        .select("id,ai_scan_enabled")
        .eq("github_id", metadata.github_repository_id)
        .eq("github_installation_id", metadata.installation_id)
        .limit(1)
        .execute()
        .data
    )
    if not rows:
        raise AdapterError("repository_not_connected")
    if rows[0].get("ai_scan_enabled") is not True:
        raise AdapterError("ai_not_authorized")


class GitHubAPI:
    def __init__(self, settings: Settings, transport=None):
        self.settings = settings
        self.transport = transport

    def app_token(self) -> str:
        key = self.settings.github_app_private_key_b64
        if not key or not self.settings.github_app_id:
            raise SourceUnavailable()
        try:
            pem = base64.b64decode(key.get_secret_value(), validate=True)
            now = int(time.time())
            return jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": self.settings.github_app_id},
                pem,
                algorithm="RS256",
            )
        except Exception:
            raise AdapterError("github_configuration") from None

    async def request(self, method: str, path: str, token: str, body=None) -> dict:
        if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
            raise AdapterError("invalid_input")
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            transport=self.transport,
            follow_redirects=False,
            timeout=15,
            trust_env=False,
        ) as client:
            async with client.stream(
                method,
                path,
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            ) as response:
                if (
                    response.status_code >= 500
                    or response.status_code == 429
                    or (
                        response.status_code == 403
                        and (
                            response.headers.get("X-RateLimit-Remaining") == "0"
                            or response.headers.get("Retry-After") is not None
                        )
                    )
                ):
                    raise AdapterError("upstream_unavailable", retryable=True)
                if response.status_code >= 300:
                    raise AdapterError("github_access_denied")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(data) + len(chunk) > 2_000_000:
                        raise AdapterError("source_incomplete")
                    data.extend(chunk)
                try:
                    result = json.loads(data)
                except ValueError:
                    raise AdapterError("source_incomplete") from None
                if not isinstance(result, dict):
                    raise AdapterError("source_incomplete")
                return result

    async def installation_token(self, metadata: ScanMetadata) -> str:
        # App JWT verifies that this installation belongs to this app and repo.
        name = RepositoryRef(
            id=metadata.github_repository_id, full_name=metadata.repository_full_name
        ).full_name
        app_jwt = self.app_token()
        installation = await self.request("GET", f"/repos/{name}/installation", app_jwt)
        if installation.get("id") != metadata.installation_id:
            raise AdapterError("repository_not_connected")
        data = await self.request(
            "POST",
            f"/app/installations/{metadata.installation_id}/access_tokens",
            app_jwt,
            {
                "repository_ids": [metadata.github_repository_id],
                "permissions": {"contents": "read", "pull_requests": "read"},
            },
        )
        token = data.get("token")
        if not isinstance(token, str) or not token:
            raise AdapterError("github_access_denied")
        return token


HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_patch(patch: str, filename: str, additions: int, deletions: int):
    ranges = []
    findings = []
    added = removed = 0
    old_left = new_left = 0
    line_no = 0
    seen = False
    for line in patch.splitlines():
        match = HUNK.match(line)
        if match:
            if old_left or new_left:
                raise AdapterError("source_incomplete")
            seen = True
            old_left = int(match[2] if match[2] is not None else 1)
            new_left = int(match[4] if match[4] is not None else 1)
            line_no = int(match[3])
            if new_left:
                ranges.append((line_no, line_no + new_left - 1))
            continue
        if line.startswith("\\ No newline"):
            continue
        if not seen or not line or line[0] not in " +-":
            raise AdapterError("source_incomplete")
        if line[0] in " -":
            old_left -= 1
        if line[0] == "-":
            removed += 1
        if line[0] == "+":
            added += 1
            if contains_secret(line[1:]):
                findings.append(
                    Finding(
                        rule_id="aegis.hardcoded-secret",
                        file_path=filename,
                        line=line_no,
                        severity=Severity.high,
                        message=(
                            "Potential hardcoded credential detected. Value redacted; "
                            "rotate it and use a secret manager."
                        ),
                    )
                )
        if line[0] in " +":
            new_left -= 1
            line_no += 1
        if min(old_left, new_left) < 0:
            raise AdapterError("source_incomplete")
    if not seen or old_left or new_left or (added, removed) != (additions, deletions):
        raise AdapterError("source_incomplete")
    return ranges, findings


def source_from_compare(metadata: ScanMetadata, data: dict, settings: Settings) -> SourceBundle:
    files = data.get("files")
    commits = data.get("commits")
    # Fail closed on pagination, GitHub's 300-file cap, binary/omitted/truncated patches.
    if (
        not isinstance(files, list)
        or len(files) > settings.scan_max_files
        or not isinstance(commits, list)
        or data.get("total_commits") != len(commits)
        or not commits
        or commits[-1].get("sha") != metadata.commit_sha
        or data.get("base_commit", {}).get("sha") != metadata.base_sha
    ):
        raise AdapterError("source_incomplete")
    patches, paths, ranges, local = [], [], {}, []
    for file in files:
        name = file.get("filename", "")
        path = PurePosixPath(name)
        if (
            not name
            or len(name) > 1024
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or any(ord(c) < 32 for c in name)
            or name in paths
        ):
            raise AdapterError("invalid_input")
        patch = file.get("patch")
        if not isinstance(patch, str) or not patch:
            raise AdapterError("source_incomplete")
        spans, detected = parse_patch(patch, name, file.get("additions"), file.get("deletions"))
        paths.append(name)
        ranges[name] = spans
        local.extend(detected)
        patches.append({"file": name, "status": file.get("status"), "patch": redact(patch)})
    diff = json.dumps(patches, ensure_ascii=True)
    if len(diff) > settings.scan_max_diff_chars:
        raise AdapterError("source_incomplete")
    return SourceBundle(
        commit_sha=metadata.commit_sha,
        diff=diff,
        files=paths,
        line_ranges=ranges,
        local_findings=local,
    )


class GitHubSourceProvider:
    def __init__(
        self, settings: Settings | None = None, *, transport=None, authorize=authorize_source
    ):
        self.settings = settings or get_settings()
        self.api = GitHubAPI(self.settings, transport)
        self.authorize = authorize

    async def fetch(self, metadata: ScanMetadata) -> SourceBundle:
        if not self.settings.github_app_id or not self.settings.github_app_private_key_b64:
            raise SourceUnavailable()
        if not self.settings.ai_scanning_enabled:
            raise AdapterError("ai_not_authorized")
        await asyncio.to_thread(self.authorize, metadata)
        token = await self.api.installation_token(metadata)
        repo = await self.api.request(
            "GET", f"/repositories/{metadata.github_repository_id}", token
        )
        ref = RepositoryRef.model_validate(repo)
        if ref.id != metadata.github_repository_id:
            raise AdapterError("repository_not_connected")
        # Never follow payload clone/patch URLs or mutable PR branches.
        data = await self.api.request(
            "GET",
            f"/repos/{ref.full_name}/compare/"
            f"{metadata.base_sha}...{metadata.commit_sha}?per_page=100",
            token,
        )
        return source_from_compare(metadata, data, self.settings)
