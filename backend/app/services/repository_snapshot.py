"""Bounded, disposable repository snapshot from immutable Git blobs."""

import asyncio
import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import Path

from app.core.config import Settings, get_settings
from app.models.dispatch import RepositoryRef, ScanMetadata
from app.services.adapter_errors import AdapterError
from app.services.github_source import GitHubAPI, authorize_repository

SHA = re.compile(r"^[0-9a-f]{40}$")


def safe_path(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 1024
        and not value.startswith("/")
        and all(part not in ("", ".", "..") for part in value.split("/"))
        and "\\" not in value
        and all(ord(c) >= 32 for c in value)
    )


@dataclass(frozen=True)
class Snapshot:
    root: Path
    paths: frozenset[str]
    commit_sha: str


class RepositorySnapshotProvider:
    def __init__(
        self, settings: Settings | None = None, *, transport=None, authorize=authorize_repository
    ):
        self.settings = settings or get_settings()
        self.api = GitHubAPI(self.settings, transport)
        self.authorize = authorize

    async def fetch_into(self, metadata: ScanMetadata, root: Path) -> Snapshot:
        await asyncio.to_thread(self.authorize, metadata)
        token = await self.api.installation_token(metadata)
        repo = await self.api.request(
            "GET", f"/repositories/{metadata.github_repository_id}", token
        )
        ref = RepositoryRef.model_validate(repo)
        if ref.id != metadata.github_repository_id:
            raise AdapterError("repository_not_connected")
        data = await self.api.request(
            "GET", f"/repos/{ref.full_name}/git/trees/{metadata.commit_sha}?recursive=1", token
        )
        entries = data.get("tree")
        if data.get("truncated") or not isinstance(entries, list) or len(entries) > 2000:
            raise AdapterError("source_incomplete")
        paths = set()
        total = 0
        blobs = []
        for entry in entries:
            if not isinstance(entry, dict) or not safe_path(entry.get("path", "")):
                raise AdapterError("source_incomplete")
            if entry.get("type") == "tree":
                continue
            if entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755"):
                raise AdapterError("source_incomplete")
            path, sha, size = entry["path"], entry.get("sha"), entry.get("size")
            if path in paths or not isinstance(sha, str) or not SHA.fullmatch(sha):
                raise AdapterError("source_incomplete")
            if not isinstance(size, int) or size < 0 or size > 1_000_000:
                raise AdapterError("source_incomplete")
            total += size
            if total > 40_000_000:
                raise AdapterError("source_incomplete")
            paths.add(path)
            blobs.append((path, sha, size))
        if not blobs:
            raise AdapterError("source_incomplete")
        semaphore = asyncio.Semaphore(8)

        async def write_blob(path: str, sha: str, size: int):
            async with semaphore:
                blob = await self.api.request(
                    "GET", f"/repos/{ref.full_name}/git/blobs/{sha}", token
                )
                encoded = blob.get("content")
                if blob.get("encoding") != "base64" or not isinstance(encoded, str):
                    raise AdapterError("source_incomplete")
                try:
                    content = base64.b64decode(
                        encoded.replace("\n", "").replace("\r", ""), validate=True
                    )
                except binascii.Error:
                    raise AdapterError("source_incomplete") from None
                if len(content) != size or len(content) > 1_000_000:
                    raise AdapterError("source_incomplete")
                target = root.joinpath(*path.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)

        await asyncio.gather(*(write_blob(*blob) for blob in blobs))
        return Snapshot(root=root, paths=frozenset(paths), commit_sha=metadata.commit_sha)
