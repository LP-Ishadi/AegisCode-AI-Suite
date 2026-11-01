"""Local scanner binaries run only in the dedicated, non-root scanner worker."""

import asyncio
import json
import re
from functools import lru_cache
from pathlib import Path

from app.models.dispatch import ScanResult
from app.models.schemas import Finding, Severity
from app.services.adapter_errors import AdapterError
from app.services.redaction import redact
from app.services.repository_snapshot import Snapshot

OUTPUT_LIMIT = 8_000_000
RULES = Path("/opt/aegis/rules/aegis.yaml")
SAFE_ID = re.compile(r"[^A-Za-z0-9_.:-]+")
FROM_LINE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE)
IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")
PUBLIC_REGISTRIES = {"docker.io", "index.docker.io", "ghcr.io", "quay.io", "registry.k8s.io"}


def allowed_image_reference(reference: str) -> bool:
    """Only fetch images from explicitly trusted public registry hostnames."""
    if not IMAGE_REF.fullmatch(reference) or "://" in reference:
        return False
    if "/" not in reference:
        return "." not in reference.split(":", 1)[0]  # image:tag on Docker Hub
    first = reference.split("/", 1)[0].lower()
    if "." in first or ":" in first or first == "localhost":
        return first in PUBLIC_REGISTRIES
    return True  # Unqualified references resolve through Docker Hub.


def relative_path(snapshot: Snapshot, raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise AdapterError("source_incomplete")
    path = Path(raw)
    absolute = path if path.is_absolute() else snapshot.root / path
    try:
        relative = absolute.resolve().relative_to(snapshot.root.resolve()).as_posix()
    except ValueError:
        raise AdapterError("source_incomplete") from None
    if relative not in snapshot.paths:
        raise AdapterError("source_incomplete")
    return relative


def severity(value: str) -> Severity:
    return {
        "CRITICAL": Severity.critical,
        "HIGH": Severity.high,
        "ERROR": Severity.high,
        "MEDIUM": Severity.medium,
        "WARNING": Severity.medium,
        "LOW": Severity.low,
        "INFO": Severity.info,
        "UNKNOWN": Severity.info,
    }.get(str(value).upper(), Severity.info)


def finding(rule: str, path: str, line: int, level: str, message: str) -> Finding:
    return Finding(
        rule_id=SAFE_ID.sub("-", rule)[:255],
        file_path=path,
        line=line,
        severity=severity(level),
        message=redact(message)[:8000],
    )


@lru_cache(maxsize=1)
def semgrep_rule_messages() -> dict[str, str]:
    # Messages come from our bundled rules, never from source-controlled scan output.
    import yaml

    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    return {rule["id"]: rule["message"] for rule in rules}


def parse_semgrep(data: dict, snapshot: Snapshot) -> list[Finding]:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise AdapterError("scanner_unavailable")
    if data.get("errors"):
        raise AdapterError("scanner_unavailable")
    result = []
    for item in data["results"]:
        extra = item.get("extra", {})
        check_id = str(item["check_id"])
        message = next(
            (
                text
                for rule_id, text in semgrep_rule_messages().items()
                if check_id == rule_id or check_id.endswith("." + rule_id)
            ),
            "Static analysis rule matched; inspect this code path for the reported risk.",
        )
        result.append(
            finding(
                "semgrep." + check_id,
                relative_path(snapshot, item["path"]),
                int(item["start"]["line"]),
                extra.get("severity", "INFO"),
                message,
            )
        )
    return result


def parse_trivy(data: dict, snapshot: Snapshot) -> list[Finding]:
    if not isinstance(data, dict) or "SchemaVersion" not in data:
        raise AdapterError("scanner_unavailable")
    groups = data.get("Results") or []
    if not isinstance(groups, list):
        raise AdapterError("scanner_unavailable")
    result = []
    for group in groups:
        vulnerabilities = group.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise AdapterError("scanner_unavailable")
        if not vulnerabilities:
            continue
        path = relative_path(snapshot, group.get("Target"))
        for vuln in vulnerabilities:
            name = str(vuln.get("PkgName", "package"))[:120]
            version = str(vuln.get("InstalledVersion", "unknown"))[:80]
            fixed = str(vuln.get("FixedVersion", "not listed"))[:80]
            identifier = str(vuln["VulnerabilityID"])
            result.append(
                finding(
                    "trivy." + identifier + "." + name,
                    path,
                    1,
                    vuln.get("Severity", "UNKNOWN"),
                    f"{identifier} affects {name} {version}; fixed version: {fixed}. "
                    "File-level dependency finding; exact line unavailable.",
                )
            )
    return result


def image_references(snapshot: Snapshot) -> list[tuple[str, int, str]]:
    references = []
    for path in sorted(snapshot.paths):
        if not (Path(path).name == "Dockerfile" or Path(path).name.startswith("Dockerfile.")):
            continue
        try:
            lines = (snapshot.root / path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            raise AdapterError("source_incomplete") from None
        stages = set()
        for number, line in enumerate(lines, 1):
            match = FROM_LINE.match(line)
            if not match:
                continue
            reference = match[1]
            if "$" in reference or not allowed_image_reference(reference):
                raise AdapterError("source_incomplete")
            if reference.lower() not in stages and reference.lower() != "scratch":
                references.append((path, number, reference))
            words = line.split()
            if len(words) >= 4 and words[-2].lower() == "as":
                stages.add(words[-1].lower())
    if len({reference for _, _, reference in references}) > 8:
        raise AdapterError("source_incomplete")
    return references


def parse_trivy_image(data: dict, path: str, line: int, reference: str) -> list[Finding]:
    if not isinstance(data, dict) or "SchemaVersion" not in data:
        raise AdapterError("scanner_unavailable")
    groups = data.get("Results") or []
    if not isinstance(groups, list):
        raise AdapterError("scanner_unavailable")
    result = []
    for group in groups:
        vulnerabilities = group.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise AdapterError("scanner_unavailable")
        for vuln in vulnerabilities:
            identifier = str(vuln["VulnerabilityID"])
            package = str(vuln.get("PkgName", "package"))[:120]
            version = str(vuln.get("InstalledVersion", "unknown"))[:80]
            fixed = str(vuln.get("FixedVersion", "not listed"))[:80]
            result.append(
                finding(
                    "trivy.image." + identifier + "." + package,
                    path,
                    line,
                    vuln.get("Severity", "UNKNOWN"),
                    f"Image {reference}: {identifier} affects {package} {version}; "
                    f"fixed version: {fixed}.",
                )
            )
    return result


def parse_trufflehog(output: bytes, snapshot: Snapshot) -> list[Finding]:
    result = []
    for raw in output.splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except ValueError:
            raise AdapterError("scanner_unavailable") from None
        data = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem")
        if not isinstance(data, dict):
            # Scanner progress messages are not findings.
            continue
        path = relative_path(snapshot, data.get("file"))
        line = int(data.get("line") or 1)
        detector = SAFE_ID.sub("-", str(item.get("DetectorName", "secret")))[:80]
        result.append(
            finding(
                "trufflehog." + detector,
                path,
                line,
                "HIGH",
                f"Potential {detector} credential detected (unverified). "
                "Remove it and rotate the credential if valid. No secret value stored.",
            )
        )
    return result


async def run_command(argv: list[str], *, timeout: int = 35) -> bytes:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": "/tmp",
                "XDG_CACHE_HOME": "/tmp/cache",
                "TRIVY_CACHE_DIR": "/cache/trivy",
            },
        )
    except OSError:
        raise AdapterError("scanner_unavailable") from None
    try:

        async def collect():
            output = bytearray()
            while chunk := await process.stdout.read(65_536):
                if len(output) + len(chunk) > OUTPUT_LIMIT:
                    raise AdapterError("scanner_unavailable")
                output.extend(chunk)
            await process.wait()
            return bytes(output)

        output = await asyncio.wait_for(collect(), timeout)
        if process.returncode != 0:
            raise AdapterError("scanner_unavailable", retryable=True)
        return output
    except (TimeoutError, AdapterError) as exc:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise AdapterError("scanner_unavailable", retryable=True) from exc
    except asyncio.CancelledError:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise


class ScannerSuite:
    async def scan(self, snapshot: Snapshot) -> ScanResult:
        root = str(snapshot.root)
        # A repository-controlled ignore file can remove arbitrary targets from Semgrep.
        # Until a trusted override is supported, fail the whole scan instead of passing it.
        if any(Path(path).name == ".semgrepignore" for path in snapshot.paths):
            raise AdapterError("source_incomplete")
        image_refs = image_references(snapshot)
        unique_images = sorted({reference for _, _, reference in image_refs})
        trivy_lock = asyncio.Semaphore(1)

        async def trivy_command(argv: list[str]) -> bytes:
            async with trivy_lock:
                return await run_command(argv, timeout=75)

        commands = [
            run_command(
                [
                    "semgrep",
                    "scan",
                    "--config",
                    str(RULES),
                    "--json",
                    "--metrics",
                    "off",
                    "--disable-version-check",
                    "--disable-nosem",
                    "--no-git-ignore",
                    root,
                ]
            ),
            trivy_command(
                [
                    "trivy",
                    "fs",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--cache-backend",
                    "memory",
                    "--quiet",
                    "--disable-telemetry",
                    root,
                ],
            ),
            run_command(
                ["trufflehog", "--no-verification", "--no-update", "--json", "filesystem", root]
            ),
        ]
        for reference in unique_images:
            commands.append(
                trivy_command(
                    [
                        "trivy",
                        "image",
                        "--image-src",
                        "remote",
                        "--scanners",
                        "vuln",
                        "--format",
                        "json",
                        "--cache-backend",
                        "memory",
                        "--quiet",
                        "--disable-telemetry",
                        reference,
                    ],
                )
            )
        tasks = [asyncio.create_task(command) for command in commands]
        try:
            semgrep, trivy, trufflehog, *images = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        try:
            findings = (
                parse_semgrep(json.loads(semgrep), snapshot)
                + parse_trivy(json.loads(trivy), snapshot)
                + parse_trufflehog(trufflehog, snapshot)
            )
            image_results = dict(zip(unique_images, images, strict=True))
            for path, line, reference in image_refs:
                findings.extend(
                    parse_trivy_image(json.loads(image_results[reference]), path, line, reference)
                )
        except (KeyError, TypeError, ValueError):
            raise AdapterError("scanner_unavailable") from None
        if len(findings) > 500:
            raise AdapterError("scanner_unavailable")
        unique = {(f.rule_id, f.file_path, f.line): f for f in findings}
        return ScanResult(
            findings=list(unique.values()), engine_version="semgrep+trivy+trufflehog/v1"
        )
