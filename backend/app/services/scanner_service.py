"""Semgrep boundary; no repository code is executed in the API process."""

from typing import Protocol

from app.models.schemas import Finding, ScanRequest


class ScannerUnavailable(RuntimeError):
    pass


class ScannerService(Protocol):
    async def scan(self, request: ScanRequest) -> list[Finding]: ...


class SemgrepScannerService:
    async def scan(self, request: ScanRequest) -> list[Finding]:
        """Implement in an isolated runner with pinned rules and strict resource limits.

        Resolve repository IDs through trusted installation mappings. Fetch the exact
        commit into bounded ephemeral scratch, reject traversal/symlinks, disable
        networking and repository configs, and run a fixed argv without a shell.
        Store normalized findings in Supabase; destroy scratch at job completion.
        An unconfigured scanner must never return an empty (apparently clean) scan.
        """
        raise ScannerUnavailable("Isolated Semgrep runner has not been configured")
