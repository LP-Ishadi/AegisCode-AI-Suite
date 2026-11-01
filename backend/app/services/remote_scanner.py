"""Send a disposable snapshot path to the unprivileged scanner service."""

from pathlib import Path

import httpx

from app.models.dispatch import ScanResult
from app.services.adapter_errors import AdapterError
from app.services.repository_snapshot import Snapshot


class RemoteScannerSuite:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    async def scan(self, snapshot: Snapshot) -> ScanResult:
        # The directory is a private shared volume; source bytes never enter logs or DB.
        if snapshot.root.parent.parent != Path("/scan-data"):
            raise AdapterError("scanner_unavailable")
        try:
            async with httpx.AsyncClient(timeout=200.0, trust_env=False) as client:
                response = await client.post(
                    self.url + "/scan",
                    json={
                        "directory": snapshot.root.parent.name,
                        "paths": sorted(snapshot.paths),
                        "commit_sha": snapshot.commit_sha,
                    },
                )
            if response.status_code == 422 and response.json().get("detail") == "source_incomplete":
                raise AdapterError("source_incomplete")
            response.raise_for_status()
            return ScanResult.model_validate(response.json())
        except AdapterError:
            raise
        except (httpx.HTTPError, ValueError):
            raise AdapterError("scanner_unavailable", retryable=True) from None
