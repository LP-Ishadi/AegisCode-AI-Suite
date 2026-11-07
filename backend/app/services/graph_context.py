"""Build graph routing hints through the unprivileged scanner service."""

import httpx

from app.core.config import get_settings
from app.models.dispatch import ScanMetadata
from app.services.adapter_errors import AdapterError
from app.services.github_source import GitHubAPI
from app.services.repository_snapshot import Snapshot, safe_path


class RemoteGraph:
    def __init__(self, url: str, *, api: GitHubAPI | None = None):
        self.url = url.rstrip("/")
        self.api = api or GitHubAPI(get_settings())

    async def rank(self, snapshot: Snapshot, metadata: ScanMetadata) -> dict | None:
        """Return None on graph failure; scanner findings remain independent."""
        try:
            token = await self.api.installation_token(metadata)
            compare = await self.api.request(
                "GET",
                f"/repos/{metadata.repository_full_name}/compare/"
                f"{metadata.base_sha}...{metadata.commit_sha}?per_page=100",
                token,
            )
            if not isinstance(compare, dict):
                return None
            files = compare.get("files")
            if not isinstance(files, list) or len(files) > 80:
                return None
            changed = []
            for item in files:
                if not isinstance(item, dict):
                    return None
                if item.get("status") == "removed":
                    continue
                path = item.get("filename")
                if not isinstance(path, str) or not safe_path(path) or path not in snapshot.paths:
                    return None
                changed.append(path)
            if not changed:
                return None
            async with httpx.AsyncClient(timeout=80.0, trust_env=False) as client:
                response = await client.post(
                    self.url + "/graph/related",
                    json={
                        "directory": snapshot.root.parent.name,
                        "paths": sorted(snapshot.paths),
                        "commit_sha": snapshot.commit_sha,
                        "changed_paths": changed,
                    },
                )
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                return None
            candidates = result.get("candidates")
            if result.get("commit") != metadata.commit_sha or not isinstance(candidates, list):
                return None
            if len(candidates) > 32 or any(
                not isinstance(item, dict) or item.get("path") not in snapshot.paths
                for item in candidates
            ):
                return None
            return result
        except (AdapterError, ValueError, KeyError, TypeError, httpx.HTTPError):
            return None
