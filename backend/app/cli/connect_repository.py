"""Verify a GitHub App installation and explicitly map its repository to a tenant."""

import argparse
import asyncio
from uuid import UUID

from app.core.config import get_settings
from app.database.supabase_client import get_service_client
from app.models.dispatch import RepositoryRef
from app.services.adapter_errors import AdapterError
from app.services.github_source import GitHubAPI


async def connect(organization_id: UUID, repository: str, enable_ai: bool) -> dict:
    # No user-supplied tenant information from a webhook is trusted here.
    RepositoryRef(id=1, full_name=repository)
    api = GitHubAPI(get_settings())
    installation = await api.request("GET", f"/repos/{repository}/installation", api.app_token())
    installation_id = installation.get("id")
    if not isinstance(installation_id, int) or installation_id <= 0:
        raise AdapterError("github_access_denied")
    token_data = await api.request(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        api.app_token(),
        {
            "repositories": [repository.split("/")[1]],
            "permissions": {"contents": "read", "pull_requests": "read"},
        },
    )
    token = token_data.get("token")
    if not isinstance(token, str) or not token:
        raise AdapterError("github_access_denied")
    repo = RepositoryRef.model_validate(await api.request("GET", f"/repos/{repository}", token))
    # The RPC refuses to move a repository from a different organization.
    return (
        get_service_client()
        .rpc(
            "connect_github_repository",
            {
                "p_organization_id": str(organization_id),
                "p_github_id": repo.id,
                "p_full_name": repo.full_name,
                "p_installation_id": installation_id,
                "p_enable_ai": enable_ai,
            },
        )
        .execute()
        .data
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization-id", type=UUID, required=True)
    parser.add_argument("--repository", required=True, help="owner/repository")
    parser.add_argument(
        "--enable-ai",
        action="store_true",
        help="Authorize sending redacted diffs from this repo to OpenAI",
    )
    args = parser.parse_args()
    try:
        result = asyncio.run(connect(args.organization_id, args.repository, args.enable_ai))
    except Exception:
        # Provider errors can contain credentials or payloads; never echo their text.
        parser.exit(
            1,
            "Connection failed. Check GitHub App credentials/permissions, organization "
            "UUID, migrations, and existing repository ownership.\n",
        )
    print(f"Connected repository id={result['id']} ai_scan_enabled={result['ai_scan_enabled']}")


if __name__ == "__main__":
    main()
