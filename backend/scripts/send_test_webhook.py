"""Send synthetic, signed GitHub events; never print secrets or response bodies."""

import argparse
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from dotenv import dotenv_values


def build_request(
    event: str,
    secret: str,
    tamper: bool = False,
    *,
    repository_id: int = 1,
    installation_id: int = 1,
    repository: str = "aegis-test/example",
) -> tuple[bytes, dict[str, str]]:
    payload = (
        {"zen": "AegisCode local webhook test"}
        if event == "ping"
        else {
            "action": "opened",
            "repository": {"id": repository_id, "full_name": repository},
            "installation": {"id": installation_id},
            "pull_request": {
                "number": 1,
                "title": "Synthetic webhook test",
                "user": {"login": "test-user"},
                "head": {"sha": "a" * 40, "ref": "feature"},
                "base": {"sha": "b" * 40, "ref": "main"},
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        }
    )
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": str(uuid4()),
        "X-Hub-Signature-256": "sha256=" + signature,
    }
    # Alter signed bytes to prove the server rejects tampering.
    return (body + b" " if tamper else body), headers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/webhooks/github")
    parser.add_argument("--event", choices=["ping", "pull_request"], default="ping")
    parser.add_argument("--tamper", action="store_true", help="Expect signature rejection (401)")
    parser.add_argument("--repository-id", type=int, default=1)
    parser.add_argument("--installation-id", type=int, default=1)
    parser.add_argument("--repository", default="aegis-test/example")
    args = parser.parse_args()
    url = urlsplit(args.url)
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or (url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"})
    ):
        parser.error(
            "Use an HTTPS endpoint, or HTTP on localhost, without credentials/query/fragment"
        )
    values = dotenv_values(Path(__file__).resolve().parents[2] / ".env", interpolate=False)
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", values.get("GITHUB_WEBHOOK_SECRET"))
    if not secret or secret.startswith(("REPLACE_", "YOUR_")):
        parser.error("Set a real GITHUB_WEBHOOK_SECRET in the root .env or process environment")
    body, headers = build_request(
        args.event,
        secret,
        args.tamper,
        repository_id=args.repository_id,
        installation_id=args.installation_id,
        repository=args.repository,
    )
    try:
        # Preserve the exact signed body; do not follow redirects to another host.
        response = httpx.post(
            args.url, content=body, headers=headers, timeout=15, follow_redirects=False
        )
    except httpx.HTTPError:
        print("Request failed. Check the backend, tunnel URL, network, and TLS configuration.")
        return 1
    expected = 401 if args.tamper else 200 if args.event == "ping" else 202
    matches = response.status_code == expected
    if matches and expected == 200:
        try:
            matches = response.json() == {"status": "pong"}
        except ValueError:
            matches = False
    if expected == 401 and matches:
        try:
            matches = response.json() == {"detail": "Invalid webhook signature"}
        except ValueError:
            matches = False
    if expected == 202:
        try:
            matches = response.status_code in {200, 202} and response.json().get("status") in {
                "queued",
                "duplicate",
            }
        except ValueError:
            matches = False
    print(
        f"{'PASS' if matches else 'FAIL'}: HTTP {response.status_code}; "
        f"expected {expected} (or 200 for a duplicate PR)."
    )
    if matches and expected == 202:
        print("Durable scan job recorded; the worker processes it separately.")
    return 0 if matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
