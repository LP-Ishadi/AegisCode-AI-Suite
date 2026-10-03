"""Send synthetic, signed GitHub events; never print secrets or response bodies."""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from dotenv import dotenv_values


def build_request(event: str, secret: str, tamper: bool = False) -> tuple[bytes, dict[str, str]]:
    payload = (
        {"zen": "AegisCode local webhook test"}
        if event == "ping"
        else {
            "action": "opened",
            "repository": {"id": 1, "full_name": "aegis-test/example"},
            "pull_request": {"number": 1, "head": {"sha": "a" * 40}},
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
    body, headers = build_request(args.event, secret, args.tamper)
    try:
        # Preserve the exact signed body; do not follow redirects to another host.
        response = httpx.post(
            args.url, content=body, headers=headers, timeout=15, follow_redirects=False
        )
    except httpx.HTTPError:
        print("Request failed. Check the backend, tunnel URL, network, and TLS configuration.")
        return 1
    expected = 401 if args.tamper else 200 if args.event == "ping" else 501
    matches = response.status_code == expected
    if matches and expected == 200:
        try:
            matches = response.json() == {"status": "pong"}
        except ValueError:
            matches = False
    if matches and expected in {401, 501}:
        try:
            detail = (
                "Invalid webhook signature"
                if expected == 401
                else "Durable scan dispatch is not implemented"
            )
            matches = response.json() == {"detail": detail}
        except ValueError:
            matches = False
    print(f"{'PASS' if matches else 'FAIL'}: HTTP {response.status_code}; expected {expected}.")
    if matches and expected == 501:
        print(
            "Signature and PR validation passed. Scan dispatch is not implemented; no scan queued."
        )
    return 0 if matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
