import asyncio
import hashlib
import hmac
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from pydantic import ValidationError
from supabase_auth.errors import AuthApiError

from app.core.config import Settings
from app.core.security import UserContext, require_user, verify_webhook_signature
from app.main import create_app
from app.models.schemas import ScanRequest
from app.services.scanner_service import ScannerUnavailable, SemgrepScannerService

SECRET = "test-only-webhook-secret"
DELIVERY = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def client(monkeypatch):
    settings = Settings(_env_file=None, environment="test", github_webhook_secret=SECRET)
    monkeypatch.setattr("app.main.get_settings", lambda: settings)
    monkeypatch.setattr("app.api.webhooks.get_settings", lambda: settings)
    with TestClient(create_app()) as test_client:
        yield test_client


def signed_headers(body: bytes, event: str = "pull_request") -> dict[str, str]:
    signature = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return {
        "x-hub-signature-256": f"sha256={signature}",
        "x-github-delivery": DELIVERY,
        "x-github-event": event,
        "content-type": "application/json",
    }


def test_health_and_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", ["/api/v1/auth/me", "/api/v1/repos"])
def test_private_routes_require_auth(client, path):
    assert client.get(path).status_code == 401


def test_tampered_webhook_rejected(client):
    body = b'{"action":"opened"}'
    response = client.post(
        "/api/v1/webhooks/github", content=body + b" ", headers=signed_headers(body)
    )
    assert response.status_code == 401


@pytest.mark.parametrize("signature", [None, "", "sha1=abc", "sha256=wrong", "sha256=" + "z" * 64])
def test_invalid_signatures(signature):
    assert not verify_webhook_signature(b"payload", signature, SECRET)


def test_signed_ping(client):
    body = b"{}"
    response = client.post(
        "/api/v1/webhooks/github", content=body, headers=signed_headers(body, "ping")
    )
    assert response.json() == {"status": "pong"}


def test_oversized_webhook_rejected_before_validation(client):
    body = b"a" * (1_048_576 + 1)
    assert client.post("/api/v1/webhooks/github", content=body).status_code == 413


def test_invalid_signed_payload_is_redacted(client):
    body = b'{"secret":"do-not-echo"}'
    response = client.post("/api/v1/webhooks/github", content=body, headers=signed_headers(body))
    assert response.status_code == 422
    assert "do-not-echo" not in response.text


def test_scan_webhook_never_falsely_acknowledged(client, monkeypatch):
    from app.services.dispatch_service import DispatchUnavailable
    from scripts.send_test_webhook import build_request

    def unavailable(*args):
        raise DispatchUnavailable

    monkeypatch.setattr("app.api.webhooks.DispatchService.enqueue", unavailable)
    body, headers = build_request("pull_request", SECRET)
    assert client.post("/api/v1/webhooks/github", content=body, headers=headers).status_code == 503


def test_rejected_cors_origin(client):
    response = client.options(
        "/api/v1/repos",
        headers={
            "origin": "https://evil.example",
            "access-control-request-method": "GET",
        },
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_allowed_cors_origin(client):
    response = client.options(
        "/api/v1/repos",
        headers={
            "origin": "http://localhost:5173",
            "access-control-request-method": "GET",
        },
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_query_validation(client):
    client.app.dependency_overrides[require_user] = lambda: UserContext(
        user_id=UUID(DELIVERY),
        client=SimpleNamespace(),
    )
    assert client.get("/api/v1/repos?limit=101").status_code == 422


def test_production_requires_secrets():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="production")


def test_scan_rejects_arbitrary_paths_and_shell_inputs():
    with pytest.raises(ValidationError):
        ScanRequest(repository_id=DELIVERY, pull_request_number=1, commit_sha="$(bad)")
    with pytest.raises(ValidationError):
        ScanRequest(
            repository_id=DELIVERY, pull_request_number=1, commit_sha="a" * 40, path="../../etc"
        )


def test_scanner_stub_cannot_report_clean():
    request = ScanRequest(repository_id=DELIVERY, pull_request_number=1, commit_sha="a" * 40)
    with pytest.raises(ScannerUnavailable):
        asyncio.run(SemgrepScannerService().scan(request))


def test_bearer_is_verified_with_supabase(monkeypatch):
    tokens = []

    def get_user(token):
        tokens.append(token)
        return SimpleNamespace(user=SimpleNamespace(id=DELIVERY))

    fake = SimpleNamespace(auth=SimpleNamespace(get_user=get_user))
    monkeypatch.setattr("app.core.security.get_supabase_client", lambda token: fake)
    context = require_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials="test-jwt"))
    assert tokens == ["test-jwt"]
    assert context.user_id == UUID(DELIVERY)
    assert context.client is fake


def test_expired_bearer_is_rejected(monkeypatch):
    def get_user(token):
        raise AuthApiError("expired", 401, "bad_jwt")

    fake = SimpleNamespace(auth=SimpleNamespace(get_user=get_user))
    monkeypatch.setattr("app.core.security.get_supabase_client", lambda token: fake)
    with pytest.raises(HTTPException) as error:
        require_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials="expired-jwt"))
    assert error.value.status_code == 401


def test_user_database_client_never_uses_service_key(monkeypatch):
    from app.database.supabase_client import get_supabase_client

    settings = Settings(
        _env_file=None,
        environment="test",
        supabase_url="https://test.supabase.co",
        supabase_anon_key="public-key",
        supabase_service_key="privileged-key",
    )
    monkeypatch.setattr("app.database.supabase_client.get_settings", lambda: settings)
    captured = {}

    def factory(url, key, options):
        captured.update(url=url, key=key, options=options)
        return SimpleNamespace()

    monkeypatch.setattr("app.database.supabase_client.create_client", factory)
    get_supabase_client("user-jwt")
    assert captured["key"] == "public-key"
    assert captured["options"].headers["Authorization"] == "Bearer user-jwt"
    assert captured["options"].persist_session is False


@pytest.mark.parametrize(
    "event,tamper,expected",
    [
        ("ping", False, 200),
        ("ping", True, 401),
        ("pull_request", False, 202),
    ],
)
def test_helper_requests_through_forwarded_host(client, monkeypatch, event, tamper, expected):
    monkeypatch.setattr(
        "app.api.webhooks.DispatchService.enqueue",
        lambda *args: {"status": "queued", "scan_id": DELIVERY},
    )
    from scripts.send_test_webhook import build_request

    body, headers = build_request(event, SECRET, tamper)
    headers.update({"host": "example.ngrok-free.app", "x-forwarded-proto": "https"})
    response = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    assert response.status_code == expected


def test_signature_matches_github_reference_vector():
    signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    assert verify_webhook_signature(b"Hello, World!", signature, "It's a Secret to Everybody")
