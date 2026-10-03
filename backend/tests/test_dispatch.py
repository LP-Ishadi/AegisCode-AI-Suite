import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app
from app.models.dispatch import PRDispatchEvent, ScanMetadata, ScanResult, SourceBundle
from app.services.dispatch_service import DispatchUnavailable, RepositoryNotConnected
from app.services.scan_pipeline import AIScanEngine, GitHubSourceProvider, ScanPipeline
from app.workers.scan_worker import process_one
from scripts.send_test_webhook import build_request


def event_data():
    return json.loads(build_request("pull_request", "test-secret")[0])


def metadata():
    return ScanMetadata.from_event(PRDispatchEvent.model_validate(event_data()))


def test_metadata_ignores_injected_urls_and_preserves_revisions():
    data = event_data()
    data["repository"]["clone_url"] = "http://169.254.169.254/secrets"
    data["pull_request"]["patch_url"] = "http://evil.example/patch"
    data["pull_request"]["head"]["repo"] = {"id": 2, "full_name": "fork-owner/example"}
    result = ScanMetadata.from_event(PRDispatchEvent.model_validate(data))
    assert result.clone_url == "https://github.com/aegis-test/example.git"
    assert result.head_clone_url == "https://github.com/fork-owner/example.git"
    assert result.patch_url.startswith("https://github.com/")
    assert result.commit_sha == "a" * 40
    assert result.base_sha == "b" * 40


def test_merge_uses_merge_commit_and_requires_it():
    data = event_data()
    data["action"] = "closed"
    data["pull_request"]["merged"] = True
    with pytest.raises(ValidationError):
        PRDispatchEvent.model_validate(data)
    data["pull_request"]["merge_commit_sha"] = "c" * 40
    result = ScanMetadata.from_event(PRDispatchEvent.model_validate(data))
    assert result.commit_sha == "c" * 40
    assert result.head_sha == "a" * 40


@pytest.mark.parametrize(
    "action,merged,expected",
    [
        ("opened", False, 202),
        ("synchronize", False, 202),
        ("reopened", False, 202),
        ("ready_for_review", False, 202),
        ("closed", True, 202),
        ("closed", False, 200),
        ("labeled", False, 200),
        ("merged", False, 200),
    ],
)
def test_webhook_routing(monkeypatch, action, merged, expected):
    import hashlib
    import hmac

    data = event_data()
    data["action"] = action
    data["pull_request"].update(merged=merged, merge_commit_sha="c" * 40 if merged else None)
    body = json.dumps(data).encode()
    headers = build_request("pull_request", "test-secret")[1]
    headers["X-Hub-Signature-256"] = (
        "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    )
    settings = Settings(_env_file=None, environment="test", github_webhook_secret="test-secret")
    monkeypatch.setattr("app.api.webhooks.get_settings", lambda: settings)
    enqueue = Mock(return_value={"status": "queued", "scan_id": str(uuid4())})
    monkeypatch.setattr("app.api.webhooks.DispatchService.enqueue", enqueue)
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    assert response.status_code == expected
    assert enqueue.call_count == (1 if expected == 202 else 0)


@pytest.mark.parametrize(
    "failure,expected",
    [
        (RepositoryNotConnected, 403),
        (DispatchUnavailable, 503),
    ],
)
def test_dispatch_errors_are_not_acknowledged(monkeypatch, failure, expected):
    settings = Settings(_env_file=None, environment="test", github_webhook_secret="test-secret")
    monkeypatch.setattr("app.api.webhooks.get_settings", lambda: settings)
    monkeypatch.setattr("app.api.webhooks.DispatchService.enqueue", Mock(side_effect=failure))
    body, headers = build_request("pull_request", "test-secret")
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    assert response.status_code == expected


def queue():
    return SimpleNamespace(
        claim=Mock(
            return_value={
                "id": str(uuid4()),
                "scan_id": str(uuid4()),
                "lease_token": str(uuid4()),
                "payload": metadata().model_dump(mode="json"),
            }
        ),
        finish=Mock(return_value=True),
    )


def test_worker_hands_source_to_engine_and_persists_result():
    source = SourceBundle(commit_sha="a" * 40, diff="test diff", files=["api.py"])
    provider = SimpleNamespace(fetch=AsyncMock(return_value=source))
    result = ScanResult(findings=[], engine_version="test-engine")
    engine = SimpleNamespace(analyze=AsyncMock(return_value=result))
    jobs = queue()
    assert asyncio.run(process_one(jobs, ScanPipeline(provider, engine)))
    engine.analyze.assert_awaited_once_with(
        ScanMetadata.model_validate(jobs.claim.return_value["payload"]), source
    )
    assert jobs.finish.call_args.kwargs["result"] == result
    assert jobs.finish.call_args.kwargs["error"] is None


def test_unconfigured_pipeline_fails_instead_of_reporting_clean():
    jobs = queue()
    asyncio.run(process_one(jobs, ScanPipeline(GitHubSourceProvider(), AIScanEngine())))
    assert jobs.finish.call_args.kwargs["error"] == "adapter_unavailable"
    assert jobs.finish.call_args.kwargs["retryable"] is False


def test_mismatched_commit_never_reaches_engine():
    source = SimpleNamespace(
        fetch=AsyncMock(return_value=SourceBundle(commit_sha="b" * 40, diff="wrong revision"))
    )
    engine = SimpleNamespace(analyze=AsyncMock())
    jobs = queue()
    asyncio.run(process_one(jobs, ScanPipeline(source, engine)))
    engine.analyze.assert_not_awaited()
    assert jobs.finish.call_args.kwargs["error"] == "invalid_input"


def test_worker_timeout_retries():
    jobs = queue()
    pipeline = SimpleNamespace(run=AsyncMock(side_effect=TimeoutError))
    asyncio.run(process_one(jobs, pipeline))
    assert jobs.finish.call_args.kwargs["error"] == "timeout"
    assert jobs.finish.call_args.kwargs["retryable"] is True


def test_idle_worker_does_not_run_engine():
    jobs = queue()
    jobs.claim.return_value = None
    pipeline = SimpleNamespace(run=AsyncMock())
    assert not asyncio.run(process_one(jobs, pipeline))
    pipeline.run.assert_not_awaited()
