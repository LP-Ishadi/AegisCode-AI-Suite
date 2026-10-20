import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest
from postgrest.exceptions import APIError
from test_dispatch import event_data, metadata, queue

from app.core.config import Settings
from app.models.dispatch import PRDispatchEvent, ScanResult
from app.models.schemas import Finding
from app.services.adapter_errors import AdapterError
from app.services.ai_scanner import AIScanEngine, Analysis
from app.services.dispatch_service import (
    DispatchService,
    DispatchUnavailable,
    RepositoryNotConnected,
)
from app.services.github_source import GitHubAPI, GitHubSourceProvider, source_from_compare
from app.services.scan_pipeline import ScanPipeline
from app.workers.scan_worker import process_one


def settings():
    return Settings(
        _env_file=None,
        environment="test",
        github_app_id="123",
        github_app_private_key_b64="dGVzdA==",
        ai_scanning_enabled=True,
        openai_api_key="test-only",
    )


def compare():
    return {
        "base_commit": {"sha": "b" * 40},
        "commits": [{"sha": "a" * 40}],
        "total_commits": 1,
        "files": [
            {
                "filename": "app.py",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": "@@ -1 +1 @@\n-old\n+eval(user_input)",
            }
        ],
    }


def finding(**kwargs):
    return Finding(
        rule_id="code-injection",
        file_path="app.py",
        line=1,
        severity="high",
        message="Untrusted input reaches eval.",
        **kwargs,
    )


def ai_factory(findings=None, status="completed"):
    parse = AsyncMock(
        return_value=SimpleNamespace(status=status, output_parsed=Analysis(findings=findings or []))
    )
    client = AsyncMock()
    client.__aenter__.return_value = SimpleNamespace(responses=SimpleNamespace(parse=parse))
    return Mock(return_value=client), parse


def test_real_adapters_through_worker_persist_findings():
    requests = []

    def handle(request):
        requests.append(request)
        path = request.url.path
        if path.endswith("/installation"):
            return httpx.Response(200, json={"id": metadata().installation_id})
        if path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "installation-test-token"})
        if path.startswith("/repositories/"):
            return httpx.Response(
                200, json={"id": metadata().github_repository_id, "full_name": "aegis-test/example"}
            )
        assert "/compare/" in path
        return httpx.Response(200, json=compare())

    authorize = Mock()
    source = GitHubSourceProvider(
        settings(), transport=httpx.MockTransport(handle), authorize=authorize
    )
    source.api.app_token = Mock(return_value="app-test-jwt")
    factory, parse = ai_factory([finding()])
    jobs = queue()
    asyncio.run(
        process_one(jobs, ScanPipeline(source, AIScanEngine(settings(), client_factory=factory)))
    )
    result = jobs.finish.call_args.kwargs["result"]
    assert isinstance(result, ScanResult) and result.findings == [finding()]
    assert jobs.finish.call_args.kwargs["error"] is None
    authorize.assert_called_once()
    assert all(r.url.host == "api.github.com" for r in requests)
    assert parse.call_args.kwargs["store"] is False
    assert parse.call_args.kwargs["max_output_tokens"] == 6000


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(total_commits=101),
        lambda d: d["files"][0].pop("patch"),
        lambda d: d["files"][0].update(patch="@@ -1 +1 @@\n-old"),
        lambda d: d["commits"][0].update(sha="c" * 40),
        lambda d: d["files"][0].update(filename="../secret"),
    ],
)
def test_incomplete_or_unsafe_sources_fail_closed(mutation):
    data = compare()
    mutation(data)
    with pytest.raises(AdapterError):
        source_from_compare(metadata(), data, settings())


def test_secret_redacted_before_ai_and_locally_reported():
    data = compare()
    data["files"][0]["patch"] = '@@ -1 +1 @@\n-old\n+password = "secret-test-value"'
    source = source_from_compare(metadata(), data, settings())
    assert "secret-test-value" not in source.diff
    assert source.local_findings[0].rule_id == "aegis.hardcoded-secret"
    factory, _ = ai_factory()
    result = asyncio.run(
        AIScanEngine(settings(), client_factory=factory).analyze(metadata(), source)
    )
    assert len(result.findings) == 1


@pytest.mark.parametrize("status,line", [("incomplete", 1), ("completed", 999)])
def test_untrusted_model_output_cannot_complete(status, line):
    factory, _ = ai_factory([finding().model_copy(update={"line": line})], status=status)
    source = source_from_compare(metadata(), compare(), settings())
    with pytest.raises(AdapterError, match="invalid_ai_output"):
        asyncio.run(AIScanEngine(settings(), client_factory=factory).analyze(metadata(), source))


def test_ai_disabled_never_calls_provider():
    config = settings()
    config.ai_scanning_enabled = False
    factory, _ = ai_factory()
    with pytest.raises(AdapterError, match="ai_not_authorized"):
        asyncio.run(
            AIScanEngine(config, client_factory=factory).analyze(
                metadata(), source_from_compare(metadata(), compare(), config)
            )
        )
    factory.assert_not_called()


def test_redirects_are_not_followed():
    handle = Mock(return_value=httpx.Response(302, headers={"Location": "http://localhost/secret"}))
    api = GitHubAPI(settings(), httpx.MockTransport(handle))
    with pytest.raises(AdapterError, match="github_access_denied"):
        asyncio.run(api.request("GET", "/repos/owner/repo", "test"))
    assert handle.call_count == 1


def test_rate_limit_is_retryable():
    api = GitHubAPI(settings(), httpx.MockTransport(lambda _: httpx.Response(429)))
    with pytest.raises(AdapterError) as error:
        asyncio.run(api.request("GET", "/repos/owner/repo", "test"))
    assert error.value.retryable


@pytest.mark.parametrize(
    "code,message,expected",
    [
        ("PT403", "Repository installation is not connected", RepositoryNotConnected),
        ("42501", "Repository installation is not connected", RepositoryNotConnected),
        ("42501", "permission denied for table repositories", DispatchUnavailable),
    ],
)
def test_database_permission_failure_is_not_mislabeled_mapping(
    monkeypatch, code, message, expected
):
    client = Mock()
    client.rpc.return_value.execute.side_effect = APIError(
        {"code": code, "message": message, "details": None, "hint": None}
    )
    monkeypatch.setattr("app.services.dispatch_service.get_service_client", lambda: client)
    with pytest.raises(expected):
        DispatchService().enqueue(uuid4(), PRDispatchEvent.model_validate(event_data()))


def test_worker_persists_adapter_failure_and_retryability():
    jobs = queue()
    pipeline = SimpleNamespace(
        run=AsyncMock(side_effect=AdapterError("upstream_unavailable", retryable=True))
    )
    asyncio.run(process_one(jobs, pipeline))
    assert jobs.finish.call_args.kwargs["error"] == "upstream_unavailable"
    assert jobs.finish.call_args.kwargs["retryable"] is True


def test_repository_opt_in_checked_before_github_requests():
    handle = Mock()
    source = GitHubSourceProvider(
        settings(),
        transport=httpx.MockTransport(handle),
        authorize=Mock(side_effect=AdapterError("ai_not_authorized")),
    )
    with pytest.raises(AdapterError, match="ai_not_authorized"):
        asyncio.run(source.fetch(metadata()))
    handle.assert_not_called()


def test_installation_mismatch_never_mints_token():
    handle = Mock(return_value=httpx.Response(200, json={"id": metadata().installation_id + 1}))
    api = GitHubAPI(settings(), httpx.MockTransport(handle))
    api.app_token = Mock(return_value="test")
    with pytest.raises(AdapterError, match="repository_not_connected"):
        asyncio.run(api.installation_token(metadata()))
    assert handle.call_count == 1
