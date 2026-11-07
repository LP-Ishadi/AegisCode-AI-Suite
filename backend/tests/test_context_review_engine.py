import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from app.models.dispatch import ScanMetadata, ScanResult, SourceBundle
from app.models.schemas import CoverageStatus, Finding, ReviewCoverage, ReviewMode
from app.services.adapter_errors import AdapterError
from app.services.context_review_engine import ContextReviewEngine
from app.services.manual_review import RepositoryTools, prepared_prompt, prompt
from app.services.repository_snapshot import Snapshot
from app.services.review_evidence import scanner_evidence
from app.services.scan_pipeline import ScannerPipeline


def metadata():
    return ScanMetadata.model_construct(
        repository_full_name="owner/repo",
        pull_request_number=3,
        commit_sha="a" * 40,
        base_sha="b" * 40,
    )


def settings():
    return SimpleNamespace(
        ai_scanning_enabled=True,
        openai_api_key=SecretStr("fake-key"),
        openai_model="test-model",
    )


def fake_client(replies):
    client = MagicMock()
    client.responses.parse = AsyncMock(
        side_effect=[SimpleNamespace(status="completed", output_parsed=reply) for reply in replies]
    )
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def test_scanner_evidence_keeps_counts_when_samples_are_bounded():
    findings = [
        Finding(
            rule_id=f"trivy.image.CVE-{number}.libc",
            file_path="Dockerfile",
            line=1,
            severity="high",
            message="Image package advisory",
        )
        for number in range(25)
    ]
    findings.append(
        Finding(
            rule_id="semgrep.auth-check",
            file_path="app/auth.py",
            line=3,
            severity="critical",
            message="Missing authorization check",
        )
    )
    evidence = scanner_evidence(findings)
    assert evidence["counts"]["image"] == 25
    assert evidence["counts"]["code"] == 1
    assert evidence["omitted_findings"] == 17
    assert len(evidence["sampled_findings"]) == 9
    assert any(item["rule_id"] == "semgrep.auth-check" for item in evidence["sampled_findings"])


def test_manual_prompt_includes_scanner_evidence():
    meta = metadata()
    source = SourceBundle.model_construct(commit_sha=meta.commit_sha, diff="[]", local_findings=[])
    tools = RepositoryTools(meta)
    tools.paths = []
    finding = Finding(
        rule_id="trivy.CVE-123.openssl",
        file_path="requirements.txt",
        line=1,
        severity="high",
        message="Package advisory",
    )
    request = asyncio.run(prepared_prompt(meta, source, tools, [finding]))
    assert request["scanner_evidence"]["counts"]["dependency"] == 1
    assert request["scanner_evidence"]["sampled_findings"][0]["rule_id"] == finding.rule_id


def test_automated_review_rejects_early_final_then_reads_file():
    meta = metadata()
    source = SourceBundle.model_construct(commit_sha=meta.commit_sha, diff="[]", local_findings=[])
    finding = Finding(
        rule_id="semgrep.auth-check",
        file_path="app/auth.py",
        line=3,
        severity="high",
        message="Missing authorization check",
    )
    client = fake_client(
        [
            {"kind": "final", "findings": []},
            {"kind": "tool", "tool": {"name": "read_file", "path": "app/auth.py"}},
            {"kind": "final", "findings": []},
        ]
    )
    tools = MagicMock()
    tools.ready = AsyncMock()
    tools.execute = AsyncMock(
        return_value={"path": "app/auth.py", "commit": meta.commit_sha, "content": "pass"}
    )
    request = prompt(
        meta,
        source.diff,
        step=0,
        scanner_evidence=scanner_evidence([finding]),
        evidence_scope={
            "commit": meta.commit_sha,
            "diff_lines": {},
            "auto_context_paths": [],
            "read_file_paths": [],
        },
    )
    with (
        patch("app.services.context_review_engine.RepositoryTools", return_value=tools),
        patch(
            "app.services.context_review_engine.prepared_prompt",
            new=AsyncMock(return_value=request),
        ) as prepare,
        patch(
            "app.services.context_review_engine.checked_findings",
            new=AsyncMock(return_value=[]),
        ),
    ):
        result = asyncio.run(
            ContextReviewEngine(settings(), client_factory=lambda **_: client).analyze(
                meta, source, [finding]
            )
        )
    assert result.findings == []
    assert result.engine_version == "openai-context/test-model"
    assert client.responses.parse.await_count == 3
    prepare.assert_awaited_once_with(meta, source, tools, [finding], graph_result=None)
    tools.execute.assert_awaited_once()


def test_automated_review_fails_closed_when_no_file_is_read():
    meta = metadata()
    source = SourceBundle.model_construct(commit_sha=meta.commit_sha, diff="[]", local_findings=[])
    client = fake_client([{"kind": "final", "findings": []}] * 5)
    tools = MagicMock()
    tools.ready = AsyncMock()
    request = prompt(meta, source.diff, step=0)
    with (
        patch("app.services.context_review_engine.RepositoryTools", return_value=tools),
        patch(
            "app.services.context_review_engine.prepared_prompt",
            new=AsyncMock(return_value=request),
        ),
    ):
        with pytest.raises(AdapterError) as error:
            asyncio.run(
                ContextReviewEngine(settings(), client_factory=lambda **_: client).analyze(
                    meta, source, []
                )
            )
    assert error.value.code == "invalid_ai_output"
    tools.execute.assert_not_called()


def test_pipeline_passes_scanner_findings_to_automated_review():
    meta = metadata()
    finding = Finding(
        rule_id="semgrep.auth-check",
        file_path="app/auth.py",
        line=3,
        severity="high",
        message="Missing authorization check",
    )
    source = SourceBundle.model_construct(commit_sha=meta.commit_sha, diff="[]", local_findings=[])
    snapshot = MagicMock()

    async def fetch_into(_metadata, root):
        return Snapshot(root, frozenset(), meta.commit_sha)

    snapshot.fetch_into = fetch_into
    scanners = MagicMock()
    scanners.scan = AsyncMock(
        return_value=ScanResult(findings=[finding], engine_version="scanner-suite-test")
    )
    source_provider = MagicMock()
    source_provider.fetch = AsyncMock(return_value=source)
    engine = MagicMock()
    engine.analyze = AsyncMock(
        return_value=ScanResult(
            findings=[],
            engine_version="openai-context/test-model",
            review_mode=ReviewMode.automated,
            coverage=[ReviewCoverage(
                mode=ReviewMode.automated,
                status=CoverageStatus.complete,
                commit_sha=meta.commit_sha,
            )],
        )
    )
    config = settings()
    config.scanner_service_url = None
    with patch("app.services.scan_pipeline.get_settings", return_value=config):
        pipeline = ScannerPipeline(
            snapshot=snapshot,
            scanners=scanners,
            source=source_provider,
            engine=engine,
            authorize=lambda _: {"ai_scan_enabled": True},
        )
        result = asyncio.run(pipeline.run(meta))
    engine.analyze.assert_awaited_once_with(meta, source, [finding], graph_result=None)
    assert result.findings == [finding]
    assert result.engine_version == "scanner-suite-test+openai-context"
