import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from app.models.dispatch import ScanMetadata, ScanResult
from app.models.schemas import (
    CoverageStatus,
    EvidenceReference,
    EvidenceStatus,
    Finding,
    FindingOrigin,
    ReviewCoverage,
    ReviewMode,
)
from app.services.manual_review import checked_findings
from app.workers.scan_worker import ScanQueue


def test_old_finding_and_scan_result_use_scanner_defaults():
    old_row = {
        "rule_id": "semgrep.test",
        "file_path": "app.py",
        "line": 2,
        "severity": "high",
        "message": "Review this code",
    }
    finding = Finding.model_validate(old_row)
    result = ScanResult(findings=[finding], engine_version="old-scanner")
    assert finding.origin is FindingOrigin.scanner
    assert finding.review_mode is ReviewMode.scanner_only
    assert finding.evidence_status is EvidenceStatus.scanner_reported
    assert result.review_mode is ReviewMode.scanner_only


def test_manual_validator_assigns_ai_origin_even_if_response_claims_scanner():
    metadata = ScanMetadata.model_construct(commit_sha="a" * 40)
    tools = SimpleNamespace(
        read_file=AsyncMock(
            return_value={
                "path": "app.py",
                "commit": metadata.commit_sha,
                "content": "print('ok')\n",
            }
        )
    )
    reply = Finding(
        rule_id="security.issue",
        file_path="app.py",
        line=1,
        severity="medium",
        message="Review this behavior",
        evidence=[
            EvidenceReference(
                commit_sha=metadata.commit_sha,
                file_path="app.py",
                line=1,
                role="changed_code",
                source="read_file",
            )
        ],
    )
    scope = {
        "commit": metadata.commit_sha,
        "diff_lines": {},
        "auto_context_paths": [],
        "read_file_paths": ["app.py"],
    }
    checked = asyncio.run(checked_findings(metadata, [reply], tools, evidence_scope=scope))
    assert checked[0].origin is FindingOrigin.ai
    assert checked[0].review_mode is ReviewMode.manual
    assert checked[0].evidence_status is EvidenceStatus.location_checked
    assert checked[0].file_path == "app.py"


def test_coverage_and_evidence_contracts_reject_unpinned_locations():
    coverage = ReviewCoverage(
        mode="scanner_only",
        status="complete",
        commit_sha="a" * 40,
        selected_files=["app.py"],
        supplied_files=[],
        read_files=[],
    )
    assert coverage.status is CoverageStatus.complete
    with pytest.raises(ValidationError):
        EvidenceReference(
            commit_sha="main",
            file_path="app.py",
            line=1,
            role="changed_code",
            source="diff",
        )
    with pytest.raises(ValidationError):
        ReviewCoverage(mode="scanner_only", status="safe", commit_sha="a" * 40)


def test_worker_uses_versioned_rpc_and_persists_review_mode():
    finding = Finding(
        rule_id="ai.test",
        file_path="app.py",
        line=1,
        severity="high",
        message="Review this behavior",
        origin=FindingOrigin.ai,
        review_mode=ReviewMode.automated,
        evidence_status=EvidenceStatus.location_checked,
    )
    result = ScanResult(
        findings=[finding],
        engine_version="context-test",
        review_mode=ReviewMode.automated,
    )
    client = MagicMock()
    client.rpc.return_value.execute.return_value.data = True
    with patch("app.workers.scan_worker.get_service_client", return_value=client):
        assert ScanQueue().finish("job", "lease", commit_sha="a" * 40, result=result)
    name, payload = client.rpc.call_args.args
    assert name == "finish_scan_job_v3"
    assert payload["p_review_mode"] == "automated"
    assert payload["p_findings"][0]["origin"] == "ai"


def test_worker_persists_failure_coverage_when_result_is_incomplete():
    client = MagicMock()
    client.rpc.return_value.execute.return_value.data = True
    incomplete = ScanResult(findings=[], engine_version="test", coverage=[])
    with patch("app.workers.scan_worker.get_service_client", return_value=client):
        assert ScanQueue().finish(
            "job", "lease", commit_sha="a" * 40,
            result=incomplete, error="source_incomplete",
        )
    _, payload = client.rpc.call_args.args
    assert payload["p_findings"] == []
    assert payload["p_coverage"][0]["status"] == "failed"
    assert payload["p_coverage"][0]["summary"]["reason"] == "source_incomplete"
