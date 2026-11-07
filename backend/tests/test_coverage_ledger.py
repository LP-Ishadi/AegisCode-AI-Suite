from app.models.schemas import CoverageFileOutcome, CoverageStatus, ReviewMode
from app.services.coverage_ledger import ai_coverage, coverage_payload, scanner_coverage


def test_ai_ledger_distinguishes_supplied_read_and_omitted_files():
    sha = "a" * 40
    scope = {
        "commit": sha,
        "diff_lines": {"changed.py": [1], "large.py": [1]},
        "auto_context_paths": ["changed.py", "related.py"],
        "read_file_paths": ["large.py"],
    }
    coverage = ai_coverage(
        sha,
        ReviewMode.manual,
        scope,
        {"omitted": [{"path": "other.py", "reason": "budget_limit"}]},
        [],
    )
    outcomes = {item.path: item.outcome for item in coverage.files}
    assert outcomes == {
        "changed.py": CoverageFileOutcome.supplied_context,
        "large.py": CoverageFileOutcome.read_file,
        "other.py": CoverageFileOutcome.omitted,
        "related.py": CoverageFileOutcome.supplied_context,
    }
    assert coverage.status is CoverageStatus.complete
    payload = coverage_payload(coverage)
    assert payload["summary"]["omitted_count"] == 1
    assert payload["summary"]["read_count"] == 1
    assert "content" not in str(payload)


def test_pending_changed_file_marks_review_partial():
    sha = "a" * 40
    coverage = ai_coverage(
        sha,
        ReviewMode.automated,
        {"commit": sha, "diff_lines": {"large.py": [2]},
         "auto_context_paths": [], "read_file_paths": []},
        {"omitted": [{"path": "large.py", "reason": "file_too_large"}]},
        ["large.py"],
    )
    assert coverage.status is CoverageStatus.partial
    assert coverage.reason == "pending_changed_files"
    assert coverage.files[0].reason == "file_too_large"


def test_scanner_ledger_describes_acquired_snapshot_without_claiming_ai_read():
    coverage = scanner_coverage("a" * 40, frozenset({"a.py", "b.py"}))
    assert coverage.mode is ReviewMode.scanner_only
    assert coverage.status is CoverageStatus.complete
    assert all(item.outcome is CoverageFileOutcome.snapshot_acquired
               for item in coverage.files)
    assert coverage.read_files == []
