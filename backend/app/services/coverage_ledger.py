"""Bounded, content-free records of what a review actually received."""

from app.models.schemas import (
    CoverageFile,
    CoverageFileOutcome,
    CoverageStatus,
    ReviewCoverage,
    ReviewMode,
)


def scanner_coverage(commit_sha: str, paths: set[str] | frozenset[str]) -> ReviewCoverage:
    ordered = sorted(paths)
    return ReviewCoverage(
        mode=ReviewMode.scanner_only,
        status=CoverageStatus.complete,
        commit_sha=commit_sha,
        selected_files=ordered,
        supplied_files=ordered,
        scanner_stages={
            "source_snapshot": "completed",
            "semgrep": "completed",
            "trivy_filesystem": "completed",
            "trufflehog": "completed",
            "trivy_base_images": "completed",
        },
        files=[CoverageFile(path=path, outcome=CoverageFileOutcome.snapshot_acquired)
               for path in ordered],
    )


def ai_coverage(
    commit_sha: str,
    mode: ReviewMode,
    scope: dict,
    context: dict | None,
    pending: list[str],
) -> ReviewCoverage:
    if scope.get("commit") != commit_sha:
        raise ValueError("Coverage scope does not match review commit")
    outcomes: dict[str, CoverageFile] = {}
    for path in scope.get("diff_lines", {}):
        outcomes[path] = CoverageFile(path=path, outcome=CoverageFileOutcome.diff_only)
    for item in (context or {}).get("omitted", []):
        path = item["path"]
        outcomes[path] = CoverageFile(
            path=path,
            outcome=(CoverageFileOutcome.diff_only if path in outcomes
                     else CoverageFileOutcome.omitted),
            reason=item["reason"],
        )
    for path in scope.get("auto_context_paths", []):
        outcomes[path] = CoverageFile(path=path, outcome=CoverageFileOutcome.supplied_context)
    for path in scope.get("read_file_paths", []):
        outcomes[path] = CoverageFile(path=path, outcome=CoverageFileOutcome.read_file)
    files = [outcomes[path] for path in sorted(outcomes)]
    return ReviewCoverage(
        mode=mode,
        status=CoverageStatus.partial if pending else CoverageStatus.complete,
        commit_sha=commit_sha,
        selected_files=[item.path for item in files],
        supplied_files=[
            item.path for item in files if item.outcome is not CoverageFileOutcome.omitted
        ],
        read_files=sorted(set(scope.get("read_file_paths", []))),
        skipped=[{"path": item.path, "reason": item.reason}
                 for item in files if item.reason is not None],
        scanner_stages={"ai_review": "completed"},
        files=files,
        reason="pending_changed_files" if pending else None,
        selection=(context or {}).get("selection"),
        graph_status=(context or {}).get("graph", {}).get("status"),
    )


def failure_coverage(commit_sha: str, reason: str, *, pending: bool) -> ReviewCoverage:
    return ReviewCoverage(
        mode=ReviewMode.scanner_only,
        status=CoverageStatus.pending if pending else CoverageStatus.failed,
        commit_sha=commit_sha,
        scanner_stages={"worker_pipeline": "retrying" if pending else "failed"},
        reason=reason,
    )


def legacy_diff_coverage(commit_sha: str, paths: list[str]) -> ReviewCoverage:
    ordered = sorted(set(paths))
    return ReviewCoverage(
        mode=ReviewMode.legacy_ai,
        status=CoverageStatus.complete,
        commit_sha=commit_sha,
        selected_files=ordered,
        supplied_files=ordered,
        scanner_stages={"legacy_diff_review": "completed"},
        files=[CoverageFile(path=path, outcome=CoverageFileOutcome.diff_only)
               for path in ordered],
        reason="diff_only_scope",
    )


def coverage_payload(coverage: ReviewCoverage) -> dict:
    """Keep source text out of the database and large file lists out of summary."""
    return {
        "mode": coverage.mode.value,
        "status": coverage.status.value,
        "commit_sha": coverage.commit_sha,
        "summary": {
            "selected_count": len(coverage.selected_files),
            "supplied_count": len(coverage.supplied_files),
            "read_count": len(coverage.read_files),
            "omitted_count": len(coverage.skipped),
            "scanner_stages": coverage.scanner_stages,
            "reason": coverage.reason,
            "scope": "bounded_selected_files",
            "selection": coverage.selection,
            "graph_status": coverage.graph_status,
        },
        "files": [item.model_dump(mode="json") for item in coverage.files],
    }
