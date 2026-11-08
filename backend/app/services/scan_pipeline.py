"""Injectable source and AI adapters. No repository execution in the API/worker."""

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol

from app.core.config import get_settings
from app.models.dispatch import ScanMetadata, ScanResult, SourceBundle
from app.models.schemas import ReviewMode
from app.services.adapter_errors import AdapterError
from app.services.ai_scanner import AIScanEngine as AIScanEngine
from app.services.context_review_engine import ContextReviewEngine
from app.services.coverage_ledger import legacy_diff_coverage, scanner_coverage
from app.services.github_source import GitHubSourceProvider as GitHubSourceProvider
from app.services.github_source import SourceUnavailable as SourceUnavailable
from app.services.github_source import authorize_repository
from app.services.graph_context import RemoteGraph
from app.services.remote_scanner import RemoteScannerSuite
from app.services.repository_snapshot import RepositorySnapshotProvider


class SourceProvider(Protocol):
    async def fetch(self, metadata: ScanMetadata) -> SourceBundle: ...


class ScanEngine(Protocol):
    async def analyze(self, metadata: ScanMetadata, source: SourceBundle) -> ScanResult: ...


class ScanPipeline:
    def __init__(self, source: SourceProvider, engine: ScanEngine):
        self.source = source
        self.engine = engine

    async def run(self, metadata: ScanMetadata) -> ScanResult:
        source = SourceBundle.model_validate(await self.source.fetch(metadata))
        if source.commit_sha != metadata.commit_sha:
            raise ValueError("Fetched source does not match the queued immutable commit")
        result = ScanResult.model_validate(await self.engine.analyze(metadata, source))
        if not result.coverage:
            result = result.model_copy(update={
                "review_mode": ReviewMode.legacy_ai,
                "coverage": [legacy_diff_coverage(metadata.commit_sha, source.files)],
            })
        return result


class ScannerPipeline:
    def __init__(
        self, snapshot=None, scanners=None, source=None, engine=None,
        graph=None, authorize=authorize_repository
    ):
        self.snapshot = snapshot or RepositorySnapshotProvider()
        settings = get_settings()
        self.scanners = scanners or (
            RemoteScannerSuite(str(settings.scanner_service_url))
            if settings.scanner_service_url
            else None
        )
        self.source = source or GitHubSourceProvider()
        self.engine = engine or ContextReviewEngine()
        self.graph = graph if graph is not None else (
            RemoteGraph(str(settings.scanner_service_url))
            if scanners is None and settings.scanner_service_url else None
        )
        self.authorize = authorize

    async def run(self, metadata: ScanMetadata) -> ScanResult:
        settings = get_settings()
        if self.scanners is None:
            raise AdapterError("scanner_unavailable")
        shared_root = "/scan-data" if settings.scanner_service_url else None
        with TemporaryDirectory(prefix="aegis-scan-", dir=shared_root) as directory:
            root = Path(directory) / "source"
            root.mkdir()
            snapshot = await self.snapshot.fetch_into(metadata, root)
            graph_task = (
                asyncio.create_task(self.graph.rank(snapshot, metadata))
                if self.graph else None
            )
            try:
                result = await self.scanners.scan(snapshot)
            except BaseException:
                if graph_task:
                    graph_task.cancel()
                raise
            graph_result = None
            if graph_task:
                try:
                    graph_result = await asyncio.wait_for(graph_task, timeout=5)
                except (Exception, asyncio.CancelledError):
                    # Context hints are optional; they never determine whether
                    # the scanner findings are complete.
                    graph_result = None
        findings = list(result.findings)
        engine_version = result.engine_version
        review_mode = ReviewMode.scanner_only
        coverage = [scanner_coverage(metadata.commit_sha, snapshot.paths)]
        if settings.ai_scanning_enabled:
            repo = await asyncio.to_thread(self.authorize, metadata)
            if repo.get("ai_scan_enabled") is True:
                source = await self.source.fetch(metadata)
                if source.commit_sha != metadata.commit_sha:
                    raise ValueError("Fetched AI source does not match the queued commit")
                ai_result = await self.engine.analyze(
                    metadata, source, findings, graph_result=graph_result
                )
                seen = {(f.rule_id, f.file_path, f.line) for f in findings}
                findings.extend(
                    f for f in ai_result.findings if (f.rule_id, f.file_path, f.line) not in seen
                )
                engine_version = (engine_version + "+" + ai_result.engine_version)[:100]
                review_mode = ReviewMode.automated
                if not ai_result.coverage:
                    raise AdapterError("source_incomplete")
                coverage.extend(ai_result.coverage)
        return ScanResult(
            findings=findings, engine_version=engine_version,
            review_mode=review_mode, coverage=coverage,
            context_graph=graph_result,
        )
