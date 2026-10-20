"""Injectable source and AI adapters. No repository execution in the API/worker."""

from typing import Protocol

from app.models.dispatch import ScanMetadata, ScanResult, SourceBundle
from app.services.ai_scanner import AIScanEngine as AIScanEngine
from app.services.github_source import GitHubSourceProvider as GitHubSourceProvider
from app.services.github_source import SourceUnavailable as SourceUnavailable


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
        return ScanResult.model_validate(await self.engine.analyze(metadata, source))
