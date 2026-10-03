"""Injectable source and AI adapters. No repository execution in the API/worker."""

from typing import Protocol

from app.models.dispatch import ScanMetadata, ScanResult, SourceBundle
from app.services.ai_service import AIServiceUnavailable


class SourceUnavailable(RuntimeError):
    pass


class SourceProvider(Protocol):
    async def fetch(self, metadata: ScanMetadata) -> SourceBundle: ...


class ScanEngine(Protocol):
    async def analyze(self, metadata: ScanMetadata, source: SourceBundle) -> ScanResult: ...


class GitHubSourceProvider:
    async def fetch(self, metadata: ScanMetadata) -> SourceBundle:
        """Implement installation-token acquisition and immutable compare fetching.

        Verify installation/repository IDs, permit api.github.com only, disallow
        redirects, bound response sizes and time, redact secrets and reject unsafe
        paths. PR .patch/.diff URLs are metadata only: they move with new commits.
        Handle forks and compare truncation explicitly; never claim a partial scan
        is complete. No clone/subprocess or disk persistence in this stub.
        """
        raise SourceUnavailable("GitHub source acquisition adapter is not configured")


class AIScanEngine:
    async def analyze(self, metadata: ScanMetadata, source: SourceBundle) -> ScanResult:
        """Wire redacted source to OpenAI/Claude after tenant opt-in and budgeting.

        Treat code as data, validate structured output, never execute model output.
        Returning zero findings must mean the configured engine really ran.
        """
        raise AIServiceUnavailable("AI scan adapter is not configured")


class ScanPipeline:
    def __init__(self, source: SourceProvider, engine: ScanEngine):
        self.source = source
        self.engine = engine

    async def run(self, metadata: ScanMetadata) -> ScanResult:
        source = SourceBundle.model_validate(await self.source.fetch(metadata))
        if source.commit_sha != metadata.commit_sha:
            raise ValueError("Fetched source does not match the queued immutable commit")
        return ScanResult.model_validate(await self.engine.analyze(metadata, source))
