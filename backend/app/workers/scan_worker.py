"""Run with python -m app.workers.scan_worker [--once]. Supabase is the durable queue."""

import argparse
import asyncio
import logging

from httpx import HTTPError
from pydantic import ValidationError

from app.database.supabase_client import get_service_client
from app.models.dispatch import ScanJob, ScanResult
from app.services.ai_service import AIServiceUnavailable
from app.services.scan_pipeline import (
    AIScanEngine,
    GitHubSourceProvider,
    ScanPipeline,
    SourceUnavailable,
)

logger = logging.getLogger(__name__)


class ScanQueue:
    def claim(self) -> dict | None:
        return get_service_client().rpc("claim_scan_job").execute().data

    def finish(
        self,
        job_id: str,
        lease_token: str,
        *,
        result: ScanResult | None = None,
        error: str | None = None,
        retryable: bool = False,
    ) -> bool:
        return (
            get_service_client()
            .rpc(
                "finish_scan_job",
                {
                    "p_job_id": job_id,
                    "p_lease_token": lease_token,
                    "p_findings": [f.model_dump(mode="json") for f in result.findings]
                    if result
                    else [],
                    "p_engine_version": result.engine_version if result else None,
                    "p_error_code": error,
                    "p_retryable": retryable,
                },
            )
            .execute()
            .data
            is True
        )


async def process_one(queue: ScanQueue, pipeline: ScanPipeline) -> bool:
    raw = await asyncio.to_thread(queue.claim)
    if not raw:
        return False
    result = None
    error = None
    retryable = False
    try:
        job = ScanJob.model_validate(raw)
        # Keep the hard work deadline well inside the 300-second DB lease.
        result = await asyncio.wait_for(pipeline.run(job.payload), timeout=120)
    except (SourceUnavailable, AIServiceUnavailable):
        error = "adapter_unavailable"
    except TimeoutError:
        error, retryable = "timeout", True
    except HTTPError:
        error, retryable = "upstream_unavailable", True
    except (ValidationError, ValueError):
        error = "invalid_input"
    except Exception:
        error = "engine_error"
    # If persistence fails, let the lease expire. Never acknowledge locally.
    finished = await asyncio.to_thread(
        queue.finish,
        str(raw["id"]),
        str(raw["lease_token"]),
        result=result,
        error=error,
        retryable=retryable,
    )
    logger.info("Scan completion persisted=%s outcome=%s", finished, error or "completed")
    return True


async def run(once: bool = False) -> None:
    queue = ScanQueue()
    pipeline = ScanPipeline(GitHubSourceProvider(), AIScanEngine())
    while True:
        try:
            processed = await process_one(queue, pipeline)
        except Exception:
            # Do not log exception text, queued metadata, tokens, diffs or findings.
            logger.error("Queue operation failed; any held lease will expire")
            if once:
                raise SystemExit(1) from None
            processed = False
        if once:
            return
        if not processed:
            await asyncio.sleep(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(run(args.once))
    except KeyboardInterrupt:
        pass
