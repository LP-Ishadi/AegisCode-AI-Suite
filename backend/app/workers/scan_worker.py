"""Run with python -m app.workers.scan_worker [--once]. Supabase is the durable queue."""

import argparse
import asyncio
import logging

from httpx import HTTPError
from pydantic import ValidationError

from app.core.config import get_settings
from app.database.supabase_client import get_service_client
from app.models.dispatch import ScanJob, ScanResult
from app.models.schemas import CoverageStatus
from app.services.adapter_errors import AdapterError
from app.services.ai_service import AIServiceUnavailable
from app.services.coverage_ledger import coverage_payload, failure_coverage
from app.services.scan_pipeline import (
    AIScanEngine,
    GitHubSourceProvider,
    ScannerPipeline,
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
        commit_sha: str,
        result: ScanResult | None = None,
        error: str | None = None,
        retryable: bool = False,
    ) -> bool:
        accepted = (
            get_service_client()
            .rpc(
                "finish_scan_job_v3",
                {
                    "p_job_id": job_id,
                    "p_lease_token": lease_token,
                    "p_findings": [f.model_dump(mode="json") for f in result.findings]
                    if result and error is None
                    else [],
                    "p_engine_version": result.engine_version if result and error is None else None,
                    "p_error_code": error,
                    "p_retryable": retryable,
                    "p_review_mode": result.review_mode.value
                    if result and error is None else "scanner_only",
                    "p_coverage": [coverage_payload(item) for item in result.coverage]
                    if result and error is None else [coverage_payload(failure_coverage(
                        commit_sha, error or "engine_error", pending=retryable
                    ))],
                },
            )
            .execute()
            .data
            is True
        )
        if accepted and result and error is None and result.context_graph:
            # Graph hints are optional. A failed metadata write never changes
            # the authoritative scan result or its coverage record.
            try:
                saved = get_service_client().rpc(
                    "put_scan_context_graph",
                    {"p_job_id": job_id, "p_graph": result.context_graph},
                ).execute().data
                if saved is not True:
                    logger.warning("Graph hints were not accepted for completed scan")
            except Exception:
                logger.warning("Graph hints unavailable for completed scan")
        return accepted


async def process_one(queue: ScanQueue, pipeline: ScanPipeline) -> bool:
    raw = await asyncio.to_thread(queue.claim)
    if not raw:
        return False
    result = None
    error = None
    retryable = False
    try:
        job = ScanJob.model_validate(raw)
        # Keep the hard work deadline inside the 300-second DB lease.
        result = await asyncio.wait_for(pipeline.run(job.payload), timeout=240)
        accepted_modes = {
            item.mode for item in result.coverage
            if item.commit_sha == job.payload.commit_sha
            and (item.status is CoverageStatus.complete
                 or (result.findings and item.status is CoverageStatus.partial))
        }
        if result.review_mode not in accepted_modes:
            raise AdapterError("source_incomplete")
    except AdapterError as exc:
        error, retryable = (
            "adapter_unavailable" if exc.code == "scanner_unavailable" else exc.code,
            exc.retryable,
        )
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
        commit_sha=raw["payload"]["commit_sha"],
        result=result,
        error=error,
        retryable=retryable,
    )
    logger.info("Scan completion persisted=%s outcome=%s", finished, error or "completed")
    return True


async def run(once: bool = False) -> None:
    queue = ScanQueue()
    pipeline = (
        ScannerPipeline()
        if get_settings().scanners_enabled
        else ScanPipeline(GitHubSourceProvider(), AIScanEngine())
    )
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
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        asyncio.run(run(args.once))
    except KeyboardInterrupt:
        pass
