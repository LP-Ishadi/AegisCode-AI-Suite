"""Authenticated operator interface for human-mediated LLM reviews."""

import asyncio
from uuid import UUID

from fastapi import APIRouter, HTTPException
from httpx import HTTPError
from postgrest.exceptions import APIError
from pydantic import Field

from app.core.security import AuthenticatedUser
from app.database.supabase_client import get_service_client
from app.models.dispatch import ScanMetadata
from app.models.schemas import CoverageStatus, Finding, ReviewMode, StrictModel
from app.services.adapter_errors import AdapterError
from app.services.coverage_ledger import ai_coverage, coverage_payload
from app.services.manual_review import (
    ModelReply,
    RepositoryTools,
    checked_findings,
    initial_prompt,
    prompt,
    record_file_read,
    require_context_for_clean,
    require_file_read,
)

router = APIRouter(prefix="/manual-reviews", tags=["manual reviews"])


class Submission(StrictModel):
    step: int = Field(ge=0, lt=20)
    response: ModelReply


def operator_scan(user: AuthenticatedUser, scan_id: UUID) -> dict:
    try:
        rows = (
            user.client.table("scans")
            .select("id,organization_id,status,pull_request_id")
            .eq("id", str(scan_id))
            .limit(1)
            .execute()
            .data
        )
        if not rows:
            raise HTTPException(404, "Scan not found")
        memberships = (
            user.client.table("organization_members")
            .select("role")
            .eq("organization_id", rows[0]["organization_id"])
            .eq("user_id", str(user.user_id))
            .limit(1)
            .execute()
            .data
        )
        if not memberships or memberships[0]["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Organization administrator required")
        return rows[0]
    except (APIError, HTTPError) as exc:
        raise HTTPException(503, "Review data unavailable") from exc


def load_review(user: AuthenticatedUser, review_id: UUID) -> dict:
    try:
        rows = (
            user.client.table("manual_reviews")
            .select("*")
            .eq("id", str(review_id))
            .limit(1)
            .execute()
            .data
        )
    except (APIError, HTTPError) as exc:
        raise HTTPException(503, "Review data unavailable") from exc
    if not rows:
        raise HTTPException(404, "Review not found")
    return rows[0]


def metadata_for_scan(scan_id: UUID) -> ScanMetadata:
    rows = (
        get_service_client()
        .table("scan_jobs")
        .select("payload")
        .eq("scan_id", str(scan_id))
        .limit(1)
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "Scan job not found")
    return ScanMetadata.model_validate(rows[0]["payload"])


def existing_review_id(service, scan_id: UUID) -> str | None:
    rows = (
        service.table("manual_reviews")
        .select("id")
        .eq("scan_id", str(scan_id))
        .limit(1)
        .execute()
        .data
    )
    return rows[0]["id"] if rows else None


def scanner_findings_for_scan(service, scan_id: UUID) -> list[Finding]:
    rows = (
        service.table("findings")
        .select("rule_id,file_path,line,severity,message")
        .eq("scan_id", str(scan_id))
        .limit(500)
        .execute()
        .data
    )
    return [Finding.model_validate(row) for row in rows]


def graph_for_scan(service, scan_id: UUID) -> dict | None:
    rows = (service.table("scan_context_graph")
            .select("commit_sha,graph").eq("scan_id", str(scan_id))
            .limit(1).execute().data)
    if not rows:
        return None
    graph = rows[0].get("graph")
    if isinstance(graph, dict) and graph.get("commit") == rows[0].get("commit_sha"):
        return graph
    return None


@router.post("/scans/{scan_id}")
async def start_review(scan_id: UUID, user: AuthenticatedUser):
    scan = await asyncio.to_thread(operator_scan, user, scan_id)
    if scan["status"] not in ("completed", "failed"):
        raise HTTPException(409, "Wait for the worker scan to finish")
    service = get_service_client()
    try:
        existing = await asyncio.to_thread(existing_review_id, service, scan_id)
        if existing:
            return {"id": existing}
        metadata = await asyncio.to_thread(metadata_for_scan, scan_id)
        scanner_findings = await asyncio.to_thread(scanner_findings_for_scan, service, scan_id)
        graph_result = await asyncio.to_thread(graph_for_scan, service, scan_id)
        first = await initial_prompt(
            metadata, scanner_findings, scan["status"], graph_result=graph_result
        )
        try:
            row = await asyncio.to_thread(
                lambda: (
                    service.table("manual_reviews")
                    .insert(
                        {
                            "organization_id": scan["organization_id"],
                            "scan_id": str(scan_id),
                            "prompt": first,
                            "created_by": str(user.user_id),
                        }
                    )
                    .execute()
                    .data
                )
            )
        except APIError as exc:
            if exc.code != "23505":
                raise
            # Two tabs (or React development mode) can start the same scan at
            # once. The unique scan_id means one insert wins; reuse that row.
            existing = await asyncio.to_thread(existing_review_id, service, scan_id)
            if existing:
                return {"id": existing}
            raise
    except AdapterError as exc:
        raise HTTPException(422, f"Cannot prepare review: {exc.code}") from exc
    except (APIError, HTTPError, ValueError) as exc:
        raise HTTPException(503, "Review could not be prepared") from exc
    return {"id": row[0]["id"]}


@router.get("/{review_id}")
def get_review(review_id: UUID, user: AuthenticatedUser):
    review = load_review(user, review_id)
    steps = (
        user.client.table("manual_review_steps")
        .select("step,action,response,tool_summary,created_at")
        .eq("review_id", str(review_id))
        .order("step")
        .execute()
        .data
    )
    return {"review": review, "steps": steps}


@router.post("/{review_id}/responses")
async def submit_response(review_id: UUID, submission: Submission, user: AuthenticatedUser):
    review = await asyncio.to_thread(load_review, user, review_id)
    if review["status"] != "active" or review["step"] != submission.step:
        raise HTTPException(409, "Review has already advanced; refresh the page")
    if submission.step >= 19 and submission.response.kind == "tool":
        raise HTTPException(422, "Tool limit reached; submit final findings")
    try:
        metadata = await asyncio.to_thread(metadata_for_scan, UUID(review["scan_id"]))
        tools = RepositoryTools(metadata)
        await tools.ready()
        reply = submission.response
        pending = list(review["prompt"].get("coverage_pending", []))
        file_read_completed = review["prompt"].get("file_read_completed") is True
        evidence_scope = review["prompt"].get("evidence_scope")
        coverage_context = review["prompt"].get("coverage_context")
        if reply.kind == "tool":
            result = await tools.execute(reply.tool)
            if reply.tool.name == "read_file":
                file_read_completed = (
                    record_file_read(evidence_scope, pending, result) or file_read_completed
                )
            next_prompt = prompt(
                metadata,
                "",
                step=submission.step + 1,
                tool_result=result,
                coverage_pending=pending,
                file_read_completed=file_read_completed,
                evidence_scope=evidence_scope,
                coverage_context=coverage_context,
            )
            summary = {
                "name": reply.tool.name,
                "path": reply.tool.path,
                "file_count": len(result.get("paths", [])),
            }
            findings = []
        else:
            require_file_read(file_read_completed)
            require_context_for_clean(reply.findings, pending)
            findings = await checked_findings(
                metadata, reply.findings, tools, evidence_scope=evidence_scope
            )
            next_prompt = {"status": "completed"}
            summary = {"finding_count": len(findings)}
        response = reply.model_dump(mode="json")
        if reply.kind == "final":
            response["findings"] = [f.model_dump(mode="json") for f in findings]
        coverage = ai_coverage(
            metadata.commit_sha, ReviewMode.manual, evidence_scope,
            coverage_context, pending,
        )
        if reply.kind == "tool":
            coverage = coverage.model_copy(update={
                "status": CoverageStatus.pending,
                "scanner_stages": {"ai_review": "active"},
            })
        accepted = await asyncio.to_thread(
            lambda: (
                get_service_client()
                .rpc(
                    "advance_manual_review_v2",
                    {
                        "p_review_id": str(review_id),
                        "p_step": submission.step,
                        "p_action": reply.kind,
                        "p_response": response,
                        "p_tool_summary": summary,
                        "p_next_prompt": next_prompt,
                        "p_findings": [f.model_dump(mode="json") for f in findings],
                        "p_coverage": coverage_payload(coverage),
                    },
                )
                .execute()
                .data
            )
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except AdapterError as exc:
        raise HTTPException(422, f"GitHub data unavailable: {exc.code}") from exc
    except (APIError, HTTPError) as exc:
        raise HTTPException(503, "Review could not be advanced") from exc
    if not accepted:
        raise HTTPException(409, "Review has already advanced; refresh the page")
    return {
        "status": "completed" if reply.kind == "final" else "active",
        "step": submission.step + 1,
        "prompt": next_prompt,
    }
