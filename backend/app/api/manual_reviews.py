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
from app.models.schemas import StrictModel
from app.services.adapter_errors import AdapterError
from app.services.manual_review import (
    ModelReply,
    RepositoryTools,
    checked_findings,
    initial_prompt,
    prompt,
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


@router.post("/scans/{scan_id}")
async def start_review(scan_id: UUID, user: AuthenticatedUser):
    scan = await asyncio.to_thread(operator_scan, user, scan_id)
    if scan["status"] not in ("completed", "failed"):
        raise HTTPException(409, "Wait for the worker scan to finish")
    service = get_service_client()
    existing = await asyncio.to_thread(
        lambda: (
            service.table("manual_reviews")
            .select("id")
            .eq("scan_id", str(scan_id))
            .limit(1)
            .execute()
            .data
        )
    )
    if existing:
        return {"id": existing[0]["id"]}
    try:
        metadata = await asyncio.to_thread(metadata_for_scan, scan_id)
        first = await initial_prompt(metadata)
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
        if reply.kind == "tool":
            result = await tools.execute(reply.tool)
            next_prompt = prompt(metadata, "", step=submission.step + 1, tool_result=result)
            summary = {
                "name": reply.tool.name,
                "path": reply.tool.path,
                "file_count": len(result.get("paths", [])),
            }
            findings = []
        else:
            findings = await checked_findings(metadata, reply.findings, tools)
            next_prompt = {"status": "completed"}
            summary = {"finding_count": len(findings)}
        response = reply.model_dump(mode="json")
        if reply.kind == "final":
            response["findings"] = [f.model_dump(mode="json") for f in findings]
        accepted = await asyncio.to_thread(
            lambda: (
                get_service_client()
                .rpc(
                    "advance_manual_review",
                    {
                        "p_review_id": str(review_id),
                        "p_step": submission.step,
                        "p_action": reply.kind,
                        "p_response": response,
                        "p_tool_summary": summary,
                        "p_next_prompt": next_prompt,
                        "p_findings": [f.model_dump(mode="json") for f in findings],
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
