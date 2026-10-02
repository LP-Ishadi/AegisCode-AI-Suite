from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from app.core.config import get_settings
from app.core.security import verify_webhook_signature
from app.models.schemas import PullRequestWebhook

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/github")
async def github_webhook(request: Request) -> dict[str, str]:
    settings = get_settings()
    if not settings.github_webhook_secret:
        raise HTTPException(503, "Webhook receiver is not configured")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > settings.max_webhook_bytes:
            raise HTTPException(413, "Webhook payload too large")
        body.extend(chunk)
    if not verify_webhook_signature(
        bytes(body),
        request.headers.get("x-hub-signature-256"),
        settings.github_webhook_secret.get_secret_value(),
    ):
        raise HTTPException(401, "Invalid webhook signature")
    try:
        UUID(request.headers.get("x-github-delivery", ""))
    except ValueError as exc:
        raise HTTPException(400, "Valid delivery ID required") from exc
    event = request.headers.get("x-github-event")
    if not event:
        raise HTTPException(400, "GitHub event header required")
    if event == "ping":
        return {"status": "pong"}
    if event != "pull_request":
        return {"status": "ignored"}
    try:
        payload = PullRequestWebhook.model_validate_json(bytes(body))
    except ValidationError as exc:
        # Do not echo signed payloads, source code, or secrets in error details.
        raise HTTPException(422, "Invalid pull request payload") from exc
    if payload.action not in {"opened", "reopened", "synchronize", "ready_for_review"}:
        return {"status": "ignored"}
    # Implement atomic delivery deduplication + durable outbox in Supabase before
    # returning 202. Do not acknowledge work that has not actually been persisted.
    raise HTTPException(501, "Durable scan dispatch is not implemented")
