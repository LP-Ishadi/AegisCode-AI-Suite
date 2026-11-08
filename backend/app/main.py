import logging
import re

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import auth, manual_reviews, repos, webhooks
from app.core.config import get_settings

logger = logging.getLogger(__name__)


def manual_review_validation_detail(exc: RequestValidationError) -> str:
    """Explain model errors without echoing pasted source code or AI output."""
    messages = []
    for error in exc.errors()[:5]:
        location = ".".join(
            str(part) for part in error.get("loc", ())
            if isinstance(part, int) or
            (isinstance(part, str) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", part))
        )
        kind = error.get("type")
        if kind == "string_too_long":
            limit = error.get("ctx", {}).get("max_length")
            explanation = (
                f"must be {limit} characters or fewer"
                if isinstance(limit, int) else "is too long"
            )
        elif kind == "string_too_short":
            explanation = "must not be empty"
        elif kind == "missing":
            explanation = "is required"
        elif kind == "extra_forbidden":
            explanation = "is not allowed"
        elif kind in ("literal_error", "string_pattern_mismatch", "enum"):
            explanation = "has an unsupported value; check the response examples and schema"
        else:
            explanation = "has an invalid value; check the response examples and schema"
        messages.append(f"{location}: {explanation}" if location else explanation)
    return "AI JSON response is invalid: " + "; ".join(messages)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AegisCode AI Suite",
        version="0.1.0",
        description="Cloud-native secure code review foundation",
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment != "production" else None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin).rstrip("/") for origin in settings.cors_origins],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/api/v1/manual-reviews/"):
            return JSONResponse(
                status_code=422, content={"detail": manual_review_validation_detail(exc)}
            )
        return JSONResponse(status_code=422, content={"detail": "Invalid request parameters"})

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        logger.error("Unhandled API error: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        # Liveness only; this does not assert provider or worker readiness.
        return {"status": "ok", "service": "aegiscode-api"}

    for router in (auth.router, repos.router, webhooks.router, manual_reviews.router):
        app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
