"""Public tunnel target: only the signed GitHub webhook route exists here."""

from fastapi import FastAPI

from app.api.webhooks import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router, prefix="/api/v1")
