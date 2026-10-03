"""Stateless clients. Never attach user sessions to a shared service-role client."""

from fastapi import HTTPException
from supabase import Client, ClientOptions, create_client

from app.core.config import get_settings


def get_supabase_client(access_token: str | None = None) -> Client:
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_anon_key:
        raise HTTPException(503, "Supabase is not configured")
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    return create_client(
        str(settings.supabase_url).rstrip("/"),
        settings.supabase_anon_key.get_secret_value(),
        options=ClientOptions(
            persist_session=False,
            auto_refresh_token=False,
            headers=headers,
            postgrest_client_timeout=10,
        ),
    )


def get_service_client() -> Client:
    """Trusted workers/webhook RPCs only; never use in user-authenticated routes."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise RuntimeError("Supabase service credentials are not configured")
    return create_client(
        str(settings.supabase_url).rstrip("/"),
        settings.supabase_service_key.get_secret_value(),
        options=ClientOptions(
            persist_session=False, auto_refresh_token=False, postgrest_client_timeout=5
        ),
    )
