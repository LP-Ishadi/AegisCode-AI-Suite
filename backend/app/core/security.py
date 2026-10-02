import hashlib
import hmac
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from httpx import HTTPError
from supabase import Client
from supabase_auth.errors import AuthApiError

from app.database.supabase_client import get_supabase_client

bearer = HTTPBearer(auto_error=False)


def verify_webhook_signature(body: bytes, signature: str | None, secret: str) -> bool:
    if not signature or not signature.startswith("sha256=") or len(signature) != 71:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode(), signature.encode())


@dataclass
class UserContext:
    user_id: UUID
    client: Client


def require_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> UserContext:
    if credentials is None:
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    client = get_supabase_client(credentials.credentials)
    try:
        response = client.auth.get_user(credentials.credentials)
    except AuthApiError as exc:
        raise HTTPException(401, "Invalid or expired token") from exc
    except HTTPError as exc:
        raise HTTPException(503, "Authentication service unavailable") from exc
    if response.user is None:
        raise HTTPException(401, "Invalid or expired token")
    return UserContext(user_id=UUID(response.user.id), client=client)


AuthenticatedUser = Annotated[UserContext, Depends(require_user)]
