from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from httpx import HTTPError
from postgrest.exceptions import APIError

from app.core.security import AuthenticatedUser

router = APIRouter(prefix="/repos", tags=["repositories"])


@router.get("")
def list_repositories(
    user: AuthenticatedUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
) -> dict:
    try:
        result = (
            user.client.table("repositories")
            .select("id,organization_id,full_name,default_branch,created_at")
            .order("created_at", desc=True)
            .order("id")
            .range(offset, offset + limit - 1)
            .execute()
        )
    except (APIError, HTTPError) as exc:
        raise HTTPException(503, "Repository data unavailable") from exc
    return {"items": result.data}
