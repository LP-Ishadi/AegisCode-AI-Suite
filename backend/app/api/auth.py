from fastapi import APIRouter

from app.core.security import AuthenticatedUser

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me")
def me(user: AuthenticatedUser) -> dict[str, str]:
    return {"id": str(user.user_id)}
