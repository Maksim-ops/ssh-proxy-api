from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import is_superadmin
from app.db.repositories import list_servers


router = APIRouter(prefix="/api/v1", tags=["servers"])


@router.get("/servers")
async def get_servers(user: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "servers": list_servers(is_superadmin=is_superadmin(user), team_id=user.team_id),
    }
