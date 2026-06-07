from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth import AuthenticatedUser, require_auth
from app.db.repositories import list_servers


router = APIRouter(prefix="/api/v1", tags=["servers"])


@router.get("/servers")
async def get_servers(_: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "servers": list_servers(),
    }
