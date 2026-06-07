from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.errors import make_error_body
from app.auth import AuthenticatedUser, require_auth
from app.db.repositories import get_session_detail, list_sessions


router = APIRouter(prefix="/api/v1", tags=["sessions"])


@router.get("/sessions")
async def get_sessions(limit: int = Query(default=100, ge=1, le=500), user: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "sessions": list_sessions(user_id=user.id, is_admin=user.role == "admin", limit=limit),
    }


@router.get("/sessions/{request_id}")
async def get_session_by_request_id(request_id: str, user: AuthenticatedUser = Depends(require_auth)):
    item = get_session_detail(request_id=request_id, user_id=user.id, is_admin=user.role == "admin")
    if item is None:
        raise HTTPException(
            status_code=404,
            detail=make_error_body(error="session_not_found", message=f"Unknown session: {request_id}"),
        )

    return {
        "ok": True,
        "session": item,
    }
