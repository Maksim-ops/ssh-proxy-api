from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.errors import make_error_body
from app.audit import write_audit_event
from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import is_superadmin
from app.db.repositories import get_session_detail, hide_session, list_sessions


router = APIRouter(prefix="/api/v1", tags=["sessions"])


@router.get("/sessions")
async def get_sessions(limit: int = Query(default=100, ge=1, le=500), user: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "sessions": list_sessions(team_id=user.team_id, is_superadmin=is_superadmin(user), limit=limit),
    }


@router.get("/sessions/{request_id}")
async def get_session_by_request_id(request_id: str, user: AuthenticatedUser = Depends(require_auth)):
    item = get_session_detail(request_id=request_id, team_id=user.team_id, is_superadmin=is_superadmin(user))
    if item is None:
        raise HTTPException(
            status_code=404,
            detail=make_error_body(error="session_not_found", message=f"Unknown session: {request_id}"),
        )

    return {
        "ok": True,
        "session": item,
    }


@router.delete("/sessions/{request_id}")
async def delete_session_from_history(request_id: str, user: AuthenticatedUser = Depends(require_auth)):
    ok = hide_session(request_id=request_id, actor_user_id=user.id, is_superadmin=is_superadmin(user), team_id=user.team_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=make_error_body(error="session_not_found", message=f"Unknown session: {request_id}"),
        )
    await write_audit_event(
        {
            "event": "session_hidden",
            "request_id": request_id,
            "decision": "hidden",
        },
        action_name="SESSION_HIDDEN",
        user_id=user.id,
        session_id=user.session_id,
        resource="sessions",
        result="hidden",
    )
    return {"ok": True, "request_id": request_id, "hidden": True}
