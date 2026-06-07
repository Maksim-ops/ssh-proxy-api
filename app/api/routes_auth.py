from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.errors import make_error_body
from app.api.schemas import AuthLogoutResponse, AuthTokenRequest, AuthTokenResponse, AuthUserResponse
from app.audit import write_audit_event
from app.auth import AuthenticatedUser, require_auth
from app.db.repositories import issue_auth_token, revoke_auth_token_by_name


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/token", response_model=AuthTokenResponse)
async def create_auth_token(req: AuthTokenRequest):
    issued = issue_auth_token(req.email)
    if issued is None:
        raise HTTPException(
            status_code=404,
            detail=make_error_body(error="unknown_user", message=f"Unknown user email: {req.email}"),
        )

    user = issued["user"]
    await write_audit_event(
        {
            "event": "login",
            "email": req.email,
            "decision": "issued",
            "resource": "auth",
        },
        action_name="LOGIN",
        user_id=int(user["id"]),
        resource="auth",
        result="issued",
    )

    return AuthTokenResponse(ok=True, access_token=issued["access_token"], user=AuthUserResponse(**user))


@router.get("/me", response_model=AuthUserResponse)
async def auth_me(user: AuthenticatedUser = Depends(require_auth)):
    return AuthUserResponse(id=user.id, username=user.username, email=user.email, role=user.role)


@router.post("/logout", response_model=AuthLogoutResponse)
async def auth_logout(user: AuthenticatedUser = Depends(require_auth)):
    if user.is_static_token or not user.token_name:
        return AuthLogoutResponse(ok=True, revoked=False)

    revoked = revoke_auth_token_by_name(user.token_name)
    return AuthLogoutResponse(ok=True, revoked=revoked)
