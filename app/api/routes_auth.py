from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.errors import make_error_body
from app.api.rate_limit import clear_auth_failures, consume_auth_attempt, is_suspicious_auth_attempt, record_auth_failure
from app.api.schemas import (
    AuthLogoutResponse,
    AuthPasswordChangeRequest,
    AuthSessionsListResponse,
    AuthTokenRequest,
    AuthTokenResponse,
    AuthUserResponse,
)
from app.audit import write_audit_event
from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import is_superadmin
from app.auth.security import build_password_hash, verify_password
from app.db.repositories import (
    create_auth_session,
    get_user_auth_record,
    list_auth_sessions,
    mark_user_login,
    revoke_all_auth_sessions_for_user,
    revoke_auth_session,
    rotate_auth_session,
    set_user_password_hash,
)


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/token", response_model=AuthTokenResponse)
async def create_auth_token(req: AuthTokenRequest, request: Request):
    ip_address = _client_ip(request)
    user_agent = request.headers.get("user-agent")
    allowed, retry_after = consume_auth_attempt(ip_address=ip_address, email=req.email)

    if not allowed:
        await write_audit_event(
            {
                "event": "auth_rate_limited",
                "email": req.email,
                "ip_address": ip_address,
                "retry_after_seconds": retry_after,
                "decision": "blocked",
            },
            action_name="SUSPICIOUS_AUTH",
            ip_address=ip_address,
            resource="auth",
            result="blocked",
        )
        raise HTTPException(
            status_code=429,
            detail=make_error_body(error="too_many_requests", message="Too many authentication attempts. Try again later."),
        )

    auth_record = get_user_auth_record(req.email)
    password_hash = auth_record.get("password_hash") if auth_record else None
    password_ok = verify_password(req.password, password_hash)
    user_payload = auth_record.get("user") if auth_record else None
    is_active = bool(auth_record and auth_record.get("is_active"))

    if not auth_record or not password_ok or not is_active:
        failure_count = record_auth_failure(ip_address=ip_address, email=req.email)
        await write_audit_event(
            {
                "event": "failed_login",
                "email": req.email,
                "ip_address": ip_address,
                "decision": "denied",
                "failure_count": failure_count,
            },
            action_name="LOGIN_FAILURE",
            user_id=user_payload.get("id") if user_payload else None,
            ip_address=ip_address,
            resource="auth",
            result="denied",
        )
        if is_suspicious_auth_attempt(ip_address=ip_address, email=req.email):
            await write_audit_event(
                {
                    "event": "suspicious_auth_attempt",
                    "email": req.email,
                    "ip_address": ip_address,
                    "decision": "flagged",
                },
                action_name="SUSPICIOUS_AUTH",
                user_id=user_payload.get("id") if user_payload else None,
                ip_address=ip_address,
                resource="auth",
                result="flagged",
            )
        raise HTTPException(
            status_code=401,
            detail=make_error_body(error="invalid_credentials", message="Invalid credentials"),
        )

    clear_auth_failures(ip_address=ip_address, email=req.email)
    issued = create_auth_session(user_id=int(user_payload["id"]), ip_address=ip_address, user_agent=user_agent)
    mark_user_login(int(user_payload["id"]))

    await write_audit_event(
        {
            "event": "login",
            "email": req.email,
            "ip_address": ip_address,
            "decision": "issued",
            "session_uid": issued["session"]["session_uid"],
        },
        action_name="LOGIN_SUCCESS",
        user_id=int(user_payload["id"]),
        session_id=issued["session"]["id"],
        ip_address=ip_address,
        resource="auth",
        result="issued",
    )

    return AuthTokenResponse(
        ok=True,
        access_token=issued["access_token"],
        expires_at=issued["session"]["expires_at"],
        session=issued["session"],
        user=AuthUserResponse(**issued["user"]),
    )


@router.get("/me", response_model=AuthUserResponse)
async def auth_me(user: AuthenticatedUser = Depends(require_auth)):
    return AuthUserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        team_id=user.team_id,
        team_name=user.team_name,
        permissions=list(user.permissions),
    )


@router.get("/sessions", response_model=AuthSessionsListResponse)
async def auth_sessions(user: AuthenticatedUser = Depends(require_auth)):
    sessions = list_auth_sessions(is_superadmin=is_superadmin(user), user_id=user.id)
    return AuthSessionsListResponse(ok=True, sessions=sessions)


@router.post("/logout", response_model=AuthLogoutResponse)
async def auth_logout(request: Request, user: AuthenticatedUser = Depends(require_auth)):
    if user.is_static_token or not user.session_uid:
        return AuthLogoutResponse(ok=True, revoked=False, revoked_count=0)

    revoked = revoke_auth_session(session_uid=user.session_uid, reason="logout", restrict_user_id=user.id)
    if revoked:
        await write_audit_event(
            {
                "event": "logout",
                "ip_address": _client_ip(request),
                "decision": "revoked",
                "session_uid": user.session_uid,
            },
            action_name="LOGOUT",
            user_id=user.id,
            session_id=user.session_id,
            ip_address=_client_ip(request),
            resource="auth",
            result="revoked",
        )
    return AuthLogoutResponse(ok=True, revoked=bool(revoked), revoked_count=1 if revoked else 0)


@router.post("/logout-all", response_model=AuthLogoutResponse)
async def auth_logout_all(request: Request, user: AuthenticatedUser = Depends(require_auth)):
    count = revoke_all_auth_sessions_for_user(user_id=user.id, reason="logout_all")
    await write_audit_event(
        {
            "event": "logout_all",
            "ip_address": _client_ip(request),
            "decision": "revoked",
            "revoked_count": count,
        },
        action_name="LOGOUT",
        user_id=user.id,
        session_id=user.session_id,
        ip_address=_client_ip(request),
        resource="auth",
        result="revoked",
    )
    return AuthLogoutResponse(ok=True, revoked=count > 0, revoked_count=count)


@router.post("/sessions/{session_uid}/revoke", response_model=AuthLogoutResponse)
async def revoke_session(session_uid: str, request: Request, user: AuthenticatedUser = Depends(require_auth)):
    if not is_superadmin(user):
        raise HTTPException(status_code=403, detail=make_error_body(error="forbidden", message="Superadmin role is required"))

    revoked = revoke_auth_session(session_uid=session_uid, reason="admin_revoke", actor_user_id=user.id)
    if not revoked:
        raise HTTPException(status_code=404, detail=make_error_body(error="session_not_found", message="Auth session not found"))

    revoked_session = revoked["session"]
    revoked_user = revoked["user"]
    await write_audit_event(
        {
            "event": "token_revoked",
            "target_user_id": revoked_user["id"],
            "session_uid": revoked_session["session_uid"],
            "ip_address": _client_ip(request),
            "decision": "revoked",
        },
        action_name="SESSION_REVOKED",
        user_id=revoked_user["id"],
        session_id=revoked_session["id"],
        ip_address=_client_ip(request),
        resource="auth",
        result="revoked",
    )
    return AuthLogoutResponse(ok=True, revoked=True, revoked_count=1)


@router.post("/rotate", response_model=AuthTokenResponse)
async def rotate_session(request: Request, user: AuthenticatedUser = Depends(require_auth)):
    if user.is_static_token or not user.session_uid:
        raise HTTPException(status_code=400, detail=make_error_body(error="rotation_not_supported", message="Static token cannot be rotated"))

    issued = rotate_auth_session(session_uid=user.session_uid, ip_address=_client_ip(request), user_agent=request.headers.get("user-agent"))
    if issued is None:
        raise HTTPException(status_code=401, detail=make_error_body(error="session_expired", message="Current session is no longer active"))

    await write_audit_event(
        {
            "event": "session_rotated",
            "ip_address": _client_ip(request),
            "decision": "rotated",
            "new_session_uid": issued["session"]["session_uid"],
        },
        action_name="SESSION_ROTATED",
        user_id=user.id,
        session_id=issued["session"]["id"],
        ip_address=_client_ip(request),
        resource="auth",
        result="rotated",
    )
    return AuthTokenResponse(
        ok=True,
        access_token=issued["access_token"],
        expires_at=issued["session"]["expires_at"],
        session=issued["session"],
        user=AuthUserResponse(**issued["user"]),
    )


@router.post("/password", response_model=AuthTokenResponse)
async def change_password(payload: AuthPasswordChangeRequest, request: Request, user: AuthenticatedUser = Depends(require_auth)):
    if user.is_static_token or not user.session_uid:
        raise HTTPException(status_code=400, detail=make_error_body(error="password_change_not_supported", message="Static token cannot change password"))

    auth_record = get_user_auth_record(user.email)
    if auth_record is None or not verify_password(payload.current_password, auth_record.get("password_hash")):
        raise HTTPException(status_code=401, detail=make_error_body(error="invalid_credentials", message="Invalid credentials"))

    updated = set_user_password_hash(user_id=user.id, password_hash=build_password_hash(payload.new_password))
    if updated is None:
        raise HTTPException(status_code=404, detail=make_error_body(error="user_not_found", message="User not found"))

    revoke_all_auth_sessions_for_user(user_id=user.id, reason="password_changed", except_session_uid=user.session_uid)
    issued = rotate_auth_session(session_uid=user.session_uid, ip_address=_client_ip(request), user_agent=request.headers.get("user-agent"))
    if issued is None:
        raise HTTPException(status_code=401, detail=make_error_body(error="session_expired", message="Current session is no longer active"))

    await write_audit_event(
        {
            "event": "password_changed",
            "ip_address": _client_ip(request),
            "decision": "rotated",
            "new_session_uid": issued["session"]["session_uid"],
        },
        action_name="PASSWORD_CHANGED",
        user_id=user.id,
        session_id=issued["session"]["id"],
        ip_address=_client_ip(request),
        resource="auth",
        result="rotated",
    )
    return AuthTokenResponse(
        ok=True,
        access_token=issued["access_token"],
        expires_at=issued["session"]["expires_at"],
        session=issued["session"],
        user=AuthUserResponse(**issued["user"]),
    )
