from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Query, WebSocket

from app.api.errors import make_error_body
from app.auth.permissions import normalize_role, permissions_for_role
from app.config import SETTINGS
from app.db.repositories import find_stream_access, get_authenticated_user_for_token


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    username: str
    email: str
    role: str
    team_id: int | None = None
    team_name: str | None = None
    permissions: tuple[str, ...] = ()
    session_id: int | None = None
    session_uid: str | None = None
    session_expires_at: str | None = None
    token_name: str | None = None
    is_static_token: bool = False
    is_share_token: bool = False


def _default_user() -> AuthenticatedUser:
    role = normalize_role("superadmin")
    return AuthenticatedUser(
        id=1,
        username=SETTINGS.superadmin_username,
        email=SETTINGS.superadmin_email,
        role=role,
        permissions=tuple(permissions_for_role(role)),
        token_name="default-api-token",
        is_static_token=True,
    )


def _share_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        id=0,
        username="share-link",
        email="share-link@local",
        role="share",
        is_share_token=True,
    )


def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    token = authorization[len(prefix):].strip()
    return token or None


def _authenticate_token(token_value: str) -> Optional[AuthenticatedUser]:
    if SETTINGS.api_token and token_value == SETTINGS.api_token:
        return _default_user()

    token_data = get_authenticated_user_for_token(token_value)
    if token_data is None:
        return None

    user = token_data["user"]
    auth_session = token_data["session"]
    role = normalize_role(str(user.get("role") or "engineer"))
    return AuthenticatedUser(
        id=int(user["id"]),
        username=str(user["username"]),
        email=str(user["email"]),
        role=role,
        team_id=user.get("team_id"),
        team_name=user.get("team_name"),
        permissions=tuple(user.get("permissions") or permissions_for_role(role)),
        session_id=auth_session.get("id"),
        session_uid=auth_session.get("session_uid"),
        session_expires_at=auth_session.get("expires_at"),
        is_static_token=False,
    )


async def require_auth(authorization: Optional[str] = Header(default=None)) -> AuthenticatedUser:
    token_value = _extract_bearer_token(authorization)
    if not token_value:
        raise HTTPException(
            status_code=401,
            detail=make_error_body(error="unauthorized", message="Missing Authorization Bearer token"),
        )

    user = _authenticate_token(token_value)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail=make_error_body(error="unauthorized", message="Invalid or expired Authorization Bearer token"),
        )

    return user


async def require_ws_access(
    websocket: WebSocket,
    stream_id: Optional[int] = Query(default=None),
    share_token: Optional[str] = Query(default=None),
    token: Optional[str] = Query(default=None),
) -> AuthenticatedUser:
    auth_header = websocket.headers.get("authorization")
    header_token = _extract_bearer_token(auth_header)

    if header_token:
        user = _authenticate_token(header_token)
        if user is not None:
            return user

    if token:
        user = _authenticate_token(token)
        if user is not None:
            return user

    if stream_id is not None and share_token and find_stream_access(stream_id=stream_id, share_token=share_token):
        return _share_user()

    raise HTTPException(
        status_code=401,
        detail=make_error_body(
            error="unauthorized_ws",
            message="Authorization header, token query parameter or valid share_token is required",
        ),
    )
