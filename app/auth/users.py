from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Query, WebSocket

from app.api.errors import make_error_body
from app.config import SETTINGS
from app.db.repositories import find_stream_access, get_authenticated_user_for_token


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    username: str
    email: str
    role: str
    token_name: str | None = None
    is_static_token: bool = False


def _default_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        id=1,
        username=SETTINGS.username,
        email=SETTINGS.user_email,
        role="admin",
        token_name="default-api-token",
        is_static_token=True,
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
    return AuthenticatedUser(
        id=int(user["id"]),
        username=str(user["username"]),
        email=str(user["email"]),
        role=str(user["role"]),
        token_name=str(token_data.get("token_name") or ""),
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
            detail=make_error_body(error="unauthorized", message="Invalid Authorization Bearer token"),
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

    if stream_id is not None and share_token:
        access = find_stream_access(stream_id=stream_id, share_token=share_token)
        if access:
            return _default_user()

    raise HTTPException(
        status_code=401,
        detail=make_error_body(error="unauthorized_ws", message="Authorization header, token query parameter or valid share_token is required"),
    )
