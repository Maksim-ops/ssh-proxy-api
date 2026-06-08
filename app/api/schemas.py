from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class AuthTokenRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)


class AuthUserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    team_id: int | None = None
    team_name: str | None = None
    permissions: list[str] = Field(default_factory=list)


class AuthSessionResponse(BaseModel):
    id: int
    session_uid: str
    user_id: int
    created_at: str | None = None
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None
    revoked_reason: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    user: AuthUserResponse | None = None


class AuthTokenResponse(BaseModel):
    ok: bool
    token_type: str = "Bearer"
    access_token: str
    expires_at: str | None = None
    session: AuthSessionResponse
    user: AuthUserResponse


class AuthLogoutResponse(BaseModel):
    ok: bool
    revoked: bool
    revoked_count: int = 0


class AuthSessionsListResponse(BaseModel):
    ok: bool
    sessions: list[AuthSessionResponse]


class AuthPasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8)


class ExecRequest(BaseModel):
    server: str
    argv: list[str] = Field(..., min_length=1)
    request_id: Optional[str] = None
    client_type: Literal["CLI", "WEB", "API"] = "CLI"


class ExecAcceptedResponse(BaseModel):
    ok: bool
    request_id: str
    job_id: int
    stream_id: int
    status: str
    server: str
    argv: list[str]
    share_token: str
    ws_path: str
    share_ws_path: str


class CancelRequest(BaseModel):
    request_id: str


class CanIRequest(BaseModel):
    server: str
    argv: list[str] = Field(..., min_length=1)


class CanIResponse(BaseModel):
    ok: bool
    allowed: bool
    server: str
    argv: list[str]
    policy: Optional[str] = None
    reason: str
