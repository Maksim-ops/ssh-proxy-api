from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class AuthTokenRequest(BaseModel):
    email: str = Field(..., min_length=3)


class AuthUserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str


class AuthTokenResponse(BaseModel):
    ok: bool
    token_type: str = "Bearer"
    access_token: str
    user: AuthUserResponse


class AuthLogoutResponse(BaseModel):
    ok: bool
    revoked: bool


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
