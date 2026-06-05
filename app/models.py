from typing import Optional, List
from dataclasses import dataclass

from pydantic import BaseModel, Field


class ExecRequest(BaseModel):
    server: str
    argv: List[str] = Field(..., min_length=1)
    request_id: Optional[str] = None


class ExecResponse(BaseModel):
    ok: bool
    error: Optional[str] = None
    message: Optional[str] = None

    request_id: str
    server: Optional[str] = None
    argv: List[str] = Field(default_factory=list)

    remote_command: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_ms: int = 0

    policy: Optional[str] = None

    stdout_truncated: bool = False
    stderr_truncated: bool = False


class ServerRequest(BaseModel):
    server: str


class CancelRequest(BaseModel):
    request_id: str


class CanIRequest(BaseModel):
    server: str
    argv: List[str] = Field(..., min_length=1)


class CanIResponse(BaseModel):
    ok: bool
    allowed: bool
    server: str
    argv: List[str]
    policy: Optional[str] = None
    reason: str


@dataclass
class PolicyDecision:
    allowed: bool
    policy: Optional[str]
    reason: str