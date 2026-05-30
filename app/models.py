from typing import Optional, List
from dataclasses import dataclass

from pydantic import BaseModel, Field


class ExecRequest(BaseModel):
    server: str
    argv: List[str] = Field(..., min_length=1)


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


class ServerRequest(BaseModel):
    server: str


@dataclass
class PolicyDecision:
    allowed: bool
    policy: Optional[str]
    reason: str