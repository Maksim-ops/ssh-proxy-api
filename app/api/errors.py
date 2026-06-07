from __future__ import annotations

import uuid
from typing import Any, Optional


def make_error_body(
    *,
    error: str,
    message: str,
    request_id: Optional[str] = None,
    server: Optional[str] = None,
    argv: Optional[list[str]] = None,
    stdout: str = "",
    stderr: str = "",
    exit_code: Optional[int] = None,
    policy: Optional[str] = None,
    duration_ms: int = 0,
) -> dict[str, Any]:
    return {
        "ok": False,
        "error": error,
        "message": message,
        "request_id": request_id or str(uuid.uuid4()),
        "server": server,
        "argv": argv or [],
        "remote_command": None,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "policy": policy,
    }
