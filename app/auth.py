from typing import Optional

from fastapi import Header, HTTPException

from .settings import API_TOKEN
from .errors import make_error_body


async def require_auth(authorization: Optional[str] = Header(default=None)) -> None:
    if not API_TOKEN:
        raise HTTPException(
            status_code=500,
            detail=make_error_body(
                error="auth_not_configured",
                message="PCTL_API_TOKEN is not configured",
            ),
        )

    expected = f"Bearer {API_TOKEN}"

    if authorization != expected:
        raise HTTPException(
            status_code=401,
            detail=make_error_body(
                error="unauthorized",
                message="Invalid or missing Authorization Bearer token",
            ),
        )