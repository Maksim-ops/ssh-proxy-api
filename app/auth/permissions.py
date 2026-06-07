from __future__ import annotations

from fastapi import HTTPException

from app.api.errors import make_error_body

from .users import AuthenticatedUser


def ensure_admin(user: AuthenticatedUser) -> AuthenticatedUser:
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail=make_error_body(error="forbidden", message="Admin role is required"),
        )

    return user
