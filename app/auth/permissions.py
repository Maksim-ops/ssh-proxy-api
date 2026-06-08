from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException

from app.api.errors import make_error_body

if TYPE_CHECKING:
    from .users import AuthenticatedUser


ROLE_SUPERADMIN = "superadmin"
ROLE_ENGINEER = "engineer"
ROLE_TL = "tl"
ROLE_PM = "pm"
ROLE_ADMIN_LEGACY = "admin"

ROLE_PERMISSIONS = {
    ROLE_SUPERADMIN: {
        "audit:read_all",
        "auth:revoke_any_session",
        "auth:view_all_sessions",
        "jobs:read_all",
        "servers:manage",
        "servers:read_all",
        "teams:manage",
        "teams:read_all",
        "users:manage",
    },
    ROLE_ADMIN_LEGACY: {
        "audit:read_all",
        "auth:revoke_any_session",
        "auth:view_all_sessions",
        "jobs:read_all",
        "servers:manage",
        "servers:read_all",
        "teams:manage",
        "teams:read_all",
        "users:manage",
    },
    ROLE_ENGINEER: {
        "jobs:read_team",
        "servers:read_team",
    },
    ROLE_TL: {
        "jobs:read_team",
        "servers:read_team",
    },
    ROLE_PM: {
        "jobs:read_team",
        "servers:read_team",
    },
}


def normalize_role(role: str) -> str:
    role_value = (role or ROLE_ENGINEER).strip().lower()
    if role_value not in ROLE_PERMISSIONS:
        return ROLE_ENGINEER
    return role_value


def permissions_for_role(role: str) -> list[str]:
    return sorted(ROLE_PERMISSIONS.get(normalize_role(role), set()))


def is_superadmin_role(role: str) -> bool:
    return normalize_role(role) in {ROLE_SUPERADMIN, ROLE_ADMIN_LEGACY}


def is_superadmin(user: AuthenticatedUser) -> bool:
    return is_superadmin_role(user.role)


def require_superadmin(user: AuthenticatedUser) -> AuthenticatedUser:
    if not is_superadmin(user):
        raise HTTPException(
            status_code=403,
            detail=make_error_body(error="forbidden", message="Superadmin role is required"),
        )
    return user


def require_permission(user: AuthenticatedUser, permission: str) -> AuthenticatedUser:
    if permission not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail=make_error_body(error="forbidden", message=f"Missing permission: {permission}"),
        )
    return user
