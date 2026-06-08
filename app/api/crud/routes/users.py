from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.users import UserCreate, UserResponse, UserUpdate
from app.audit import write_audit_event
from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import require_superadmin
from app.db.crud import create_user, delete_user, get_user, list_users, update_user
from app.db.repositories import revoke_all_auth_sessions_for_user


router = APIRouter(prefix="/api/v1/users", tags=["crud-users"])


@router.get("", response_model=list[UserResponse])
async def get_users(user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    return list_users()


@router.get("/{user_id}", response_model=UserResponse)
async def get_user_by_id(user_id: int, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return get_user(user_id)
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc, item_id=user_id)


@router.post("", response_model=UserResponse)
async def create_user_endpoint(payload: UserCreate, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        created = create_user(payload.model_dump())
        return created
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user_endpoint(user_id: int, payload: UserUpdate, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        updated = update_user(user_id, payload.model_dump(exclude_unset=True))
        if payload.password:
            revoked_count = revoke_all_auth_sessions_for_user(user_id=user_id, reason="admin_password_reset")
            await write_audit_event(
                {
                    "event": "admin_password_reset",
                    "target_user_id": user_id,
                    "decision": "revoked",
                    "revoked_count": revoked_count,
                },
                action_name="SESSION_REVOKED",
                user_id=user_id,
                session_id=user.session_id,
                resource="auth",
                result="revoked",
            )
        return updated
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc, item_id=user_id)


@router.delete("/{user_id}")
async def delete_user_endpoint(user_id: int, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        revoke_all_auth_sessions_for_user(user_id=user_id, reason="user_deleted")
        delete_user(user_id)
        return {"ok": True, "deleted_id": user_id}
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc, item_id=user_id)
