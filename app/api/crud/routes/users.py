from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.users import UserCreate, UserResponse, UserUpdate
from app.auth import AuthenticatedUser, require_auth
from app.db.crud import create_user, delete_user, get_user, list_users, update_user


router = APIRouter(prefix="/api/v1/users", tags=["crud-users"])


@router.get("", response_model=list[UserResponse])
async def get_users(_: AuthenticatedUser = Depends(require_auth)):
    return list_users()


@router.get("/{user_id}", response_model=UserResponse)
async def get_user_by_id(user_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return get_user(user_id)
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc, item_id=user_id)


@router.post("", response_model=UserResponse)
async def create_user_endpoint(payload: UserCreate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return create_user(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user_endpoint(user_id: int, payload: UserUpdate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return update_user(user_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc, item_id=user_id)


@router.delete("/{user_id}")
async def delete_user_endpoint(user_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        delete_user(user_id)
        return {"ok": True, "deleted_id": user_id}
    except Exception as exc:
        handle_crud_error(entity="user", exc=exc, item_id=user_id)
