from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.actions import ActionCreate, ActionResponse, ActionUpdate
from app.auth import AuthenticatedUser, require_auth
from app.db.crud import create_action, delete_action, get_action, list_actions, update_action


router = APIRouter(prefix="/api/v1/actions", tags=["crud-actions"])


@router.get("", response_model=list[ActionResponse])
async def get_actions(_: AuthenticatedUser = Depends(require_auth)):
    return list_actions()


@router.get("/{action_id}", response_model=ActionResponse)
async def get_action_by_id(action_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return get_action(action_id)
    except Exception as exc:
        handle_crud_error(entity="action", exc=exc, item_id=action_id)


@router.post("", response_model=ActionResponse)
async def create_action_endpoint(payload: ActionCreate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return create_action(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="action", exc=exc)


@router.patch("/{action_id}", response_model=ActionResponse)
async def update_action_endpoint(action_id: int, payload: ActionUpdate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return update_action(action_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="action", exc=exc, item_id=action_id)


@router.delete("/{action_id}")
async def delete_action_endpoint(action_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        delete_action(action_id)
        return {"ok": True, "deleted_id": action_id}
    except Exception as exc:
        handle_crud_error(entity="action", exc=exc, item_id=action_id)
