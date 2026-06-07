from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.tokens import TokenCreate, TokenResponse, TokenUpdate
from app.auth import AuthenticatedUser, require_auth
from app.db.crud import create_token, delete_token, get_token, list_tokens, update_token


router = APIRouter(prefix="/api/v1/tokens", tags=["crud-tokens"])


@router.get("", response_model=list[TokenResponse])
async def get_tokens(_: AuthenticatedUser = Depends(require_auth)):
    return list_tokens()


@router.get("/{token_id}", response_model=TokenResponse)
async def get_token_by_id(token_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return get_token(token_id)
    except Exception as exc:
        handle_crud_error(entity="token", exc=exc, item_id=token_id)


@router.post("", response_model=TokenResponse)
async def create_token_endpoint(payload: TokenCreate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return create_token(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="token", exc=exc)


@router.patch("/{token_id}", response_model=TokenResponse)
async def update_token_endpoint(token_id: int, payload: TokenUpdate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return update_token(token_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="token", exc=exc, item_id=token_id)


@router.delete("/{token_id}")
async def delete_token_endpoint(token_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        delete_token(token_id)
        return {"ok": True, "deleted_id": token_id}
    except Exception as exc:
        handle_crud_error(entity="token", exc=exc, item_id=token_id)
