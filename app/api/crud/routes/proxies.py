from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.proxies import ProxyCreate, ProxyResponse, ProxyUpdate
from app.auth import AuthenticatedUser, require_auth
from app.db.crud import create_proxy, delete_proxy, get_proxy, list_proxies, update_proxy


router = APIRouter(prefix="/api/v1/proxies", tags=["crud-proxies"])


@router.get("", response_model=list[ProxyResponse])
async def get_proxies(_: AuthenticatedUser = Depends(require_auth)):
    return list_proxies()


@router.get("/{proxy_id}", response_model=ProxyResponse)
async def get_proxy_by_id(proxy_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return get_proxy(proxy_id)
    except Exception as exc:
        handle_crud_error(entity="proxy", exc=exc, item_id=proxy_id)


@router.post("", response_model=ProxyResponse)
async def create_proxy_endpoint(payload: ProxyCreate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return create_proxy(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="proxy", exc=exc)


@router.patch("/{proxy_id}", response_model=ProxyResponse)
async def update_proxy_endpoint(proxy_id: int, payload: ProxyUpdate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return update_proxy(proxy_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="proxy", exc=exc, item_id=proxy_id)


@router.delete("/{proxy_id}")
async def delete_proxy_endpoint(proxy_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        delete_proxy(proxy_id)
        return {"ok": True, "deleted_id": proxy_id}
    except Exception as exc:
        handle_crud_error(entity="proxy", exc=exc, item_id=proxy_id)
