from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.servers import ServerCreate, ServerResponse, ServerUpdate
from app.auth import AuthenticatedUser, require_auth
from app.db.crud import create_server, delete_server, get_server, list_servers_crud, update_server


router = APIRouter(prefix="/api/v1/servers", tags=["crud-servers"])


@router.get("", response_model=list[ServerResponse])
async def get_servers(_: AuthenticatedUser = Depends(require_auth)):
    return list_servers_crud()


@router.get("/{server_id}", response_model=ServerResponse)
async def get_server_by_id(server_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return get_server(server_id)
    except Exception as exc:
        handle_crud_error(entity="server", exc=exc, item_id=server_id)


@router.post("", response_model=ServerResponse)
async def create_server_endpoint(payload: ServerCreate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return create_server(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="server", exc=exc)


@router.patch("/{server_id}", response_model=ServerResponse)
async def update_server_endpoint(server_id: int, payload: ServerUpdate, _: AuthenticatedUser = Depends(require_auth)):
    try:
        return update_server(server_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="server", exc=exc, item_id=server_id)


@router.delete("/{server_id}")
async def delete_server_endpoint(server_id: int, _: AuthenticatedUser = Depends(require_auth)):
    try:
        delete_server(server_id)
        return {"ok": True, "deleted_id": server_id}
    except Exception as exc:
        handle_crud_error(entity="server", exc=exc, item_id=server_id)
