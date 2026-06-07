from __future__ import annotations

from fastapi import HTTPException

from app.api.errors import make_error_body
from app.db.crud import EntityConflictError, EntityNotFoundError


def handle_crud_error(*, entity: str, exc: Exception, item_id: int | None = None) -> None:
    if isinstance(exc, EntityNotFoundError):
        message = f"{entity} not found"
        if item_id is not None:
            message = f"{entity} {item_id} not found"
        raise HTTPException(
            status_code=404,
            detail=make_error_body(error=f"{entity}_not_found", message=message),
        ) from exc

    if isinstance(exc, EntityConflictError):
        raise HTTPException(
            status_code=409,
            detail=make_error_body(error=f"{entity}_conflict", message=str(exc)),
        ) from exc

    raise exc
