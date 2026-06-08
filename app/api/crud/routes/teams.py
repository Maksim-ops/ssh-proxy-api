from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.teams import TeamCreate, TeamResponse, TeamUpdate
from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import require_superadmin
from app.db.crud import create_team, delete_team, get_team, list_teams_crud, update_team


router = APIRouter(prefix="/api/v1/teams", tags=["crud-teams"])


@router.get("", response_model=list[TeamResponse])
async def get_teams(user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    return list_teams_crud()


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team_by_id(team_id: int, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return get_team(team_id)
    except Exception as exc:
        handle_crud_error(entity="team", exc=exc, item_id=team_id)


@router.post("", response_model=TeamResponse)
async def create_team_endpoint(payload: TeamCreate, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return create_team(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="team", exc=exc)


@router.patch("/{team_id}", response_model=TeamResponse)
async def update_team_endpoint(team_id: int, payload: TeamUpdate, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return update_team(team_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="team", exc=exc, item_id=team_id)


@router.delete("/{team_id}")
async def delete_team_endpoint(team_id: int, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        delete_team(team_id)
        return {"ok": True, "deleted_id": team_id}
    except Exception as exc:
        handle_crud_error(entity="team", exc=exc, item_id=team_id)
