from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.crud.routes.common import handle_crud_error
from app.api.crud.schemas.projects import ProjectCreate, ProjectResponse, ProjectUpdate
from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import require_superadmin
from app.db.crud import create_project, delete_project, get_project, list_projects_crud, update_project


router = APIRouter(prefix="/api/v1/projects", tags=["crud-projects"])


@router.get("", response_model=list[ProjectResponse])
async def get_projects(user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    return list_projects_crud()


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project_by_id(project_id: int, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return get_project(project_id)
    except Exception as exc:
        handle_crud_error(entity="project", exc=exc, item_id=project_id)


@router.post("", response_model=ProjectResponse)
async def create_project_endpoint(payload: ProjectCreate, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return create_project(payload.model_dump())
    except Exception as exc:
        handle_crud_error(entity="project", exc=exc)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project_endpoint(project_id: int, payload: ProjectUpdate, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        return update_project(project_id, payload.model_dump(exclude_unset=True))
    except Exception as exc:
        handle_crud_error(entity="project", exc=exc, item_id=project_id)


@router.delete("/{project_id}")
async def delete_project_endpoint(project_id: int, user: AuthenticatedUser = Depends(require_auth)):
    require_superadmin(user)
    try:
        delete_project(project_id)
        return {"ok": True, "deleted_id": project_id}
    except Exception as exc:
        handle_crud_error(entity="project", exc=exc, item_id=project_id)
