from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProjectCreate(BaseModel):
    name: str
    slug: str
    team_id: int


class ProjectUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None
    team_id: int | None = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    team_id: int
    team_name: str | None = None
    created_at: datetime
