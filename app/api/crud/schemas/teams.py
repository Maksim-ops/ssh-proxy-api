from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TeamCreate(BaseModel):
    name: str
    slug: str


class TeamUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None


class TeamResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    created_at: datetime
    user_names: str = ''
    project_names: str = ''
    user_count: int = 0
    project_count: int = 0
