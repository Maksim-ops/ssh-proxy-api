from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ActionCreate(BaseModel):
    name: str


class ActionUpdate(BaseModel):
    name: str | None = None


class ActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
