from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserCreate(BaseModel):
    username: str
    email: str
    role: str = "engineer"
    team_id: int | None = None
    password: str | None = None
    is_active: bool = True
    public_key: str | None = None
    last_login: datetime | None = None


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    role: str | None = None
    team_id: int | None = None
    password: str | None = None
    is_active: bool | None = None
    public_key: str | None = None
    last_login: datetime | None = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    team_id: int | None = None
    team_name: str | None = None
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None
    public_key: str | None = None
    permissions: list[str] = Field(default_factory=list)
