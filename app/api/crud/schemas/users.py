from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserCreate(BaseModel):
    username: str
    email: str
    role: str = "user"
    public_key: str | None = None
    last_login: datetime | None = None


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    role: str | None = None
    public_key: str | None = None
    last_login: datetime | None = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    created_at: datetime
    last_login: datetime | None = None
    public_key: str | None = None
