from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TokenCreate(BaseModel):
    name: str
    token: str = Field(..., min_length=1)
    enabled: bool = True


class TokenUpdate(BaseModel):
    name: str | None = None
    token: str | None = Field(default=None, min_length=1)
    enabled: bool | None = None


class TokenResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    enabled: bool
    created_at: datetime
