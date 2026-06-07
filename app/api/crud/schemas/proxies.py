from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ProxyCreate(BaseModel):
    proxy: str


class ProxyUpdate(BaseModel):
    proxy: str | None = None


class ProxyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    proxy: str
