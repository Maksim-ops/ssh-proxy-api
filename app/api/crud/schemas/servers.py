from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ServerCreate(BaseModel):
    name: str
    host: str
    ip: str | None = None
    proxy_id: int | None = None
    team_id: int | None = None
    project_id: int | None = None
    port: int = 22
    environment: str = "dev"
    type: str | None = None
    enabled: bool = True


class ServerUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    ip: str | None = None
    proxy_id: int | None = None
    team_id: int | None = None
    project_id: int | None = None
    port: int | None = None
    environment: str | None = None
    type: str | None = None
    enabled: bool | None = None


class ServerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    host: str
    ip: str | None = None
    proxy_id: int | None = None
    proxy_name: str | None = None
    team_id: int | None = None
    team_name: str | None = None
    project_id: int | None = None
    project_name: str | None = None
    port: int
    environment: str
    type: str | None = None
    enabled: bool
    created_at: datetime
