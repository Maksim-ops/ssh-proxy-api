from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.errors import make_error_body
from app.auth import AuthenticatedUser, require_auth
from app.auth.permissions import is_superadmin
from app.config import CONFIG, get_configured_servers, reload_config
from app.db.repositories import get_server_runtime_config, list_audit_events, list_jobs, list_servers
from app.ssh.manager import list_ssh_connection_status
from app.ssh.state import list_running_commands


router = APIRouter(prefix="/api/v1", tags=["admin"])


@router.get("/jobs")
async def get_jobs(limit: int = Query(default=100, ge=1, le=500), user: AuthenticatedUser = Depends(require_auth)):
    if not is_superadmin(user):
        raise HTTPException(status_code=403, detail=make_error_body(error="forbidden", message="Superadmin role is required"))
    return {
        "ok": True,
        "jobs": list_jobs(limit=limit, is_superadmin=True),
    }


@router.get("/audit")
async def get_audit(limit: int = Query(default=100, ge=1, le=500), user: AuthenticatedUser = Depends(require_auth)):
    if not is_superadmin(user):
        raise HTTPException(status_code=403, detail=make_error_body(error="forbidden", message="Superadmin role is required"))
    return {
        "ok": True,
        "audit": list_audit_events(limit=limit),
    }


@router.get("/running")
async def get_running(user: AuthenticatedUser = Depends(require_auth)):
    visible_servers = list_servers(is_superadmin=is_superadmin(user), team_id=user.team_id)
    server_map = {item["name"]: item for item in visible_servers}

    running = []
    for item in await list_running_commands():
        server = server_map.get(item.get("server"))
        if not is_superadmin(user) and server is None:
            continue
        if server is not None:
            item = {
                **item,
                "team_id": server.get("team_id"),
                "team_name": server.get("team_name"),
                "project_id": server.get("project_id"),
                "project_name": server.get("project_name"),
                "enabled": server.get("enabled"),
            }
        running.append(item)
    return {
        "ok": True,
        "running": running,
    }


@router.get("/ssh/status")
async def get_ssh_status(user: AuthenticatedUser = Depends(require_auth)):
    visible_servers = list_servers(is_superadmin=is_superadmin(user), team_id=user.team_id)
    runtime_servers = {}
    configured_servers = get_configured_servers()
    for item in visible_servers:
        runtime_servers[item["name"]] = configured_servers.get(item["name"]) or get_server_runtime_config(item["name"]) or {}
    return {
        "ok": True,
        "connections": list_ssh_connection_status(runtime_servers),
    }


@router.post("/reload")
async def reload_runtime_config(user: AuthenticatedUser = Depends(require_auth)):
    if not is_superadmin(user):
        raise HTTPException(status_code=403, detail=make_error_body(error="forbidden", message="Superadmin role is required"))
    new_config = reload_config()
    return {
        "ok": True,
        "servers": list((new_config.get("servers") or {}).keys()),
        "globalPolicies": [
            item.get("name", "<unnamed-policy>")
            for item in (CONFIG.get("globalPolicies") or [])
        ],
    }
