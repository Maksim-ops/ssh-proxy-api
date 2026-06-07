from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.auth import AuthenticatedUser, require_auth
from app.config import CONFIG, get_configured_servers, reload_config
from app.db.repositories import list_audit_events, list_jobs
from app.ssh.manager import list_ssh_connection_status
from app.ssh.state import list_running_commands


router = APIRouter(prefix="/api/v1", tags=["admin"])


@router.get("/jobs")
async def get_jobs(limit: int = Query(default=100, ge=1, le=500), _: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "jobs": list_jobs(limit=limit),
    }


@router.get("/audit")
async def get_audit(limit: int = Query(default=100, ge=1, le=500), _: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "audit": list_audit_events(limit=limit),
    }


@router.get("/running")
async def get_running(_: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "running": await list_running_commands(),
    }


@router.get("/ssh/status")
async def get_ssh_status(_: AuthenticatedUser = Depends(require_auth)):
    return {
        "ok": True,
        "connections": list_ssh_connection_status(get_configured_servers()),
    }


@router.post("/reload")
async def reload_runtime_config(_: AuthenticatedUser = Depends(require_auth)):
    new_config = reload_config()
    return {
        "ok": True,
        "servers": list((new_config.get("servers") or {}).keys()),
        "globalPolicies": [
            item.get("name", "<unnamed-policy>")
            for item in (CONFIG.get("globalPolicies") or [])
        ],
    }
