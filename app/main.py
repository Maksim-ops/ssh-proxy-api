import time
import uuid
import shlex
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .settings import CONFIG_PATH, API_TOKEN
from .models import ExecRequest, ExecResponse, ServerRequest
from .errors import make_error_body
from .auth import require_auth
from .config import (
    CONFIG,
    get_server_config,
    get_global_policies,
    get_configured_servers,
)
from .policy import evaluate_policy
from .ssh_manager import (
    get_ssh_manager,
    get_existing_ssh_manager,
)
from .audit import write_audit_event


app = FastAPI(
    title="pctl MVP Proxy",
    version="0.4.0",
)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
        )

    return JSONResponse(
        status_code=exc.status_code,
        content=make_error_body(
            error="http_error",
            message=str(exc.detail),
        ),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=make_error_body(
            error="validation_error",
            message=str(exc),
        ),
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "config": CONFIG_PATH,
        "servers": list(CONFIG.get("servers", {}).keys()),
        "globalPolicies": [
            p.get("name", "<unnamed-policy>")
            for p in CONFIG.get("globalPolicies", []) or []
        ],
        "auth": "enabled" if API_TOKEN else "disabled",
    }


@app.get("/api/v1/servers")
async def servers(
    _: None = Depends(require_auth),
):
    """
    Возвращает список серверов из config.yml и статус SSH-соединения,
    если соединение уже открыто.
    """

    result = []

    for server_name, server_cfg in get_configured_servers().items():
        manager = get_existing_ssh_manager(server_name)

        ssh_host = server_cfg.get("sshHost", server_name)

        result.append(
            {
                "server": server_name,
                "ssh_host": ssh_host,
                "connected": manager.is_connected() if manager else False,
                "commandTimeoutSeconds": int(server_cfg.get("commandTimeoutSeconds", 60)),
                "disableGlobalPolicies": bool(server_cfg.get("disableGlobalPolicies", False)),
                "policies_count": len(server_cfg.get("policies", []) or []),
            }
        )

    return {
        "ok": True,
        "servers": result,
    }


@app.get("/ssh/status")
async def ssh_status(
    server: str = Query(...),
    _: None = Depends(require_auth),
):
    server_cfg = get_server_config(server)
    manager = get_ssh_manager(server, server_cfg)

    return {
        "server": server,
        "ssh_host": manager.ssh_host,
        "connected": manager.is_connected(),
    }


@app.post("/ssh/connect")
async def ssh_connect(
    req: ServerRequest,
    request: Request,
    _: None = Depends(require_auth),
):
    manager = get_ssh_manager(req.server, get_server_config(req.server))

    try:
        await manager.connect()
    except Exception as exc:
        await write_audit_event(
            {
                "event": "ssh_connect",
                "server": req.server,
                "ssh_host": manager.ssh_host,
                "decision": "error",
                "error": "ssh_connect_failed",
                "message": str(exc),
                "client": request.client.host if request.client else None,
            }
        )

        raise HTTPException(
            status_code=502,
            detail=make_error_body(
                error="ssh_connect_failed",
                message=str(exc),
                server=req.server,
            ),
        )

    await write_audit_event(
        {
            "event": "ssh_connect",
            "server": req.server,
            "ssh_host": manager.ssh_host,
            "decision": "ok",
            "client": request.client.host if request.client else None,
        }
    )

    return {
        "ok": True,
        "server": req.server,
        "ssh_host": manager.ssh_host,
        "status": "connected",
    }


@app.post("/ssh/disconnect")
async def ssh_disconnect(
    req: ServerRequest,
    request: Request,
    _: None = Depends(require_auth),
):
    manager = get_ssh_manager(req.server, get_server_config(req.server))
    await manager.close()

    await write_audit_event(
        {
            "event": "ssh_disconnect",
            "server": req.server,
            "ssh_host": manager.ssh_host,
            "decision": "ok",
            "client": request.client.host if request.client else None,
        }
    )

    return {
        "ok": True,
        "server": req.server,
        "ssh_host": manager.ssh_host,
        "status": "disconnected",
    }


@app.post("/api/v1/exec", response_model=ExecResponse)
async def exec_command(
    req: ExecRequest,
    request: Request,
    _: None = Depends(require_auth),
):
    request_id = str(uuid.uuid4())
    started_at = time.monotonic()

    server_cfg = get_server_config(req.server, request_id=request_id)

    print(
        f"[pctl] request_id={request_id} "
        f"server={req.server} "
        f"argv={req.argv}",
        flush=True,
    )

    # 1. Policy check
    decision = evaluate_policy(
        server_cfg=server_cfg,
        global_policies=get_global_policies(),
        argv=req.argv,
    )

    if not decision.allowed:
        duration_ms = int((time.monotonic() - started_at) * 1000)

        print(
            f"[pctl] request_id={request_id} "
            f"decision=deny "
            f"reason={decision.reason} "
            f"argv={req.argv}",
            flush=True,
        )

        await write_audit_event(
            {
                "event": "exec",
                "request_id": request_id,
                "server": req.server,
                "argv": req.argv,
                "decision": "deny",
                "reason": decision.reason,
                "policy": decision.policy,
                "duration_ms": duration_ms,
                "client": request.client.host if request.client else None,
            }
        )

        return JSONResponse(
            status_code=403,
            content=make_error_body(
                error="command_denied",
                message=decision.reason,
                request_id=request_id,
                server=req.server,
                argv=req.argv,
                duration_ms=duration_ms,
            ),
        )

    # 2. Safe remote command construction
    remote_command = " ".join(shlex.quote(arg) for arg in req.argv)

    print(
        f"[pctl] request_id={request_id} "
        f"decision=allow "
        f"policy={decision.policy} "
        f"remote_command={remote_command}",
        flush=True,
    )

    manager = get_ssh_manager(req.server, server_cfg)

    # 3. Execute over SSH
    try:
        result = await manager.run(remote_command)
    except Exception as exc:
        duration_ms = int((time.monotonic() - started_at) * 1000)

        await write_audit_event(
            {
                "event": "exec",
                "request_id": request_id,
                "server": req.server,
                "argv": req.argv,
                "remote_command": remote_command,
                "decision": "error",
                "error": "ssh_command_failed",
                "message": str(exc),
                "policy": decision.policy,
                "duration_ms": duration_ms,
                "client": request.client.host if request.client else None,
            }
        )

        raise HTTPException(
            status_code=502,
            detail=make_error_body(
                error="ssh_command_failed",
                message=str(exc),
                request_id=request_id,
                server=req.server,
                argv=req.argv,
                duration_ms=duration_ms,
                policy=decision.policy,
            ),
        )

    duration_ms = int((time.monotonic() - started_at) * 1000)

    stdout = result.stdout or ""
    stderr = result.stderr or ""

    exit_code = result.exit_status

    if exit_code is None:
        exit_code = -1

    print(
        f"[pctl] request_id={request_id} "
        f"exit_code={exit_code} "
        f"duration_ms={duration_ms} "
        f"stdout_bytes={len(stdout)} "
        f"stderr_bytes={len(stderr)}",
        flush=True,
    )

    await write_audit_event(
        {
            "event": "exec",
            "request_id": request_id,
            "server": req.server,
            "argv": req.argv,
            "remote_command": remote_command,
            "decision": "allow",
            "policy": decision.policy,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stderr_bytes": len(stderr.encode("utf-8")),
            "client": request.client.host if request.client else None,
        }
    )

    return ExecResponse(
        ok=True,
        error=None,
        message=None,
        request_id=request_id,
        server=req.server,
        argv=req.argv,
        remote_command=remote_command,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        policy=decision.policy,
    )