import time
import uuid
import shlex

from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .settings import CONFIG_PATH, API_TOKEN
from .models import (
    ExecRequest,
    ExecResponse,
    ServerRequest,
    CancelRequest,
    CanIRequest,
    CanIResponse,
)
from .running import cancel_running_command, list_running_commands
from .errors import make_error_body
from .auth import require_auth
from .config import (
    CONFIG,
    get_server_config,
    get_global_policies,
    get_configured_servers,
    reload_config,
)
from .limits import apply_output_limits
from .rate_limiter import wait_for_rate_limit
from .policy import evaluate_policy
from .ssh_manager import (
    get_ssh_manager,
    get_existing_ssh_manager,
)
from .audit import write_audit_event


app = FastAPI(
    title="pctl MVP Proxy",
    version="0.5.0",
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
        "version": "0.5.0",
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
                "rateLimit": server_cfg.get("rateLimit", None),
                "limits": server_cfg.get("limits", None),
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
    request_id = req.request_id or str(uuid.uuid4())
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

    # 3. Rate limit before sending command to server
    rate_limit_wait_ms = await wait_for_rate_limit(
        server=req.server,
        server_cfg=server_cfg,
    )

    if rate_limit_wait_ms > 0:
        print(
            f"[pctl] request_id={request_id} "
            f"rate_limit_wait_ms={rate_limit_wait_ms}",
            flush=True,
        )

    manager = get_ssh_manager(req.server, server_cfg)

    # 4. Execute over SSH
    try:
        result = await manager.run(
          command=remote_command,
          request_id=request_id,
          argv=req.argv,
        )
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
                "rate_limit_wait_ms": rate_limit_wait_ms,
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

    # 5. Apply output limits
    stdout, stderr, stdout_truncated, stderr_truncated = apply_output_limits(
        stdout=stdout,
        stderr=stderr,
        server_cfg=server_cfg,
    )

    exit_code = result.exit_status


    if exit_code is None:
        exit_code = -1


    stdout_bytes = len(stdout.encode("utf-8"))
    stderr_bytes = len(stderr.encode("utf-8"))

    print(
        f"[pctl] request_id={request_id} "
        f"exit_code={exit_code} "
        f"duration_ms={duration_ms} "
        f"stdout_bytes={stdout_bytes} "
        f"stderr_bytes={stderr_bytes} "
        f"stdout_truncated={stdout_truncated} "
        f"stderr_truncated={stderr_truncated}",
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
            "rate_limit_wait_ms": rate_limit_wait_ms,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
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
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )

@app.get("/api/v1/running")
async def running_commands(
    _: None = Depends(require_auth),
):
    return {
        "ok": True,
        "running": await list_running_commands(),
    }


@app.post("/api/v1/reload")
async def reload_proxy_config(
    request: Request,
    _: None = Depends(require_auth),
):
    """
    Перечитывает YAML config без рестарта контейнера.

    Важно:
      - новые политики/лимиты/rateLimit применятся к новым запросам;
      - уже открытые SSH-соединения не пересоздаются автоматически;
      - если поменяли sshHost, лучше сделать disconnect/connect или restart.
    """

    try:
        config = reload_config()
    except Exception as exc:
        await write_audit_event(
            {
                "event": "reload",
                "decision": "error",
                "message": str(exc),
                "client": request.client.host if request.client else None,
            }
        )

        raise HTTPException(
            status_code=500,
            detail=make_error_body(
                error="reload_failed",
                message=str(exc),
            ),
        )

    await write_audit_event(
        {
            "event": "reload",
            "decision": "ok",
            "servers": list(config.get("servers", {}).keys()),
            "globalPolicies": [
                p.get("name", "<unnamed-policy>")
                for p in config.get("globalPolicies", []) or []
            ],
            "client": request.client.host if request.client else None,
        }
    )

    return {
        "ok": True,
        "message": "config reloaded",
        "servers": list(config.get("servers", {}).keys()),
        "globalPolicies": [
            p.get("name", "<unnamed-policy>")
            for p in config.get("globalPolicies", []) or []
        ],
    }


@app.post("/api/v1/cancel")
async def cancel_command(
    req: CancelRequest,
    request: Request,
    _: None = Depends(require_auth),
):
    ok, message, item = await cancel_running_command(req.request_id)

    if not ok:
        await write_audit_event(
            {
                "event": "cancel",
                "request_id": req.request_id,
                "decision": "not_found_or_error",
                "message": message,
                "client": request.client.host if request.client else None,
            }
        )

        return JSONResponse(
            status_code=404,
            content=make_error_body(
                error="cancel_failed",
                message=message,
                request_id=req.request_id,
            ),
        )

    await write_audit_event(
        {
            "event": "cancel",
            "request_id": req.request_id,
            "server": item.server if item else None,
            "argv": item.argv if item else [],
            "remote_command": item.remote_command if item else None,
            "decision": "ok",
            "message": message,
            "client": request.client.host if request.client else None,
        }
    )

    return {
        "ok": True,
        "request_id": req.request_id,
        "message": message,
        "server": item.server if item else None,
        "argv": item.argv if item else [],
    }


@app.post("/api/v1/can-i", response_model=CanIResponse)
async def can_i(
    req: CanIRequest,
    request: Request,
    _: None = Depends(require_auth),
):
    server_cfg = get_server_config(req.server)

    decision = evaluate_policy(
        server_cfg=server_cfg,
        global_policies=get_global_policies(),
        argv=req.argv,
    )

    await write_audit_event(
        {
            "event": "can_i",
            "server": req.server,
            "argv": req.argv,
            "decision": "allow" if decision.allowed else "deny",
            "policy": decision.policy,
            "reason": decision.reason,
            "client": request.client.host if request.client else None,
        }
    )

    return CanIResponse(
        ok=True,
        allowed=decision.allowed,
        server=req.server,
        argv=req.argv,
        policy=decision.policy,
        reason=decision.reason,
    )