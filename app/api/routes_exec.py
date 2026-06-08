from __future__ import annotations

import asyncio
import shlex
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect

from app.api.errors import make_error_body
from app.api.rate_limit import wait_for_rate_limit
from app.api.schemas import CancelRequest, CanIRequest, CanIResponse, ExecAcceptedResponse, ExecRequest
from app.audit import write_audit_event
from app.auth import AuthenticatedUser, require_auth, require_ws_access
from app.auth.permissions import is_superadmin
from app.config import SETTINGS, get_global_policies, get_server_config
from app.db.repositories import (
    build_job_log_entries,
    create_command_stream,
    create_job,
    get_job_by_request_id,
    get_server_by_name,
    get_stream_meta,
    get_user_by_email,
    replace_job_logs,
    update_job_finished,
    update_job_started,
    user_can_access_server,
    user_can_access_stream,
)
from app.policy import evaluate_policy
from app.ssh.manager import get_ssh_manager
from app.ssh.state import CommandStream, get_stream, register_stream, remove_running_command, request_cancel


router = APIRouter(tags=["exec"])


def _build_ws_paths(stream_id: int, share_token: str) -> tuple[str, str]:
    ws_path = f"/ws?stream_id={stream_id}"
    share_ws_path = f"/ws?stream_id={stream_id}&share_token={share_token}"
    return ws_path, share_ws_path


def _ensure_server_scope(server_name: str, user: AuthenticatedUser, request_id: str | None = None) -> None:
    allowed = user_can_access_server(server_name=server_name, is_superadmin=is_superadmin(user), team_id=user.team_id)
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=make_error_body(
                error="forbidden_server",
                message=f"Access to server '{server_name}' is forbidden",
                request_id=request_id,
                server=server_name,
            ),
        )


async def _execute_job(*, job_id: int, stream: CommandStream, request_id: str, server_name: str, argv: list[str], user: AuthenticatedUser, server_row_id: Optional[int]) -> None:
    server_cfg = get_server_config(server_name, request_id=request_id)
    remote_command = shlex.join(argv)
    manager = get_ssh_manager(server_name, server_cfg)

    await stream.publish(
        {
            "type": "started",
            "stream_id": stream.stream_id,
            "job_id": job_id,
            "request_id": request_id,
            "server": server_name,
            "argv": argv,
            "command": remote_command,
        }
    )

    update_job_started(job_id)

    try:
        result = await manager.run(command=remote_command, request_id=request_id, argv=argv, job_id=job_id, stream=stream)
    except Exception as exc:
        await stream.publish(
            {
                "type": "error",
                "stream_id": stream.stream_id,
                "job_id": job_id,
                "request_id": request_id,
                "message": str(exc),
            }
        )
        update_job_finished(job_id, status="failed", exit_code=1, stdout_lines=stream.stdout_lines, stderr_lines=stream.stderr_lines)
        replace_job_logs(job_id, build_job_log_entries(job_id, stream.stdout_log_path, stream.stdout_lines, stream.stderr_log_path, stream.stderr_lines))
        await write_audit_event(
            {
                "event": "exec_error",
                "request_id": request_id,
                "server": server_name,
                "argv": argv,
                "message": str(exc),
                "decision": "error",
            },
            action_name="EXEC_ALLOWED",
            request_id=request_id,
            user_id=user.id,
            server_id=server_row_id,
            session_id=user.session_id,
            resource="exec",
            result="failed",
        )
        await stream.close()
        return

    terminal_type = "finished"
    terminal_status = "completed"
    exit_code = result.exit_code

    if result.timeout:
        terminal_type = "error"
        terminal_status = "timeout"
        exit_code = 124

    if result.cancelled:
        terminal_type = "cancelled"
        terminal_status = "cancelled"

    if not stream.closed:
        await stream.publish(
            {
                "type": terminal_type,
                "stream_id": stream.stream_id,
                "job_id": job_id,
                "request_id": request_id,
                "exit_code": exit_code,
                "status": terminal_status,
            }
        )

    update_job_finished(job_id, status=terminal_status, exit_code=exit_code, stdout_lines=stream.stdout_lines, stderr_lines=stream.stderr_lines)
    replace_job_logs(job_id, build_job_log_entries(job_id, stream.stdout_log_path, stream.stdout_lines, stream.stderr_log_path, stream.stderr_lines))

    if not (result.cancelled and stream.closed):
        await write_audit_event(
            {
                "event": "exec_finished",
                "request_id": request_id,
                "server": server_name,
                "argv": argv,
                "decision": terminal_status,
            },
            action_name="EXEC_ALLOWED",
            request_id=request_id,
            user_id=user.id,
            server_id=server_row_id,
            session_id=user.session_id,
            resource="exec",
            result=terminal_status,
        )
    await stream.close()


@router.post("/api/v1/can-i", response_model=CanIResponse)
async def can_i(req: CanIRequest, user: AuthenticatedUser = Depends(require_auth)):
    _ensure_server_scope(req.server, user)
    server_cfg = get_server_config(req.server)
    decision = evaluate_policy(server_cfg=server_cfg, global_policies=get_global_policies(), argv=req.argv)
    return CanIResponse(ok=True, allowed=decision.allowed, server=req.server, argv=req.argv, policy=decision.policy, reason=decision.reason)


@router.post("/api/v1/exec", response_model=ExecAcceptedResponse)
async def exec_command(req: ExecRequest, request: Request, user: AuthenticatedUser = Depends(require_auth)):
    request_id = req.request_id or str(uuid.uuid4())
    started_at = time.monotonic()

    _ensure_server_scope(req.server, user, request_id=request_id)
    server_cfg = get_server_config(req.server, request_id=request_id)
    server_row = get_server_by_name(req.server)
    user_row = get_user_by_email(user.email)

    wait_ms = await wait_for_rate_limit(server=req.server, server_cfg=server_cfg)
    decision = evaluate_policy(server_cfg=server_cfg, global_policies=get_global_policies(), argv=req.argv)

    if not decision.allowed:
        duration_ms = int((time.monotonic() - started_at) * 1000)
        await write_audit_event(
            {
                "event": "exec_denied",
                "request_id": request_id,
                "server": req.server,
                "argv": req.argv,
                "policy": decision.policy,
                "reason": decision.reason,
                "wait_ms": wait_ms,
                "duration_ms": duration_ms,
                "client": request.client.host if request.client else None,
                "decision": "denied",
            },
            action_name="EXEC_DENIED",
            request_id=request_id,
            user_id=user_row.id if user_row else user.id,
            server_id=server_row.id if server_row else None,
            session_id=user.session_id,
            resource="exec",
            result="denied",
        )
        raise HTTPException(
            status_code=403,
            detail=make_error_body(
                error="policy_denied",
                message=decision.reason,
                request_id=request_id,
                server=req.server,
                argv=req.argv,
                policy=decision.policy,
                duration_ms=duration_ms,
            ),
        )

    job = create_job(
        request_id=request_id,
        user_id=user_row.id if user_row else user.id,
        auth_session_id=user.session_id,
        server_id=server_row.id if server_row else None,
        server_name=req.server,
        client_type=req.client_type,
        argv=req.argv,
    )
    stream_meta = create_command_stream(job["id"], is_public=False)

    log_dir = Path(SETTINGS.log_dir) / req.server / request_id
    stream = CommandStream(
        stream_id=stream_meta["id"],
        job_id=job["id"],
        request_id=request_id,
        history_limit=SETTINGS.history_lines,
        stdout_log_path=log_dir / "stdout.log",
        stderr_log_path=log_dir / "stderr.log",
    )
    await register_stream(stream)

    await write_audit_event(
        {
            "event": "exec_queued",
            "request_id": request_id,
            "server": req.server,
            "argv": req.argv,
            "decision": "queued",
            "client": request.client.host if request.client else None,
            "wait_ms": wait_ms,
        },
        action_name="EXEC_ALLOWED",
        request_id=request_id,
        user_id=user_row.id if user_row else user.id,
        server_id=server_row.id if server_row else None,
        session_id=user.session_id,
        resource="exec",
        result="queued",
    )

    asyncio.create_task(
        _execute_job(
            job_id=job["id"],
            stream=stream,
            request_id=request_id,
            server_name=req.server,
            argv=req.argv,
            user=user,
            server_row_id=server_row.id if server_row else None,
        )
    )

    ws_path, share_ws_path = _build_ws_paths(stream_meta["id"], stream_meta["share_token"])
    return ExecAcceptedResponse(
        ok=True,
        request_id=request_id,
        job_id=job["id"],
        stream_id=stream_meta["id"],
        status="queued",
        server=req.server,
        argv=req.argv,
        share_token=stream_meta["share_token"],
        ws_path=ws_path,
        share_ws_path=share_ws_path,
    )


@router.post("/api/v1/cancel")
async def cancel_command(req: CancelRequest, user: AuthenticatedUser = Depends(require_auth)):
    running = await request_cancel(req.request_id)

    if running is not None:
        _ensure_server_scope(running.server, user, request_id=req.request_id)
    else:
        job = get_job_by_request_id(req.request_id)
        if job is None:
            raise HTTPException(status_code=404, detail=make_error_body(error="session_not_found", message="Unknown request_id", request_id=req.request_id))
        _ensure_server_scope(job["server_name"], user, request_id=req.request_id)
        await write_audit_event(
            {
                "event": "cancel_requested",
                "request_id": req.request_id,
                "decision": "accepted",
                "message": "cancel request queued",
            },
            action_name="CANCEL",
            request_id=req.request_id,
            user_id=user.id,
            session_id=user.session_id,
            resource="exec",
            result="accepted",
        )
        return {"ok": True, "request_id": req.request_id, "message": "cancel request queued"}

    ok, message = await running.manager.cancel_process(running.process)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail=make_error_body(error="cancel_failed", message=message, request_id=req.request_id),
        )

    await running.stream.publish(
        {
            "type": "cancelled",
            "stream_id": running.stream.stream_id,
            "job_id": running.job_id,
            "request_id": req.request_id,
            "status": "cancelled",
            "exit_code": 130,
        }
    )
    await running.stream.close()
    update_job_finished(
        running.job_id,
        status="cancelled",
        exit_code=130,
        stdout_lines=running.stream.stdout_lines,
        stderr_lines=running.stream.stderr_lines,
    )
    replace_job_logs(
        running.job_id,
        build_job_log_entries(
            running.job_id,
            running.stream.stdout_log_path,
            running.stream.stdout_lines,
            running.stream.stderr_log_path,
            running.stream.stderr_lines,
        ),
    )
    await remove_running_command(req.request_id)

    server_row = get_server_by_name(running.server)
    await write_audit_event(
        {
            "event": "cancel_requested",
            "request_id": req.request_id,
            "decision": "accepted",
            "message": message,
        },
        action_name="CANCEL",
        request_id=req.request_id,
        user_id=user.id,
        server_id=server_row.id if server_row else None,
        session_id=user.session_id,
        resource="exec",
        result="accepted",
    )
    await write_audit_event(
        {
            "event": "exec_finished",
            "request_id": req.request_id,
            "server": running.server,
            "argv": running.argv,
            "decision": "cancelled",
        },
        action_name="EXEC_ALLOWED",
        request_id=req.request_id,
        user_id=user.id,
        server_id=server_row.id if server_row else None,
        session_id=user.session_id,
        resource="exec",
        result="cancelled",
    )
    return {"ok": True, "request_id": req.request_id, "message": message}


@router.websocket("/ws")
async def websocket_stream(
    websocket: WebSocket,
    stream_id: int = Query(...),
    history_lines: int = Query(default=1000, ge=0, le=5000),
    user: AuthenticatedUser = Depends(require_ws_access),
):
    if not user.is_share_token and not user_can_access_stream(stream_id=stream_id, is_superadmin=is_superadmin(user), team_id=user.team_id):
        await websocket.close(code=4403)
        return

    stream = await get_stream(stream_id)
    meta = get_stream_meta(stream_id)

    if stream is None or meta is None:
        await websocket.close(code=4404)
        return

    await websocket.accept()
    subscriber = await stream.subscribe(history_lines=history_lines)

    try:
        while True:
            event = await subscriber.queue.get()
            await websocket.send_json(event)
            if event.get("type") in {"finished", "cancelled", "error"} and stream.closed:
                break
    except WebSocketDisconnect:
        return
    finally:
        await stream.unsubscribe(subscriber)
