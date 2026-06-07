from __future__ import annotations

import hashlib
import secrets
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select

from app.config import CONFIG, SETTINGS
from app.db.models import Action, AuditEvent, CommandStreamMeta, Job, JobLog, Proxy, Server, Token, User, utcnow
from app.db.session import get_session_factory


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _serialize_user(item: User) -> dict[str, Any]:
    return {
        "id": item.id,
        "username": item.username,
        "email": item.email,
        "role": item.role,
    }


def _extract_auth_email(token_name: str) -> Optional[str]:
    if not token_name.startswith("auth:"):
        return None
    _, email, _ = token_name.split(":", 2)
    return email or None


def ensure_seed_data() -> None:
    session = get_session_factory()()

    try:
        for action_name in ("EXEC_ALLOWED", "EXEC_DENIED", "LOGIN", "CANCEL"):
            if session.scalar(select(Action).where(Action.name == action_name)) is None:
                session.add(Action(name=action_name))

        if session.scalar(select(User).where(User.email == SETTINGS.user_email)) is None:
            session.add(User(username=SETTINGS.username, email=SETTINGS.user_email, role="admin"))

        if SETTINGS.api_token and session.scalar(select(Token).where(Token.name == "default-api-token")) is None:
            session.add(Token(name="default-api-token", token_hash=_sha256(SETTINGS.api_token), enabled=True))

        proxy = session.scalar(select(Proxy).where(Proxy.proxy == "direct"))
        if proxy is None:
            proxy = Proxy(proxy="direct")
            session.add(proxy)
            session.flush()

        servers_cfg = CONFIG.get("servers", {}) or {}
        if session.scalar(select(Server).where(Server.name == "lifeorient")) is None:
            ssh_host = str(servers_cfg.get("lifeorient", {}).get("sshHost", "lifeorient"))
            session.add(
                Server(
                    name="lifeorient",
                    host=ssh_host,
                    ip="84.54.28.170",
                    proxy_id=proxy.id,
                    port=22,
                    environment="dev",
                    enabled=True,
                )
            )

        session.commit()
    finally:
        session.close()


def get_user_by_email(email: str) -> Optional[User]:
    session = get_session_factory()()
    try:
        return session.scalar(select(User).where(User.email == email))
    finally:
        session.close()


def issue_auth_token(email: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        user = session.scalar(select(User).where(User.email == email))
        if user is None:
            return None

        raw_token = secrets.token_urlsafe(32)
        token_name = f"auth:{user.email}:{secrets.token_hex(8)}"
        session.add(Token(name=token_name, token_hash=_sha256(raw_token), enabled=True))
        user.last_login = utcnow()
        session.commit()

        return {
            "access_token": raw_token,
            "token_name": token_name,
            "user": _serialize_user(user),
        }
    finally:
        session.close()


def get_authenticated_user_for_token(token_value: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        token = session.scalar(
            select(Token).where(
                Token.token_hash == _sha256(token_value),
                Token.enabled.is_(True),
            )
        )
        if token is None:
            return None

        email = _extract_auth_email(token.name)
        if not email:
            return None

        user = session.scalar(select(User).where(User.email == email))
        if user is None:
            return None

        return {
            "user": _serialize_user(user),
            "token_name": token.name,
        }
    finally:
        session.close()


def revoke_auth_token_by_name(token_name: str) -> bool:
    session = get_session_factory()()
    try:
        token = session.scalar(select(Token).where(Token.name == token_name, Token.enabled.is_(True)))
        if token is None or not token.name.startswith("auth:"):
            return False

        token.enabled = False
        session.commit()
        return True
    finally:
        session.close()


def get_server_by_name(name: str) -> Optional[Server]:
    session = get_session_factory()()
    try:
        return session.scalar(select(Server).where(Server.name == name))
    finally:
        session.close()


def _serialize_job(item: Job) -> dict[str, Any]:
    return {
        "id": item.id,
        "request_id": item.request_id,
        "user_id": item.user_id,
        "server_id": item.server_id,
        "server_name": item.server_name,
        "client_type": item.client_type,
        "command": item.command,
        "status": item.status,
        "stdout_lines": item.stdout_lines,
        "stderr_lines": item.stderr_lines,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "finished_at": item.finished_at.isoformat() if item.finished_at else None,
        "exit_code": item.exit_code,
    }


def _read_log_file(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _get_stream_meta_for_job(session, job_id: int) -> Optional[dict[str, Any]]:
    item = session.scalar(
        select(CommandStreamMeta)
        .where(CommandStreamMeta.job_id == job_id)
        .order_by(CommandStreamMeta.id.desc())
    )
    if item is None:
        return None
    return {
        "stream_id": item.id,
        "share_token": item.share_token,
        "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def list_servers() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        items = session.scalars(select(Server).order_by(Server.name.asc())).all()
        return [
            {
                "id": item.id,
                "name": item.name,
                "host": item.host,
                "ip": item.ip,
                "proxy_id": item.proxy_id,
                "port": item.port,
                "environment": item.environment,
                "enabled": item.enabled,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in items
        ]
    finally:
        session.close()


def create_job(*, request_id: str, user_id: Optional[int], server_id: Optional[int], server_name: str, client_type: str, argv: list[str]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        job = Job(
            request_id=request_id,
            user_id=user_id,
            server_id=server_id,
            server_name=server_name,
            client_type=client_type,
            command=shlex.join(argv),
            status="queued",
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        return {"id": job.id, "request_id": job.request_id}
    finally:
        session.close()


def create_command_stream(job_id: int, *, is_public: bool = False, ttl_hours: int = 24) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        stream = CommandStreamMeta(
            job_id=job_id,
            share_token=hashlib.sha256(f"{job_id}:{utcnow().isoformat()}".encode("utf-8")).hexdigest()[:40],
            is_public=is_public,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
        )
        session.add(stream)
        session.commit()
        session.refresh(stream)
        return {
            "id": stream.id,
            "share_token": stream.share_token,
            "expires_at": stream.expires_at.isoformat() if stream.expires_at else None,
        }
    finally:
        session.close()


def update_job_started(job_id: int) -> None:
    session = get_session_factory()()
    try:
        job = session.get(Job, job_id)
        if job is None:
            return
        job.status = "running"
        job.started_at = utcnow()
        session.commit()
    finally:
        session.close()


def update_job_finished(job_id: int, *, status: str, exit_code: Optional[int], stdout_lines: int, stderr_lines: int) -> None:
    session = get_session_factory()()
    try:
        job = session.get(Job, job_id)
        if job is None:
            return
        job.status = status
        job.exit_code = exit_code
        job.stdout_lines = stdout_lines
        job.stderr_lines = stderr_lines
        job.finished_at = utcnow()
        if job.started_at is None:
            job.started_at = job.finished_at
        session.commit()
    finally:
        session.close()


def replace_job_logs(job_id: int, entries: list[dict[str, Any]]) -> None:
    session = get_session_factory()()
    try:
        for item in session.scalars(select(JobLog).where(JobLog.job_id == job_id)).all():
            session.delete(item)
        session.flush()

        for entry in entries:
            session.add(
                JobLog(
                    job_id=job_id,
                    log_file=entry["log_file"],
                    size_bytes=int(entry["size_bytes"]),
                    line_count=int(entry["line_count"]),
                )
            )
        session.commit()
    finally:
        session.close()


def list_jobs(limit: int = 100) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        jobs = session.scalars(select(Job).order_by(Job.id.desc()).limit(limit)).all()
        return [_serialize_job(item) for item in jobs]
    finally:
        session.close()


def list_audit_events(limit: int = 100) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        rows = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)).all()
        return [
            {
                "id": item.id,
                "request_id": item.request_id,
                "user_id": item.user_id,
                "server_id": item.server_id,
                "action_id": item.action_id,
                "resource": item.resource,
                "result": item.result,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in rows
        ]
    finally:
        session.close()


def create_audit_event(*, request_id: str, user_id: Optional[int], server_id: Optional[int], action_name: str, resource: str, result: str) -> None:
    session = get_session_factory()()
    try:
        action = session.scalar(select(Action).where(Action.name == action_name))
        event = AuditEvent(
            request_id=request_id or None,
            user_id=user_id,
            server_id=server_id,
            action_id=action.id if action else None,
            resource=resource,
            result=result,
        )
        session.add(event)
        session.commit()
    finally:
        session.close()


def find_stream_access(*, stream_id: int, share_token: str) -> bool:
    session = get_session_factory()()
    try:
        stream = session.scalar(
            select(CommandStreamMeta).where(
                CommandStreamMeta.id == stream_id,
                CommandStreamMeta.share_token == share_token,
            )
        )
        return stream is not None
    finally:
        session.close()


def get_stream_meta(stream_id: int) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        item = session.get(CommandStreamMeta, stream_id)
        if item is None:
            return None
        return {
            "id": item.id,
            "job_id": item.job_id,
            "share_token": item.share_token,
            "is_public": item.is_public,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        }
    finally:
        session.close()


def build_job_log_entries(job_id: int, stdout_path: Path, stdout_lines: int, stderr_path: Path, stderr_lines: int) -> list[dict[str, Any]]:
    entries = []

    for path, line_count in ((stdout_path, stdout_lines), (stderr_path, stderr_lines)):
        if path.exists():
            entries.append(
                {
                    "job_id": job_id,
                    "log_file": str(path),
                    "size_bytes": path.stat().st_size,
                    "line_count": line_count,
                }
            )

    return entries



def list_sessions(*, user_id: int, is_admin: bool, limit: int = 100) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = select(Job).order_by(Job.id.desc()).limit(limit)
        if not is_admin:
            stmt = stmt.where(Job.user_id == user_id)
        jobs = session.scalars(stmt).all()
        items: list[dict[str, Any]] = []
        for job in jobs:
            row = _serialize_job(job)
            row["stream"] = _get_stream_meta_for_job(session, job.id)
            items.append(row)
        return items
    finally:
        session.close()



def get_session_detail(*, request_id: str, user_id: int, is_admin: bool) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = select(Job).where(Job.request_id == request_id)
        if not is_admin:
            stmt = stmt.where(Job.user_id == user_id)
        job = session.scalar(stmt)
        if job is None:
            return None

        stdout = ""
        stderr = ""
        log_entries: list[dict[str, Any]] = []
        for item in session.scalars(select(JobLog).where(JobLog.job_id == job.id).order_by(JobLog.id.asc())).all():
            path = Path(item.log_file)
            entry = {
                "id": item.id,
                "log_file": item.log_file,
                "size_bytes": item.size_bytes,
                "line_count": item.line_count,
            }
            log_entries.append(entry)
            if path.name == "stdout.log":
                stdout = _read_log_file(path)
            elif path.name == "stderr.log":
                stderr = _read_log_file(path)

        row = _serialize_job(job)
        row["stream"] = _get_stream_meta_for_job(session, job.id)
        row["stdout"] = stdout
        row["stderr"] = stderr
        row["logs"] = log_entries
        return row
    finally:
        session.close()
