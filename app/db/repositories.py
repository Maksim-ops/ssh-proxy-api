from __future__ import annotations

import json
import secrets
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import aliased

from app.auth.permissions import is_superadmin_role, normalize_role, permissions_for_role
from app.auth.security import build_password_hash, generate_session_token, generate_session_uid, hash_token
from app.config import CONFIG, SETTINGS
from app.db.models import (
    Action,
    AuditEvent,
    CommandStreamMeta,
    Job,
    JobLog,
    Project,
    Proxy,
    Server,
    Team,
    Token,
    User,
    UserSession,
    utcnow,
)
from app.db.session import get_session_factory


def _serialize_team(item: Team) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "slug": item.slug,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _serialize_user(item: User, team: Team | None = None) -> dict[str, Any]:
    resolved_team_name = team.name if team else None
    return {
        "id": item.id,
        "username": item.username,
        "email": item.email,
        "role": normalize_role(item.role),
        "team_id": item.team_id,
        "team_name": resolved_team_name,
        "is_active": item.is_active,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "last_login": item.last_login.isoformat() if item.last_login else None,
        "public_key": item.public_key,
        "permissions": permissions_for_role(item.role),
    }


def _serialize_project(item: Project, team: Team | None = None) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "slug": item.slug,
        "team_id": item.team_id,
        "team_name": team.name if team else None,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _serialize_server(item: Server, team: Team | None = None, project: Project | None = None, proxy: Proxy | None = None) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "host": item.host,
        "ip": item.ip,
        "proxy_id": item.proxy_id,
        "proxy_name": proxy.proxy if proxy else None,
        "team_id": item.team_id,
        "team_name": team.name if team else None,
        "project_id": item.project_id,
        "project_name": project.name if project else None,
        "port": item.port,
        "environment": item.environment,
        "enabled": item.enabled,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _serialize_job(
    item: Job,
    server: Server | None = None,
    team: Team | None = None,
    project: Project | None = None,
) -> dict[str, Any]:
    resolved_server = server.name if server else item.server_name
    return {
        "id": item.id,
        "request_id": item.request_id,
        "user_id": item.user_id,
        "auth_session_id": item.auth_session_id,
        "server_id": item.server_id,
        "server_name": resolved_server,
        "team_id": team.id if team else None,
        "team_name": team.name if team else None,
        "project_id": project.id if project else None,
        "project_name": project.name if project else None,
        "client_type": item.client_type,
        "command": item.command,
        "status": item.status,
        "stdout_lines": item.stdout_lines,
        "stderr_lines": item.stderr_lines,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "finished_at": item.finished_at.isoformat() if item.finished_at else None,
        "exit_code": item.exit_code,
        "hidden_at": item.hidden_at.isoformat() if item.hidden_at else None,
    }


def _serialize_audit_event(
    item: AuditEvent,
    action: Action | None = None,
    server: Server | None = None,
    server_team: Team | None = None,
    project: Project | None = None,
    user: User | None = None,
    user_team: Team | None = None,
) -> dict[str, Any]:
    details = None
    if item.details_json:
        try:
            details = json.loads(item.details_json)
        except json.JSONDecodeError:
            details = {"raw": item.details_json}
    resolved_team = server_team or user_team
    return {
        "id": item.id,
        "request_id": item.request_id,
        "user_id": item.user_id,
        "server_id": item.server_id,
        "server_name": server.name if server else None,
        "team_id": resolved_team.id if resolved_team else None,
        "team_name": resolved_team.name if resolved_team else None,
        "project_id": project.id if project else None,
        "project_name": project.name if project else None,
        "action_id": item.action_id,
        "action": action.name if action else None,
        "session_id": item.session_id,
        "resource": item.resource,
        "result": item.result,
        "ip_address": item.ip_address,
        "user_email": user.email if user else None,
        "details": details,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _serialize_auth_session(item: UserSession, user: User | None = None, team: Team | None = None) -> dict[str, Any]:
    payload = {
        "id": item.id,
        "session_uid": item.session_uid,
        "user_id": item.user_id,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        "last_used_at": item.last_used_at.isoformat() if item.last_used_at else None,
        "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
        "revoked_reason": item.revoked_reason,
        "ip_address": item.ip_address,
        "user_agent": item.user_agent,
    }
    if user is not None:
        payload["user"] = _serialize_user(user, team)
    return payload


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


def _read_log_file(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _team_scope_stmt(stmt: Select, *, is_superadmin: bool, team_id: int | None) -> Select:
    if is_superadmin:
        return stmt
    if team_id is None:
        return stmt.where(Server.id == -1)
    return stmt.where(Server.team_id == team_id)


def _job_scope_stmt(stmt: Select, *, is_superadmin: bool, team_id: int | None) -> Select:
    if is_superadmin:
        return stmt
    if team_id is None:
        return stmt.where(Job.id == -1)
    return stmt.join(Server, Server.id == Job.server_id, isouter=True).where(Server.team_id == team_id)


def ensure_seed_data() -> None:
    session = get_session_factory()()

    try:
        for action_name in (
            "EXEC_ALLOWED",
            "EXEC_DENIED",
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE",
            "LOGOUT",
            "SESSION_REVOKED",
            "SUSPICIOUS_AUTH",
            "CANCEL",
            "PASSWORD_CHANGED",
            "SESSION_ROTATED",
            "SESSION_HIDDEN",
        ):
            if session.scalar(select(Action).where(Action.name == action_name)) is None:
                session.add(Action(name=action_name))

        platform_team = session.scalar(select(Team).where(Team.slug == "platform"))
        if platform_team is None:
            platform_team = Team(name="Platform", slug="platform")
            session.add(platform_team)
            session.flush()

        platform_project = session.scalar(
            select(Project).where(Project.team_id == platform_team.id, Project.slug == "platform")
        )
        if platform_project is None:
            platform_project = Project(name="platform", slug="platform", team_id=platform_team.id)
            session.add(platform_project)
            session.flush()

        superadmin = session.scalar(select(User).where(User.email == SETTINGS.superadmin_email))
        superadmin_password_hash = build_password_hash(SETTINGS.superadmin_password)
        if superadmin is None:
            superadmin = User(
                username=SETTINGS.superadmin_username,
                email=SETTINGS.superadmin_email,
                role="superadmin",
                team_id=None,
                password_hash=superadmin_password_hash,
                is_active=True,
            )
            session.add(superadmin)
        else:
            superadmin.username = SETTINGS.superadmin_username
            superadmin.role = "superadmin"
            superadmin.password_hash = superadmin_password_hash
            superadmin.is_active = True
            superadmin.team_id = None

        if SETTINGS.user_email and SETTINGS.user_email != SETTINGS.superadmin_email:
            bootstrap_user = session.scalar(select(User).where(User.email == SETTINGS.user_email))
            if bootstrap_user is None:
                session.add(
                    User(
                        username=SETTINGS.username,
                        email=SETTINGS.user_email,
                        role="engineer",
                        team_id=platform_team.id,
                        password_hash=None,
                        is_active=True,
                    )
                )

        if SETTINGS.api_token and session.scalar(select(Token).where(Token.name == "default-api-token")) is None:
            session.add(Token(name="default-api-token", token_hash=hash_token(SETTINGS.api_token), enabled=True))

        proxy = session.scalar(select(Proxy).where(Proxy.proxy == "direct"))
        if proxy is None:
            proxy = Proxy(proxy="direct")
            session.add(proxy)
            session.flush()

        servers_cfg = CONFIG.get("servers", {}) or {}
        server = session.scalar(select(Server).where(Server.name == "lifeorient"))
        ssh_host = str(servers_cfg.get("lifeorient", {}).get("sshHost", "lifeorient"))
        if server is None:
            session.add(
                Server(
                    name="lifeorient",
                    host=ssh_host,
                    ip="84.54.28.170",
                    proxy_id=proxy.id,
                    team_id=platform_team.id,
                    project_id=platform_project.id,
                    port=22,
                    environment="dev",
                    enabled=True,
                )
            )
        else:
            if server.team_id is None:
                server.team_id = platform_team.id
            if server.project_id is None:
                server.project_id = platform_project.id
            server.host = ssh_host

        session.commit()
    finally:
        session.close()


def get_user_by_email(email: str) -> Optional[User]:
    session = get_session_factory()()
    try:
        return session.scalar(select(User).where(User.email == email))
    finally:
        session.close()


def get_user_auth_record(email: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        row = session.execute(
            select(User, Team)
            .join(Team, Team.id == User.team_id, isouter=True)
            .where(User.email == email)
        ).first()
        if row is None:
            return None
        user, team = row
        return {
            "user": _serialize_user(user, team),
            "password_hash": user.password_hash,
            "is_active": user.is_active,
        }
    finally:
        session.close()


def mark_user_login(user_id: int) -> None:
    session = get_session_factory()()
    try:
        user = session.get(User, user_id)
        if user is None:
            return
        user.last_login = utcnow()
        session.commit()
    finally:
        session.close()


def create_auth_session(*, user_id: int, ip_address: str | None, user_agent: str | None, rotated_from_session_id: int | None = None) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        user = session.get(User, user_id)
        if user is None:
            raise RuntimeError(f"user {user_id} not found")

        raw_token = generate_session_token()
        session_row = UserSession(
            session_uid=generate_session_uid(),
            user_id=user_id,
            token_hash=hash_token(raw_token),
            expires_at=utcnow() + timedelta(minutes=SETTINGS.auth_access_ttl_minutes),
            last_used_at=utcnow(),
            rotated_from_session_id=rotated_from_session_id,
            user_agent=(user_agent or "")[:255] or None,
            ip_address=(ip_address or "")[:64] or None,
        )
        session.add(session_row)
        session.commit()
        session.refresh(session_row)

        team = session.get(Team, user.team_id) if user.team_id else None
        return {
            "access_token": raw_token,
            "session": _serialize_auth_session(session_row, user, team),
            "user": _serialize_user(user, team),
        }
    finally:
        session.close()


def get_authenticated_user_for_token(token_value: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        row = session.execute(
            select(UserSession, User, Team)
            .join(User, User.id == UserSession.user_id)
            .join(Team, Team.id == User.team_id, isouter=True)
            .where(
                UserSession.token_hash == hash_token(token_value),
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > utcnow(),
                User.is_active.is_(True),
            )
        ).first()
        if row is None:
            return None

        auth_session, user, team = row
        auth_session.last_used_at = utcnow()
        session.commit()

        return {
            "user": _serialize_user(user, team),
            "session": _serialize_auth_session(auth_session, user, team),
        }
    finally:
        session.close()


def revoke_auth_session(*, session_uid: str, reason: str, actor_user_id: int | None = None, restrict_user_id: int | None = None) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        row = session.execute(
            select(UserSession, User, Team)
            .join(User, User.id == UserSession.user_id)
            .join(Team, Team.id == User.team_id, isouter=True)
            .where(UserSession.session_uid == session_uid)
        ).first()
        if row is None:
            return None

        auth_session, user, team = row
        if restrict_user_id is not None and auth_session.user_id != restrict_user_id:
            return None
        if auth_session.revoked_at is None:
            auth_session.revoked_at = utcnow()
            auth_session.revoked_reason = reason[:128]
            session.commit()
        return {
            "session": _serialize_auth_session(auth_session, user, team),
            "user": _serialize_user(user, team),
            "actor_user_id": actor_user_id,
        }
    finally:
        session.close()


def revoke_all_auth_sessions_for_user(*, user_id: int, reason: str, except_session_uid: str | None = None) -> int:
    session = get_session_factory()()
    try:
        stmt = select(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
        if except_session_uid is not None:
            stmt = stmt.where(UserSession.session_uid != except_session_uid)
        items = session.scalars(stmt).all()
        count = 0
        for item in items:
            item.revoked_at = utcnow()
            item.revoked_reason = reason[:128]
            count += 1
        if count:
            session.commit()
        return count
    finally:
        session.close()


def rotate_auth_session(*, session_uid: str, ip_address: str | None, user_agent: str | None) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        item = session.scalar(
            select(UserSession).where(
                UserSession.session_uid == session_uid,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > utcnow(),
            )
        )
        if item is None:
            return None
        user_id = item.user_id
        old_id = item.id
        item.revoked_at = utcnow()
        item.revoked_reason = "rotated"
        session.commit()
    finally:
        session.close()

    return create_auth_session(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        rotated_from_session_id=old_id,
    )


def list_auth_sessions(*, is_superadmin: bool, user_id: int, limit: int = 200) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = (
            select(UserSession, User, Team)
            .join(User, User.id == UserSession.user_id)
            .join(Team, Team.id == User.team_id, isouter=True)
            .order_by(UserSession.id.desc())
            .limit(limit)
        )
        if not is_superadmin:
            stmt = stmt.where(UserSession.user_id == user_id)
        rows = session.execute(stmt).all()
        return [_serialize_auth_session(auth_session, user, team) for auth_session, user, team in rows]
    finally:
        session.close()


def list_teams() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        items = session.scalars(select(Team).order_by(Team.name.asc())).all()
        return [_serialize_team(item) for item in items]
    finally:
        session.close()


def list_servers(*, is_superadmin: bool = True, team_id: int | None = None) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = (
            select(Server, Team, Project, Proxy)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .join(Proxy, Proxy.id == Server.proxy_id, isouter=True)
            .order_by(Server.name.asc())
        )
        if not is_superadmin:
            if team_id is None:
                return []
            stmt = stmt.where(Server.team_id == team_id)
        items = session.execute(stmt).all()
        return [_serialize_server(server, team, project, proxy) for server, team, project, proxy in items]
    finally:
        session.close()


def get_server_by_name(name: str) -> Optional[Server]:
    session = get_session_factory()()
    try:
        return session.scalar(select(Server).where(Server.name == name))
    finally:
        session.close()


def user_can_access_server(*, server_name: str, is_superadmin: bool, team_id: int | None) -> bool:
    session = get_session_factory()()
    try:
        stmt = select(Server).where(Server.name == server_name)
        if not is_superadmin:
            if team_id is None:
                return False
            stmt = stmt.where(Server.team_id == team_id)
        return session.scalar(stmt) is not None
    finally:
        session.close()


def create_job(*, request_id: str, user_id: Optional[int], auth_session_id: Optional[int], server_id: Optional[int], server_name: str, client_type: str, argv: list[str]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        job = Job(
            request_id=request_id,
            user_id=user_id,
            auth_session_id=auth_session_id,
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
            share_token=secrets.token_hex(20),
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


def list_jobs(*, limit: int = 100, is_superadmin: bool = True, team_id: int | None = None) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = (
            select(Job, Server, Team, Project)
            .join(Server, Server.id == Job.server_id, isouter=True)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .order_by(Job.id.desc())
            .limit(limit)
        )
        if not is_superadmin:
            if team_id is None:
                return []
            stmt = stmt.where(Server.team_id == team_id)
        rows = session.execute(stmt).all()
        return [_serialize_job(job, server, team, project) for job, server, team, project in rows]
    finally:
        session.close()


def list_audit_events(limit: int = 100) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        user_team = aliased(Team)
        rows = session.execute(
            select(AuditEvent, Action, Server, Team, Project, User, user_team)
            .join(Action, Action.id == AuditEvent.action_id, isouter=True)
            .join(Server, Server.id == AuditEvent.server_id, isouter=True)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .join(User, User.id == AuditEvent.user_id, isouter=True)
            .join(user_team, user_team.id == User.team_id, isouter=True)
            .order_by(AuditEvent.id.desc())
            .limit(limit)
        ).all()
        return [
            _serialize_audit_event(item, action, server, server_team, project, user, audit_user_team)
            for item, action, server, server_team, project, user, audit_user_team in rows
        ]
    finally:
        session.close()


def create_audit_event(
    *,
    request_id: str,
    user_id: Optional[int],
    server_id: Optional[int],
    action_name: str,
    resource: str,
    result: str,
    session_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> None:
    session = get_session_factory()()
    try:
        action = session.scalar(select(Action).where(Action.name == action_name))
        event = AuditEvent(
            request_id=request_id or None,
            user_id=user_id,
            server_id=server_id,
            action_id=action.id if action else None,
            session_id=session_id,
            resource=resource,
            result=result,
            ip_address=ip_address,
            details_json=json.dumps(details, ensure_ascii=False) if details is not None else None,
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
                or_(CommandStreamMeta.expires_at.is_(None), CommandStreamMeta.expires_at > utcnow()),
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


def user_can_access_stream(*, stream_id: int, is_superadmin: bool, team_id: int | None) -> bool:
    session = get_session_factory()()
    try:
        stmt = (
            select(CommandStreamMeta)
            .join(Job, Job.id == CommandStreamMeta.job_id)
            .join(Server, Server.id == Job.server_id, isouter=True)
            .where(CommandStreamMeta.id == stream_id)
        )
        if not is_superadmin:
            if team_id is None:
                return False
            stmt = stmt.where(Server.team_id == team_id)
        return session.scalar(stmt) is not None
    finally:
        session.close()


def list_sessions(*, team_id: int | None, is_superadmin: bool, limit: int = 100) -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = (
            select(Job, Server, Team, Project)
            .join(Server, Server.id == Job.server_id, isouter=True)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .where(Job.hidden_at.is_(None))
            .order_by(Job.id.desc())
            .limit(limit)
        )
        if not is_superadmin:
            if team_id is None:
                return []
            stmt = stmt.where(Server.team_id == team_id)
        rows = session.execute(stmt).all()
        items: list[dict[str, Any]] = []
        for job, server, team, project in rows:
            row = _serialize_job(job, server, team, project)
            row["stream"] = _get_stream_meta_for_job(session, job.id)
            items.append(row)
        return items
    finally:
        session.close()


def get_session_detail(*, request_id: str, team_id: int | None, is_superadmin: bool) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        stmt = (
            select(Job, Server, Team, Project)
            .join(Server, Server.id == Job.server_id, isouter=True)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .where(Job.request_id == request_id, Job.hidden_at.is_(None))
        )
        if not is_superadmin:
            if team_id is None:
                return None
            stmt = stmt.where(Server.team_id == team_id)
        row = session.execute(stmt).first()
        if row is None:
            return None
        job, server, team, project = row

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

        payload = _serialize_job(job, server, team, project)
        payload["stream"] = _get_stream_meta_for_job(session, job.id)
        payload["stdout"] = stdout
        payload["stderr"] = stderr
        payload["logs"] = log_entries
        return payload
    finally:
        session.close()


def hide_session(*, request_id: str, actor_user_id: int, is_superadmin: bool, team_id: int | None) -> bool:
    session = get_session_factory()()
    try:
        stmt = select(Job).where(Job.request_id == request_id, Job.hidden_at.is_(None))
        if not is_superadmin:
            if team_id is None:
                return False
            stmt = stmt.join(Server, Server.id == Job.server_id, isouter=True).where(Server.team_id == team_id)
        job = session.scalar(stmt)
        if job is None:
            return False
        job.hidden_at = utcnow()
        job.hidden_by_user_id = actor_user_id
        session.commit()
        return True
    finally:
        session.close()


def get_job_by_request_id(request_id: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        row = session.execute(
            select(Job, Server, Team, Project)
            .join(Server, Server.id == Job.server_id, isouter=True)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .where(Job.request_id == request_id)
        ).first()
        if row is None:
            return None
        job, server, team, project = row
        return _serialize_job(job, server, team, project)
    finally:
        session.close()


def set_user_password_hash(*, user_id: int, password_hash: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        row = session.execute(
            select(User, Team)
            .join(Team, Team.id == User.team_id, isouter=True)
            .where(User.id == user_id)
        ).first()
        if row is None:
            return None
        user, team = row
        user.password_hash = password_hash
        session.commit()
        return _serialize_user(user, team)
    finally:
        session.close()



def get_server_runtime_config(name: str) -> Optional[dict[str, Any]]:
    session = get_session_factory()()
    try:
        server = session.scalar(select(Server).where(Server.name == name, Server.enabled.is_(True)))
        if server is None:
            return None
        return {
            "sshHost": server.name,
            "commandTimeoutSeconds": 120,
            "idleDisconnectSeconds": 300,
            "policies": [],
        }
    finally:
        session.close()
