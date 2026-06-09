from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.auth.permissions import normalize_role, permissions_for_role
from app.auth.security import build_password_hash
from app.db.models import Action, Project, Proxy, Server, Team, Token, User
from app.db.session import get_session_factory


class EntityNotFoundError(Exception):
    pass


class EntityConflictError(Exception):
    pass


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _commit(session) -> None:
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise EntityConflictError(str(exc.orig or exc)) from exc


def _dt(value):
    return value.isoformat() if value else None


def _serialize_team(item: Team, *, users: list[User] | None = None, projects: list[Project] | None = None) -> dict[str, Any]:
    user_names = [user.username for user in users or []]
    project_names = [project.name for project in projects or []]
    return {
        "id": item.id,
        "name": item.name,
        "slug": item.slug,
        "created_at": _dt(item.created_at),
        "user_names": ", ".join(user_names),
        "project_names": ", ".join(project_names),
        "user_count": len(user_names),
        "project_count": len(project_names),
    }


def _serialize_project(item: Project, team: Team | None = None) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "slug": item.slug,
        "team_id": item.team_id,
        "team_name": team.name if team else None,
        "created_at": _dt(item.created_at),
    }


def _serialize_user(item: User, team: Team | None = None) -> dict[str, Any]:
    return {
        "id": item.id,
        "username": item.username,
        "email": item.email,
        "role": normalize_role(item.role),
        "team_id": item.team_id,
        "team_name": team.name if team else None,
        "is_active": item.is_active,
        "created_at": _dt(item.created_at),
        "last_login": _dt(item.last_login),
        "public_key": item.public_key,
        "permissions": permissions_for_role(item.role),
    }


def _serialize_proxy(item: Proxy) -> dict[str, Any]:
    return {
        "id": item.id,
        "proxy": item.proxy,
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
        "type": item.server_type,
        "enabled": item.enabled,
        "created_at": _dt(item.created_at),
    }


def _serialize_action(item: Action) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
    }


def _serialize_token(item: Token) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "enabled": item.enabled,
        "created_at": _dt(item.created_at),
    }


def _resolve_project_team_id(session, project_id: int | None, fallback_team_id: int | None) -> int | None:
    if project_id is None:
        return fallback_team_id
    project = session.get(Project, project_id)
    if project is None:
        raise EntityNotFoundError(f"project {project_id} not found")
    return project.team_id


def list_teams_crud() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        teams = session.scalars(select(Team).order_by(Team.id.asc())).all()
        items: list[dict[str, Any]] = []
        for team in teams:
            users = session.scalars(select(User).where(User.team_id == team.id).order_by(User.username.asc())).all()
            projects = session.scalars(select(Project).where(Project.team_id == team.id).order_by(Project.name.asc())).all()
            items.append(_serialize_team(team, users=users, projects=projects))
        return items
    finally:
        session.close()


def get_team(team_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Team, team_id)
        if item is None:
            raise EntityNotFoundError(f"team {team_id} not found")
        users = session.scalars(select(User).where(User.team_id == team_id).order_by(User.username.asc())).all()
        projects = session.scalars(select(Project).where(Project.team_id == team_id).order_by(Project.name.asc())).all()
        return _serialize_team(item, users=users, projects=projects)
    finally:
        session.close()


def create_team(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = Team(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        return _serialize_team(item)
    finally:
        session.close()


def update_team(team_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Team, team_id)
        if item is None:
            raise EntityNotFoundError(f"team {team_id} not found")
        for key, value in data.items():
            setattr(item, key, value)
        _commit(session)
        session.refresh(item)
        users = session.scalars(select(User).where(User.team_id == team_id).order_by(User.username.asc())).all()
        projects = session.scalars(select(Project).where(Project.team_id == team_id).order_by(Project.name.asc())).all()
        return _serialize_team(item, users=users, projects=projects)
    finally:
        session.close()


def delete_team(team_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(Team, team_id)
        if item is None:
            raise EntityNotFoundError(f"team {team_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()


def list_projects_crud() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        rows = session.execute(select(Project, Team).join(Team, Team.id == Project.team_id).order_by(Project.id.asc())).all()
        return [_serialize_project(project, team) for project, team in rows]
    finally:
        session.close()


def get_project(project_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        row = session.execute(select(Project, Team).join(Team, Team.id == Project.team_id).where(Project.id == project_id)).first()
        if row is None:
            raise EntityNotFoundError(f"project {project_id} not found")
        project, team = row
        return _serialize_project(project, team)
    finally:
        session.close()


def create_project(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = Project(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        team = session.get(Team, item.team_id)
        return _serialize_project(item, team)
    finally:
        session.close()


def update_project(project_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Project, project_id)
        if item is None:
            raise EntityNotFoundError(f"project {project_id} not found")
        for key, value in data.items():
            setattr(item, key, value)
        _commit(session)
        session.refresh(item)
        team = session.get(Team, item.team_id)
        session.execute(
            Server.__table__.update().where(Server.project_id == item.id).values(team_id=item.team_id)
        )
        session.commit()
        return _serialize_project(item, team)
    finally:
        session.close()


def delete_project(project_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(Project, project_id)
        if item is None:
            raise EntityNotFoundError(f"project {project_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()


def list_users() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        rows = session.execute(select(User, Team).join(Team, Team.id == User.team_id, isouter=True).order_by(User.id.asc())).all()
        return [_serialize_user(user, team) for user, team in rows]
    finally:
        session.close()


def get_user(user_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        row = session.execute(select(User, Team).join(Team, Team.id == User.team_id, isouter=True).where(User.id == user_id)).first()
        if row is None:
            raise EntityNotFoundError(f"user {user_id} not found")
        user, team = row
        return _serialize_user(user, team)
    finally:
        session.close()


def create_user(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        raw_password = data.pop("password", None)
        if raw_password:
            data["password_hash"] = build_password_hash(raw_password)
        data["role"] = normalize_role(data.get("role") or "engineer")
        item = User(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        team = session.get(Team, item.team_id) if item.team_id else None
        return _serialize_user(item, team)
    finally:
        session.close()


def update_user(user_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(User, user_id)
        if item is None:
            raise EntityNotFoundError(f"user {user_id} not found")
        raw_password = data.pop("password", None)
        if "role" in data and data["role"] is not None:
            data["role"] = normalize_role(data["role"])
        for key, value in data.items():
            setattr(item, key, value)
        if raw_password:
            item.password_hash = build_password_hash(raw_password)
        _commit(session)
        session.refresh(item)
        team = session.get(Team, item.team_id) if item.team_id else None
        return _serialize_user(item, team)
    finally:
        session.close()


def delete_user(user_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(User, user_id)
        if item is None:
            raise EntityNotFoundError(f"user {user_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()


def list_proxies() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        items = session.scalars(select(Proxy).order_by(Proxy.id.asc())).all()
        return [_serialize_proxy(item) for item in items]
    finally:
        session.close()


def get_proxy(proxy_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Proxy, proxy_id)
        if item is None:
            raise EntityNotFoundError(f"proxy {proxy_id} not found")
        return _serialize_proxy(item)
    finally:
        session.close()


def create_proxy(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = Proxy(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        return _serialize_proxy(item)
    finally:
        session.close()


def update_proxy(proxy_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Proxy, proxy_id)
        if item is None:
            raise EntityNotFoundError(f"proxy {proxy_id} not found")
        for key, value in data.items():
            setattr(item, key, value)
        _commit(session)
        session.refresh(item)
        return _serialize_proxy(item)
    finally:
        session.close()


def delete_proxy(proxy_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(Proxy, proxy_id)
        if item is None:
            raise EntityNotFoundError(f"proxy {proxy_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()


def list_servers_crud() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        rows = session.execute(
            select(Server, Team, Project, Proxy)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .join(Proxy, Proxy.id == Server.proxy_id, isouter=True)
            .order_by(Server.id.asc())
        ).all()
        return [_serialize_server(server, team, project, proxy) for server, team, project, proxy in rows]
    finally:
        session.close()


def get_server(server_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        row = session.execute(
            select(Server, Team, Project, Proxy)
            .join(Team, Team.id == Server.team_id, isouter=True)
            .join(Project, Project.id == Server.project_id, isouter=True)
            .join(Proxy, Proxy.id == Server.proxy_id, isouter=True)
            .where(Server.id == server_id)
        ).first()
        if row is None:
            raise EntityNotFoundError(f"server {server_id} not found")
        server, team, project, proxy = row
        return _serialize_server(server, team, project, proxy)
    finally:
        session.close()


def create_server(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        data["team_id"] = _resolve_project_team_id(session, data.get("project_id"), data.get("team_id"))
        item = Server(**{"server_type" if key == "type" else key: value for key, value in data.items()})
        session.add(item)
        _commit(session)
        session.refresh(item)
        team = session.get(Team, item.team_id) if item.team_id else None
        project = session.get(Project, item.project_id) if item.project_id else None
        proxy = session.get(Proxy, item.proxy_id) if item.proxy_id else None
        return _serialize_server(item, team, project, proxy)
    finally:
        session.close()


def update_server(server_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Server, server_id)
        if item is None:
            raise EntityNotFoundError(f"server {server_id} not found")
        merged_project_id = data.get("project_id", item.project_id)
        merged_team_id = data.get("team_id", item.team_id)
        resolved_team_id = _resolve_project_team_id(session, merged_project_id, merged_team_id)
        for key, value in data.items():
            setattr(item, "server_type" if key == "type" else key, value)
        item.team_id = resolved_team_id
        _commit(session)
        session.refresh(item)
        team = session.get(Team, item.team_id) if item.team_id else None
        project = session.get(Project, item.project_id) if item.project_id else None
        proxy = session.get(Proxy, item.proxy_id) if item.proxy_id else None
        return _serialize_server(item, team, project, proxy)
    finally:
        session.close()


def delete_server(server_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(Server, server_id)
        if item is None:
            raise EntityNotFoundError(f"server {server_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()


def list_actions() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        items = session.scalars(select(Action).order_by(Action.id.asc())).all()
        return [_serialize_action(item) for item in items]
    finally:
        session.close()


def get_action(action_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Action, action_id)
        if item is None:
            raise EntityNotFoundError(f"action {action_id} not found")
        return _serialize_action(item)
    finally:
        session.close()


def create_action(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = Action(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        return _serialize_action(item)
    finally:
        session.close()


def update_action(action_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Action, action_id)
        if item is None:
            raise EntityNotFoundError(f"action {action_id} not found")
        for key, value in data.items():
            setattr(item, key, value)
        _commit(session)
        session.refresh(item)
        return _serialize_action(item)
    finally:
        session.close()


def delete_action(action_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(Action, action_id)
        if item is None:
            raise EntityNotFoundError(f"action {action_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()


def list_tokens() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        items = session.scalars(select(Token).order_by(Token.id.asc())).all()
        return [_serialize_token(item) for item in items]
    finally:
        session.close()


def get_token(token_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Token, token_id)
        if item is None:
            raise EntityNotFoundError(f"token {token_id} not found")
        return _serialize_token(item)
    finally:
        session.close()


def create_token(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        raw_token = data.pop("token")
        item = Token(name=data["name"], token_hash=_sha256(raw_token), enabled=data.get("enabled", True))
        session.add(item)
        _commit(session)
        session.refresh(item)
        return _serialize_token(item)
    finally:
        session.close()


def update_token(token_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Token, token_id)
        if item is None:
            raise EntityNotFoundError(f"token {token_id} not found")

        raw_token = data.pop("token", None)
        for key, value in data.items():
            setattr(item, key, value)
        if raw_token is not None:
            item.token_hash = _sha256(raw_token)

        _commit(session)
        session.refresh(item)
        return _serialize_token(item)
    finally:
        session.close()


def delete_token(token_id: int) -> None:
    session = get_session_factory()()
    try:
        item = session.get(Token, token_id)
        if item is None:
            raise EntityNotFoundError(f"token {token_id} not found")
        session.delete(item)
        _commit(session)
    finally:
        session.close()
