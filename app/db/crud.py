from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import Action, Proxy, Server, Token, User
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


def _serialize_user(item: User) -> dict[str, Any]:
    return {
        "id": item.id,
        "username": item.username,
        "email": item.email,
        "role": item.role,
        "created_at": _dt(item.created_at),
        "last_login": _dt(item.last_login),
        "public_key": item.public_key,
    }


def _serialize_proxy(item: Proxy) -> dict[str, Any]:
    return {
        "id": item.id,
        "proxy": item.proxy,
    }


def _serialize_server(item: Server) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "host": item.host,
        "ip": item.ip,
        "proxy_id": item.proxy_id,
        "port": item.port,
        "environment": item.environment,
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


def list_users() -> list[dict[str, Any]]:
    session = get_session_factory()()
    try:
        items = session.scalars(select(User).order_by(User.id.asc())).all()
        return [_serialize_user(item) for item in items]
    finally:
        session.close()


def get_user(user_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(User, user_id)
        if item is None:
            raise EntityNotFoundError(f"user {user_id} not found")
        return _serialize_user(item)
    finally:
        session.close()


def create_user(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = User(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        return _serialize_user(item)
    finally:
        session.close()


def update_user(user_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(User, user_id)
        if item is None:
            raise EntityNotFoundError(f"user {user_id} not found")
        for key, value in data.items():
            setattr(item, key, value)
        _commit(session)
        session.refresh(item)
        return _serialize_user(item)
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
        items = session.scalars(select(Server).order_by(Server.id.asc())).all()
        return [_serialize_server(item) for item in items]
    finally:
        session.close()


def get_server(server_id: int) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Server, server_id)
        if item is None:
            raise EntityNotFoundError(f"server {server_id} not found")
        return _serialize_server(item)
    finally:
        session.close()


def create_server(data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = Server(**data)
        session.add(item)
        _commit(session)
        session.refresh(item)
        return _serialize_server(item)
    finally:
        session.close()


def update_server(server_id: int, data: dict[str, Any]) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        item = session.get(Server, server_id)
        if item is None:
            raise EntityNotFoundError(f"server {server_id} not found")
        for key, value in data.items():
            setattr(item, key, value)
        _commit(session)
        session.refresh(item)
        return _serialize_server(item)
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
