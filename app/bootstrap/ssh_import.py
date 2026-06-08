from __future__ import annotations

import ipaddress
import re
import shlex
from pathlib import Path

from sqlalchemy import select

from app.config import SETTINGS
from app.db.models import Project, Proxy, Server, Team, User
from app.db.session import get_session_factory

_HOST_RE = re.compile(r"^Host\s+(.+)$", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"^Hostname\s+(.+)$", re.IGNORECASE)
_USER_RE = re.compile(r"^User\s+(.+)$", re.IGNORECASE)
_PROXY_COMMAND_RE = re.compile(r"^ProxyCommand\s+(.+)$", re.IGNORECASE)
_PROXY_JUMP_RE = re.compile(r"^ProxyJump\s+(.+)$", re.IGNORECASE)
_DEFAULT_TEAM_SLUG = "alfa"
_PROTECTED_TEAM_SLUGS = {"platform", _DEFAULT_TEAM_SLUG}


def maybe_import_ssh_config_servers() -> None:
    mode = (SETTINGS.ssh_import_mode or "off").lower()
    if mode not in {"once", "always"}:
        return
    import_ssh_config_servers(marker=SETTINGS.ssh_import_marker)


def import_ssh_config_servers(*, marker: str) -> int:
    config_path = Path(SETTINGS.ssh_config)
    if not config_path.exists():
        return 0

    records = _parse_ssh_config(config_path.read_text(encoding="utf-8", errors="replace"), marker=marker)
    if not records:
        return 0

    session = get_session_factory()()
    imported = 0
    try:
        direct_proxy = _get_or_create_proxy(session, "direct")

        for record in records:
            team_slug, project_slug = _derive_team_and_project(record["alias"])
            team = _get_or_create_team(session, team_slug)
            project = _get_or_create_project(session, team_id=team.id, slug=project_slug)

            proxy_alias = record.get("proxy_alias")
            proxy = _get_or_create_proxy(session, proxy_alias) if proxy_alias else direct_proxy

            server = session.scalar(select(Server).where(Server.name == record["alias"]))
            if server is None:
                server = Server(name=record["alias"], host=record["hostname"], ip=_normalize_ip(record["hostname"]))
                session.add(server)
                imported += 1

            server.host = record["hostname"]
            server.ip = _normalize_ip(record["hostname"])
            server.proxy_id = proxy.id if proxy else None
            server.team_id = team.id
            server.project_id = project.id
            server.port = 22
            server.environment = "imported"
            server.enabled = True

        session.flush()
        _cleanup_orphan_import_entities(session)
        session.commit()
        return imported
    finally:
        session.close()


def _parse_ssh_config(content: str, *, marker: str) -> list[dict[str, str | None]]:
    after_marker = False
    current: dict[str, str | None] | None = None
    records: list[dict[str, str | None]] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not after_marker:
            if line == marker:
                after_marker = True
            continue

        if not line or line.startswith("#"):
            continue

        host_match = _HOST_RE.match(line)
        if host_match:
            if current and current.get("alias") and current.get("hostname"):
                records.append(current)
            alias = host_match.group(1).split()[0].strip()
            if alias == "*":
                current = None
                continue
            current = {
                "alias": alias,
                "hostname": None,
                "user": None,
                "proxy_alias": None,
            }
            continue

        if current is None:
            continue

        hostname_match = _HOSTNAME_RE.match(line)
        if hostname_match:
            current["hostname"] = hostname_match.group(1).strip()
            continue

        user_match = _USER_RE.match(line)
        if user_match:
            current["user"] = user_match.group(1).strip()
            continue

        proxy_command_match = _PROXY_COMMAND_RE.match(line)
        if proxy_command_match:
            current["proxy_alias"] = _extract_proxy_alias(proxy_command_match.group(1).strip())
            continue

        proxy_jump_match = _PROXY_JUMP_RE.match(line)
        if proxy_jump_match:
            current["proxy_alias"] = _extract_proxy_jump_alias(proxy_jump_match.group(1).strip())

    if current and current.get("alias") and current.get("hostname"):
        records.append(current)

    return records


def _derive_team_and_project(alias: str) -> tuple[str, str]:
    parts = [part.strip() for part in alias.split(".") if part.strip()]
    if not parts:
        return _DEFAULT_TEAM_SLUG, "imported"

    first = parts[0]
    if first.startswith("team-"):
        team_slug = _slugify(first[5:]) or _DEFAULT_TEAM_SLUG
        project_slug = _slugify(parts[1] if len(parts) > 1 else alias)
        return team_slug, project_slug

    return _DEFAULT_TEAM_SLUG, _slugify(first)


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-") or "default"


def _normalize_ip(hostname: str) -> str | None:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        return None


def _get_or_create_team(session, slug: str) -> Team:
    item = session.scalar(select(Team).where(Team.slug == slug))
    if item is None:
        item = Team(name=slug, slug=slug)
        session.add(item)
        session.flush()
    return item


def _get_or_create_project(session, *, team_id: int, slug: str) -> Project:
    item = session.scalar(select(Project).where(Project.team_id == team_id, Project.slug == slug))
    if item is None:
        item = Project(name=slug, slug=slug, team_id=team_id)
        session.add(item)
        session.flush()
    return item


def _get_or_create_proxy(session, alias: str) -> Proxy:
    item = session.scalar(select(Proxy).where(Proxy.proxy == alias))
    if item is None:
        item = Proxy(proxy=alias)
        session.add(item)
        session.flush()
    return item


def _extract_proxy_alias(command: str) -> str | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if not tokens:
        return None

    if tokens[0] == "ssh":
        tokens = tokens[1:]

    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue

        if token in {"-F", "-i", "-J", "-l", "-o", "-p", "-S", "-W"}:
            skip_next = True
            continue

        if token.startswith("-"):
            continue

        host_token = token.rsplit("@", 1)[-1]
        if host_token and host_token not in {"%h:%p", "%r"}:
            return host_token

    return None


def _extract_proxy_jump_alias(value: str) -> str | None:
    first_hop = value.split(",", 1)[0].strip()
    if not first_hop:
        return None
    return first_hop.rsplit("@", 1)[-1].strip() or None


def _cleanup_orphan_import_entities(session) -> None:
    projects = session.scalars(select(Project).order_by(Project.id.asc())).all()
    for project in projects:
        team = session.get(Team, project.team_id)
        if team is None or team.slug in _PROTECTED_TEAM_SLUGS:
            continue
        has_servers = session.scalar(select(Server.id).where(Server.project_id == project.id).limit(1)) is not None
        if not has_servers:
            session.delete(project)

    session.flush()

    teams = session.scalars(select(Team).order_by(Team.id.asc())).all()
    for team in teams:
        if team.slug in _PROTECTED_TEAM_SLUGS:
            continue
        has_users = session.scalar(select(User.id).where(User.team_id == team.id).limit(1)) is not None
        has_servers = session.scalar(select(Server.id).where(Server.team_id == team.id).limit(1)) is not None
        has_projects = session.scalar(select(Project.id).where(Project.team_id == team.id).limit(1)) is not None
        if not has_users and not has_servers and not has_projects:
            session.delete(team)
