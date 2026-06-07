from __future__ import annotations

import time
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from app.config import SETTINGS


_engine = None
_session_factory = None
_server_engine = None
_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "sql" / "schema_and_seed.sql"


def _get_database_url():
    return make_url(SETTINGS.database_url)


def _get_server_engine() -> Engine:
    global _server_engine

    if _server_engine is None:
        server_url = _get_database_url().set(database=None)
        _server_engine = create_engine(
            server_url,
            pool_pre_ping=True,
            future=True,
        )

    return _server_engine


def _split_sql_statements(sql_script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []

    for raw_line in sql_script.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("--") or stripped.startswith("#"):
            continue

        current.append(raw_line)
        if stripped.endswith(";"):
            statement = "\n".join(current).strip().rstrip(";").strip()
            if statement:
                statements.append(statement)
            current = []

    tail = "\n".join(current).strip().rstrip(";").strip()
    if tail:
        statements.append(tail)

    return statements


def _apply_schema_file() -> None:
    if not _SCHEMA_PATH.exists():
        raise RuntimeError(f"schema file not found: {_SCHEMA_PATH}")

    sql_script = _SCHEMA_PATH.read_text(encoding="utf-8")
    statements = _split_sql_statements(sql_script)

    if not statements:
        return

    with get_engine().begin() as conn:
        for statement in statements:
            conn.execute(text(statement))


def get_engine():
    global _engine

    if _engine is None:
        _engine = create_engine(
            SETTINGS.database_url,
            pool_pre_ping=True,
            future=True,
        )

    return _engine


def get_session_factory():
    global _session_factory

    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

    return _session_factory


def wait_for_db(max_attempts: int = 30, sleep_seconds: float = 2.0) -> None:
    last_error = None

    for _ in range(max_attempts):
        try:
            with _get_server_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:
            last_error = exc
            time.sleep(sleep_seconds)

    raise RuntimeError(f"database is not ready after {max_attempts} attempts: {last_error}")


def init_db() -> None:
    database_name = _get_database_url().database
    if not database_name:
        raise RuntimeError("database name is not set in PCTL_DATABASE_URL")

    with _get_server_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f"CREATE DATABASE IF NOT EXISTS `{database_name}`"))

    _apply_schema_file()


def get_db() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
