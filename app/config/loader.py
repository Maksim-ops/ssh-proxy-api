from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from fastapi import HTTPException

from app.api.errors import make_error_body
from app.config.settings import API_TOKEN, AUDIT_LOG_PATH, CONFIG_PATH, SSH_CONFIG, SSH_KNOWN_HOSTS


@dataclass(frozen=True)
class AppSettings:
    config_path: str
    ssh_config: str
    ssh_known_hosts: str
    api_token: Optional[str]
    audit_log_path: str
    database_url: str
    log_dir: str
    history_lines: int
    user_email: str
    username: str


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _merge_config(base_config: Dict[str, Any]) -> Dict[str, Any]:
    policies_file = base_config.get("policiesFile")

    if not policies_file:
        return base_config

    policies_path = Path(str(policies_file))

    if not policies_path.is_absolute():
        policies_path = Path(CONFIG_PATH).resolve().parent / policies_path

    policy_config = _load_yaml_file(policies_path)
    merged = dict(policy_config)
    merged.update(base_config)

    for key in ("servers", "globalPolicies", "rateLimit", "outputLimits"):
        if key not in base_config and key in policy_config:
            merged[key] = policy_config[key]

    return merged


def build_settings(config: Dict[str, Any]) -> AppSettings:
    streaming_cfg = config.get("streaming", {}) or {}
    app_cfg = config.get("app", {}) or {}
    db_cfg = config.get("database", {}) or {}

    return AppSettings(
        config_path=CONFIG_PATH,
        ssh_config=SSH_CONFIG,
        ssh_known_hosts=SSH_KNOWN_HOSTS,
        api_token=API_TOKEN,
        audit_log_path=AUDIT_LOG_PATH,
        database_url=os.getenv(
            "PCTL_DATABASE_URL",
            str(db_cfg.get("url", "mysql+pymysql://core_api:core_api@mysql:3306/core_api")),
        ),
        log_dir=os.getenv("PCTL_LOG_DIR", str(app_cfg.get("logDir", "/var/log/core-api/jobs"))),
        history_lines=int(streaming_cfg.get("history_lines", 1000)),
        user_email=str(app_cfg.get("userEmail", "maksim.nikitin@flant.com")),
        username=str(app_cfg.get("username", "maksim.nikitin")),
    )


CONFIG: Dict[str, Any] = {}
SETTINGS = AppSettings(
    config_path=CONFIG_PATH,
    ssh_config=SSH_CONFIG,
    ssh_known_hosts=SSH_KNOWN_HOSTS,
    api_token=API_TOKEN,
    audit_log_path=AUDIT_LOG_PATH,
    database_url=os.getenv("PCTL_DATABASE_URL", "mysql+pymysql://core_api:core_api@mysql:3306/core_api"),
    log_dir=os.getenv("PCTL_LOG_DIR", "/var/log/core-api/jobs"),
    history_lines=1000,
    user_email="maksim.nikitin@flant.com",
    username="maksim.nikitin",
)


def load_config_from_file() -> Dict[str, Any]:
    config = _load_yaml_file(Path(CONFIG_PATH))
    return _merge_config(config)


def reload_config() -> Dict[str, Any]:
    global SETTINGS

    new_config = load_config_from_file()
    CONFIG.clear()
    CONFIG.update(new_config)
    SETTINGS = build_settings(CONFIG)
    return CONFIG


reload_config()


def get_server_config(server: str, request_id: Optional[str] = None) -> Dict[str, Any]:
    servers = CONFIG.get("servers", {})

    if server not in servers:
        raise HTTPException(
            status_code=404,
            detail=make_error_body(
                error="unknown_server",
                message=f"Unknown server: {server}",
                request_id=request_id,
                server=server,
            ),
        )

    return servers[server]


def get_global_policies() -> list[dict[str, Any]]:
    return CONFIG.get("globalPolicies", []) or []


def get_configured_servers() -> Dict[str, Any]:
    return CONFIG.get("servers", {}) or {}


def get_global_limits() -> Dict[str, Any]:
    return CONFIG.get("outputLimits", {}) or {}


def get_global_rate_limit() -> Dict[str, Any]:
    return CONFIG.get("rateLimit", {}) or {}
