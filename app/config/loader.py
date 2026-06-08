from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from fastapi import HTTPException

from app.api.errors import make_error_body
from app.config.settings import (
    API_TOKEN,
    AUDIT_LOG_PATH,
    AUTH_ACCESS_TTL_MINUTES,
    AUTH_PASSWORD_ITERATIONS,
    AUTH_PASSWORD_PEPPER,
    AUTH_RATE_LIMIT_MAX_ATTEMPTS,
    AUTH_RATE_LIMIT_WINDOW_SECONDS,
    AUTH_SUSPICIOUS_THRESHOLD,
    CONFIG_PATH,
    SSH_CONFIG,
    SSH_IMPORT_MARKER,
    SSH_IMPORT_MODE,
    SSH_KNOWN_HOSTS,
    SUPERADMIN_EMAIL,
    SUPERADMIN_PASSWORD,
    SUPERADMIN_USERNAME,
)


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
    superadmin_email: str
    superadmin_username: str
    superadmin_password: str
    auth_access_ttl_minutes: int
    auth_rate_limit_window_seconds: int
    auth_rate_limit_max_attempts: int
    auth_suspicious_threshold: int
    auth_password_iterations: int
    auth_password_pepper: str
    ssh_import_mode: str
    ssh_import_marker: str


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
    auth_cfg = config.get("auth", {}) or {}
    bootstrap_cfg = config.get("bootstrap", {}) or {}

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
        superadmin_email=str(auth_cfg.get("superadminEmail", SUPERADMIN_EMAIL)),
        superadmin_username=str(auth_cfg.get("superadminUsername", SUPERADMIN_USERNAME)),
        superadmin_password=str(os.getenv("PCTL_SUPERADMIN_PASSWORD", auth_cfg.get("superadminPassword", SUPERADMIN_PASSWORD))),
        auth_access_ttl_minutes=int(auth_cfg.get("accessTtlMinutes", AUTH_ACCESS_TTL_MINUTES)),
        auth_rate_limit_window_seconds=int(auth_cfg.get("rateLimitWindowSeconds", AUTH_RATE_LIMIT_WINDOW_SECONDS)),
        auth_rate_limit_max_attempts=int(auth_cfg.get("rateLimitMaxAttempts", AUTH_RATE_LIMIT_MAX_ATTEMPTS)),
        auth_suspicious_threshold=int(auth_cfg.get("suspiciousThreshold", AUTH_SUSPICIOUS_THRESHOLD)),
        auth_password_iterations=int(auth_cfg.get("passwordIterations", AUTH_PASSWORD_ITERATIONS)),
        auth_password_pepper=os.getenv("PCTL_AUTH_PASSWORD_PEPPER", auth_cfg.get("passwordPepper", AUTH_PASSWORD_PEPPER)),
        ssh_import_mode=str(os.getenv("PCTL_IMPORT_SSH_CONFIG_MODE", bootstrap_cfg.get("importSshConfigMode", SSH_IMPORT_MODE))).lower(),
        ssh_import_marker=str(os.getenv("PCTL_IMPORT_SSH_CONFIG_MARKER", bootstrap_cfg.get("importSshConfigMarker", SSH_IMPORT_MARKER))),
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
    superadmin_email=SUPERADMIN_EMAIL,
    superadmin_username=SUPERADMIN_USERNAME,
    superadmin_password=SUPERADMIN_PASSWORD,
    auth_access_ttl_minutes=AUTH_ACCESS_TTL_MINUTES,
    auth_rate_limit_window_seconds=AUTH_RATE_LIMIT_WINDOW_SECONDS,
    auth_rate_limit_max_attempts=AUTH_RATE_LIMIT_MAX_ATTEMPTS,
    auth_suspicious_threshold=AUTH_SUSPICIOUS_THRESHOLD,
    auth_password_iterations=AUTH_PASSWORD_ITERATIONS,
    auth_password_pepper=AUTH_PASSWORD_PEPPER,
    ssh_import_mode=SSH_IMPORT_MODE,
    ssh_import_marker=SSH_IMPORT_MARKER,
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

    if server in servers:
        return servers[server]

    from app.db.repositories import get_server_runtime_config

    runtime_cfg = get_server_runtime_config(server)
    if runtime_cfg is not None:
        return runtime_cfg

    raise HTTPException(
        status_code=404,
        detail=make_error_body(
            error="unknown_server",
            message=f"Unknown server: {server}",
            request_id=request_id,
            server=server,
        ),
    )


def get_global_policies() -> list[dict[str, Any]]:
    return CONFIG.get("globalPolicies", []) or []


def get_configured_servers() -> Dict[str, Any]:
    return CONFIG.get("servers", {}) or {}


def get_global_limits() -> Dict[str, Any]:
    return CONFIG.get("outputLimits", {}) or {}


def get_global_rate_limit() -> Dict[str, Any]:
    return CONFIG.get("rateLimit", {}) or {}
