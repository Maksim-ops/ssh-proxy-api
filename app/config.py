from typing import Dict, Any, Optional

import yaml
from fastapi import HTTPException

from .settings import CONFIG_PATH
from .errors import make_error_body


CONFIG: Dict[str, Any] = {}


def load_config_from_file() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    if "servers" not in config or not isinstance(config["servers"], dict):
        raise RuntimeError("Invalid config: 'servers' section is required")

    if "globalPolicies" in config and not isinstance(config["globalPolicies"], list):
        raise RuntimeError("Invalid config: 'globalPolicies' must be a list")

    return config


def reload_config() -> Dict[str, Any]:
    new_config = load_config_from_file()

    CONFIG.clear()
    CONFIG.update(new_config)

    return CONFIG


# initial load
reload_config()


def get_server_config(
    server: str,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
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
    return CONFIG.get("servers", {})


def get_global_limits() -> Dict[str, Any]:
    return CONFIG.get("limits", {}) or {}


def get_global_rate_limit() -> Dict[str, Any]:
    return CONFIG.get("rateLimit", {}) or {}