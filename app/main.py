import os
import re
import time
import uuid
import shlex
import asyncio
import posixpath
from dataclasses import dataclass
from typing import Optional, List, Any, Dict

import yaml
import asyncssh
from fastapi import FastAPI, HTTPException, Header, Depends, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


CONFIG_PATH = os.getenv("PCTL_CONFIG", "/etc/pctl/config.yml")
API_TOKEN = os.getenv("PCTL_API_TOKEN")

SSH_CONFIG = os.getenv("PCTL_SSH_CONFIG", "/home/appuser/.ssh/config")
SSH_KNOWN_HOSTS = os.getenv("PCTL_SSH_KNOWN_HOSTS", "/home/appuser/.ssh/known_hosts")


# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------

def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    if "servers" not in config or not isinstance(config["servers"], dict):
        raise RuntimeError("Invalid config: 'servers' section is required")

    if "globalPolicies" in config and not isinstance(config["globalPolicies"], list):
        raise RuntimeError("Invalid config: 'globalPolicies' must be a list")

    return config


CONFIG = load_config()


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class ExecRequest(BaseModel):
    server: str
    argv: List[str] = Field(..., min_length=1)


class ExecResponse(BaseModel):
    ok: bool
    error: Optional[str] = None
    message: Optional[str] = None

    request_id: str
    server: Optional[str] = None
    argv: List[str] = Field(default_factory=list)

    remote_command: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_ms: int = 0

    policy: Optional[str] = None


class ServerRequest(BaseModel):
    server: str


@dataclass
class PolicyDecision:
    allowed: bool
    policy: Optional[str]
    reason: str


# ---------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------

def make_error_body(
    *,
    error: str,
    message: str,
    request_id: Optional[str] = None,
    server: Optional[str] = None,
    argv: Optional[List[str]] = None,
    stdout: str = "",
    stderr: str = "",
    exit_code: Optional[int] = None,
    policy: Optional[str] = None,
    duration_ms: int = 0,
) -> Dict[str, Any]:
    return {
        "ok": False,
        "error": error,
        "message": message,
        "request_id": request_id or str(uuid.uuid4()),
        "server": server,
        "argv": argv or [],
        "remote_command": None,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "policy": policy,
    }


# ---------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------

async def require_auth(authorization: Optional[str] = Header(default=None)) -> None:
    if not API_TOKEN:
        raise HTTPException(
            status_code=500,
            detail=make_error_body(
                error="auth_not_configured",
                message="PCTL_API_TOKEN is not configured",
            ),
        )

    expected = f"Bearer {API_TOKEN}"

    if authorization != expected:
        raise HTTPException(
            status_code=401,
            detail=make_error_body(
                error="unauthorized",
                message="Invalid or missing Authorization Bearer token",
            ),
        )


# ---------------------------------------------------------------------
# Server config helpers
# ---------------------------------------------------------------------

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


def get_effective_policies(server_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Возвращает политики, применимые к серверу.

    Порядок:
      1. globalPolicies
      2. server-specific policies

    Сервер может отключить глобальные политики:

      disableGlobalPolicies: true

    Или отключить отдельные глобальные политики:

      disabledGlobalPolicies:
        - allow-df-h
    """

    result: List[Dict[str, Any]] = []

    disable_global = bool(server_cfg.get("disableGlobalPolicies", False))
    disabled_global_names = set(server_cfg.get("disabledGlobalPolicies") or [])

    if not disable_global:
        for policy in CONFIG.get("globalPolicies", []) or []:
            name = policy.get("name")

            if name in disabled_global_names:
                continue

            result.append(policy)

    result.extend(server_cfg.get("policies", []) or [])

    return result


# ---------------------------------------------------------------------
# Policy helpers: paths
# ---------------------------------------------------------------------

def normalize_policy_path(path: str) -> str:
    """
    Нормализуем путь для проверки политик.

    Примеры:
      /tmp/../root -> /root
      /tmp//a      -> /tmp/a
      ./abc        -> abc

    Важно:
    Это НЕ resolve symlinks на удалённом сервере.
    Для MVP нормально, но для строгой безопасности symlink bypass надо учитывать отдельно.
    """
    return posixpath.normpath(path)


def path_is_under(path: str, prefix: str) -> bool:
    path_norm = normalize_policy_path(path)
    prefix_norm = normalize_policy_path(prefix)

    if prefix_norm == "/":
        return path_norm.startswith("/")

    return path_norm == prefix_norm or path_norm.startswith(prefix_norm.rstrip("/") + "/")


def contains_parent_traversal(path: str) -> bool:
    parts = [p for p in path.split("/") if p not in ("", ".")]
    return ".." in parts


def validate_path_arg(path: str, path_cfg: Dict[str, Any]) -> tuple[bool, str]:
    if path == "":
        return False, "empty path is not allowed"

    if "\x00" in path or "\n" in path or "\r" in path:
        return False, "path contains forbidden control characters"

    # Чтобы путь не был случайно интерпретирован командой как опция.
    # Например: ls -- -file технически возможно, но для MVP запрещаем.
    if path.startswith("-"):
        return False, "path starting with '-' is not allowed"

    allow_parent_traversal = bool(path_cfg.get("allowParentTraversal", False))

    if not allow_parent_traversal and contains_parent_traversal(path):
        return False, "parent traversal '..' is not allowed"

    allow_globs = bool(path_cfg.get("allowGlobs", False))

    if not allow_globs:
        for ch in ["*", "?", "[", "]", "{", "}"]:
            if ch in path:
                return False, "glob characters are not allowed in path"

    is_absolute = path.startswith("/")

    allow_absolute = bool(path_cfg.get("allowAbsolute", False))
    allow_relative = bool(path_cfg.get("allowRelative", True))

    if is_absolute and not allow_absolute:
        return False, "absolute paths are not allowed"

    if not is_absolute and not allow_relative:
        return False, "relative paths are not allowed"

    path_norm = normalize_policy_path(path)

    # 1. denyPrefixes имеют высокий приоритет
    deny_prefixes = path_cfg.get("denyPrefixes") or []

    for prefix in deny_prefixes:
        if path_is_under(path_norm, prefix):
            return False, f"path '{path}' is denied by prefix '{prefix}'"

    # 2. denyRegex тоже имеет высокий приоритет
    deny_regex = path_cfg.get("denyRegex") or []

    for pattern in deny_regex:
        if re.fullmatch(pattern, path_norm):
            return False, f"path '{path}' is denied by denyRegex '{pattern}'"

    # 3. allowPrefixes, если заданы, требуют попадания хотя бы в один prefix
    allow_prefixes = path_cfg.get("allowPrefixes") or []

    if allow_prefixes:
        matched = any(path_is_under(path_norm, prefix) for prefix in allow_prefixes)

        if not matched:
            return False, f"path '{path}' is not under allowed prefixes"

    # 4. allowRegex, если заданы, требуют совпадения хотя бы с одним pattern
    allow_regex = path_cfg.get("allowRegex") or []

    if allow_regex:
        matched = any(re.fullmatch(pattern, path_norm) for pattern in allow_regex)

        if not matched:
            return False, f"path '{path}' does not match allowRegex"

    return True, "path is allowed"


# ---------------------------------------------------------------------
# Policy helpers: linux args
# ---------------------------------------------------------------------

def match_linux_args_policy(rule: Dict[str, Any], args: List[str]) -> tuple[bool, str]:
    """
    Универсальная MVP-политика для простых Linux-команд.

    Пример:

      - name: allow-ls-paths
        command: ls
        allowedFlags:
          - "-la"
          - "-lh"
        flagsPosition: anywhere
        pathArgs:
          min: 0
          max: 2
          allowAbsolute: true
          allowRelative: true
          allowGlobs: false
          allowRegex:
            - "^/tmp(/.*)?$"
          denyRegex:
            - "^/root(/.*)?$"

    flagsPosition:
      anywhere     - флаги можно до и после путей: ls /tmp -la
      beforePaths  - флаги только до первого path arg: ls -la /tmp
    """

    allowed_flags = set(rule.get("allowedFlags") or [])
    flags_position = rule.get("flagsPosition", "anywhere")

    if flags_position not in ("anywhere", "beforePaths"):
        return False, f"invalid flagsPosition: {flags_position}"

    path_cfg = rule.get("pathArgs") or {}

    min_paths = int(path_cfg.get("min", 0))
    max_paths = int(path_cfg.get("max", 0))

    flags: List[str] = []
    paths: List[str] = []

    end_of_options = False
    seen_path = False

    for arg in args:
        if arg == "--":
            end_of_options = True
            continue

        is_option_like = arg.startswith("-")

        if not end_of_options and is_option_like:
            if flags_position == "beforePaths" and seen_path:
                return False, f"flag '{arg}' after path is not allowed"

            if arg not in allowed_flags:
                return False, f"flag '{arg}' is not allowed"

            flags.append(arg)
            continue

        paths.append(arg)
        seen_path = True

    if len(paths) < min_paths:
        return False, f"too few path arguments: min={min_paths}"

    if len(paths) > max_paths:
        return False, f"too many path arguments: max={max_paths}"

    for path in paths:
        ok, reason = validate_path_arg(path, path_cfg)

        if not ok:
            return False, reason

    return True, "matched linux args policy"


# ---------------------------------------------------------------------
# Policy helpers: kubectl
# ---------------------------------------------------------------------

def normalize_resource(resource: str) -> str:
    """
    kubectl resource может быть:
      pods
      pod
      pod/my-pod
      deployments.apps

    Для MVP делаем простую нормализацию:
      pod/my-pod -> pod
      deployments.apps -> deployments
    """
    resource = resource.strip().lower()

    if "/" in resource:
        resource = resource.split("/", 1)[0]

    if "." in resource:
        resource = resource.split(".", 1)[0]

    return resource


def parse_kubectl_namespace(args: List[str]) -> tuple[Optional[str], bool]:
    namespace = None
    all_namespaces = False

    i = 0

    while i < len(args):
        arg = args[i]

        if arg in ("-A", "--all-namespaces"):
            all_namespaces = True

        elif arg in ("-n", "--namespace"):
            if i + 1 < len(args):
                namespace = args[i + 1]
                i += 1

        elif arg.startswith("--namespace="):
            namespace = arg.split("=", 1)[1]

        i += 1

    return namespace, all_namespaces


def match_kubectl_policy(rule: Dict[str, Any], argv: List[str]) -> tuple[bool, str]:
    """
    MVP-парсер kubectl.

    Поддерживаем простой формат:

      kubectl get pods
      kubectl get pods -n default
      kubectl get pods -A
      kubectl get services

    Пока НЕ поддерживаем формат:

      kubectl -n default get pods

    Это можно добавить позже.
    """

    if len(argv) < 2:
        return False, "kubectl subcommand is required"

    subcommand = argv[1]

    allowed_subcommands = rule.get("subcommands")

    if allowed_subcommands and subcommand not in allowed_subcommands:
        return False, f"kubectl subcommand '{subcommand}' is not allowed by this rule"

    allowed_resources = rule.get("resources")

    if allowed_resources:
        if len(argv) < 3:
            return False, "kubectl resource is required"

        resource = normalize_resource(argv[2])
        allowed_resources_normalized = [
            normalize_resource(r) for r in allowed_resources
        ]

        if resource not in allowed_resources_normalized:
            return False, f"kubectl resource '{resource}' is not allowed"

    allowed_namespaces = rule.get("allowNamespaces")

    if allowed_namespaces:
        namespace, all_namespaces = parse_kubectl_namespace(argv[3:])

        if "*" not in allowed_namespaces:
            if all_namespaces:
                return False, "all namespaces are not allowed"

            if namespace and namespace not in allowed_namespaces:
                return False, f"namespace '{namespace}' is not allowed"

    return True, "matched kubectl policy"


# ---------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------

def evaluate_policy(server_cfg: Dict[str, Any], argv: List[str]) -> PolicyDecision:
    if not argv:
        return PolicyDecision(
            allowed=False,
            policy=None,
            reason="empty command",
        )

    command = argv[0]
    args = argv[1:]

    policies = get_effective_policies(server_cfg)

    command_policy_seen = False
    last_denial_reason = "command is not allowed by policy"

    for rule in policies:
        rule_name = rule.get("name", "<unnamed-policy>")
        rule_command = rule.get("command")

        if rule_command != command:
            continue

        command_policy_seen = True

        # 1. Exact argv policy
        #
        # Пример:
        #
        # command: df
        # allowedArgv:
        #   - ["-h"]
        #
        # Разрешит только:
        # df -h
        #
        if "allowedArgv" in rule:
            allowed_argv_variants = rule.get("allowedArgv") or []

            for allowed_args in allowed_argv_variants:
                if args == allowed_args:
                    return PolicyDecision(
                        allowed=True,
                        policy=rule_name,
                        reason="matched exact argv policy",
                    )

            last_denial_reason = f"argv is not allowed by policy '{rule_name}'"
            continue

        # 2. Linux args policy: allowedFlags + pathArgs
        if "allowedFlags" in rule or "pathArgs" in rule:
            matched, reason = match_linux_args_policy(rule, args)

            if matched:
                return PolicyDecision(
                    allowed=True,
                    policy=rule_name,
                    reason=reason,
                )

            last_denial_reason = reason
            continue

        # 3. kubectl policy
        if command == "kubectl":
            matched, reason = match_kubectl_policy(rule, argv)

            if matched:
                return PolicyDecision(
                    allowed=True,
                    policy=rule_name,
                    reason=reason,
                )

            last_denial_reason = reason
            continue

        last_denial_reason = f"policy '{rule_name}' has unsupported policy format"

    if command_policy_seen:
        return PolicyDecision(
            allowed=False,
            policy=None,
            reason=last_denial_reason,
        )

    return PolicyDecision(
        allowed=False,
        policy=None,
        reason="command is not allowed by policy",
    )


# ---------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------

class SSHManager:
    def __init__(self, server_name: str, server_cfg: Dict[str, Any]) -> None:
        self.server_name = server_name
        self.server_cfg = server_cfg

        # sshHost — это Host alias из /home/appuser/.ssh/config.
        # Если sshHost не указан, используем имя server из API.
        self.ssh_host = server_cfg.get("sshHost", server_name)

        self.command_timeout = int(server_cfg.get("commandTimeoutSeconds", 60))

        self._conn: Optional[asyncssh.SSHClientConnection] = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._lock:
            if self._conn is not None:
                return

            print(
                f"[pctl] connecting server={self.server_name} "
                f"ssh_host={self.ssh_host}",
                flush=True,
            )
            print(f"[pctl] ssh config: {SSH_CONFIG}", flush=True)
            print(f"[pctl] known_hosts: {SSH_KNOWN_HOSTS}", flush=True)

            try:
                self._conn = await asyncssh.connect(
                    self.ssh_host,
                    config=[SSH_CONFIG],
                    known_hosts=SSH_KNOWN_HOSTS,
                    keepalive_interval=30,
                    keepalive_count_max=3,
                )
            except Exception as exc:
                self._conn = None
                print(f"[pctl] SSH connect failed: {repr(exc)}", flush=True)
                raise

            print(
                f"[pctl] SSH connected server={self.server_name} "
                f"ssh_host={self.ssh_host}",
                flush=True,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                print(
                    f"[pctl] closing SSH connection server={self.server_name}",
                    flush=True,
                )

                self._conn.close()

                try:
                    await self._conn.wait_closed()
                finally:
                    self._conn = None

    async def reset(self) -> None:
        await self.close()

    def is_connected(self) -> bool:
        return self._conn is not None

    async def run(self, command: str) -> asyncssh.SSHCompletedProcess:
        last_error: Optional[Exception] = None

        for attempt in [1, 2]:
            try:
                await self.connect()

                assert self._conn is not None

                result = await asyncio.wait_for(
                    self._conn.run(command, check=False),
                    timeout=self.command_timeout,
                )

                return result

            except Exception as exc:
                last_error = exc

                print(
                    f"[pctl] SSH command failed "
                    f"server={self.server_name} "
                    f"attempt={attempt} "
                    f"error={repr(exc)}",
                    flush=True,
                )

                await self.reset()

                if attempt == 2:
                    break

        raise RuntimeError(f"SSH command failed after reconnect: {last_error}")


ssh_managers: Dict[str, SSHManager] = {}


def get_ssh_manager(server: str) -> SSHManager:
    if server not in ssh_managers:
        server_cfg = get_server_config(server)
        ssh_managers[server] = SSHManager(server, server_cfg)

    return ssh_managers[server]


# ---------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------

app = FastAPI(
    title="pctl MVP Proxy",
    version="0.3.0",
)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc: HTTPException):
    """
    Чтобы ошибки были не так:

      {"detail": {...}}

    а сразу так:

      {"error": "...", "message": "..."}
    """

    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
        )

    return JSONResponse(
        status_code=exc.status_code,
        content=make_error_body(
            error="http_error",
            message=str(exc.detail),
        ),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=make_error_body(
            error="validation_error",
            message=str(exc),
        ),
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "config": CONFIG_PATH,
        "servers": list(CONFIG.get("servers", {}).keys()),
        "globalPolicies": [
            p.get("name", "<unnamed-policy>")
            for p in CONFIG.get("globalPolicies", []) or []
        ],
        "auth": "enabled" if API_TOKEN else "disabled",
    }


@app.get("/ssh/status")
async def ssh_status(
    server: str = Query(...),
    _: None = Depends(require_auth),
):
    manager = get_ssh_manager(server)

    return {
        "server": server,
        "ssh_host": manager.ssh_host,
        "connected": manager.is_connected(),
    }


@app.post("/ssh/connect")
async def ssh_connect(
    req: ServerRequest,
    _: None = Depends(require_auth),
):
    manager = get_ssh_manager(req.server)

    try:
        await manager.connect()
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=make_error_body(
                error="ssh_connect_failed",
                message=str(exc),
                server=req.server,
            ),
        )

    return {
        "ok": True,
        "server": req.server,
        "ssh_host": manager.ssh_host,
        "status": "connected",
    }


@app.post("/ssh/disconnect")
async def ssh_disconnect(
    req: ServerRequest,
    _: None = Depends(require_auth),
):
    manager = get_ssh_manager(req.server)
    await manager.close()

    return {
        "ok": True,
        "server": req.server,
        "ssh_host": manager.ssh_host,
        "status": "disconnected",
    }


@app.post("/api/v1/exec", response_model=ExecResponse)
async def exec_command(
    req: ExecRequest,
    _: None = Depends(require_auth),
):
    request_id = str(uuid.uuid4())
    started_at = time.monotonic()

    server_cfg = get_server_config(req.server, request_id=request_id)

    print(
        f"[pctl] request_id={request_id} "
        f"server={req.server} "
        f"argv={req.argv}",
        flush=True,
    )

    # 1. Policy check
    decision = evaluate_policy(server_cfg, req.argv)

    if not decision.allowed:
        duration_ms = int((time.monotonic() - started_at) * 1000)

        print(
            f"[pctl] request_id={request_id} "
            f"decision=deny "
            f"reason={decision.reason} "
            f"argv={req.argv}",
            flush=True,
        )

        return JSONResponse(
            status_code=403,
            content=make_error_body(
                error="command_denied",
                message=decision.reason,
                request_id=request_id,
                server=req.server,
                argv=req.argv,
                duration_ms=duration_ms,
            ),
        )

    # 2. Safe remote command construction
    #
    # Важно:
    # Команда всё равно отправляется на удалённую сторону строкой,
    # поэтому каждый argv-элемент нужно shell-quote.
    remote_command = " ".join(shlex.quote(arg) for arg in req.argv)

    print(
        f"[pctl] request_id={request_id} "
        f"decision=allow "
        f"policy={decision.policy} "
        f"remote_command={remote_command}",
        flush=True,
    )

    # 3. Execute over SSH
    manager = get_ssh_manager(req.server)

    try:
        result = await manager.run(remote_command)
    except Exception as exc:
        duration_ms = int((time.monotonic() - started_at) * 1000)

        raise HTTPException(
            status_code=502,
            detail=make_error_body(
                error="ssh_command_failed",
                message=str(exc),
                request_id=request_id,
                server=req.server,
                argv=req.argv,
                duration_ms=duration_ms,
                policy=decision.policy,
            ),
        )

    duration_ms = int((time.monotonic() - started_at) * 1000)

    stdout = result.stdout or ""
    stderr = result.stderr or ""

    exit_code = result.exit_status

    if exit_code is None:
        exit_code = -1

    print(
        f"[pctl] request_id={request_id} "
        f"exit_code={exit_code} "
        f"duration_ms={duration_ms} "
        f"stdout_bytes={len(stdout)} "
        f"stderr_bytes={len(stderr)}",
        flush=True,
    )

    return ExecResponse(
        ok=True,
        error=None,
        message=None,
        request_id=request_id,
        server=req.server,
        argv=req.argv,
        remote_command=remote_command,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        policy=decision.policy,
    )