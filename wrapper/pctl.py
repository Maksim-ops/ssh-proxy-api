#!/usr/bin/env python3

import os
import sys
import json
import uuid
import argparse
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


DEFAULT_PROXY_URL = "http://127.0.0.1:8080"
DEFAULT_STATE_FILE = "~/.config/pctl/state.json"


def get_state_file() -> Path:
    return Path(os.getenv("PCTL_STATE_FILE", DEFAULT_STATE_FILE)).expanduser()


def load_state() -> Dict[str, Any]:
    path = get_state_file()

    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    path = get_state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def get_active_server_from_state() -> Optional[str]:
    state = load_state()
    value = state.get("active_server")

    if isinstance(value, str) and value.strip():
        return value.strip()

    return None


def set_active_server(server: str) -> None:
    state = load_state()
    state["active_server"] = server
    save_state(state)


def resolve_server_value(explicit_server: Optional[str] = None) -> Optional[str]:
    """
    Приоритет:
      1. explicit --server
      2. PCTL_SERVER
      3. state file
      4. PCTL_DEFAULT_SSH_HOST
      5. PCTL_DEFAULT_SERVER
    """

    if explicit_server:
        return explicit_server

    if os.getenv("PCTL_SERVER"):
        return os.getenv("PCTL_SERVER")

    active = get_active_server_from_state()

    if active:
        return active

    if os.getenv("PCTL_DEFAULT_SSH_HOST"):
        return os.getenv("PCTL_DEFAULT_SSH_HOST")

    return os.getenv("PCTL_DEFAULT_SERVER")


def resolve_server(args) -> Optional[str]:
    return resolve_server_value(getattr(args, "server", None))


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def normalize_proxy_url(url: str) -> str:
    return url.rstrip("/")


def http_json(
    *,
    proxy_url: str,
    method: str,
    path: str,
    token: Optional[str],
    body: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, str]] = None,
    timeout: int = 300,
) -> Tuple[int, Dict[str, Any]]:
    proxy_url = normalize_proxy_url(proxy_url)

    url = proxy_url + path

    if query:
        url += "?" + urllib.parse.urlencode(query)

    data = None
    headers = {
        "Accept": "application/json",
    }

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status

    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code

    except urllib.error.URLError as exc:
        return 0, {
            "ok": False,
            "error": "proxy_unavailable",
            "message": str(exc.reason),
            "stdout": "",
            "stderr": "",
            "exit_code": None,
        }

    except Exception as exc:
        return 0, {
            "ok": False,
            "error": "proxy_request_failed",
            "message": str(exc),
            "stdout": "",
            "stderr": "",
            "exit_code": None,
        }

    text = raw.decode("utf-8", errors="replace") if raw else ""

    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {
            "ok": False,
            "error": "invalid_proxy_response",
            "message": "Proxy returned non-JSON response",
            "raw_response": text,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
        }

    return status, parsed


def exit_code_for_proxy_error(status: int, resp: Dict[str, Any]) -> int:
    if status == 401:
        return 10

    if status == 403:
        return 126

    if status == 404:
        return 127

    if status == 0:
        return 111

    if status >= 500:
        return 111

    return 1


def print_json_response(resp: Dict[str, Any]) -> None:
    print(json.dumps(resp, ensure_ascii=False, indent=2))


def print_error_response(resp: Dict[str, Any]) -> None:
    stdout = resp.get("stdout") or ""
    stderr = resp.get("stderr") or ""

    if stdout:
        sys.stdout.write(stdout)
        sys.stdout.flush()

    if stderr:
        sys.stderr.write(stderr)
        sys.stderr.flush()

    error = resp.get("error") or "error"
    message = resp.get("message") or "Unknown error"
    request_id = resp.get("request_id")

    eprint(f"pctl: {error}: {message}")

    if request_id:
        eprint(f"pctl: request_id={request_id}")


def handle_exec_response(
    *,
    status: int,
    resp: Dict[str, Any],
    as_json: bool,
) -> int:
    if as_json:
        print_json_response(resp)

        if resp.get("ok") is True:
            exit_code = resp.get("exit_code")
            return int(exit_code) if isinstance(exit_code, int) else 0

        return exit_code_for_proxy_error(status, resp)

    if status == 200 and resp.get("ok") is True:
        stdout = resp.get("stdout") or ""
        stderr = resp.get("stderr") or ""

        if stdout:
            sys.stdout.write(stdout)
            sys.stdout.flush()

        if stderr:
            sys.stderr.write(stderr)
            sys.stderr.flush()

        exit_code = resp.get("exit_code")

        if isinstance(exit_code, int):
            return exit_code

        return 0

    print_error_response(resp)
    return exit_code_for_proxy_error(status, resp)


def handle_admin_response(
    *,
    status: int,
    resp: Dict[str, Any],
    as_json: bool,
    command: str,
) -> int:
    if as_json:
        print_json_response(resp)

        if 200 <= status < 300 and resp.get("ok", True) is not False:
            return 0

        return exit_code_for_proxy_error(status, resp)

    if 200 <= status < 300 and resp.get("ok", True) is not False:
        if command == "status":
            server = resp.get("server")
            ssh_host = resp.get("ssh_host")
            connected = resp.get("connected")

            print(f"server={server} ssh_host={ssh_host} connected={connected}")
            return 0

        if command == "connect":
            server = resp.get("server")
            ssh_host = resp.get("ssh_host")
            print(f"connected: server={server} ssh_host={ssh_host}")
            return 0

        if command == "disconnect":
            server = resp.get("server")
            ssh_host = resp.get("ssh_host")
            print(f"disconnected: server={server} ssh_host={ssh_host}")
            return 0

        print_json_response(resp)
        return 0

    print_error_response(resp)
    return exit_code_for_proxy_error(status, resp)


def require_server(args) -> str:
    server = resolve_server(args)

    if not server:
        eprint(
            "pctl: server is required. Use --server <name>, "
            "or run `pctl switch <server>`, "
            "or set PCTL_SERVER/PCTL_DEFAULT_SSH_HOST/PCTL_DEFAULT_SERVER."
        )
        sys.exit(2)

    return server


def require_token(token: Optional[str]) -> str:
    if not token:
        eprint(
            "pctl: API token is required. "
            "Set PCTL_API_TOKEN or pass --token."
        )
        sys.exit(2)

    return token


def cmd_connect(args) -> int:
    server = require_server(args)
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/ssh/connect",
        token=token,
        body={"server": server},
        timeout=args.timeout,
    )

    return handle_admin_response(
        status=status,
        resp=resp,
        as_json=args.json,
        command="connect",
    )


def cmd_disconnect(args) -> int:
    server = require_server(args)
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/ssh/disconnect",
        token=token,
        body={"server": server},
        timeout=args.timeout,
    )

    return handle_admin_response(
        status=status,
        resp=resp,
        as_json=args.json,
        command="disconnect",
    )


def cmd_servers(args) -> int:
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="GET",
        path="/api/v1/servers",
        token=token,
        timeout=args.timeout,
    )

    if args.json:
        print_json_response(resp)

        if 200 <= status < 300 and resp.get("ok", True) is not False:
            return 0

        return exit_code_for_proxy_error(status, resp)

    if not (200 <= status < 300) or resp.get("ok") is False:
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    servers = resp.get("servers") or []
    active = resolve_server(args)

    for item in servers:
        name = item.get("server")
        ssh_host = item.get("ssh_host")
        connected = item.get("connected")

        marker = "*" if active and name == active else " "

        print(f"{marker} {name}\tssh_host={ssh_host}\tconnected={connected}")

    return 0


def cmd_active(args) -> int:
    server = resolve_server(args)

    if args.json:
        print_json_response(
            {
                "ok": True,
                "active_server": server,
                "state_file": str(get_state_file()),
                "arg_server": getattr(args, "server", None),
                "env_PCTL_SERVER": os.getenv("PCTL_SERVER"),
                "env_PCTL_DEFAULT_SSH_HOST": os.getenv("PCTL_DEFAULT_SSH_HOST"),
                "env_PCTL_DEFAULT_SERVER": os.getenv("PCTL_DEFAULT_SERVER"),
                "state_active_server": get_active_server_from_state(),
            }
        )
        return 0

    if server:
        print(f"active server: {server}")
    else:
        print("active server: <not set>")

    print(f"state file: {get_state_file()}")

    if getattr(args, "server", None):
        print("source: --server")
    elif os.getenv("PCTL_SERVER"):
        print("source: PCTL_SERVER")
    elif get_active_server_from_state():
        print("source: state")
    elif os.getenv("PCTL_DEFAULT_SSH_HOST"):
        print("source: PCTL_DEFAULT_SSH_HOST")
    elif os.getenv("PCTL_DEFAULT_SERVER"):
        print("source: PCTL_DEFAULT_SERVER")
    else:
        print("source: none")

    return 0


def cmd_switch(args) -> int:
    server = args.target_server.strip()

    if not server:
        eprint("pctl: switch requires server name")
        return 2

    set_active_server(server)

    if args.json:
        print_json_response(
            {
                "ok": True,
                "active_server": server,
                "state_file": str(get_state_file()),
            }
        )
    else:
        print(f"active server switched to: {server}")
        print(f"state file: {get_state_file()}")

    return 0


def cmd_cancel(args) -> int:
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/api/v1/cancel",
        token=token,
        body={"request_id": args.request_id},
        timeout=args.timeout,
    )

    if args.json:
        print_json_response(resp)
    elif 200 <= status < 300 and resp.get("ok") is True:
        print(f"cancelled: request_id={args.request_id} message={resp.get('message')}")
    else:
        print_error_response(resp)

    if 200 <= status < 300 and resp.get("ok", True) is not False:
        return 0

    return exit_code_for_proxy_error(status, resp)


def cmd_status(args) -> int:
    server = require_server(args)
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="GET",
        path="/ssh/status",
        token=token,
        query={"server": server},
        timeout=args.timeout,
    )

    return handle_admin_response(
        status=status,
        resp=resp,
        as_json=args.json,
        command="status",
    )


def cmd_exec(args) -> int:
    server = require_server(args)
    token = require_token(args.token)

    argv = args.argv or []

    if argv and argv[0] == "--":
        argv = argv[1:]

    if not argv:
        eprint("pctl: exec requires command after --")
        eprint("example: pctl --server lifeorient exec -- df -h")
        return 2

    request_id = str(uuid.uuid4())

    try:
        status, resp = http_json(
            proxy_url=args.proxy_url,
            method="POST",
            path="/api/v1/exec",
            token=token,
            body={
                "request_id": request_id,
                "server": server,
                "argv": argv,
            },
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        eprint(f"pctl: interrupted, sending cancel request_id={request_id}")

        try:
            cancel_status, cancel_resp = http_json(
                proxy_url=args.proxy_url,
                method="POST",
                path="/api/v1/cancel",
                token=token,
                body={"request_id": request_id},
                timeout=10,
            )

            if 200 <= cancel_status < 300 and cancel_resp.get("ok") is True:
                eprint(f"pctl: remote command cancelled: {cancel_resp.get('message')}")
            else:
                eprint(f"pctl: cancel failed: {cancel_resp.get('message')}")
        except Exception as exc:
            eprint(f"pctl: cancel request failed: {exc}")

        return 130

    return handle_exec_response(
        status=status,
        resp=resp,
        as_json=args.json,
    )


def cmd_ps(args) -> int:
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="GET",
        path="/api/v1/running",
        token=token,
        timeout=args.timeout,
    )

    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)

    if not (200 <= status < 300) or resp.get("ok") is False:
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    running = resp.get("running") or []

    if not running:
        print("no running commands")
        return 0

    print("REQUEST_ID\tSERVER\tDURATION_MS\tCOMMAND")

    for item in running:
        request_id = item.get("request_id")
        server = item.get("server")
        duration_ms = item.get("duration_ms")
        argv = item.get("argv") or []
        cmd = " ".join(argv)

        print(f"{request_id}\t{server}\t{duration_ms}\t{cmd}")

    return 0


def cmd_can_i(args) -> int:
    server = require_server(args)
    token = require_token(args.token)

    argv = args.argv or []

    if argv and argv[0] == "--":
        argv = argv[1:]

    if not argv:
        eprint("pctl: can-i requires command after --")
        eprint("example: pctl can-i -- df -h")
        return 2

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/api/v1/can-i",
        token=token,
        body={
            "server": server,
            "argv": argv,
        },
        timeout=args.timeout,
    )

    if args.json:
        print_json_response(resp)

        if 200 <= status < 300 and resp.get("ok", True) is not False:
            return 0 if resp.get("allowed") is True else 126

        return exit_code_for_proxy_error(status, resp)

    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    allowed = resp.get("allowed")
    policy = resp.get("policy")
    reason = resp.get("reason")

    if allowed:
        print(f"yes: policy={policy} reason={reason}")
        return 0

    print(f"no: reason={reason}")
    return 126


def cmd_reload(args) -> int:
    token = require_token(args.token)

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/api/v1/reload",
        token=token,
        timeout=args.timeout,
    )

    if args.json:
        print_json_response(resp)

        if 200 <= status < 300 and resp.get("ok", True) is not False:
            return 0

        return exit_code_for_proxy_error(status, resp)

    if not (200 <= status < 300) or resp.get("ok") is False:
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    print(
        f"reloaded: servers={len(resp.get('servers') or [])} "
        f"globalPolicies={len(resp.get('globalPolicies') or [])}"
    )

    return 0


def cmd_health(args) -> int:
    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="GET",
        path="/health",
        token=None,
        timeout=args.timeout,
    )

    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)

    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    print(
        f"proxy={resp.get('status')} "
        f"auth={resp.get('auth')} "
        f"config={resp.get('config')} "
        f"servers={len(resp.get('servers') or [])}"
    )

    return 0


def main_pctl(argv) -> int:
    parser = argparse.ArgumentParser(
        prog="pctl",
        description="CLI wrapper for pctl-proxy",
    )

    parser.add_argument(
        "--server",
        default=None,
        help=(
            "Server name from proxy config. "
            "Priority: --server, PCTL_SERVER, active state, "
            "PCTL_DEFAULT_SSH_HOST, PCTL_DEFAULT_SERVER."
        ),
    )

    parser.add_argument(
        "--proxy-url",
        default=os.getenv("PCTL_PROXY_URL", DEFAULT_PROXY_URL),
        help=f"Proxy base URL. Env: PCTL_PROXY_URL. Default: {DEFAULT_PROXY_URL}",
    )

    parser.add_argument(
        "--token",
        default=os.getenv("PCTL_API_TOKEN"),
        help="API token. Env: PCTL_API_TOKEN.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("PCTL_HTTP_TIMEOUT", "300")),
        help="HTTP request timeout in seconds. Env: PCTL_HTTP_TIMEOUT.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON response instead of transparent stdout/stderr mode.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    p_connect = subparsers.add_parser("connect", help="Open SSH connection")
    p_connect.set_defaults(func=cmd_connect)

    p_disconnect = subparsers.add_parser("disconnect", help="Close SSH connection")
    p_disconnect.set_defaults(func=cmd_disconnect)

    p_status = subparsers.add_parser("status", help="Show SSH connection status")
    p_status.set_defaults(func=cmd_status)

    p_exec = subparsers.add_parser("exec", help="Execute command through proxy")
    p_exec.add_argument("argv", nargs=argparse.REMAINDER)
    p_exec.set_defaults(func=cmd_exec)

    p_servers = subparsers.add_parser("servers", help="List configured servers")
    p_servers.set_defaults(func=cmd_servers)

    p_active = subparsers.add_parser("active", help="Show active server")
    p_active.set_defaults(func=cmd_active)

    p_switch = subparsers.add_parser("switch", help="Switch active server")
    p_switch.add_argument("target_server")
    p_switch.set_defaults(func=cmd_switch)

    p_cancel = subparsers.add_parser("cancel", help="Cancel running command by request_id")
    p_cancel.add_argument("request_id")
    p_cancel.set_defaults(func=cmd_cancel)

    p_health = subparsers.add_parser("health", help="Check proxy health")
    p_health.set_defaults(func=cmd_health)

    p_ps = subparsers.add_parser("ps", help="List running commands")
    p_ps.set_defaults(func=cmd_ps)

    p_can_i = subparsers.add_parser("can-i", help="Check whether command is allowed")
    p_can_i.add_argument("argv", nargs=argparse.REMAINDER)
    p_can_i.set_defaults(func=cmd_can_i)

    p_reload = subparsers.add_parser("reload", help="Reload proxy config")
    p_reload.set_defaults(func=cmd_reload)

    args = parser.parse_args(argv)

    args.proxy_url = normalize_proxy_url(args.proxy_url)

    return args.func(args)


def main_kubectl_shim(argv) -> int:
    """
    Если файл вызван как kubectl, то работаем как transparent shim.

    Пример:

      kubectl get pods -n default

    превращается в:

      POST /api/v1/exec
      {
        "server": "<resolved server>",
        "argv": ["kubectl", "get", "pods", "-n", "default"]
      }

    Server выбирается по приоритету:
      1. PCTL_SERVER
      2. active server из ~/.config/pctl/state.json
      3. PCTL_DEFAULT_SSH_HOST
      4. PCTL_DEFAULT_SERVER
    """

    server = resolve_server_value()

    if not server:
        eprint(
            "kubectl shim: server is required. "
            "Set PCTL_SERVER/PCTL_DEFAULT_SSH_HOST/PCTL_DEFAULT_SERVER "
            "or run `pctl switch <server>`."
        )
        return 2

    proxy_url = normalize_proxy_url(os.getenv("PCTL_PROXY_URL", DEFAULT_PROXY_URL))
    token = os.getenv("PCTL_API_TOKEN")
    timeout = int(os.getenv("PCTL_HTTP_TIMEOUT", "300"))

    if not token:
        eprint(
            "kubectl shim: API token is required. "
            "Set PCTL_API_TOKEN."
        )
        return 2

    request_id = str(uuid.uuid4())

    remote_argv = ["kubectl"] + argv

    try:
        status, resp = http_json(
            proxy_url=proxy_url,
            method="POST",
            path="/api/v1/exec",
            token=token,
            body={
                "request_id": request_id,
                "server": server,
                "argv": remote_argv,
            },
            timeout=timeout,
        )
    except KeyboardInterrupt:
        eprint(f"kubectl shim: interrupted, sending cancel request_id={request_id}")

        try:
            cancel_status, cancel_resp = http_json(
                proxy_url=proxy_url,
                method="POST",
                path="/api/v1/cancel",
                token=token,
                body={"request_id": request_id},
                timeout=10,
            )

            if 200 <= cancel_status < 300 and cancel_resp.get("ok") is True:
                eprint(
                    f"kubectl shim: remote command cancelled: "
                    f"{cancel_resp.get('message')}"
                )
            else:
                eprint(
                    f"kubectl shim: cancel failed: "
                    f"{cancel_resp.get('message')}"
                )
        except Exception as exc:
            eprint(f"kubectl shim: cancel request failed: {exc}")

        return 130

    as_json = os.getenv("PCTL_OUTPUT", "").lower() == "json"

    return handle_exec_response(
        status=status,
        resp=resp,
        as_json=as_json,
    )


def main() -> int:
    prog = os.path.basename(sys.argv[0])

    if prog == "kubectl":
        return main_kubectl_shim(sys.argv[1:])

    return main_pctl(sys.argv[1:])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("pctl: interrupted")
        sys.exit(130)