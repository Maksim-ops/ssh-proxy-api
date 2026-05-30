#!/usr/bin/env python3

import os
import sys
import json
import argparse
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, Optional, Tuple


DEFAULT_PROXY_URL = "http://127.0.0.1:8080"


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


def require_server(server: Optional[str]) -> str:
    if not server:
        eprint(
            "pctl: server is required. Use --server <name> "
            "or set PCTL_DEFAULT_SERVER/PCTL_SERVER."
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
    server = require_server(args.server)
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
    server = require_server(args.server)
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


def cmd_status(args) -> int:
    server = require_server(args.server)
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
    server = require_server(args.server)
    token = require_token(args.token)

    argv = args.argv or []

    if argv and argv[0] == "--":
        argv = argv[1:]

    if not argv:
        eprint("pctl: exec requires command after --")
        eprint("example: pctl --server lifeorient exec -- df -h")
        return 2

    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/api/v1/exec",
        token=token,
        body={
            "server": server,
            "argv": argv,
        },
        timeout=args.timeout,
    )

    return handle_exec_response(
        status=status,
        resp=resp,
        as_json=args.json,
    )


def main_pctl(argv) -> int:
    parser = argparse.ArgumentParser(
        prog="pctl",
        description="CLI wrapper for pctl-proxy",
    )

    parser.add_argument(
        "--server",
        default=os.getenv("PCTL_SERVER") or os.getenv("PCTL_DEFAULT_SERVER"),
        help="Server name from proxy config. Env: PCTL_SERVER or PCTL_DEFAULT_SERVER.",
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
        "server": "$PCTL_DEFAULT_SERVER",
        "argv": ["kubectl", "get", "pods", "-n", "default"]
      }
    """

    server = os.getenv("PCTL_SERVER") or os.getenv("PCTL_DEFAULT_SERVER")
    proxy_url = normalize_proxy_url(os.getenv("PCTL_PROXY_URL", DEFAULT_PROXY_URL))
    token = os.getenv("PCTL_API_TOKEN")
    timeout = int(os.getenv("PCTL_HTTP_TIMEOUT", "300"))

    if not server:
        eprint(
            "kubectl shim: server is required. "
            "Set PCTL_DEFAULT_SERVER or PCTL_SERVER."
        )
        return 2

    if not token:
        eprint(
            "kubectl shim: API token is required. "
            "Set PCTL_API_TOKEN."
        )
        return 2

    remote_argv = ["kubectl"] + argv

    status, resp = http_json(
        proxy_url=proxy_url,
        method="POST",
        path="/api/v1/exec",
        token=token,
        body={
            "server": server,
            "argv": remote_argv,
        },
        timeout=timeout,
    )

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
    sys.exit(main())