#!/usr/bin/env python3

import argparse
import asyncio
import base64
import hashlib
import json
import os
import ssl
import sys
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


DEFAULT_PROXY_URL = "http://127.0.0.1:8080"
DEFAULT_STATE_FILE = "~/.config/pctl/state.json"
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def get_active_server_from_state() -> Optional[str]:
    value = load_state().get("active_server")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def set_active_server(server: str) -> None:
    state = load_state()
    state["active_server"] = server
    save_state(state)


def resolve_server_value(explicit_server: Optional[str] = None) -> Optional[str]:
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


def to_ws_url(proxy_url: str, ws_path: str) -> str:
    parsed = urllib.parse.urlparse(normalize_proxy_url(proxy_url))
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urllib.parse.urlunparse((scheme, parsed.netloc, ws_path, "", "", ""))


def http_json(*, proxy_url: str, method: str, path: str, token: Optional[str], body: Optional[Dict[str, Any]] = None, query: Optional[Dict[str, str]] = None, timeout: int = 300) -> Tuple[int, Dict[str, Any]]:
    url = normalize_proxy_url(proxy_url) + path
    if query:
        url += "?" + urllib.parse.urlencode(query)

    data = None
    headers = {"Accept": "application/json"}

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url=url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except urllib.error.URLError as exc:
        return 0, {"ok": False, "error": "proxy_unavailable", "message": str(exc.reason)}
    except Exception as exc:
        return 0, {"ok": False, "error": "proxy_request_failed", "message": str(exc)}

    text = raw.decode("utf-8", errors="replace") if raw else ""
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {"ok": False, "error": "invalid_proxy_response", "message": "Proxy returned non-JSON response", "raw_response": text}
    return status, parsed


class SimpleWebSocketClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    @classmethod
    async def connect(cls, ws_url: str, headers: Dict[str, str]) -> "SimpleWebSocketClient":
        parsed = urllib.parse.urlparse(ws_url)
        if parsed.scheme not in {"ws", "wss"}:
            raise RuntimeError(f"Unsupported websocket scheme: {parsed.scheme}")

        host = parsed.hostname
        if not host:
            raise RuntimeError("Websocket URL does not include host")

        ssl_ctx = None
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        if parsed.scheme == "wss":
            ssl_ctx = ssl.create_default_context()

        reader, writer = await asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=host if ssl_ctx else None)

        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        raw_key = os.urandom(16)
        sec_key = base64.b64encode(raw_key).decode("ascii")
        host_header = host if parsed.port is None else f"{host}:{parsed.port}"

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {sec_key}",
            "Sec-WebSocket-Version: 13",
        ]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")

        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
        await writer.drain()

        status_line = await reader.readline()
        if not status_line:
            raise RuntimeError("Empty websocket handshake response")
        try:
            _, status_code, _ = status_line.decode("utf-8").rstrip("\r\n").split(" ", 2)
        except ValueError as exc:
            raise RuntimeError(f"Invalid websocket handshake status line: {status_line!r}") from exc
        if int(status_code) != 101:
            raise RuntimeError(f"Websocket handshake failed with status {status_code}")

        response_headers: Dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in {b"\r\n", b"\n", b""}:
                break
            name, value = line.decode("utf-8").split(":", 1)
            response_headers[name.strip().lower()] = value.strip()

        expected_accept = base64.b64encode(hashlib.sha1((sec_key + _WS_GUID).encode("utf-8")).digest()).decode("ascii")
        if response_headers.get("sec-websocket-accept") != expected_accept:
            raise RuntimeError("Invalid websocket accept header")

        return cls(reader=reader, writer=writer)

    async def _read_exact(self, size: int) -> bytes:
        return await self.reader.readexactly(size)

    async def _read_frame(self) -> tuple[bool, int, bytes]:
        first, second = await self._read_exact(2)
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        payload_len = second & 0x7F

        if payload_len == 126:
            payload_len = int.from_bytes(await self._read_exact(2), "big")
        elif payload_len == 127:
            payload_len = int.from_bytes(await self._read_exact(8), "big")

        mask = await self._read_exact(4) if masked else b""
        payload = await self._read_exact(payload_len) if payload_len else b""

        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))

        return fin, opcode, payload

    async def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        first = 0x80 | (opcode & 0x0F)
        mask_key = os.urandom(4)
        payload_len = len(payload)

        header = bytearray([first])
        if payload_len < 126:
            header.append(0x80 | payload_len)
        elif payload_len < (1 << 16):
            header.append(0x80 | 126)
            header.extend(payload_len.to_bytes(2, "big"))
        else:
            header.append(0x80 | 127)
            header.extend(payload_len.to_bytes(8, "big"))

        masked_payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        self.writer.write(bytes(header) + mask_key + masked_payload)
        await self.writer.drain()

    async def recv_text(self) -> Optional[str]:
        fragments: list[bytes] = []
        receiving_text = False

        while True:
            try:
                fin, opcode, payload = await self._read_frame()
            except asyncio.IncompleteReadError:
                return None

            if opcode == 0x8:
                return None
            if opcode == 0x9:
                await self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1:
                fragments = [payload]
                receiving_text = True
                if fin:
                    return payload.decode("utf-8")
                continue
            if opcode == 0x0 and receiving_text:
                fragments.append(payload)
                if fin:
                    return b"".join(fragments).decode("utf-8")
                continue

            raise RuntimeError(f"Unsupported websocket opcode: {opcode}")

    async def close(self) -> None:
        try:
            await self._send_frame(0x8)
        except Exception:
            pass
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


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
    error = resp.get("error") or "error"
    message = resp.get("message") or "Unknown error"
    request_id = resp.get("request_id")
    eprint(f"pctl: {error}: {message}")
    if request_id:
        eprint(f"pctl: request_id={request_id}")


def require_server(args) -> str:
    server = resolve_server(args)
    if not server:
        eprint("pctl: server is required. Use --server <name> or `pctl switch <server>`.")
        sys.exit(2)
    return server


def require_token(token: Optional[str]) -> str:
    if not token:
        eprint("pctl: API token is required. Set PCTL_API_TOKEN or pass --token.")
        sys.exit(2)
    return token


def send_cancel(proxy_url: str, token: str, request_id: str) -> None:
    status, resp = http_json(proxy_url=proxy_url, method="POST", path="/api/v1/cancel", token=token, body={"request_id": request_id}, timeout=10)
    if 200 <= status < 300 and resp.get("ok") is True:
        eprint(f"pctl: remote command cancelled: request_id={request_id}")
    else:
        eprint(f"pctl: cancel failed: {resp.get('message')}")


async def consume_stream(*, ws_url: str, token: str, as_json: bool) -> int:
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    result: Dict[str, Any] = {"ok": True, "status": "running", "exit_code": None}

    client = await SimpleWebSocketClient.connect(ws_url, {"Authorization": f"Bearer {token}"})
    try:
        while True:
            message = await client.recv_text()
            if message is None:
                break

            event = json.loads(message)
            event_type = event.get("type")

            if event_type == "stdout":
                line = event.get("line") or ""
                stdout_chunks.append(line)
                if not as_json:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                continue

            if event_type == "stderr":
                line = event.get("line") or ""
                stderr_chunks.append(line)
                if not as_json:
                    sys.stderr.write(line)
                    sys.stderr.flush()
                continue

            if event_type == "started":
                result.update({"request_id": event.get("request_id"), "job_id": event.get("job_id"), "stream_id": event.get("stream_id")})
                continue

            if event_type == "error":
                result["ok"] = False
                result["status"] = event.get("status") or "error"
                result["message"] = event.get("message") or "Unknown error"
                if not as_json:
                    eprint(f"# core-api: {result['message']}")
                break

            if event_type == "cancelled":
                result["ok"] = False
                result["status"] = "cancelled"
                result["exit_code"] = event.get("exit_code")
                if not as_json:
                    eprint("# core-api: command cancelled")
                break

            if event_type == "finished":
                result["status"] = event.get("status") or "completed"
                result["exit_code"] = event.get("exit_code")
                break
    finally:
        await client.close()

    if as_json:
        result["stdout"] = "".join(stdout_chunks)
        result["stderr"] = "".join(stderr_chunks)
        print_json_response(result)

    if result.get("status") == "cancelled":
        return 130
    if result.get("status") == "timeout":
        return 124
    if isinstance(result.get("exit_code"), int):
        return int(result["exit_code"])
    return 1 if result.get("ok") is False else 0


def cmd_exec(args) -> int:
    server = require_server(args)
    token = require_token(args.token)

    argv = args.argv or []
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        eprint("pctl: exec requires command after --")
        return 2

    request_id = str(uuid.uuid4())
    status, resp = http_json(
        proxy_url=args.proxy_url,
        method="POST",
        path="/api/v1/exec",
        token=token,
        body={"request_id": request_id, "server": server, "argv": argv, "client_type": "CLI"},
        timeout=args.timeout,
    )

    if not (200 <= status < 300) or resp.get("ok") is False:
        if args.json:
            print_json_response(resp)
        else:
            print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    ws_url = to_ws_url(args.proxy_url, resp["ws_path"])

    try:
        return asyncio.run(consume_stream(ws_url=ws_url, token=token, as_json=args.json))
    except KeyboardInterrupt:
        eprint(f"pctl: interrupted, sending cancel request_id={request_id}")
        send_cancel(args.proxy_url, token, request_id)
        return 130


def cmd_can_i(args) -> int:
    server = require_server(args)
    token = require_token(args.token)
    argv = args.argv or []
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        eprint("pctl: can-i requires command after --")
        return 2

    status, resp = http_json(proxy_url=args.proxy_url, method="POST", path="/api/v1/can-i", token=token, body={"server": server, "argv": argv}, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        if 200 <= status < 300:
            return 0 if resp.get("allowed") else 126
        return exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    if resp.get("allowed"):
        print(f"yes: policy={resp.get('policy')} reason={resp.get('reason')}")
        return 0
    print(f"no: reason={resp.get('reason')}")
    return 126


def cmd_servers(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="GET", path="/api/v1/servers", token=token, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    active = resolve_server(args)
    items = resp if isinstance(resp, list) else (resp.get("servers") or [])
    for item in items:
        marker = "*" if active and item.get("name") == active else " "
        print(f"{marker} {item.get('name')}\thost={item.get('host')}\tip={item.get('ip')}\tenabled={item.get('enabled')}")
    return 0


def cmd_jobs(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="GET", path="/api/v1/jobs", token=token, query={"limit": str(args.limit)}, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    print("JOB_ID\tREQUEST_ID\tSERVER\tSTATUS\tEXIT_CODE\tCOMMAND")
    for item in resp.get("jobs") or []:
        print(f"{item.get('id')}\t{item.get('request_id')}\t{item.get('server_name')}\t{item.get('status')}\t{item.get('exit_code')}\t{item.get('command')}")
    return 0


def cmd_audit(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="GET", path="/api/v1/audit", token=token, query={"limit": str(args.limit)}, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    print("AUDIT_ID\tREQUEST_ID\tRESOURCE\tRESULT\tCREATED_AT")
    for item in resp.get("audit") or []:
        print(f"{item.get('id')}\t{item.get('request_id')}\t{item.get('resource')}\t{item.get('result')}\t{item.get('created_at')}")
    return 0


def cmd_ps(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="GET", path="/api/v1/running", token=token, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    running = resp.get("running") or []
    if not running:
        print("no running commands")
        return 0
    print("REQUEST_ID\tSERVER\tSTREAM_ID\tCOMMAND")
    for item in running:
        print(f"{item.get('request_id')}\t{item.get('server')}\t{item.get('stream_id')}\t{' '.join(item.get('argv') or [])}")
    return 0


def cmd_ssh_status(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="GET", path="/api/v1/ssh/status", token=token, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)

    items = resp.get("connections") or []
    if not items:
        print("no ssh connections")
        return 0

    print("SERVER	CONNECTED	ACTIVE	SSH_HOST	LAST_USED	IDLE_IN	IDLE_AT")
    for item in items:
        print(
            f"{item.get('server')}	{item.get('connected')}	{item.get('active_commands')}	"
            f"{item.get('ssh_host')}	{item.get('last_used_at')}	"
            f"{item.get('idle_disconnect_in_seconds')}	{item.get('idle_disconnect_at')}"
        )
    return 0


def cmd_cancel(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="POST", path="/api/v1/cancel", token=token, body={"request_id": args.request_id}, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
    elif 200 <= status < 300 and resp.get("ok") is True:
        print(f"cancelled: request_id={args.request_id} message={resp.get('message')}")
    else:
        print_error_response(resp)
    if 200 <= status < 300 and resp.get("ok", True) is not False:
        return 0
    return exit_code_for_proxy_error(status, resp)


def cmd_active(args) -> int:
    server = resolve_server(args)
    if args.json:
        print_json_response({"ok": True, "active_server": server, "state_file": str(get_state_file())})
        return 0
    print(f"active server: {server or '<not set>'}")
    print(f"state file: {get_state_file()}")
    return 0


def cmd_switch(args) -> int:
    server = args.target_server.strip()
    if not server:
        eprint("pctl: switch requires server name")
        return 2
    set_active_server(server)
    if args.json:
        print_json_response({"ok": True, "active_server": server, "state_file": str(get_state_file())})
    else:
        print(f"active server switched to: {server}")
        print(f"state file: {get_state_file()}")
    return 0


def cmd_reload(args) -> int:
    token = require_token(args.token)
    status, resp = http_json(proxy_url=args.proxy_url, method="POST", path="/api/v1/reload", token=token, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    print(f"reloaded: servers={len(resp.get('servers') or [])} globalPolicies={len(resp.get('globalPolicies') or [])}")
    return 0


def cmd_health(args) -> int:
    status, resp = http_json(proxy_url=args.proxy_url, method="GET", path="/health", token=None, timeout=args.timeout)
    if args.json:
        print_json_response(resp)
        return 0 if 200 <= status < 300 else exit_code_for_proxy_error(status, resp)
    if not (200 <= status < 300):
        print_error_response(resp)
        return exit_code_for_proxy_error(status, resp)
    print(f"service={resp.get('service')} status={resp.get('status')} auth={resp.get('auth')} servers={len(resp.get('servers') or [])}")
    return 0


def main_pctl(argv) -> int:
    parser = argparse.ArgumentParser(prog="pctl", description="CLI wrapper for core-api")
    parser.add_argument("--server", default=None)
    parser.add_argument("--proxy-url", default=os.getenv("PCTL_PROXY_URL", DEFAULT_PROXY_URL))
    parser.add_argument("--token", default=os.getenv("PCTL_API_TOKEN"))
    parser.add_argument("--timeout", type=int, default=int(os.getenv("PCTL_HTTP_TIMEOUT", "300")))
    parser.add_argument("--json", action="store_true")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_exec = subparsers.add_parser("exec", help="Execute command through core-api")
    p_exec.add_argument("argv", nargs=argparse.REMAINDER)
    p_exec.set_defaults(func=cmd_exec)

    p_can_i = subparsers.add_parser("can-i", help="Check whether command is allowed")
    p_can_i.add_argument("argv", nargs=argparse.REMAINDER)
    p_can_i.set_defaults(func=cmd_can_i)

    p_servers = subparsers.add_parser("servers", help="List servers")
    p_servers.set_defaults(func=cmd_servers)

    p_jobs = subparsers.add_parser("jobs", help="List jobs")
    p_jobs.add_argument("--limit", type=int, default=20)
    p_jobs.set_defaults(func=cmd_jobs)

    p_audit = subparsers.add_parser("audit", help="List audit events")
    p_audit.add_argument("--limit", type=int, default=20)
    p_audit.set_defaults(func=cmd_audit)

    p_ps = subparsers.add_parser("ps", help="List running commands")
    p_ps.set_defaults(func=cmd_ps)

    p_ssh_status = subparsers.add_parser("ssh-status", help="Show SSH connection status")
    p_ssh_status.set_defaults(func=cmd_ssh_status)

    p_cancel = subparsers.add_parser("cancel", help="Cancel running command by request_id")
    p_cancel.add_argument("request_id")
    p_cancel.set_defaults(func=cmd_cancel)

    p_active = subparsers.add_parser("active", help="Show active server")
    p_active.set_defaults(func=cmd_active)

    p_switch = subparsers.add_parser("switch", help="Switch active server")
    p_switch.add_argument("target_server")
    p_switch.set_defaults(func=cmd_switch)

    p_reload = subparsers.add_parser("reload", help="Reload proxy config")
    p_reload.set_defaults(func=cmd_reload)

    p_health = subparsers.add_parser("health", help="Check core-api health")
    p_health.set_defaults(func=cmd_health)

    args = parser.parse_args(argv)
    args.proxy_url = normalize_proxy_url(args.proxy_url)
    return args.func(args)


def main_kubectl_shim(argv) -> int:
    server = resolve_server_value()
    if not server:
        eprint("kubectl shim: server is required. Set PCTL_SERVER or run `pctl switch <server>`.")
        return 2

    proxy_url = normalize_proxy_url(os.getenv("PCTL_PROXY_URL", DEFAULT_PROXY_URL))
    token = os.getenv("PCTL_API_TOKEN")
    timeout = int(os.getenv("PCTL_HTTP_TIMEOUT", "300"))

    if not token:
        eprint("kubectl shim: API token is required. Set PCTL_API_TOKEN.")
        return 2

    args = argparse.Namespace(
        server=server,
        proxy_url=proxy_url,
        token=token,
        timeout=timeout,
        json=os.getenv("PCTL_OUTPUT", "").lower() == "json",
        argv=["kubectl", *argv],
    )
    return cmd_exec(args)


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
