from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import asyncssh

from app.config import SETTINGS
from app.ssh.state import CommandStream, RunningCommand, is_cancel_requested, register_running_command, unregister_running_command


@dataclass
class SSHExecutionResult:
    exit_code: Optional[int]
    cancelled: bool
    timeout: bool


class SSHManager:
    def __init__(self, server_name: str, server_cfg: dict[str, Any]) -> None:
        self.server_name = server_name
        self.server_cfg = server_cfg
        self.ssh_host = str(server_cfg.get("sshHost", server_name))
        self.command_timeout = int(server_cfg.get("commandTimeoutSeconds", 120))
        self.idle_disconnect_seconds = int(server_cfg.get("idleDisconnectSeconds", 300))
        self._conn: Optional[asyncssh.SSHClientConnection] = None
        self._lock = asyncio.Lock()
        self._active_commands = 0
        self._idle_close_task: Optional[asyncio.Task[None]] = None
        self._connected_at: Optional[datetime] = None
        self._last_used_at: Optional[datetime] = None
        self._idle_disconnect_at: Optional[datetime] = None

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def _mark_used(self) -> None:
        self._last_used_at = self._utcnow()

    def _cancel_idle_close_task(self) -> None:
        if self._idle_close_task is not None:
            self._idle_close_task.cancel()
            self._idle_close_task = None
        self._idle_disconnect_at = None

    async def _idle_close_after_timeout(self) -> None:
        try:
            await asyncio.sleep(self.idle_disconnect_seconds)
        except asyncio.CancelledError:
            return

        async with self._lock:
            if self._active_commands > 0 or self._conn is None:
                return

            self._conn.close()
            try:
                await self._conn.wait_closed()
            finally:
                self._conn = None
                self._connected_at = None
                self._idle_close_task = None
                self._idle_disconnect_at = None

    def _schedule_idle_close(self) -> None:
        if self.idle_disconnect_seconds <= 0:
            return
        self._cancel_idle_close_task()
        self._idle_disconnect_at = self._utcnow() + timedelta(seconds=self.idle_disconnect_seconds)
        self._idle_close_task = asyncio.create_task(self._idle_close_after_timeout())

    async def connect(self) -> None:
        async with self._lock:
            self._cancel_idle_close_task()

            if self._conn is not None:
                self._mark_used()
                return

            self._conn = await asyncssh.connect(
                self.ssh_host,
                config=[SETTINGS.ssh_config],
                known_hosts=SETTINGS.ssh_known_hosts,
                keepalive_interval=30,
                keepalive_count_max=3,
            )
            self._connected_at = self._utcnow()
            self._mark_used()

    async def close(self) -> None:
        async with self._lock:
            self._cancel_idle_close_task()
            if self._conn is None:
                return
            self._conn.close()
            try:
                await self._conn.wait_closed()
            finally:
                self._conn = None
                self._connected_at = None

    async def reset(self) -> None:
        await self.close()

    def get_status(self) -> dict[str, Any]:
        idle_disconnect_in_seconds = None
        if self._idle_disconnect_at is not None:
            idle_disconnect_in_seconds = max(0, int((self._idle_disconnect_at - self._utcnow()).total_seconds()))

        return {
            "server": self.server_name,
            "ssh_host": self.ssh_host,
            "connected": self._conn is not None,
            "active_commands": self._active_commands,
            "connected_at": self._connected_at.isoformat() if self._connected_at else None,
            "last_used_at": self._last_used_at.isoformat() if self._last_used_at else None,
            "idle_disconnect_at": self._idle_disconnect_at.isoformat() if self._idle_disconnect_at else None,
            "idle_disconnect_in_seconds": idle_disconnect_in_seconds,
            "idle_disconnect_seconds": self.idle_disconnect_seconds,
            "command_timeout_seconds": self.command_timeout,
        }

    async def _terminate_process(self, process: asyncssh.SSHClientProcess) -> None:
        try:
            process.terminate()
        except Exception:
            try:
                process.kill()
            except Exception:
                return

        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except Exception:
            try:
                process.kill()
                await asyncio.wait_for(process.wait(), timeout=3)
            except Exception:
                return

    async def cancel_process(self, process: asyncssh.SSHClientProcess, grace_seconds: float = 3.0) -> tuple[bool, str]:
        try:
            process.terminate()
        except Exception:
            pass

        try:
            await asyncio.wait_for(process.wait(), timeout=grace_seconds)
            return True, "terminated"
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            return False, f"terminate wait failed: {exc}"

        try:
            process.kill()
        except Exception as exc:
            return False, f"kill failed: {exc}"

        try:
            await asyncio.wait_for(process.wait(), timeout=grace_seconds)
            return True, "killed"
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            return False, f"kill wait failed: {exc}"

        channel = getattr(process, "channel", None)
        if channel is not None:
            try:
                channel.abort()
            except Exception:
                try:
                    channel.close()
                except Exception:
                    pass

        try:
            await self.reset()
        except Exception:
            pass

        return True, "connection reset after kill timeout"

    async def _pump_reader(self, reader: Any, event_type: str, stream: CommandStream) -> None:
        while True:
            line = await reader.readline()
            if not line:
                return
            await stream.publish(
                {
                    "type": event_type,
                    "stream_id": stream.stream_id,
                    "job_id": stream.job_id,
                    "request_id": stream.request_id,
                    "line": line,
                }
            )

    async def run(self, *, command: str, request_id: str, argv: list[str], job_id: int, stream: CommandStream) -> SSHExecutionResult:
        last_error: Optional[Exception] = None

        for attempt in (1, 2):
            process = None
            command_registered = False

            try:
                await self.connect()

                if await is_cancel_requested(request_id):
                    return SSHExecutionResult(exit_code=None, cancelled=True, timeout=False)

                assert self._conn is not None
                self._active_commands += 1
                self._mark_used()
                process = await self._conn.create_process(f"exec {command}")

                registered = await register_running_command(
                    RunningCommand(
                        request_id=request_id,
                        job_id=job_id,
                        server=self.server_name,
                        argv=argv,
                        remote_command=command,
                        process=process,
                        stream=stream,
                        manager=self,
                    )
                )
                if not registered:
                    await self._terminate_process(process)
                    return SSHExecutionResult(exit_code=None, cancelled=True, timeout=False)

                command_registered = True
                stdout_task = asyncio.create_task(self._pump_reader(process.stdout, "stdout", stream))
                stderr_task = asyncio.create_task(self._pump_reader(process.stderr, "stderr", stream))

                try:
                    await asyncio.wait_for(process.wait(), timeout=self.command_timeout)
                except asyncio.TimeoutError:
                    await self._terminate_process(process)
                    await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
                    return SSHExecutionResult(exit_code=124, cancelled=False, timeout=True)

                await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

                cancelled = await is_cancel_requested(request_id)
                return SSHExecutionResult(exit_code=process.exit_status, cancelled=cancelled, timeout=False)

            except Exception as exc:
                last_error = exc
                await self.reset()
                if attempt == 2:
                    raise
            finally:
                if command_registered:
                    await unregister_running_command(request_id)
                if self._active_commands > 0:
                    self._active_commands -= 1
                self._mark_used()
                if self._conn is not None and self._active_commands == 0:
                    self._schedule_idle_close()

        raise RuntimeError(f"SSH command failed after reconnect: {last_error}")


_managers: dict[str, SSHManager] = {}


def get_ssh_manager(server: str, server_cfg: dict[str, Any]) -> SSHManager:
    if server not in _managers:
        _managers[server] = SSHManager(server, server_cfg)
    return _managers[server]


def list_ssh_connection_status(server_cfgs: dict[str, Any]) -> list[dict[str, Any]]:
    statuses: list[dict[str, Any]] = []

    for server in sorted(set(server_cfgs.keys()) | set(_managers.keys())):
        manager = _managers.get(server)
        if manager is None:
            server_cfg = server_cfgs.get(server, {}) or {}
            statuses.append(
                {
                    "server": server,
                    "ssh_host": str(server_cfg.get("sshHost", server)),
                    "connected": False,
                    "active_commands": 0,
                    "connected_at": None,
                    "last_used_at": None,
                    "idle_disconnect_at": None,
                    "idle_disconnect_in_seconds": None,
                    "idle_disconnect_seconds": int(server_cfg.get("idleDisconnectSeconds", 300)),
                    "command_timeout_seconds": int(server_cfg.get("commandTimeoutSeconds", 120)),
                }
            )
            continue

        statuses.append(manager.get_status())

    return statuses
