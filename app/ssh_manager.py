import asyncio
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

import asyncssh

from .settings import SSH_CONFIG, SSH_KNOWN_HOSTS
from .config import get_server_config
from .running import (
    register_running_command,
    unregister_running_command,
    is_cancel_requested,
)

@dataclass
class SSHRunResult:
    stdout: str
    stderr: str
    exit_status: Optional[int]


class SSHManager:
    def __init__(self, server_name: str, server_cfg: Dict[str, Any]) -> None:
        self.server_name = server_name
        self.server_cfg = server_cfg

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
            return
        except asyncio.TimeoutError:
            pass
        except Exception:
            return

        try:
            process.kill()
            await asyncio.wait_for(process.wait(), timeout=3)
        except Exception:
            pass

    async def run(
        self,
        *,
        command: str,
        request_id: str,
        argv: List[str],
    ) -> SSHRunResult:
        """
        Выполняет команду через create_process(), чтобы её можно было отменить
        через /api/v1/cancel.
        """

        last_error: Optional[Exception] = None

        for attempt in [1, 2]:
            process = None

            try:
                await self.connect()

                assert self._conn is not None

                if await is_cancel_requested(request_id):
                    raise RuntimeError("command was cancelled before it was sent")

                actual_command = f"exec {command}"
                process = await self._conn.create_process(actual_command)

                registered = await register_running_command(
                    request_id=request_id,
                    server=self.server_name,
                    argv=argv,
                    remote_command=command,
                    process=process,
                )

                if not registered:
                    await self._terminate_process(process)
                    raise RuntimeError("command was cancelled before it was sent")

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.command_timeout,
                    )
                except asyncio.TimeoutError:
                    await self._terminate_process(process)
                    raise TimeoutError(
                        f"command timeout after {self.command_timeout} seconds"
                    )

                return SSHRunResult(
                    stdout=stdout or "",
                    stderr=stderr or "",
                    exit_status=process.exit_status,
                )

            except TimeoutError:
                await unregister_running_command(request_id)
                raise

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

            finally:
                await unregister_running_command(request_id)

        raise RuntimeError(f"SSH command failed after reconnect: {last_error}")


ssh_managers: Dict[str, SSHManager] = {}


def get_ssh_manager(
    server: str,
    server_cfg: Optional[Dict[str, Any]] = None,
) -> SSHManager:
    if server not in ssh_managers:
        if server_cfg is None:
            server_cfg = get_server_config(server)

        ssh_managers[server] = SSHManager(server, server_cfg)

    return ssh_managers[server]


def get_existing_ssh_manager(server: str) -> Optional[SSHManager]:
    return ssh_managers.get(server)