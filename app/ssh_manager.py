import asyncio
from typing import Optional, Dict, Any

import asyncssh

from .settings import SSH_CONFIG, SSH_KNOWN_HOSTS
from .config import get_server_config


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


def get_ssh_manager(server: str, server_cfg: Optional[Dict[str, Any]] = None) -> SSHManager:
    if server not in ssh_managers:
        if server_cfg is None:
            server_cfg = get_server_config(server)

        ssh_managers[server] = SSHManager(server, server_cfg)

    return ssh_managers[server]


def get_existing_ssh_manager(server: str) -> Optional[SSHManager]:
    return ssh_managers.get(server)