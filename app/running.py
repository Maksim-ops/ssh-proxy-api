import time
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Optional, List


@dataclass
class RunningCommand:
    request_id: str
    server: str
    argv: List[str]
    remote_command: str
    process: Any
    started_at: float


_running: Dict[str, RunningCommand] = {}
_lock = asyncio.Lock()


async def register_running_command(
    *,
    request_id: str,
    server: str,
    argv: List[str],
    remote_command: str,
    process: Any,
) -> None:
    async with _lock:
        _running[request_id] = RunningCommand(
            request_id=request_id,
            server=server,
            argv=argv,
            remote_command=remote_command,
            process=process,
            started_at=time.monotonic(),
        )


async def unregister_running_command(request_id: str) -> None:
    async with _lock:
        _running.pop(request_id, None)


async def get_running_command(request_id: str) -> Optional[RunningCommand]:
    async with _lock:
        return _running.get(request_id)


async def list_running_commands() -> list[dict]:
    async with _lock:
        now = time.monotonic()

        return [
            {
                "request_id": item.request_id,
                "server": item.server,
                "argv": item.argv,
                "remote_command": item.remote_command,
                "duration_ms": int((now - item.started_at) * 1000),
            }
            for item in _running.values()
        ]


async def cancel_running_command(
    request_id: str,
    grace_seconds: float = 3.0,
) -> tuple[bool, str, Optional[RunningCommand]]:
    item = await get_running_command(request_id)

    if item is None:
        return False, "running command not found", None

    process = item.process

    try:
        process.terminate()
    except Exception:
        try:
            process.kill()
        except Exception as exc:
            return False, f"failed to terminate process: {exc}", item

    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
        return True, "terminated", item
    except asyncio.TimeoutError:
        try:
            process.kill()
        except Exception as exc:
            return False, f"failed to kill process after timeout: {exc}", item

        try:
            await asyncio.wait_for(process.wait(), timeout=grace_seconds)
        except Exception:
            pass

        return True, "killed", item
    except Exception as exc:
        return False, f"cancel failed: {exc}", item