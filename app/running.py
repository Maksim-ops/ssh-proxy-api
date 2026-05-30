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
_cancel_requested: Dict[str, float] = {}
_lock = asyncio.Lock()


async def request_cancel(request_id: str) -> None:
    async with _lock:
        _cancel_requested[request_id] = time.monotonic()


async def clear_cancel_request(request_id: str) -> None:
    async with _lock:
        _cancel_requested.pop(request_id, None)


async def is_cancel_requested(request_id: str) -> bool:
    async with _lock:
        return request_id in _cancel_requested


async def register_running_command(
    *,
    request_id: str,
    server: str,
    argv: List[str],
    remote_command: str,
    process: Any,
) -> bool:
    """
    Регистрирует running command.

    Возвращает:
      True  - команда зарегистрирована;
      False - cancel уже был запрошен до регистрации.

    Если False, вызывающий код должен немедленно остановить process.
    """
    async with _lock:
        if request_id in _cancel_requested:
            return False

        _running[request_id] = RunningCommand(
            request_id=request_id,
            server=server,
            argv=argv,
            remote_command=remote_command,
            process=process,
            started_at=time.monotonic(),
        )

        return True


async def unregister_running_command(request_id: str) -> None:
    async with _lock:
        _running.pop(request_id, None)
        _cancel_requested.pop(request_id, None)


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
    """
    Пытается отменить команду.

    Варианты:
      - running command найден: terminate -> wait -> kill -> wait
      - running command не найден: записываем pending cancel

    Возвращает:
      (ok, message, running_command)
    """

    async with _lock:
        item = _running.get(request_id)

        if item is None:
            _cancel_requested[request_id] = time.monotonic()
            return True, "cancel requested before command was sent", None

    process = item.process

    # 1. Сначала мягко просим процесс завершиться
    try:
        process.terminate()
    except Exception:
        # Если terminate не сработал, пробуем сразу kill
        try:
            process.kill()
        except Exception as exc:
            return False, f"failed to terminate or kill process: {exc}", item

        try:
            await asyncio.wait_for(process.wait(), timeout=grace_seconds)
            return True, "killed", item
        except asyncio.TimeoutError:
            return True, "kill signal sent but process did not confirm exit", item
        except Exception as exc:
            return True, f"kill signal sent, wait failed: {exc}", item

    # 2. Ждём после terminate
    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
        return True, "terminated", item
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        return False, f"cancel failed while waiting after terminate: {exc}", item

    # 3. Если terminate не помог, делаем kill
    try:
        process.kill()
    except Exception as exc:
        return False, f"failed to kill process after timeout: {exc}", item

    # 4. Ждём после kill
    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
        return True, "killed", item
    except asyncio.TimeoutError:
        return True, "kill signal sent but process did not confirm exit", item
    except Exception as exc:
        return True, f"kill signal sent, wait failed: {exc}", item