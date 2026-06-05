import time
import asyncio
from typing import Dict, Any

from .config import get_global_rate_limit


_locks: dict[str, asyncio.Lock] = {}
_last_sent_at: dict[str, float] = {}


def get_effective_rate_limit_seconds(server_cfg: Dict[str, Any]) -> float:
    global_rl = get_global_rate_limit()
    server_rl = server_cfg.get("rateLimit", {}) or {}

    value = server_rl.get(
        "minIntervalSeconds",
        global_rl.get("minIntervalSeconds", 0),
    )

    return float(value or 0)


async def wait_for_rate_limit(
    *,
    server: str,
    server_cfg: Dict[str, Any],
) -> int:
    """
    Возвращает wait_ms.
    Ограничивает частоту старта команд на server.
    """

    min_interval = get_effective_rate_limit_seconds(server_cfg)

    if min_interval <= 0:
        return 0

    if server not in _locks:
        _locks[server] = asyncio.Lock()

    async with _locks[server]:
        now = time.monotonic()
        last = _last_sent_at.get(server)

        wait_seconds = 0.0

        if last is not None:
            elapsed = now - last

            if elapsed < min_interval:
                wait_seconds = min_interval - elapsed

        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)

        _last_sent_at[server] = time.monotonic()

        return int(wait_seconds * 1000)