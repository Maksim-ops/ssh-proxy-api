from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from app.config import SETTINGS, get_global_rate_limit


_locks: dict[str, asyncio.Lock] = {}
_last_sent_at: dict[str, float] = {}
_auth_attempts: dict[str, deque[float]] = {}
_auth_failures: dict[str, deque[float]] = {}


def get_effective_rate_limit_seconds(server_cfg: dict[str, Any]) -> float:
    global_rl = get_global_rate_limit()
    server_rl = server_cfg.get("rateLimit", {}) or {}
    value = server_rl.get("minIntervalSeconds", global_rl.get("minIntervalSeconds", 0))
    return float(value or 0)


async def wait_for_rate_limit(*, server: str, server_cfg: dict[str, Any]) -> int:
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


def consume_auth_attempt(*, ip_address: str | None, email: str | None) -> tuple[bool, int]:
    now = time.monotonic()
    window = max(1, SETTINGS.auth_rate_limit_window_seconds)
    limit = max(1, SETTINGS.auth_rate_limit_max_attempts)
    key = _auth_key(ip_address, email)
    bucket = _auth_attempts.setdefault(key, deque())
    _prune(bucket, now, window)
    if len(bucket) >= limit:
        retry_after = max(1, int(window - (now - bucket[0])))
        return False, retry_after
    bucket.append(now)
    return True, 0


def record_auth_failure(*, ip_address: str | None, email: str | None) -> int:
    now = time.monotonic()
    window = max(1, SETTINGS.auth_rate_limit_window_seconds)
    key = _auth_key(ip_address, email)
    bucket = _auth_failures.setdefault(key, deque())
    _prune(bucket, now, window)
    bucket.append(now)
    return len(bucket)


def clear_auth_failures(*, ip_address: str | None, email: str | None) -> None:
    _auth_failures.pop(_auth_key(ip_address, email), None)


def is_suspicious_auth_attempt(*, ip_address: str | None, email: str | None) -> bool:
    now = time.monotonic()
    window = max(1, SETTINGS.auth_rate_limit_window_seconds)
    key = _auth_key(ip_address, email)
    bucket = _auth_failures.setdefault(key, deque())
    _prune(bucket, now, window)
    return len(bucket) >= SETTINGS.auth_suspicious_threshold


def _auth_key(ip_address: str | None, email: str | None) -> str:
    return f"{(ip_address or 'unknown').strip()}::{(email or '').strip().lower()}"


def _prune(bucket: deque[float], now: float, window: int) -> None:
    while bucket and now - bucket[0] > window:
        bucket.popleft()
