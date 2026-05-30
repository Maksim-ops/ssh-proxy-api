import os
import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any

from .settings import AUDIT_LOG_PATH


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_audit_event_sync(event: Dict[str, Any]) -> None:
    event = dict(event)
    event.setdefault("ts", utc_now_iso())

    log_dir = os.path.dirname(AUDIT_LOG_PATH)

    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))

    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


async def write_audit_event(event: Dict[str, Any]) -> None:
    """
    Пишем audit log через asyncio.to_thread, чтобы не блокировать event loop.
    """
    try:
        await asyncio.to_thread(write_audit_event_sync, event)
    except Exception as exc:
        # Audit не должен ломать выполнение команд.
        print(f"[pctl] audit write failed: {repr(exc)}", flush=True)