from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import SETTINGS
from app.db.repositories import create_audit_event


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_jsonl(event: Dict[str, Any]) -> None:
    path = Path(SETTINGS.audit_log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


async def write_audit_event(
    event: Dict[str, Any],
    *,
    action_name: Optional[str] = None,
    request_id: Optional[str] = None,
    user_id: Optional[int] = None,
    server_id: Optional[int] = None,
    resource: Optional[str] = None,
    result: Optional[str] = None,
) -> None:
    payload = dict(event)
    payload.setdefault("ts", utc_now_iso())

    try:
        await asyncio.to_thread(_append_jsonl, payload)
    except Exception as exc:
        print(f"[core-api] failed to write audit jsonl: {exc!r}", flush=True)

    if action_name:
        try:
            await asyncio.to_thread(
                create_audit_event,
                request_id=request_id or str(payload.get("request_id") or ""),
                user_id=user_id,
                server_id=server_id,
                action_name=action_name,
                resource=resource or str(payload.get("resource") or payload.get("event") or "unknown"),
                result=result or str(payload.get("decision") or payload.get("result") or "unknown"),
            )
        except Exception as exc:
            print(f"[core-api] failed to write audit event to db: {exc!r}", flush=True)
