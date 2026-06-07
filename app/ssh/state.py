from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(eq=False)
class StreamSubscriber:
    queue: asyncio.Queue[dict[str, Any]]

    async def push(self, event: dict[str, Any]) -> None:
        await self.queue.put(event)


class CommandStream:
    def __init__(
        self,
        *,
        stream_id: int,
        job_id: int,
        request_id: str,
        history_limit: int,
        stdout_log_path: Path,
        stderr_log_path: Path,
    ) -> None:
        self.stream_id = stream_id
        self.job_id = job_id
        self.request_id = request_id
        self.history = deque(maxlen=history_limit)
        self.subscribers: set[StreamSubscriber] = set()
        self.stdout_log_path = stdout_log_path
        self.stderr_log_path = stderr_log_path
        self.stdout_lines = 0
        self.stderr_lines = 0
        self.closed = False
        self._lock = asyncio.Lock()

        self.stdout_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.stderr_log_path.parent.mkdir(parents=True, exist_ok=True)

    async def publish(self, event: dict[str, Any]) -> None:
        async with self._lock:
            self.history.append(event)

            event_type = event.get("type")
            line = event.get("line")

            if event_type == "stdout" and isinstance(line, str):
                with self.stdout_log_path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
                self.stdout_lines += 1

            if event_type == "stderr" and isinstance(line, str):
                with self.stderr_log_path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
                self.stderr_lines += 1

            subscribers = list(self.subscribers)

        for subscriber in subscribers:
            await subscriber.push(event)

    async def subscribe(self, history_lines: Optional[int] = None) -> StreamSubscriber:
        subscriber = StreamSubscriber(queue=asyncio.Queue())

        async with self._lock:
            self.subscribers.add(subscriber)
            history = list(self.history)

        if history_lines is not None:
            history = history[-history_lines:]

        for event in history:
            await subscriber.push(event)

        return subscriber

    async def unsubscribe(self, subscriber: StreamSubscriber) -> None:
        async with self._lock:
            self.subscribers.discard(subscriber)

    async def close(self) -> None:
        async with self._lock:
            self.closed = True


@dataclass
class RunningCommand:
    request_id: str
    job_id: int
    server: str
    argv: list[str]
    remote_command: str
    process: Any
    stream: CommandStream
    manager: Any


_streams: dict[int, CommandStream] = {}
_running: dict[str, RunningCommand] = {}
_cancel_requested: set[str] = set()
_lock = asyncio.Lock()


async def register_stream(stream: CommandStream) -> None:
    async with _lock:
        _streams[stream.stream_id] = stream


async def get_stream(stream_id: int) -> Optional[CommandStream]:
    async with _lock:
        return _streams.get(stream_id)


async def register_running_command(item: RunningCommand) -> bool:
    async with _lock:
        if item.request_id in _cancel_requested:
            return False

        _running[item.request_id] = item
        return True


async def unregister_running_command(request_id: str) -> None:
    async with _lock:
        _running.pop(request_id, None)
        _cancel_requested.discard(request_id)


async def remove_running_command(request_id: str) -> None:
    async with _lock:
        _running.pop(request_id, None)


async def request_cancel(request_id: str) -> Optional[RunningCommand]:
    async with _lock:
        _cancel_requested.add(request_id)
        return _running.get(request_id)


async def is_cancel_requested(request_id: str) -> bool:
    async with _lock:
        return request_id in _cancel_requested


async def list_running_commands() -> list[dict[str, Any]]:
    async with _lock:
        return [
            {
                "request_id": item.request_id,
                "job_id": item.job_id,
                "server": item.server,
                "argv": item.argv,
                "remote_command": item.remote_command,
                "stream_id": item.stream.stream_id,
            }
            for item in _running.values()
        ]
