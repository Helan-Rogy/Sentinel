"""In-process pub/sub that fans messages out to connected WebSockets."""
from __future__ import annotations

import asyncio
import json
from typing import Any


class Bus:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, topic: str, payload: Any) -> None:
        msg = json.dumps({"topic": topic, "data": payload}, default=str)
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # slow consumer: drop rather than block the pipeline
