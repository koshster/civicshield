"""A small in-process sliding-window limiter for login attempts.

Good enough for a single-instance, self-hosted deployment. With several API replicas
this would move to Redis (same interface, shared counters).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record an attempt; return False if the key is over its limit."""
        now = time.monotonic() if now is None else now
        q = self._events[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.max_events:
            return False
        q.append(now)
        return True

    def reset(self, key: str) -> None:
        self._events.pop(key, None)
