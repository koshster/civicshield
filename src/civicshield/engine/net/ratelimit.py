"""Per-host token-bucket rate limiting.

A token bucket allows short bursts (up to ``capacity`` requests back to back) but caps
the sustained rate at ``rate`` requests/second. Small nonprofit sites often run on cheap
shared hosting, so politeness here is a feature, not just etiquette.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class TokenBucket:
    def __init__(
        self,
        rate: float,
        capacity: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self.tokens = min(self.capacity, self.tokens + (now - self._updated) * self.rate)
        self._updated = now

    async def acquire(self) -> None:
        # The lock makes concurrent callers queue up fairly instead of all waking at once.
        async with self._lock:
            self._refill()
            while self.tokens < 1:
                await self._sleep((1 - self.tokens) / self.rate)
                self._refill()
            self.tokens -= 1


class HostRateLimiter:
    def __init__(self, rate: float, burst: int) -> None:
        self.rate = rate
        self.burst = burst
        self._buckets: dict[str, TokenBucket] = {}

    async def acquire(self, host: str) -> None:
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = self._buckets[host] = TokenBucket(self.rate, self.burst)
        await bucket.acquire()
