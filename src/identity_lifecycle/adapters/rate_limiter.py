"""Rate limiting adapter using the limits package."""

from __future__ import annotations

from limits import parse
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter


class MovingWindowLimiter:
    """Moving window rate limiter backed by in-memory storage."""

    def __init__(self) -> None:
        self._storage = MemoryStorage()
        self._limiter = MovingWindowRateLimiter(self._storage)

    def hit(self, rate_spec: str, key: str) -> bool:
        """Attempt to consume one token for the given rate specification and key."""
        item = parse(rate_spec)
        return bool(self._limiter.hit(item, key))

    def get_retry_after(self, rate_spec: str, key: str, current_time: float) -> int:
        """Calculate seconds until reset for the given rate specification and key."""
        item = parse(rate_spec)
        stats = self._limiter.get_window_stats(item, key)
        return max(1, int(stats.reset_time - current_time))
