"""The process clock, and the one place this package reads "now".

``Clock`` is a port; this is its production implementation. It exists so the
outbox lease and the retry schedule take time from a constructor argument
rather than calling ``datetime.now`` inline, which is what lets an integration
test move time without sleeping (design 15.3: dependencies pass through
constructors, and there is no global mutable state).
"""

from __future__ import annotations

from datetime import UTC, datetime


class SystemClock:
    """An aware UTC ``datetime`` per call."""

    def now(self) -> datetime:
        """Return the current instant in UTC; never a naive value."""
        return datetime.now(UTC)
