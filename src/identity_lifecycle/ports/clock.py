"""The clock the core reads, so a test controls lease expiry.

Time is a dependency, not a call to ``datetime.now``: the outbox lease, the
retry schedule, and the skew check all read one injected clock, so a test can
move time without sleeping and production can be told a different instant
(design 15.3: dependencies pass through constructors, and there is no global
mutable state).

The contract is one method. An implementation returns an aware UTC
``datetime``; a naive or non-UTC value is not a clock reading (design 10.10,
NFR22).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """The single source of "now" for one process."""

    def now(self) -> datetime:
        """Return the current instant as an aware UTC ``datetime``.

        The caller never adjusts the result into UTC: converting an offset is
        the implementation's job, exactly as converting a vendor timestamp is
        the adapter's.
        """
        ...
