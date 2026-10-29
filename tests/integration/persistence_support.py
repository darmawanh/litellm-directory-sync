"""Shared values for the persistence integration tests: a clock, an event, an engine.

Nothing here touches a database. The engine comes from ``fresh_database`` and
``alembic_upgrade`` in ``conftest.py``; this module only builds the values a test
writes through the unit of work.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.engine import Engine

from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)

#: The instant every test starts at, so a failure names a stable timestamp.
START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class FakeClock:
    """A ``Clock`` whose instant a test moves; production uses ``SystemClock``.

    It implements the port rather than subclassing ``SystemClock`` so a test can
    advance time without sleeping and without a global.
    """

    def __init__(self, now: datetime = START) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


class FixedRandom(random.Random):
    """A ``random.Random`` whose draw is the midpoint, so a backoff is exact.

    Full jitter draws uniformly from ``[0, ceiling]``; the midpoint makes the
    delay ``ceiling / 2``, which is a value the test can assert instead of a
    range it hopes covers it.
    """

    def uniform(self, a: float, b: float) -> float:
        return a + (b - a) / 2


def system_clock() -> SystemClock:
    """Return the production clock, for the one test that checks its offset."""
    return SystemClock()


def member_added(
    *,
    source: str = "corp-ad",
    source_user_id: str = "object-guid-1",
    employee_number: str | None = "E20002",
    event_id: UUID | None = None,
) -> CanonicalEvent:
    """One ``group.member_added`` envelope for the tests to store and claim."""
    return CanonicalEvent(
        event_id=uuid4() if event_id is None else event_id,
        source=source,
        source_event_id="source-event-1",
        type=EventType.GROUP_MEMBER_ADDED,
        occurred_at=START,
        person=EventPerson(source_user_id=source_user_id, employee_number=employee_number),
        group=EventGroup(source_group_id="group-ai-platform", name="AI-Platform-Users"),
    )


def engine_for(database_url: str) -> Engine:
    """One engine per test, built the way production builds it."""
    return build_engine(database_url)
