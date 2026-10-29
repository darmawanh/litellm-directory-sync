"""``processed_events``: which ``event_id`` values already took effect.

The table is the idempotency guard of processing rule 1. It is written in the
use case's transaction, beside the state change, so a crash before the commit
leaves neither the effect nor the record.

``mark_processed`` is idempotent at the store: a repeated call is a no-op rather
than a unique-violation, because a duplicate event is a normal at-least-once
delivery, not a failure.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


class ProcessedEventStore:
    """The ``processed_events`` rows."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def is_processed(self, event_id: UUID) -> bool:
        """Return whether this event has already been applied."""
        return (
            self._connection.execute(
                text("select 1 from processed_events where event_id = :event_id"),
                {"event_id": event_id},
            ).first()
            is not None
        )

    def mark_processed(self, event_id: UUID) -> None:
        """Record the event as applied; a second call for the same id is a no-op."""
        self._connection.execute(
            text(
                "insert into processed_events (event_id) values (:event_id)"
                " on conflict (event_id) do nothing"
            ),
            {"event_id": event_id},
        )
