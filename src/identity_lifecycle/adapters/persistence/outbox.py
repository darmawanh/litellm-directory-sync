"""The outbox state machine over ``identity_event_outbox``.

Three operations, each its own short transaction because ADR-002 section 4
splits a use case across claim, process, and settle:

- ``enqueue`` writes the row in the caller's transaction. A duplicate
  ``event_id`` is an outcome, not an exception: the sender is told to stop
  retrying.
- ``claim`` marks up to ``limit`` due rows ``processing`` under
  ``FOR UPDATE SKIP LOCKED`` and **commits before returning**, so two workers
  never claim the same row and no transaction spans a vendor call (NFR13,
  ADR-002 section 4).
- ``settle`` records one attempt: ``done``, a retry with backoff, or ``dead``.

``last_error`` holds the settle path that killed the row — ``permanent``,
``retry_limit``, or the exception class of an unreadable payload — and stays
null while a row is merely waiting to retry. ``Settlement`` carries no message,
so this is the adapter's own short reason, not a vendor error string; adding a
message to the port would need an ADR.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import bindparam, text
from sqlalchemy.engine import Connection

from identity_lifecycle.adapters.persistence.errors import StoreError
from identity_lifecycle.adapters.persistence.payload import (
    event_from_payload,
    event_to_payload,
    person_key,
)
from identity_lifecycle.adapters.persistence.retry import MAX_ATTEMPTS, backoff_delay
from identity_lifecycle.adapters.persistence.rows import event_id_of, payload_of, row_id_of
from identity_lifecycle.domain.errors import DomainError
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, ReplayOutcome, Settlement

#: How long a claim is invisible to the reaper. ADR-002 section 4 writes
#: ``<lease>`` without a number; this value must exceed design 10.6's 30-second
#: shutdown window, and a shorter lease would reap a row that is still being
#: processed. It is a constructor argument so a test can move it.
DEFAULT_LEASE_SECONDS = 300.0


class OutboxStore:
    """The ``identity_event_outbox`` rows, in ``CanonicalEvent`` terms."""

    def __init__(
        self,
        connection: Connection,
        clock: Clock,
        *,
        rng: random.Random | None = None,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self._connection = connection
        self._clock = clock
        self._rng = random.Random() if rng is None else rng
        self._lease = timedelta(seconds=lease_seconds)

    def enqueue(self, event: CanonicalEvent) -> EnqueueOutcome:
        """Write the event in the caller's transaction; a replay is ``DUPLICATE``."""
        now = self._clock.now()
        result = self._connection.execute(
            text(
                "insert into identity_event_outbox"
                " (event_id, source, source_event_id, person_key, event_type,"
                "  payload, status, next_attempt_at, created_at, updated_at)"
                " values (:event_id, :source, :source_event_id, :person_key, :event_type,"
                "  cast(:payload as jsonb), 'pending', :now, :now, :now)"
                " on conflict (event_id) do nothing"
            ),
            {
                "event_id": event.event_id,
                "source": event.source,
                "source_event_id": event.source_event_id,
                "person_key": person_key(event),
                "event_type": event.type.value,
                "payload": json.dumps(event_to_payload(event)),
                "now": now,
            },
        )
        return EnqueueOutcome.INSERTED if result.rowcount else EnqueueOutcome.DUPLICATE

    def claim(self, limit: int) -> tuple[CanonicalEvent, ...]:
        """Claim up to ``limit`` due events, commit, and return their envelopes.

        The commit is inside this method on purpose: a claim transaction held
        open across the vendor call would keep ``processing`` invisible and the
        reaper blind. The unit of work's own ``commit`` is
        for the settle transaction that follows.
        """
        if limit < 1:
            return ()
        now = self._clock.now()
        rows = (
            self._connection.execute(
                text(
                    # PostgreSQL puts LIMIT before FOR UPDATE; design 9.1's
                    # sample query has the two the other way round.
                    # ``event_id`` is selected beside the surrogate ``id``: the
                    # dead-letter and settle paths match on ``event_id``, so a
                    # claim that fetched only ``id`` could not settle a row.
                    "select id, event_id, payload from identity_event_outbox"
                    " where status = 'pending' and next_attempt_at <= :now"
                    " order by next_attempt_at, id"
                    " limit :limit"
                    " for update skip locked"
                ),
                {"now": now, "limit": limit},
            )
            .mappings()
            .all()
        )
        if not rows:
            self._connection.commit()
            return ()

        ids = [row_id_of(row) for row in rows]
        self._connection.execute(
            text(
                "update identity_event_outbox"
                " set status = 'processing', locked_until = :locked_until, updated_at = :now"
                " where id in :ids"
            ).bindparams(bindparam("ids", expanding=True)),
            {"ids": ids, "locked_until": now + self._lease, "now": now},
        )

        events: list[CanonicalEvent] = []
        for row in rows:
            try:
                events.append(event_from_payload(payload_of(row)))
            except (DomainError, KeyError, TypeError, ValueError) as error:
                # Design 9.1's poison-event path: a payload that cannot describe
                # a legal event will fail identically on every retry, so it goes
                # dead now rather than spinning until the lease expires
                # .
                # ``event_id``, not ``id``: ``_mark_dead`` matches the
                # ``event_id`` column, so the primary key would match no row and
                # raise before the commit, stalling the whole batch (F1).
                self._mark_dead(event_id_of(row), now, type(error).__name__)
        self._connection.commit()
        return tuple(events)

    def settle(self, event_id: UUID, outcome: Settlement) -> None:
        """Record one attempt's result; the caller commits the transaction."""
        now = self._clock.now()
        # Compared with ``==``, not ``is``: ``Settlement`` is a ``StrEnum``, so
        # an exact member and its string value both name the path, and a plain
        # string cannot silently fall through to the retry branch.
        if outcome == Settlement.DONE:
            self._finish(event_id, status="done", now=now)
            return
        if outcome == Settlement.PERMANENT:
            self._mark_dead(event_id, now, "permanent")
            return
        self._retry(event_id, now)

    def replay(self, target_id: UUID) -> ReplayOutcome | None:
        """Reset an outbox row to 'pending' with 0 attempts and clear errors."""
        now = self._clock.now()
        row = (
            self._connection.execute(
                text(
                    "select id, event_id, status, event_type, locked_until"
                    " from identity_event_outbox"
                    " where id = :target_id or event_id = :target_id"
                    " for update"
                ),
                {"target_id": target_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None

        current_status = str(row["status"])
        locked_until = row["locked_until"]
        if current_status == "processing" and locked_until is not None and locked_until > now:
            raise StoreError(
                f"cannot replay outbox row {target_id}: row is currently processing"
                f" (locked until {locked_until})"
            )

        self._connection.execute(
            text(
                "update identity_event_outbox"
                " set status = 'pending', attempts = 0, next_attempt_at = :now,"
                "     locked_until = null, last_error = null, updated_at = :now"
                " where id = :row_id"
            ),
            {"now": now, "row_id": row["id"]},
        )
        return ReplayOutcome(
            row_id=row["id"],
            event_id=row["event_id"],
            previous_status=current_status,
            event_type=str(row["event_type"]),
        )

    def _finish(self, event_id: UUID, *, status: str, now: datetime) -> None:
        result = self._connection.execute(
            text(
                "update identity_event_outbox"
                " set status = :status, locked_until = null, updated_at = :now"
                " where event_id = :event_id"
            ),
            {"status": status, "now": now, "event_id": event_id},
        )
        if not result.rowcount:
            raise StoreError(f"settle for event_id {event_id} found no outbox row")

    def _mark_dead(self, event_id: UUID, now: datetime, reason: str) -> None:
        result = self._connection.execute(
            text(
                "update identity_event_outbox"
                " set status = 'dead', locked_until = null, last_error = :last_error,"
                " updated_at = :now"
                " where event_id = :event_id"
            ),
            {"last_error": reason, "now": now, "event_id": event_id},
        )
        if not result.rowcount:
            raise StoreError(f"dead-letter for event_id {event_id} found no outbox row")

    def _retry(self, event_id: UUID, now: datetime) -> None:
        """Increment ``attempts``; back off, or go dead at ADR-002 section 6's limit."""
        row = (
            self._connection.execute(
                text(
                    "select attempts from identity_event_outbox"
                    " where event_id = :event_id"
                    " for update"
                ),
                {"event_id": event_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise StoreError(f"settle for event_id {event_id} found no outbox row")
        attempts = row["attempts"]
        if not isinstance(attempts, int):
            raise StoreError(f"identity_event_outbox.attempts is {type(attempts).__name__}")
        next_attempt = attempts + 1
        if next_attempt >= MAX_ATTEMPTS:
            self._mark_dead(event_id, now, "retry_limit")
            return
        delay = backoff_delay(next_attempt, self._rng)
        self._connection.execute(
            text(
                "update identity_event_outbox"
                " set status = 'pending', attempts = :attempts,"
                " next_attempt_at = :next_attempt_at, locked_until = null, updated_at = :now"
                " where event_id = :event_id"
            ),
            {
                "attempts": next_attempt,
                "next_attempt_at": now + timedelta(seconds=delay),
                "now": now,
                "event_id": event_id,
            },
        )


def reap_expired_leases(connection: Connection, *, now: datetime) -> int:
    """Return ``processing`` rows whose lease has passed to ``pending``.

    Per ADR-002 section 7 this is worker-level code over the table, not a unit of
    work method, so it is a function rather than a repository. The caller owns
    the transaction: the reaper runs in its own short one.
    """
    result = connection.execute(
        text(
            "update identity_event_outbox"
            " set status = 'pending', locked_until = null, updated_at = :now"
            " where status = 'processing' and locked_until is not null"
            " and locked_until < :now"
        ),
        {"now": now},
    )
    return int(result.rowcount or 0)


__all__ = ["OutboxStore", "DEFAULT_LEASE_SECONDS", "reap_expired_leases"]
