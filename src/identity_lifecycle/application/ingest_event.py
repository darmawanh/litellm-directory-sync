"""The ingest use case: validate, deduplicate, enqueue, return.

The hook route and the poller both end here. The event is already a
``CanonicalEvent`` — the envelope validated itself on construction —
so this use case adds the one check the envelope cannot make, that the source is
one this deployment reads, and then writes the row in **one** transaction. It
returns only after ``commit``, because design 9.1 step 2 says 2xx is sent only
after the row is durable: a sender that retried on a 5xx must never have been
told "accepted" for a row that was rolled back.

A duplicate ``event_id`` is an outcome, not an error (``EnqueueOutcome.DUPLICATE``):
the unique column is the enqueue guard, and the sender is told to stop retrying
. Nothing is written on that path, so nothing is committed.

This module imports the standard library, ``domain``, and ``ports`` only. It does
not know which adapter supplies the unit of work.
"""

from __future__ import annotations

import structlog

from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.events import CanonicalEvent, EventValidationError
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome

logger = structlog.get_logger(__name__)


class IngestEvent:
    """Write one canonical event to the outbox.

        ``unit_of_work`` is a factory taking the event's source, not a unit of work:
        one ingest is one transaction, and a shared instance would let two ingests
        share a commit. ``enabled_sources`` is the set of configured source names
    ; an event from any other source is rejected before a row exists.
    """

    def __init__(
        self,
        unit_of_work: UnitOfWorkFactory,
        *,
        enabled_sources: frozenset[str],
    ) -> None:
        self._unit_of_work = unit_of_work
        self._enabled_sources = enabled_sources

    def ingest(self, event: CanonicalEvent) -> EnqueueOutcome:
        """Enqueue ``event`` and return what the outbox did.

                Raises ``EventValidationError`` — permanent, never retried — when the
                event names a source this deployment does not read. A database
                failure propagates, so the caller can answer 5xx and let the sender retry
        .
        """
        if event.source not in self._enabled_sources:
            raise EventValidationError(
                f"source {event.source!r} is not configured; enabled sources are "
                f"{sorted(self._enabled_sources)}"
            )

        with self._unit_of_work(event.source) as uow:
            outcome = uow.outbox.enqueue(event)
            if outcome is EnqueueOutcome.INSERTED:
                uow.commit()
            else:
                logger.info(
                    "event_already_enqueued",
                    event_id=str(event.event_id),
                    source=event.source,
                )
            return outcome
