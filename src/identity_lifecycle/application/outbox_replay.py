"""Outbox replay use case: replay dead or failed outbox events.

Allows operators to reset dead or settled outbox events back to pending status
with cleared retry counts and reset errors, enabling immediate re-evaluation by
the worker process.
"""

from __future__ import annotations

from uuid import UUID

import structlog

from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import ReplayOutcome

logger = structlog.get_logger(__name__)


class OutboxReplayError(PermanentError):
    """Base error for outbox replay failures."""


class OutboxNotFoundError(OutboxReplayError):
    """The requested outbox row ID or event UUID was not found."""


class OutboxConflictError(OutboxReplayError):
    """The outbox row cannot be replayed due to an active processing lock."""


class OutboxReplay:
    """Replay one dead or failed outbox event by row ID or canonical event ID."""

    def __init__(self, unit_of_work: UnitOfWorkFactory, clock: Clock) -> None:
        self._unit_of_work = unit_of_work
        self._clock = clock

    def replay(self, target_id: UUID | str) -> ReplayOutcome:
        """Reset the target outbox row to pending with 0 attempts."""
        if isinstance(target_id, str):
            try:
                parsed_id = UUID(target_id)
            except (ValueError, TypeError, AttributeError) as exc:
                raise OutboxReplayError(f"Invalid UUID for outbox replay: {target_id!r}") from exc
        elif isinstance(target_id, UUID):
            parsed_id = target_id
        else:
            raise OutboxReplayError(
                f"Invalid UUID type for outbox replay: {type(target_id).__name__}"
            )

        with self._unit_of_work("outbox-replay") as uow:
            try:
                outcome = uow.outbox.replay(parsed_id)
            except OutboxReplayError:
                raise
            except Exception as exc:
                raise OutboxConflictError(
                    f"Failed to replay outbox row {parsed_id}: {exc}"
                ) from exc

            if outcome is None:
                raise OutboxNotFoundError(f"Outbox row with ID or event_id {parsed_id} not found")

            uow.commit()

        logger.info(
            "outbox_replayed",
            row_id=str(outcome.row_id),
            event_id=str(outcome.event_id),
            previous_status=outcome.previous_status,
            event_type=outcome.event_type,
        )
        return outcome
