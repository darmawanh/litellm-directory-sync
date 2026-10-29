"""Application use case for on-demand identity source polling.

Coordinates polling of configured identity sources, committing change events to
the outbox and advancing directory cursors and snapshots within atomic transactions.
Pure application layer: imports no vendor code or database libraries.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.ports.clock import Clock


class SourcePoller(Protocol):
    """Contract for an identity source poller cycle."""

    def poll_once(self) -> int:
        """Poll one cycle or page; return number of events enqueued."""
        ...


class SourceNotFoundError(PermanentError):
    """Raised when an unknown or disabled source is requested for polling."""


@dataclass(frozen=True)
class PollCycleResult:
    """Outcome of executing a polling cycle against an identity source."""

    source_name: str
    enqueued_count: int
    duration_ms: float
    error: str | None = None
    exception: Exception | None = None


class SourcePoll:
    """Use case coordinating one-shot or manual source polling passes."""

    def __init__(
        self,
        pollers: Mapping[str, SourcePoller],
        clock: Clock,
    ) -> None:
        self._pollers = dict(pollers)
        self._clock = clock

    def poll_once(self, source_name: str | None = None) -> tuple[PollCycleResult, ...]:
        """Poll the targeted source, or all configured sources in deterministic order."""
        if source_name is not None:
            if source_name not in self._pollers:
                raise SourceNotFoundError(f"source {source_name!r} is not configured or enabled")
            target_pollers = [(source_name, self._pollers[source_name])]
        else:
            target_pollers = sorted(self._pollers.items(), key=lambda item: item[0])

        results: list[PollCycleResult] = []
        for name, poller in target_pollers:
            start = time.perf_counter()
            total_enqueued = 0
            try:
                enqueued = poller.poll_once()
                total_enqueued += enqueued
                # If the poller has a multi-page drain in progress (e.g. multi-page log feeds),
                # drain subsequent pages until the current drain window is complete.
                while getattr(poller, "has_more_pages", False):
                    enqueued = poller.poll_once()
                    total_enqueued += enqueued

                duration_ms = (time.perf_counter() - start) * 1000.0
                results.append(
                    PollCycleResult(
                        source_name=name,
                        enqueued_count=total_enqueued,
                        duration_ms=duration_ms,
                    )
                )
            except Exception as exc:
                duration_ms = (time.perf_counter() - start) * 1000.0
                results.append(
                    PollCycleResult(
                        source_name=name,
                        enqueued_count=total_enqueued,
                        duration_ms=duration_ms,
                        error=str(exc),
                        exception=exc,
                    )
                )

        return tuple(results)
