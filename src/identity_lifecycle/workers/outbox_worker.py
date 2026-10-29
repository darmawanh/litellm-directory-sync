"""The worker process: claim, process, settle, sleep.

The loop **is** the process: there is no background thread or queue in memory.
One iteration polls due source callbacks, reaps expired leases, claims a batch,
hands each event to ``ProcessEvent`` (which owns the effect, the audit row, and
the settle), and sleeps only when the batch came back empty.

The gateway and unit-of-work factory are injected, so the worker does not choose
which adapters it uses:

- the ``Gateway``, so this process holds no vendor client;
- the ``UnitOfWork`` factory, so the claim runs in the same store the use case
  uses.

The reaper and source poll callback are also injected as callables, not port
methods. The poll callback composes the configured source adapters in ``main``.
The reaper is a *callable*, not a port method.
ADR-002 section 7 makes lease recovery worker-level code over the outbox table
rather than a use case, so ``reap_expired_leases`` is a plain function that
``main.py`` binds to a connection; calling it here as a function is what keeps
the port's nine repositories unchanged (``ports/unit_of_work.py``).

``main.py`` binds configured adapter pollers to the callback; the worker does
not know which source or vendor it is polling. The poller commits its page
before this loop claims the resulting outbox rows.

The claim opens a unit of work with ``CLAIM_SOURCE`` because a claim writes no
audit row: the store takes the source at construction, and the empty string is
the one value no configured source can be (``source_name`` matches
``^[a-z0-9][a-z0-9_-]*$``). The settle uses the event's own source, inside
``ProcessEvent``.

SIGTERM sets one flag. The loop stops claiming immediately and finishes the
batch it already holds; there is no thread to interrupt, so the in-flight rows
run to completion and the process exits when they do. Design 10.6 step 4's
30-second budget is measured and logged, not enforced by killing work: a row
still locked after the process dies is recovered by the reaper once its lease
expires.
"""

from __future__ import annotations

import signal
import time
from collections.abc import Callable
from types import FrameType

import structlog

from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.domain.events import CanonicalEvent

logger = structlog.get_logger(__name__)

#: A claim writes no audit row, so the store's source is unused here. No
#: configured ``source_name`` can be empty, so this value
#: cannot collide with a real source.
CLAIM_SOURCE = ""

#: Design 10.6 step 4: stop claiming, finish in-flight rows, exit within 30 s.
SHUTDOWN_SECONDS = 30.0


class OutboxWorker:
    """One process's claim/process/settle loop."""

    def __init__(
        self,
        unit_of_work: UnitOfWorkFactory,
        process: ProcessEvent,
        reap: Callable[[], int],
        *,
        batch_size: int,
        poll_interval_seconds: float,
        poll_sources: Callable[[], None] | None = None,
        shutdown_seconds: float = SHUTDOWN_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if batch_size < 1:
            raise ValueError(f"batch_size must be at least 1; got {batch_size}")
        if poll_interval_seconds < 0:
            raise ValueError(
                f"poll_interval_seconds must not be negative; got {poll_interval_seconds}"
            )
        self._unit_of_work = unit_of_work
        self._process = process
        self._reap = reap
        self._batch_size = batch_size
        self._poll_interval = poll_interval_seconds
        self._poll_sources = poll_sources
        self._shutdown_seconds = shutdown_seconds
        self._sleep = sleep
        self._stopping = False

    # signal handling

    def request_stop(self, signum: int | None = None, frame: FrameType | None = None) -> None:
        """Stop claiming after the batch in hand; the handler signature is the signal's."""
        if not self._stopping:
            logger.info("worker_stop_requested", signal=None if signum is None else signum)
        self._stopping = True

    # the loop

    def run(self) -> None:
        """Claim and process until a stop is requested."""
        previous = self._install_handlers()
        try:
            while not self._stopping:
                if self._poll_sources is not None:
                    self._poll_sources()
                self._reap_once()
                events = self._claim()
                if not events:
                    self._idle()
                    continue
                self._finish(events)
        finally:
            self._restore_handlers(previous)
            logger.info("worker_stopped")

    def _claim(self) -> tuple[CanonicalEvent, ...]:
        """Claim one batch; ``claim`` commits before it returns."""
        with self._unit_of_work(CLAIM_SOURCE) as uow:
            return uow.outbox.claim(self._batch_size)

    def _finish(self, events: tuple[CanonicalEvent, ...]) -> None:
        """Process every claimed row, then report a shutdown that overran its budget.

        The loop does not stop part-way through a batch: the rows are already
        ``processing`` with a lease, and abandoning one would hide it until the
        lease expired. That is design 10.6 step 2, "finish in-flight rows".
        """
        started = time.monotonic()
        for event in events:
            self._process.process(event)
        elapsed = time.monotonic() - started
        if self._stopping and elapsed > self._shutdown_seconds:
            # Design 10.6 step 4's budget is reported, not enforced by killing a
            # row mid-write: the lease is the recovery path.
            logger.warning(
                "worker_shutdown_overran",
                seconds=round(elapsed, 3),
                budget_seconds=self._shutdown_seconds,
                rows=len(events),
            )

    def _reap_once(self) -> None:
        """Return expired leases to ``pending`` before claiming."""
        reaped = self._reap()
        if reaped:
            logger.info("outbox_leases_reaped", rows=reaped)

    def _idle(self) -> None:
        """Nothing is due: wait one poll interval, unless a stop arrived meanwhile."""
        if not self._stopping:
            self._sleep(self._poll_interval)

    # signal plumbing

    def _install_handlers(self) -> dict[int, object]:
        """Install the SIGTERM (and SIGINT) handlers, when this thread may.

        ``signal.signal`` raises ``ValueError`` off the main thread, and a worker
        driven by a test or a thread is not a reason to fail startup: the caller
        can call :meth:`request_stop` instead.
        """
        previous: dict[int, object] = {}
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                previous[signum] = signal.getsignal(signum)
                signal.signal(signum, self.request_stop)
            except ValueError:
                previous.pop(signum, None)
        return previous

    def _restore_handlers(self, previous: dict[int, object]) -> None:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)  # type: ignore[arg-type]
            except ValueError:
                return
