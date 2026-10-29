"""The reconciliation scheduler process: periodic alignment loop.

Executes the reconciliation engine at configured intervals or cron schedules,
handling graceful shutdown via SIGTERM/SIGINT signals.
"""

from __future__ import annotations

import contextlib
import re
import signal
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import FrameType

import structlog

from identity_lifecycle.application.reconcile import Reconcile, ReconciliationResult

logger = structlog.get_logger(__name__)

CRON_MACROS = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
}


def _match_field(value: int, pattern: str) -> bool:
    """Check if an integer value matches a cron field pattern."""
    if pattern == "*":
        return True
    for part in pattern.split(","):
        if "/" in part:
            subparts = part.split("/")
            if len(subparts) != 2:
                return False
            base, step_str = subparts
            if not step_str.isdigit():
                return False
            step = int(step_str)
            if step <= 0:
                return False
            if base == "*":
                if value % step == 0:
                    return True
            elif base.isdigit() and value >= int(base) and (value - int(base)) % step == 0:
                return True
        elif "-" in part:
            subparts = part.split("-")
            if len(subparts) != 2 or not subparts[0].isdigit() or not subparts[1].isdigit():
                return False
            if int(subparts[0]) <= value <= int(subparts[1]):
                return True
        elif part.isdigit() and int(part) == value:
            return True
    return False


def _matches_cron(dt: datetime, fields: list[str]) -> bool:
    """Check whether a datetime matches the 5 cron fields [min, hour, dom, mon, dow]."""
    # cron dow: 0 = Sunday, 1 = Monday,..., 6 = Saturday (or 7 = Sunday)
    dow = (dt.weekday() + 1) % 7
    return (
        _match_field(dt.minute, fields[0])
        and _match_field(dt.hour, fields[1])
        and _match_field(dt.day, fields[2])
        and _match_field(dt.month, fields[3])
        and (_match_field(dow, fields[4]) or (fields[4] == "7" and dow == 0))
    )


def seconds_until_next_cron(cron_expr: str, now: datetime | None = None) -> float:
    """Calculate seconds from now until the next matching cron moment."""
    if cron_expr in CRON_MACROS:
        cron_expr = CRON_MACROS[cron_expr]
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression (expected 5 fields): {cron_expr!r}")

    current = datetime.now(UTC) if now is None else now
    # Round up to the next minute
    candidate = current.replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = candidate + timedelta(days=366)

    while candidate < limit:
        if _matches_cron(candidate, parts):
            return max(1.0, (candidate - current).total_seconds())
        candidate += timedelta(minutes=1)

    return 3600.0


def parse_schedule_interval(schedule: str, now: datetime | None = None) -> float:
    """Parse a schedule string into a duration in seconds until the next run.

    Supports:
    - Pure integer or float seconds: '3600', '60.0'
    - Human durations: '30s', '15m', '1h', '24h', '1d'
    - Cron expressions / macros: '0 * * * *', '@hourly', '@daily'
    """
    cleaned = schedule.strip()
    if not cleaned:
        raise ValueError("Schedule cannot be empty")

    # Try numeric seconds
    try:
        val = float(cleaned)
    except ValueError:
        val = None

    if val is not None:
        if val <= 0:
            raise ValueError(f"Schedule duration must be positive: {cleaned!r}")
        return val

    # Try human units
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([smhd])$", cleaned, re.IGNORECASE)
    if match:
        amount = float(match.group(1))
        unit = match.group(2).lower()
        multipliers = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
        seconds = amount * multipliers[unit]
        if seconds <= 0:
            raise ValueError(f"Schedule duration must be positive: {cleaned!r}")
        return seconds

    # Try cron expression
    return seconds_until_next_cron(cleaned, now)


class ReconciliationScheduler:
    """Periodic execution loop for the reconciliation engine."""

    def __init__(
        self,
        reconcile: Reconcile,
        *,
        schedule: str,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._reconcile = reconcile
        self._schedule = schedule
        self._sleep = sleep
        self._stopping = False

    def request_stop(self, signum: int | None = None, frame: FrameType | None = None) -> None:
        """Signal the scheduler to finish and stop."""
        if not self._stopping:
            logger.info("scheduler_stop_requested", signal=signum)
        self._stopping = True

    def run_once(self) -> ReconciliationResult:
        """Execute a single reconciliation run."""
        logger.info("reconciliation_run_started", schedule=self._schedule)
        result = self._reconcile.reconcile()
        logger.info(
            "reconciliation_run_finished",
            drifts=len(result.drifts),
            events_emitted=len(result.events_emitted),
            misses_recorded=len(result.misses_recorded),
            dry_run=result.dry_run,
        )
        return result

    def next_interval(self) -> float:
        """Determine seconds until the next scheduled run."""
        return parse_schedule_interval(self._schedule)

    def run(self, max_runs: int | None = None) -> None:
        """Run the scheduler loop until stopped or max_runs reached."""
        previous = self._install_handlers()
        logger.info("scheduler_started", schedule=self._schedule)
        runs = 0
        try:
            while not self._stopping:
                if max_runs is not None and runs >= max_runs:
                    break

                self.run_once()
                runs += 1

                if max_runs is not None and runs >= max_runs:
                    break

                interval = self.next_interval()
                logger.debug("scheduler_sleeping", interval_seconds=interval)
                if not self._stopping:
                    self._sleep(interval)

        finally:
            self._restore_handlers(previous)
            logger.info("scheduler_stopped", total_runs=runs)

    def _install_handlers(self) -> dict[int, object]:
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
            with contextlib.suppress(ValueError):
                signal.signal(signum, handler)  # type: ignore[arg-type]
