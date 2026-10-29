"""Unit tests for the reconciliation scheduler worker."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from identity_lifecycle.application.reconcile import ReconciliationResult
from identity_lifecycle.workers.scheduler import (
    ReconciliationScheduler,
    parse_schedule_interval,
    seconds_until_next_cron,
)

pytestmark = pytest.mark.unit


def test_parse_schedule_interval_numeric() -> None:
    assert parse_schedule_interval("3600") == 3600.0
    assert parse_schedule_interval("45.5") == 45.5
    with pytest.raises(ValueError, match="Schedule duration must be positive"):
        parse_schedule_interval("-10")


def test_parse_schedule_interval_units() -> None:
    assert parse_schedule_interval("30s") == 30.0
    assert parse_schedule_interval("15m") == 900.0
    assert parse_schedule_interval("2h") == 7200.0
    assert parse_schedule_interval("1d") == 86400.0


def test_parse_schedule_interval_cron_hourly() -> None:
    # 12:15:30 -> next hourly match is 13:00:00 -> 44 minutes 30 seconds = 2670s
    fixed_now = datetime(2026, 1, 1, 12, 15, 30, tzinfo=UTC)
    interval = parse_schedule_interval("0 * * * *", now=fixed_now)
    assert interval == 2670.0


def test_seconds_until_next_cron_macros() -> None:
    # 23:45:00 -> next @daily is 00:00:00 next day -> 15 minutes = 900s
    fixed_now = datetime(2026, 1, 1, 23, 45, 0, tzinfo=UTC)
    assert seconds_until_next_cron("@daily", now=fixed_now) == 900.0


def test_invalid_cron_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Invalid cron expression"):
        seconds_until_next_cron("not a cron")


class FakeReconcile:
    def __init__(self) -> None:
        self.call_count = 0

    def reconcile(self, *, dry_run: bool | None = None) -> ReconciliationResult:
        self.call_count += 1
        return ReconciliationResult(
            drifts=(),
            events_emitted=(),
            misses_recorded=(),
            misses_cleared=(),
            dry_run=bool(dry_run),
        )


def test_scheduler_run_once() -> None:
    reconcile = FakeReconcile()
    scheduler = ReconciliationScheduler(
        reconcile,  # type: ignore[arg-type]
        schedule="3600",
    )

    result = scheduler.run_once()
    assert isinstance(result, ReconciliationResult)
    assert reconcile.call_count == 1


def test_scheduler_run_bounded_max_runs() -> None:
    reconcile = FakeReconcile()
    sleeps: list[float] = []

    scheduler = ReconciliationScheduler(
        reconcile,  # type: ignore[arg-type]
        schedule="60",
        sleep=sleeps.append,
    )

    scheduler.run(max_runs=3)

    assert reconcile.call_count == 3
    # Two sleeps between 3 runs
    assert len(sleeps) == 2
    assert sleeps == [60.0, 60.0]


def test_scheduler_request_stop_breaks_loop() -> None:
    reconcile = FakeReconcile()

    def stopping_sleep(duration: float) -> None:
        scheduler.request_stop()

    scheduler = ReconciliationScheduler(
        reconcile,  # type: ignore[arg-type]
        schedule="3600",
        sleep=stopping_sleep,
    )

    scheduler.run()
    assert reconcile.call_count == 1
