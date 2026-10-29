"""Unit tests for the outbox replay use case and operator CLI command."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

import identity_lifecycle.main as cli
from identity_lifecycle.application.outbox_replay import (
    OutboxConflictError,
    OutboxNotFoundError,
    OutboxReplay,
    OutboxReplayError,
)
from identity_lifecycle.config import ConfigError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventPerson,
    EventType,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import ReplayOutcome
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork, OutboxRow
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.unit


def _valid_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    cfg_path = tmp_path / "valid_config.yaml"
    cfg_path.write_text(_text(), encoding="utf-8")
    return cfg_path


class FakeClock(Clock):
    def __init__(self, current: datetime | None = None) -> None:
        self._current = current or datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self._current

    def advance(self, seconds: float) -> None:
        self._current += timedelta(seconds=seconds)


def _sample_event(event_id: UUID | None = None) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id or uuid4(),
        source="corp-okta",
        source_event_id="evt-12345",
        type=EventType.USER_CREATED,
        occurred_at=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
        person=EventPerson(
            source_user_id="00u123",
            employee_number="E123",
        ),
        group=None,
    )


def test_replay_dead_outbox_row_by_row_id() -> None:
    store = InMemoryStore()
    clock = FakeClock()
    event = _sample_event()
    row_id = uuid4()
    store.outbox[event.event_id] = OutboxRow(
        event=event,
        next_attempt_at=clock.now() - timedelta(minutes=10),
        status="dead",
        attempts=8,
        last_error="retry_limit",
        row_id=row_id,
    )

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    outcome = use_case.replay(row_id)

    assert isinstance(outcome, ReplayOutcome)
    assert outcome.row_id == row_id
    assert outcome.event_id == event.event_id
    assert outcome.previous_status == "dead"
    assert outcome.event_type == EventType.USER_CREATED.value

    # Verify state in store
    saved_row = store.outbox[event.event_id]
    assert saved_row.status == "pending"
    assert saved_row.attempts == 0
    assert saved_row.next_attempt_at == clock.now()
    assert saved_row.last_error is None
    assert saved_row.locked_until is None


def test_replay_dead_outbox_row_by_canonical_event_id() -> None:
    store = InMemoryStore()
    clock = FakeClock()
    event = _sample_event()
    row_id = uuid4()
    store.outbox[event.event_id] = OutboxRow(
        event=event,
        next_attempt_at=clock.now() - timedelta(minutes=10),
        status="dead",
        attempts=8,
        last_error="retry_limit",
        row_id=row_id,
    )

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    outcome = use_case.replay(event.event_id)

    assert outcome.row_id == row_id
    assert outcome.event_id == event.event_id
    assert outcome.previous_status == "dead"


def test_replay_with_string_uuid() -> None:
    store = InMemoryStore()
    clock = FakeClock()
    event = _sample_event()
    store.outbox[event.event_id] = OutboxRow(
        event=event,
        next_attempt_at=clock.now(),
        status="dead",
        attempts=1,
        last_error="permanent",
    )

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    outcome = use_case.replay(str(event.event_id))
    assert outcome.event_id == event.event_id


def test_replay_rejects_invalid_uuid_string() -> None:
    store = InMemoryStore()
    clock = FakeClock()

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    with pytest.raises(OutboxReplayError, match="Invalid UUID"):
        use_case.replay("not-a-valid-uuid")


def test_replay_rejects_invalid_type() -> None:
    store = InMemoryStore()
    clock = FakeClock()

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    with pytest.raises(OutboxReplayError, match="Invalid UUID type"):
        use_case.replay(12345)  # type: ignore[arg-type]


def test_replay_raises_not_found_when_row_missing() -> None:
    store = InMemoryStore()
    clock = FakeClock()

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    missing_id = uuid4()
    with pytest.raises(OutboxNotFoundError, match="not found"):
        use_case.replay(missing_id)


def test_replay_rejects_actively_processing_row() -> None:
    store = InMemoryStore()
    clock = FakeClock()
    event = _sample_event()
    row_id = uuid4()
    store.outbox[event.event_id] = OutboxRow(
        event=event,
        next_attempt_at=clock.now(),
        status="processing",
        locked_until=clock.now() + timedelta(seconds=300),
        row_id=row_id,
    )

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    use_case = OutboxReplay(uow_factory, clock)
    with pytest.raises(OutboxConflictError, match="currently processing"):
        use_case.replay(row_id)


def test_replay_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["outbox", "replay", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "--id" in captured.out
    assert "--config" in captured.out
    assert "--log-level" in captured.out


def test_replay_cli_missing_id_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["outbox", "replay"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "required: --id" in captured.err or "--id" in captured.err


def test_replay_cli_end_to_end_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    store = InMemoryStore()
    clock = FakeClock()
    event = _sample_event()
    row_id = uuid4()
    store.outbox[event.event_id] = OutboxRow(
        event=event,
        next_attempt_at=clock.now(),
        status="dead",
        attempts=8,
        last_error="retry_limit",
        row_id=row_id,
    )

    def uow_factory(source: str = "test") -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    original_run = cli._run_outbox_replay
    monkeypatch.setattr(
        cli,
        "_run_outbox_replay",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "unit_of_work_factory": uow_factory, "clock": clock}
        ),
    )

    exit_code = cli.main(
        [
            "outbox",
            "replay",
            "--config",
            str(cfg),
            "--id",
            str(row_id),
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert f"Replayed outbox event {event.event_id} (row {row_id}):" in stdout_text
    assert "status reset from 'dead' to 'pending'" in stdout_text


def test_replay_cli_missing_database_url_raises_config_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        cli._run_outbox_replay(
            config_path=cfg,
            log_level="INFO",
            target_id=str(uuid4()),
        )
    assert exc_info.value.key == "DATABASE_URL"
