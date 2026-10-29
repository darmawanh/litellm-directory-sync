"""Integration tests for operator CLI subcommand: outbox replay."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine, RowMapping

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventPerson,
    EventType,
)
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.integration


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, migrated_database: str) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, migrated_database)
    cfg_file = tmp_path / "integration_config.yaml"
    cfg_file.write_text(_text(), encoding="utf-8")
    return cfg_file


def _sample_event(event_id: UUID | None = None) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id or uuid4(),
        source="corp-okta",
        source_event_id="evt-integration-1",
        type=EventType.USER_CREATED,
        occurred_at=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
        person=EventPerson(
            source_user_id="00u-replay-test",
            employee_number="E999",
        ),
        group=None,
    )


def _row(engine: Engine, event_id: UUID) -> RowMapping:
    with engine.connect() as conn:
        return (
            conn.execute(
                sqlalchemy.text(
                    "select id, event_id, status, attempts, next_attempt_at, "
                    "locked_until, last_error "
                    "from identity_event_outbox where event_id = :event_id"
                ),
                {"event_id": event_id},
            )
            .mappings()
            .one()
        )


def test_outbox_replay_dead_row_by_event_id(
    engine: Engine, config_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    clock = SystemClock()
    event = _sample_event()

    # 1. Enqueue and settle dead
    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        assert uow.outbox.enqueue(event) is EnqueueOutcome.INSERTED
        uow.commit()

    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        claimed = uow.outbox.claim(1)
        assert len(claimed) == 1
        uow.outbox.settle(event.event_id, Settlement.PERMANENT)
        uow.commit()

    dead_row = _row(engine, event.event_id)
    assert dead_row["status"] == "dead"
    assert dead_row["last_error"] == "permanent"

    # 2. Run CLI replay command by event_id
    exit_code = cli.main(
        [
            "outbox",
            "replay",
            "--config",
            str(config_path),
            "--id",
            str(event.event_id),
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    # 3. Assert database row is reset
    replayed_row = _row(engine, event.event_id)
    assert replayed_row["status"] == "pending"
    assert replayed_row["attempts"] == 0
    assert replayed_row["last_error"] is None
    assert replayed_row["locked_until"] is None

    # 4. Outbox worker can now claim and process it
    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        reclaimed = uow.outbox.claim(1)
        assert len(reclaimed) == 1
        assert reclaimed[0].event_id == event.event_id


def test_outbox_replay_dead_row_by_surrogate_row_id(engine: Engine, config_path: Path) -> None:
    clock = SystemClock()
    event = _sample_event()

    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        uow.outbox.enqueue(event)
        uow.commit()

    # Move row to dead status through retry limit
    with engine.begin() as conn:
        conn.execute(
            sqlalchemy.text(
                "update identity_event_outbox "
                "set status = 'dead', attempts = 8, last_error = 'retry_limit' "
                "where event_id = :event_id"
            ),
            {"event_id": event.event_id},
        )

    dead_row = _row(engine, event.event_id)
    row_id = dead_row["id"]

    # Run CLI replay command by surrogate row id
    exit_code = cli.main(
        [
            "outbox",
            "replay",
            "--config",
            str(config_path),
            "--id",
            str(row_id),
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    replayed_row = _row(engine, event.event_id)
    assert replayed_row["status"] == "pending"
    assert replayed_row["attempts"] == 0
    assert replayed_row["last_error"] is None


def test_outbox_replay_non_existent_id_exits_permanent(
    engine: Engine, config_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    missing_id = uuid4()
    exit_code = cli.main(
        [
            "outbox",
            "replay",
            "--config",
            str(config_path),
            "--id",
            str(missing_id),
        ]
    )
    assert exit_code == cli.ExitCode.PERMANENT
    captured = capsysbinary.readouterr()
    err_text = captured.err.decode("utf-8")
    assert "error=permanent" in err_text
    assert "not found" in err_text


def test_outbox_replay_actively_processing_row_fails(
    engine: Engine, config_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    clock = SystemClock()
    event = _sample_event()

    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        uow.outbox.enqueue(event)
        uow.commit()

    # Claim leaves row in 'processing' status with future locked_until
    with PostgresUnitOfWork(engine, clock, source="corp-okta") as uow:
        claimed = uow.outbox.claim(1)
        assert len(claimed) == 1

    processing_row = _row(engine, event.event_id)
    assert processing_row["status"] == "processing"

    exit_code = cli.main(
        [
            "outbox",
            "replay",
            "--config",
            str(config_path),
            "--id",
            str(event.event_id),
        ]
    )
    assert exit_code == cli.ExitCode.PERMANENT
    captured = capsysbinary.readouterr()
    err_text = captured.err.decode("utf-8")
    assert "error=permanent" in err_text
    assert "currently processing" in err_text
