"""Integration tests for operator CLI subcommands (reconcile, sync)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.ports.identity_source import IdentityUser
from tests.fixtures.fakes import FakeGateway, FakeIdentitySource
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.integration

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SOURCE = "corp-okta"
MAPPED_GROUP = "00gEXAMPLE0000000000"


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


def test_reconcile_command_dry_run_and_live_against_postgres(
    engine: Engine,
    config_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source=SOURCE,
        users={
            "user-1": IdentityUser(
                source_user_id="user-1",
                employee_number="E9001",
                email="user1@example.com",
                display_name="User One",
                enabled=True,
            )
        },
        groups={MAPPED_GROUP: ("user-1",)},
    )

    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({SOURCE: fake_source}, ()),
    )

    # 1. Reconcile with --dry-run: detects drift but commits no rows to postgres outbox
    dry_code = cli.main(["reconcile", "--dry-run", "--config", str(config_path)])
    assert dry_code == cli.ExitCode.SUCCESS

    dry_out = capsysbinary.readouterr().out
    assert b"Reconciliation completed (dry_run=True):" in dry_out
    assert b"Drifts detected: 1" in dry_out
    assert b"Events enqueued: 1" in dry_out

    with engine.connect() as conn:
        count = conn.execute(sqlalchemy.text("select count(*) from identity_event_outbox")).scalar()
        assert count == 0

    # 2. Live reconcile: commits corrective outbox event to postgres
    live_code = cli.main(["reconcile", "--config", str(config_path)])
    assert live_code == cli.ExitCode.SUCCESS

    live_out = capsysbinary.readouterr().out
    assert b"Reconciliation completed (dry_run=False):" in live_out
    assert b"Drifts detected: 1" in live_out

    with engine.connect() as conn:
        rows = list(
            conn.execute(
                sqlalchemy.text("select status, source, payload from identity_event_outbox")
            ).mappings()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row["status"] == "pending"
        assert row["source"] == SOURCE
        payload = row["payload"]
        assert payload["type"] == "group.member_added"
        assert payload["person"]["source_user_id"] == "user-1"


def test_sync_command_employee_and_user_against_postgres(
    engine: Engine,
    config_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source=SOURCE,
        users={
            "user-entitled": IdentityUser(
                source_user_id="user-entitled",
                employee_number="E9002",
                email="user2@example.com",
                display_name="User Two",
                enabled=True,
            ),
            "user-disabled": IdentityUser(
                source_user_id="user-disabled",
                employee_number="E9003",
                email="user3@example.com",
                display_name="User Three",
                enabled=False,
            ),
        },
        groups={MAPPED_GROUP: ("user-entitled",)},
    )

    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({SOURCE: fake_source}, ()),
    )

    # 1. Sync by employee number: commits group.member_added
    emp_code = cli.main(["sync", "--employee", "E9002", "--config", str(config_path)])
    assert emp_code == cli.ExitCode.SUCCESS

    emp_out = capsysbinary.readouterr().out
    assert b"Manual sync completed for employee E9002" in emp_out
    assert b"Event enqueued: group.member_added" in emp_out

    with engine.connect() as conn:
        rows = list(
            conn.execute(
                sqlalchemy.text("select status, source, payload from identity_event_outbox")
            ).mappings()
        )
        assert len(rows) == 1
        assert rows[0]["payload"]["type"] == "group.member_added"
        assert rows[0]["payload"]["person"]["source_user_id"] == "user-entitled"

    # 2. Sync by source user ID for disabled user: commits user.disabled
    usr_code = cli.main(["sync", "--user", "user-disabled", "--config", str(config_path)])
    assert usr_code == cli.ExitCode.SUCCESS

    usr_out = capsysbinary.readouterr().out
    assert b"Manual sync completed for user user-disabled" in usr_out
    assert b"Event enqueued: user.disabled" in usr_out

    with engine.connect() as conn:
        rows = list(
            conn.execute(
                sqlalchemy.text(
                    "select status, source, payload from identity_event_outbox "
                    "where source = :src order by created_at"
                ),
                {"src": SOURCE},
            ).mappings()
        )
        assert len(rows) == 2
        assert rows[1]["payload"]["type"] == "user.disabled"
        assert rows[1]["payload"]["person"]["source_user_id"] == "user-disabled"
