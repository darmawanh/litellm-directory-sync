"""Integration tests for operator CLI subcommand: audit export."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.application.audit_export import EXPORT_COLUMNS
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.integration

T1 = datetime(2026, 1, 10, 10, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
T3 = datetime(2026, 1, 20, 14, 0, 0, tzinfo=UTC)


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


def _insert_fixture_data(engine: Engine) -> dict[str, str]:
    ev1 = str(uuid4())
    ev2 = str(uuid4())
    ev3 = str(uuid4())

    with engine.begin() as conn:
        # 1. Insert persons
        conn.execute(
            sqlalchemy.text(
                "insert into persons (person_id, employee_number, email, display_name, status) "
                "values (:pid, :emp, :email, :name, 'active')"
            ),
            [
                {
                    "pid": "person-1",
                    "emp": "E-1001",
                    "email": "alice@example.com",
                    "name": "Alice Smith",
                },
                {
                    "pid": "person-2",
                    "emp": "E-2002",
                    "email": "bob@example.com",
                    "name": "Bob Jones",
                },
            ],
        )

        # 2. Insert source identity links
        conn.execute(
            sqlalchemy.text(
                "insert into source_identities (source, source_user_id, person_id) "
                "values (:source, :source_user_id, :person_id)"
            ),
            [
                {
                    "source": "corp-okta",
                    "source_user_id": "00uAlice123",
                    "person_id": "person-1",
                },
                {
                    "source": "corp-okta",
                    "source_user_id": "00uBob456",
                    "person_id": "person-2",
                },
            ],
        )

        # 3. Insert audit events across timestamps
        conn.execute(
            sqlalchemy.text(
                "insert into audit_events "
                "(event_id, source_event_id, source, actor, action, target, "
                "decision, reason, occurred_at) "
                "values (:event_id, :source_event_id, :source, :actor, :action, "
                ":target, :decision, :reason, :occurred_at)"
            ),
            [
                {
                    "event_id": ev1,
                    "source_event_id": "okta-evt-1",
                    "source": "corp-okta",
                    "actor": "corp-okta",
                    "action": "create",
                    "target": "person-1",
                    "decision": "granted",
                    "reason": "new_hire",
                    "occurred_at": T1,
                },
                {
                    "event_id": ev2,
                    "source_event_id": "okta-evt-2",
                    "source": "corp-okta",
                    "actor": "corp-okta",
                    "action": "update",
                    "target": "person-1",
                    "decision": "granted",
                    "reason": "role_change",
                    "occurred_at": T2,
                },
                {
                    "event_id": ev3,
                    "source_event_id": "okta-evt-3",
                    "source": "corp-okta",
                    "actor": "corp-okta",
                    "action": "create",
                    "target": "person-2",
                    "decision": "granted",
                    "reason": "new_hire",
                    "occurred_at": T3,
                },
            ],
        )
    return {"ev1": ev1, "ev2": ev2, "ev3": ev3}


def test_audit_export_date_range_against_postgres(
    engine: Engine,
    config_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    events = _insert_fixture_data(engine)

    # Query range covering T2 only (2026-01-14 to 2026-01-16)
    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(config_path),
            "--from",
            "2026-01-14T00:00:00Z",
            "--to",
            "2026-01-16T00:00:00Z",
            "--format",
            "csv",
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    assert captured.err == b""
    csv_text = captured.out.decode("utf-8")
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 1
    row = reader[0]
    assert row["event_id"] == events["ev2"]
    assert row["person_id"] == "person-1"
    assert row["employee_number"] == "E-1001"
    assert row["email"] == "alice@example.com"
    assert row["reason"] == "role_change"
    assert row["outcome"] == "granted"
    assert row["details"] == "okta-evt-2"


def test_audit_export_employee_filter_against_postgres(
    engine: Engine,
    config_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    events = _insert_fixture_data(engine)

    # Filter by employee E-2002 (Bob)
    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(config_path),
            "--employee",
            "E-2002",
            "--format",
            "csv",
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    csv_text = captured.out.decode("utf-8")
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 1
    row = reader[0]
    assert row["event_id"] == events["ev3"]
    assert row["person_id"] == "person-2"
    assert row["employee_number"] == "E-2002"
    assert row["email"] == "bob@example.com"


def test_audit_export_user_filter_against_postgres(
    engine: Engine,
    config_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    events = _insert_fixture_data(engine)

    # Filter by source user ID 00uAlice123
    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(config_path),
            "--user",
            "00uAlice123",
            "--format",
            "csv",
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    csv_text = captured.out.decode("utf-8")
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 2
    assert [r["event_id"] for r in reader] == [events["ev1"], events["ev2"]]


def test_audit_export_json_format_against_postgres(
    engine: Engine,
    config_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    events = _insert_fixture_data(engine)

    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(config_path),
            "--employee",
            "E-2002",
            "--format",
            "json",
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    json_text = captured.out.decode("utf-8")
    parsed = json.loads(json_text)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    item = parsed[0]
    assert item["event_id"] == events["ev3"]
    assert item["person_id"] == "person-2"
    assert item["employee_number"] == "E-2002"
    assert item["outcome"] == "granted"
    assert item["details"] == "okta-evt-3"
    assert list(item.keys()) == list(EXPORT_COLUMNS)


def test_audit_export_to_file_against_postgres(
    engine: Engine,
    config_path: Path,
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _insert_fixture_data(engine)
    out_file = tmp_path / "reports" / "audit_report.csv"

    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(config_path),
            "--format",
            "csv",
            "--output",
            str(out_file),
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS
    assert capsysbinary.readouterr().out == b""
    assert out_file.exists()

    reader = list(csv.DictReader(io.StringIO(out_file.read_bytes().decode("utf-8"))))
    assert len(reader) == 3
