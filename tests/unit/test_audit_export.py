"""Unit tests for the operator CLI subcommand: audit export."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

import identity_lifecycle.main as cli
from identity_lifecycle.application.audit_export import (
    EXPORT_COLUMNS,
    AuditExport,
    AuditExportError,
)
from identity_lifecycle.domain.models import AuditEvent, Person, SourceIdentity
from identity_lifecycle.ports.unit_of_work import AuditEntry
from tests.fixtures.fakes import FakeClock, InMemoryStore, InMemoryUnitOfWork
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.unit

T1 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=UTC)
T3 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _valid_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    cfg_path = tmp_path / "valid_config.yaml"
    cfg_path.write_text(_text(), encoding="utf-8")
    return cfg_path


def _sample_audit_entry(
    *,
    event_id: UUID | None = None,
    occurred_at: datetime = T1,
    actor: str = "corp-okta",
    action: str = "create",
    source: str = "corp-okta",
    person_id: str = "p-100",
    employee_number: str | None = "E100",
    email: str | None = "alice@example.com",
    reason: str = "new_hire",
    decision: str = "granted",
    details: str = "evt-src-100",
) -> AuditEntry:
    return AuditEntry(
        event_id=event_id or uuid4(),
        occurred_at=occurred_at,
        actor=actor,
        action=action,
        source=source,
        person_id=person_id,
        employee_number=employee_number,
        email=email,
        reason=reason,
        decision=decision,
        details=details,
    )


# 1. CLI help and flag parsing


def test_audit_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["audit", "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "export" in captured.out


def test_audit_export_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["audit", "export", "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--from" in captured.out
    assert "--to" in captured.out
    assert "--employee" in captured.out
    assert "--user" in captured.out
    assert "--format" in captured.out
    assert "--ndjson" in captured.out
    assert "--output" in captured.out
    assert "--config" in captured.out
    assert "--log-level" in captured.out


def test_audit_without_subcommand_is_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["audit"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err


def test_audit_export_mutually_exclusive_employee_and_user(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["audit", "export", "--employee", "E1", "--user", "U1"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "not allowed with argument" in captured.err


def test_audit_export_invalid_format_choice(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["audit", "export", "--format", "parquet"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "invalid choice: 'parquet'" in captured.err


# 2. Date parsing and validation


def test_parse_utc_timestamp_iso_formats() -> None:
    ts_z = cli.parse_utc_timestamp("2026-01-15T10:00:00Z")
    assert ts_z == datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)

    ts_offset = cli.parse_utc_timestamp("2026-01-15T12:00:00+02:00")
    assert ts_offset == datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)

    ts_naive = cli.parse_utc_timestamp("2026-01-15T10:00:00")
    assert ts_naive == datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)


def test_parse_utc_timestamp_invalid_raises_audit_export_error() -> None:
    with pytest.raises(AuditExportError) as raised:
        cli.parse_utc_timestamp("not-an-iso-date")
    assert "Invalid ISO-8601 timestamp" in str(raised.value)


def test_audit_export_invalid_from_timestamp_exits_permanent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    exit_code = cli.main(["audit", "export", "--config", str(cfg), "--from", "bad-date"])
    assert exit_code == cli.ExitCode.PERMANENT
    err = capsysbinary.readouterr().err
    assert b"error=permanent" in err
    assert b"Invalid ISO-8601 timestamp" in err


def test_audit_export_inverted_date_range_exits_permanent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(cfg),
            "--from",
            "2026-01-15T12:00:00Z",
            "--to",
            "2026-01-15T10:00:00Z",
        ]
    )
    assert exit_code == cli.ExitCode.PERMANENT
    err = capsysbinary.readouterr().err
    assert b"error=permanent" in err
    assert b"must not be after" in err


# 3. Formatters: CSV, JSON, NDJSON


def test_to_csv_headers_and_rfc4180_compliance() -> None:
    e1 = _sample_audit_entry(
        person_id="p-1",
        employee_number="E101",
        email="user1@example.com",
        reason="highest,precedence",  # includes comma to test quoting
        decision="granted",
        details="src-1",
    )
    e2 = _sample_audit_entry(
        person_id="p-2",
        employee_number=None,
        email=None,
        reason="leaver\nconfirmed",  # includes newline to test multiline quoting
        decision="revoked",
        details="src-2",
    )

    csv_text = AuditExport.to_csv([e1, e2])
    assert csv_text.endswith("\r\n")

    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 2
    assert list(reader[0].keys()) == list(EXPORT_COLUMNS)

    row1 = reader[0]
    assert row1["person_id"] == "p-1"
    assert row1["employee_number"] == "E101"
    assert row1["email"] == "user1@example.com"
    assert row1["reason"] == "highest,precedence"
    assert row1["outcome"] == "granted"
    assert row1["details"] == "src-1"

    row2 = reader[1]
    assert row2["person_id"] == "p-2"
    assert row2["employee_number"] == ""
    assert row2["email"] == ""
    assert row2["reason"] == "leaver\nconfirmed"
    assert row2["outcome"] == "revoked"
    assert row2["details"] == "src-2"


def test_to_json_valid_array_and_keys() -> None:
    e1 = _sample_audit_entry(
        person_id="p-1",
        employee_number="E101",
        email="user1@example.com",
        reason="highest_precedence",
        decision="granted",
        details="src-1",
    )
    json_text = AuditExport.to_json([e1])
    parsed = json.loads(json_text)
    assert isinstance(parsed, list)
    assert len(parsed) == 1

    item = parsed[0]
    assert list(item.keys()) == list(EXPORT_COLUMNS)
    assert item["person_id"] == "p-1"
    assert item["employee_number"] == "E101"
    assert item["outcome"] == "granted"
    assert item["details"] == "src-1"


def test_to_ndjson_line_delimited() -> None:
    e1 = _sample_audit_entry(person_id="p-1")
    e2 = _sample_audit_entry(person_id="p-2")

    ndjson_text = AuditExport.to_ndjson([e1, e2])
    lines = [line for line in ndjson_text.split("\n") if line.strip()]
    assert len(lines) == 2

    obj1 = json.loads(lines[0])
    obj2 = json.loads(lines[1])
    assert obj1["person_id"] == "p-1"
    assert obj2["person_id"] == "p-2"


# 4. Querying and filtering in use case


def test_query_filters_by_date_range() -> None:
    store = InMemoryStore()
    clock = FakeClock(T3)
    ev1 = uuid4()
    ev2 = uuid4()
    ev3 = uuid4()

    store.persons["p-1"] = Person("p-1", "E1", "a@example.com", "Alice", "active")
    store.audit = [
        AuditEvent(ev1, "s1", "corp-okta", "create", "p-1", "granted", "join", T1),
        AuditEvent(ev2, "s2", "corp-okta", "update", "p-1", "granted", "move", T2),
        AuditEvent(ev3, "s3", "corp-okta", "revoke", "p-1", "revoked", "leave", T3),
    ]

    def uow_factory(src: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=src)

    use_case = AuditExport(uow_factory, clock)

    # 1. Query between T1 and T2
    entries_t1_t2 = use_case.query(since=T1, until=T2)
    assert len(entries_t1_t2) == 2
    assert [e.event_id for e in entries_t1_t2] == [ev1, ev2]

    # 2. Query starting from T2
    entries_from_t2 = use_case.query(since=T2)
    assert len(entries_from_t2) == 2
    assert [e.event_id for e in entries_from_t2] == [ev2, ev3]


def test_query_filters_by_employee_number() -> None:
    store = InMemoryStore()
    clock = FakeClock(T3)
    ev1 = uuid4()
    ev2 = uuid4()

    store.persons["p-1"] = Person("p-1", "E100", "a@example.com", "Alice", "active")
    store.persons["p-2"] = Person("p-2", "E200", "b@example.com", "Bob", "active")
    store.audit = [
        AuditEvent(ev1, "s1", "corp-okta", "create", "p-1", "granted", "join", T1),
        AuditEvent(ev2, "s2", "corp-okta", "create", "p-2", "granted", "join", T2),
    ]

    def uow_factory(src: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=src)

    use_case = AuditExport(uow_factory, clock)
    entries = use_case.query(employee_number="E100")
    assert len(entries) == 1
    assert entries[0].person_id == "p-1"
    assert entries[0].employee_number == "E100"


def test_query_filters_by_source_user_id() -> None:
    store = InMemoryStore()
    clock = FakeClock(T3)
    ev1 = uuid4()
    ev2 = uuid4()

    store.persons["p-1"] = Person("p-1", "E100", "a@example.com", "Alice", "active")
    store.persons["p-2"] = Person("p-2", "E200", "b@example.com", "Bob", "active")
    store.identities[("corp-okta", "00uAlice")] = SourceIdentity("corp-okta", "00uAlice", "p-1")
    store.identities[("corp-okta", "00uBob")] = SourceIdentity("corp-okta", "00uBob", "p-2")
    store.audit = [
        AuditEvent(ev1, "s1", "corp-okta", "create", "p-1", "granted", "join", T1),
        AuditEvent(ev2, "s2", "corp-okta", "create", "p-2", "granted", "join", T2),
    ]

    def uow_factory(src: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=src)

    use_case = AuditExport(uow_factory, clock)
    entries = use_case.query(source_user_id="00uBob")
    assert len(entries) == 1
    assert entries[0].person_id == "p-2"
    assert entries[0].employee_number == "E200"


# 5. Export execution and output redirection


def test_export_to_file(tmp_path: Path) -> None:
    store = InMemoryStore()
    clock = FakeClock(T1)
    ev1 = uuid4()
    store.persons["p-1"] = Person("p-1", "E100", "alice@example.com", "Alice", "active")
    store.audit = [AuditEvent(ev1, "s1", "corp-okta", "create", "p-1", "granted", "new_hire", T1)]

    def uow_factory(src: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=src)

    out_file = tmp_path / "exports" / "audit.csv"
    use_case = AuditExport(uow_factory, clock)
    content = use_case.export(format="csv", output=out_file)

    assert out_file.exists()
    assert out_file.read_bytes() == content.encode("utf-8")
    assert "event_id,timestamp,actor,action" in content
    assert "p-1" in content


def test_audit_export_cli_end_to_end_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    store = InMemoryStore()
    clock = FakeClock(T1)
    ev1 = uuid4()
    store.persons["p-1"] = Person("p-1", "E100", "alice@example.com", "Alice", "active")
    store.audit = [AuditEvent(ev1, "s1", "corp-okta", "create", "p-1", "granted", "new_hire", T1)]

    def uow_factory(src: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=src)

    # Inject mock factory for unit test
    original_run = cli._run_audit_export
    monkeypatch.setattr(
        cli,
        "_run_audit_export",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "unit_of_work_factory": uow_factory, "clock": clock}
        ),
    )

    exit_code = cli.main(
        [
            "audit",
            "export",
            "--config",
            str(cfg),
            "--format",
            "csv",
        ]
    )
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert b"event_id,timestamp,actor,action" in captured.out
    assert b"alice@example.com" in captured.out
    assert str(ev1).encode() in captured.out


def test_audit_export_cli_missing_config_exits_config_error(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    exit_code = cli.main(["audit", "export", "--config", "nonexistent-config.yaml"])
    assert exit_code == cli.ExitCode.CONFIG
    err = capsysbinary.readouterr().err
    assert b"identity-lifecycle:" in err
    assert b"unreadable" in err
