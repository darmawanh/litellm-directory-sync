"""Unit tests for the operator CLI subcommands: config validate, reconcile, sync."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import identity_lifecycle.main as cli
from identity_lifecycle.ports.identity_source import IdentityUser
from tests.fixtures.fakes import (
    FakeClock,
    FakeGateway,
    FakeIdentitySource,
    InMemoryStore,
    InMemoryUnitOfWork,
)
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.unit


def _valid_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    cfg_path = tmp_path / "valid_config.yaml"
    cfg_path.write_text(_text(), encoding="utf-8")
    return cfg_path


# 1. config validate


def test_config_validate_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    exit_code = cli.main(["config", "validate", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert b"Configuration is valid:" in captured.out
    assert str(cfg_path).encode() in captured.out


def test_config_validate_missing_env_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("OKTA_CLIENT_ID", raising=False)
    cfg_path = tmp_path / "missing_env.yaml"
    cfg_path.write_text(_text(), encoding="utf-8")

    exit_code = cli.main(["config", "validate", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.CONFIG

    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert b"identity-lifecycle:" in captured.err
    assert b"OKTA_CLIENT_ID" in captured.err


def test_config_validate_nonexistent_file(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    exit_code = cli.main(["config", "validate", "--config", "nonexistent-config-file.yaml"])
    assert exit_code == cli.ExitCode.CONFIG

    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert b"identity-lifecycle:" in captured.err
    assert b"unreadable" in captured.err


def test_config_validate_invalid_yaml_syntax(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("invalid:\n  - yaml: [unclosed", encoding="utf-8")

    exit_code = cli.main(["config", "validate", "--config", str(bad_cfg)])
    assert exit_code == cli.ExitCode.CONFIG

    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert b"identity-lifecycle:" in captured.err


# 2. reconcile


def test_reconcile_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["reconcile", "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--config" in captured.out
    assert "--log-level" in captured.out
    assert "--dry-run" in captured.out


def test_reconcile_executes_and_prints_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source="corp-okta",
        users={
            "user-1": IdentityUser(
                source_user_id="user-1",
                employee_number="E1001",
                email="u1@example.com",
                display_name="User One",
                enabled=True,
            )
        },
        groups={"00gEXAMPLE0000000000": ("user-1",)},
    )
    store = InMemoryStore()
    clock = FakeClock()

    def uow_factory(source: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=source)

    monkeypatch.setattr(cli, "build_engine", lambda _url: MagicMock())
    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({"corp-okta": fake_source}, ()),
    )

    exit_code = cli._run_reconcile(
        cfg_path,
        log_level="INFO",
        dry_run=False,
        gateway_factory=lambda _c: fake_gateway,
        engine_factory=lambda _u: MagicMock(),
        clock=clock,
    )
    assert exit_code == cli.ExitCode.SUCCESS


def test_reconcile_main_command_stdout_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source="corp-okta",
        users={
            "user-1": IdentityUser(
                source_user_id="user-1",
                employee_number="E1001",
                email="u1@example.com",
                display_name="User One",
                enabled=True,
            )
        },
        groups={"00gEXAMPLE0000000000": ("user-1",)},
    )

    store = InMemoryStore()
    clock = FakeClock()

    monkeypatch.setattr(
        cli,
        "PostgresUnitOfWork",
        lambda _engine, _clock, source: InMemoryUnitOfWork(store, clock, source=source),
    )
    monkeypatch.setattr(cli, "build_engine", lambda _url: MagicMock())
    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({"corp-okta": fake_source}, ()),
    )

    exit_code = cli.main(["reconcile", "--dry-run", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    assert b"Reconciliation completed (dry_run=True):" in captured.out
    assert b"Drifts detected:" in captured.out
    assert b"Misses recorded:" in captured.out
    assert b"Events enqueued:" in captured.out


# 3. sync


def test_sync_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["sync", "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--employee" in captured.out
    assert "--user" in captured.out
    assert "--config" in captured.out


def test_sync_requires_one_of_employee_or_user(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["sync"])
    assert raised.value.code == 2

    with pytest.raises(SystemExit) as raised:
        cli.main(["sync", "--employee", "E1", "--user", "u1"])
    assert raised.value.code == 2


def test_sync_by_employee_number_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source="corp-okta",
        users={
            "user-1": IdentityUser(
                source_user_id="user-1",
                employee_number="E1001",
                email="u1@example.com",
                display_name="User One",
                enabled=True,
            )
        },
        groups={"00gEXAMPLE0000000000": ("user-1",)},
    )
    store = InMemoryStore()
    clock = FakeClock()

    monkeypatch.setattr(
        cli,
        "PostgresUnitOfWork",
        lambda _engine, _clock, source: InMemoryUnitOfWork(store, clock, source=source),
    )
    monkeypatch.setattr(cli, "build_engine", lambda _url: MagicMock())
    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({"corp-okta": fake_source}, ()),
    )

    exit_code = cli.main(["sync", "--employee", "E1001", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    assert b"Manual sync completed for employee E1001" in captured.out
    assert b"Event enqueued: group.member_added" in captured.out
    assert b"Decision outcome: granted" in captured.out
    assert captured.err == b""


def test_sync_by_user_id_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source="corp-okta",
        users={
            "user-1": IdentityUser(
                source_user_id="user-1",
                employee_number="E1001",
                email="u1@example.com",
                display_name="User One",
                enabled=True,
            )
        },
        groups={"00gEXAMPLE0000000000": ("user-1",)},
    )
    store = InMemoryStore()
    clock = FakeClock()

    monkeypatch.setattr(
        cli,
        "PostgresUnitOfWork",
        lambda _engine, _clock, source: InMemoryUnitOfWork(store, clock, source=source),
    )
    monkeypatch.setattr(cli, "build_engine", lambda _url: MagicMock())
    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({"corp-okta": fake_source}, ()),
    )

    exit_code = cli.main(["sync", "--user", "user-1", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.SUCCESS

    captured = capsysbinary.readouterr()
    assert b"Manual sync completed for user user-1" in captured.out
    assert b"Event enqueued: group.member_added" in captured.out
    assert captured.err == b""


def test_sync_not_found_returns_permanent_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source="corp-okta",
        users={},
        groups={},
    )
    store = InMemoryStore()
    clock = FakeClock()

    monkeypatch.setattr(
        cli,
        "PostgresUnitOfWork",
        lambda _engine, _clock, source: InMemoryUnitOfWork(store, clock, source=source),
    )
    monkeypatch.setattr(cli, "build_engine", lambda _url: MagicMock())
    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({"corp-okta": fake_source}, ()),
    )

    exit_code = cli.main(["sync", "--employee", "NONEXISTENT", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.PERMANENT

    captured = capsysbinary.readouterr()
    assert b"identity-lifecycle: error=permanent type=NotFoundError" in captured.err
    assert b"no person found matching employee_number='NONEXISTENT'" in captured.err


def test_sync_ambiguous_link_returns_permanent_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg_path = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_gateway = FakeGateway()
    fake_source = FakeIdentitySource(
        source="corp-okta",
        users={
            "user-1": IdentityUser(
                source_user_id="user-1",
                employee_number="DUP100",
                email="u1@example.com",
                display_name="User One",
                enabled=True,
            ),
            "user-2": IdentityUser(
                source_user_id="user-2",
                employee_number="DUP100",
                email="u2@example.com",
                display_name="User Two",
                enabled=True,
            ),
        },
        groups={},
    )
    store = InMemoryStore()
    clock = FakeClock()

    monkeypatch.setattr(
        cli,
        "PostgresUnitOfWork",
        lambda _engine, _clock, source: InMemoryUnitOfWork(store, clock, source=source),
    )
    monkeypatch.setattr(cli, "build_engine", lambda _url: MagicMock())
    monkeypatch.setattr(cli, "build_gateway", lambda _cfg: fake_gateway)
    monkeypatch.setattr(
        cli,
        "_build_sources",
        lambda *args, **kwargs: ({"corp-okta": fake_source}, ()),
    )

    exit_code = cli.main(["sync", "--employee", "DUP100", "--config", str(cfg_path)])
    assert exit_code == cli.ExitCode.PERMANENT

    captured = capsysbinary.readouterr()
    assert b"identity-lifecycle: error=permanent type=AmbiguousLinkError" in captured.err
    assert b"ambiguous employee_number='DUP100'" in captured.err
