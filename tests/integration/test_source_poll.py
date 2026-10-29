"""Integration tests for operator CLI subcommand: source poll."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.config import Config, load_config
from tests.fixtures.ad import ldap_responses
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_client
from tests.fixtures.okta_http import FakeOktaHTTP, user
from tests.unit.test_config_loader import ENV, EXAMPLE

pytestmark = pytest.mark.integration

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _setup_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    cfg_file = tmp_path / "integration_config.yaml"
    cfg_file.write_text(text, encoding="utf-8")
    return cfg_file


def test_source_poll_okta_once_enqueues_events_and_advances_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    migrated_database: str,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.setenv("DATABASE_URL", migrated_database)

    config: Config = load_config(EXAMPLE, ENV)
    source_config = next(s for s in config.identity_sources if s.source_name == "corp-okta")
    assert source_config.okta is not None

    server = FakeOktaHTTP()
    server.group_id = source_config.okta.group_id
    server.add_user(
        user("00u-alice", employee_number="E100", email="alice@example.com"),
        member=True,
    )

    config_text = EXAMPLE.read_text(encoding="utf-8")
    cfg_file = _setup_config_file(tmp_path, monkeypatch, config_text)

    original_run = cli._run_source_poll
    monkeypatch.setattr(
        cli,
        "_run_source_poll",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "okta_client_factory": lambda _cfg: server.oauth_client()}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "poll",
            "--config",
            str(cfg_file),
            "--source",
            "corp-okta",
            "--once",
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    out = capsysbinary.readouterr().out.decode()
    assert "Polled 1 source(s):" in out
    assert "[OK] corp-okta: enqueued" in out

    # Verify directly against PostgreSQL that the cursor and snapshot were committed
    engine = build_engine(migrated_database)
    try:
        with engine.connect() as conn:
            cursor_count = conn.execute(
                sqlalchemy.text("select count(*) from source_cursors where source = 'corp-okta'")
            ).scalar_one()
            assert cursor_count >= 1

            snapshot_count = conn.execute(
                sqlalchemy.text(
                    "select count(*) from source_group_members where source = 'corp-okta'"
                )
            ).scalar_one()
            assert snapshot_count >= 1
    finally:
        engine.dispose()


def test_source_poll_ad_once_enqueues_events_and_advances_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    migrated_database: str,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.setenv("DATABASE_URL", migrated_database)

    config: Config = load_config(EXAMPLE, ENV)
    source_config = next(s for s in config.identity_sources if s.source_name == "corp-ad")
    assert source_config.ad is not None

    alice_entry = ldap_responses.alice_entry()
    alice_dn = f"CN=Alice Doe,{source_config.ad.search_base}"
    alice_entry["dn"] = alice_dn
    group_entry = ldap_responses.search_res_entry(
        source_config.ad.group_dn,
        {
            "objectClass": [b"top", b"group"],
            "cn": [b"AI-Platform-Users"],
            "distinguishedName": [source_config.ad.group_dn.encode("utf-8")],
            "objectGUID": [ldap_responses.GROUP_GUID],
            "uSNChanged": [b"25000"],
            "whenChanged": [b"20260101120000.0Z"],
            "member": [alice_dn.encode("utf-8")],
        },
    )
    fake_conn = FakeADConnection(
        group_entry=group_entry,
        users=[alice_entry],
    )
    fake_conn.group_dn = source_config.ad.group_dn

    config_text = EXAMPLE.read_text(encoding="utf-8")
    cfg_file = _setup_config_file(tmp_path, monkeypatch, config_text)

    original_run = cli._run_source_poll
    monkeypatch.setattr(
        cli,
        "_run_source_poll",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "ad_client_factory": lambda _cfg: create_fake_ad_client(fake_conn)}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "poll",
            "--config",
            str(cfg_file),
            "--source",
            "corp-ad",
            "--once",
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    out = capsysbinary.readouterr().out.decode()
    assert "Polled 1 source(s):" in out
    assert "[OK] corp-ad: enqueued" in out

    engine = build_engine(migrated_database)
    try:
        with engine.connect() as conn:
            cursor_count = conn.execute(
                sqlalchemy.text("select count(*) from source_cursors where source = 'corp-ad'")
            ).scalar_one()
            assert cursor_count >= 1
    finally:
        engine.dispose()


def test_source_poll_unknown_source_fails_with_exit_4(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    migrated_database: str,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.setenv("DATABASE_URL", migrated_database)

    config_text = EXAMPLE.read_text(encoding="utf-8")
    cfg_file = _setup_config_file(tmp_path, monkeypatch, config_text)

    exit_code = cli.main(
        [
            "source",
            "poll",
            "--config",
            str(cfg_file),
            "--source",
            "nonexistent-source",
            "--once",
        ]
    )

    assert exit_code == cli.ExitCode.PERMANENT
    err = capsysbinary.readouterr().err.decode()
    assert "nonexistent-source" in err
