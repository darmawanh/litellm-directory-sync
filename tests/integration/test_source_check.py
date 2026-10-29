"""Integration tests for operator CLI subcommand: source check."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

import identity_lifecycle.main as cli
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


def test_source_check_okta_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
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

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "okta_client_factory": lambda _cfg: server.oauth_client()}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg_file),
            "--source",
            "corp-okta",
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert "Checked 1 source(s):" in stdout_text
    assert "[OK] corp-okta:" in stdout_text
    assert "1 member(s)" in stdout_text


def test_source_check_ad_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
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

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args,
            **{
                **kwargs,
                "ad_client_factory": lambda _cfg: create_fake_ad_client(fake_conn),
            },
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg_file),
            "--source",
            "corp-ad",
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert "Checked 1 source(s):" in stdout_text
    assert "[OK] corp-ad:" in stdout_text
    assert "1 member(s)" in stdout_text


def test_source_check_all_enabled_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    config: Config = load_config(EXAMPLE, ENV)
    okta_cfg = next(s for s in config.identity_sources if s.source_name == "corp-okta").okta
    assert okta_cfg is not None
    ad_cfg = next(s for s in config.identity_sources if s.source_name == "corp-ad").ad
    assert ad_cfg is not None

    # Okta setup
    server = FakeOktaHTTP()
    server.group_id = okta_cfg.group_id
    server.add_user(
        user("00u-alice", employee_number="E100", email="alice@example.com"),
        member=True,
    )

    # AD setup
    alice_entry = ldap_responses.alice_entry()
    alice_dn = f"CN=Alice Doe,{ad_cfg.search_base}"
    alice_entry["dn"] = alice_dn
    group_entry = ldap_responses.search_res_entry(
        ad_cfg.group_dn,
        {
            "objectClass": [b"top", b"group"],
            "cn": [b"AI-Platform-Users"],
            "distinguishedName": [ad_cfg.group_dn.encode("utf-8")],
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
    fake_conn.group_dn = ad_cfg.group_dn

    config_text = EXAMPLE.read_text(encoding="utf-8")
    cfg_file = _setup_config_file(tmp_path, monkeypatch, config_text)

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args,
            **{
                **kwargs,
                "okta_client_factory": lambda _cfg: server.oauth_client(),
                "ad_client_factory": lambda _cfg: create_fake_ad_client(fake_conn),
            },
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg_file),
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert "Checked 2 source(s):" in stdout_text
    assert "[OK] corp-ad:" in stdout_text
    assert "[OK] corp-okta:" in stdout_text
