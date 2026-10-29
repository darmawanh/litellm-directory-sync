"""Unit tests for the source check use case and operator CLI command."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

import identity_lifecycle.main as cli
from identity_lifecycle.application.source_check import (
    SourceCheck,
    SourceNotFoundError,
)
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.ports.identity_source import (
    Capabilities,
    EventCondition,
    IdentityGroup,
    IdentitySource,
    IdentityUser,
    Page,
)
from tests.fixtures.fakes import FakeClock
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.unit


def _valid_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    cfg_path = tmp_path / "valid_config.yaml"
    cfg_path.write_text(_text(), encoding="utf-8")
    return cfg_path


class FakeIdentitySource(IdentitySource):
    """Test double for IdentitySource with customizable outcomes."""

    def __init__(
        self,
        name: str,
        *,
        groups: tuple[IdentityGroup, ...] = (),
        members: tuple[IdentityUser, ...] = (),
        fail_with: Exception | None = None,
    ) -> None:
        self._name = name
        self._groups = groups
        self._members = members
        self._fail_with = fail_with
        self.closed = False

    def name(self) -> str:
        return self._name

    def capabilities(self) -> Capabilities:
        return Capabilities(can_page=True, can_filter=True, has_change_feed=True)

    def list_groups(self, cursor: str | None = None) -> Page[IdentityGroup]:
        if self._fail_with:
            raise self._fail_with
        return Page(items=self._groups, next_cursor=None)

    def get_group_members(self, group_id: str, cursor: str | None = None) -> Page[IdentityUser]:
        if self._fail_with:
            raise self._fail_with
        return Page(items=self._members, next_cursor=None)

    def list_users(self, cursor: str | None = None) -> Page[IdentityUser]:
        return Page(items=self._members, next_cursor=None)

    def get_user(self, source_user_id: str) -> IdentityUser | None:
        return None

    def poll_changes(self, cursor: str | None = None) -> Page[CanonicalEvent | EventCondition]:
        return Page(items=(), next_cursor=None)

    def normalize(self, raw_event: Mapping[str, object]) -> CanonicalEvent | EventCondition:
        raise NotImplementedError

    def close(self) -> None:
        self.closed = True


def test_source_check_single_source_success() -> None:
    clock = FakeClock()
    grp = IdentityGroup(source_group_id="grp-1", name="AI-Platform-Users")
    usr = IdentityUser(
        source_user_id="u-1",
        employee_number="E100",
        email="alice@example.com",
        display_name="Alice",
        enabled=True,
    )
    src = FakeIdentitySource("corp-okta", groups=(grp,), members=(usr,))

    use_case = SourceCheck({"corp-okta": src}, clock)
    results = use_case.check("corp-okta")

    assert len(results) == 1
    res = results[0]
    assert res.source_name == "corp-okta"
    assert res.status == "ok"
    assert res.group_name == "AI-Platform-Users"
    assert res.group_id == "grp-1"
    assert res.member_count == 1
    assert res.duration_ms >= 0.0
    assert res.error is None


def test_source_check_all_sources() -> None:
    clock = FakeClock()
    src1 = FakeIdentitySource("corp-okta", groups=(IdentityGroup("g1", "OktaGroup"),))
    src2 = FakeIdentitySource("corp-ad", groups=(IdentityGroup("g2", "ADGroup"),))

    use_case = SourceCheck({"corp-okta": src1, "corp-ad": src2}, clock)
    results = use_case.check(None)

    assert len(results) == 2
    # Deterministic sorted order
    assert [r.source_name for r in results] == ["corp-ad", "corp-okta"]
    assert all(r.status == "ok" for r in results)


def test_source_check_unknown_source_raises_not_found() -> None:
    clock = FakeClock()
    src = FakeIdentitySource("corp-okta")
    use_case = SourceCheck({"corp-okta": src}, clock)

    with pytest.raises(SourceNotFoundError, match="Identity source 'missing' not found"):
        use_case.check("missing")


def test_source_check_records_permanent_failure() -> None:
    clock = FakeClock()
    error = PermanentError("401 Unauthorized: invalid client assertion")
    src = FakeIdentitySource("corp-okta", fail_with=error)

    use_case = SourceCheck({"corp-okta": src}, clock)
    results = use_case.check("corp-okta")

    assert len(results) == 1
    res = results[0]
    assert res.status == "failed"
    assert "401 Unauthorized" in str(res.error)
    assert res.exception is error


def test_source_check_records_retryable_failure() -> None:
    clock = FakeClock()
    error = RetryableError("503 Service Unavailable: connection timed out")
    src = FakeIdentitySource("corp-okta", fail_with=error)

    use_case = SourceCheck({"corp-okta": src}, clock)
    results = use_case.check("corp-okta")

    assert len(results) == 1
    res = results[0]
    assert res.status == "failed"
    assert "503 Service Unavailable" in str(res.error)
    assert res.exception is error


def test_source_check_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["source", "check", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "--source" in captured.out
    assert "--config" in captured.out
    assert "--log-level" in captured.out


def test_source_check_cli_success_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    clock = FakeClock()
    grp = IdentityGroup(source_group_id="00g-ai", name="AI-Platform-Users")
    usr = IdentityUser(
        source_user_id="u-1",
        employee_number="E100",
        email="user@example.com",
        display_name="Test User",
        enabled=True,
    )
    src = FakeIdentitySource("corp-okta", groups=(grp,), members=(usr,))

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "sources_override": {"corp-okta": src}, "clock": clock}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg),
            "--source",
            "corp-okta",
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    assert src.closed is True
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert "Checked 1 source(s):" in stdout_text
    assert "[OK] corp-okta: group='AI-Platform-Users' (id='00g-ai'), 1 member(s)" in stdout_text


def test_source_check_cli_permanent_failure_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    clock = FakeClock()
    src = FakeIdentitySource(
        "corp-okta", fail_with=PermanentError("Invalid Okta client credentials")
    )

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "sources_override": {"corp-okta": src}, "clock": clock}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg),
            "--source",
            "corp-okta",
        ]
    )

    assert exit_code == cli.ExitCode.PERMANENT
    assert src.closed is True
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert "[FAILED] corp-okta: Invalid Okta client credentials" in stdout_text
    stderr_text = captured.err.decode("utf-8")
    assert "error=permanent" in stderr_text


def test_source_check_cli_retryable_failure_exits_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    clock = FakeClock()
    src = FakeIdentitySource(
        "corp-ad", fail_with=RetryableError("LDAPS server connection timed out")
    )

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "sources_override": {"corp-ad": src}, "clock": clock}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg),
            "--source",
            "corp-ad",
        ]
    )

    assert exit_code == cli.ExitCode.RETRYABLE
    assert src.closed is True
    captured = capsysbinary.readouterr()
    stdout_text = captured.out.decode("utf-8")
    assert "[FAILED] corp-ad: LDAPS server connection timed out" in stdout_text
    stderr_text = captured.err.decode("utf-8")
    assert "error=retryable" in stderr_text


def test_source_check_cli_unknown_source_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    cfg = _valid_config_file(tmp_path, monkeypatch)
    clock = FakeClock()
    src = FakeIdentitySource("corp-okta")

    original_run = cli._run_source_check
    monkeypatch.setattr(
        cli,
        "_run_source_check",
        lambda *args, **kwargs: original_run(
            *args, **{**kwargs, "sources_override": {"corp-okta": src}, "clock": clock}
        ),
    )

    exit_code = cli.main(
        [
            "source",
            "check",
            "--config",
            str(cfg),
            "--source",
            "unknown-source",
        ]
    )

    assert exit_code == cli.ExitCode.PERMANENT
    captured = capsysbinary.readouterr()
    stderr_text = captured.err.decode("utf-8")
    assert "error=permanent" in stderr_text
    assert "unknown-source" in stderr_text
