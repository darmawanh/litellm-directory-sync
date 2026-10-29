"""Unit tests for the source poll use case and CLI subcommand."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from identity_lifecycle import main as cli
from identity_lifecycle.application.source_poll import (
    SourceNotFoundError,
    SourcePoll,
)
from identity_lifecycle.domain.errors import RetryableError
from tests.fixtures.fakes import FakeClock
from tests.unit.test_config_loader import ENV, _text

pytestmark = pytest.mark.unit


class FakePoller:
    def __init__(self, events_to_enqueue: int = 1, pages: int = 1) -> None:
        self.calls = 0
        self._events = events_to_enqueue
        self._total_pages = pages

    @property
    def has_more_pages(self) -> bool:
        return self.calls < self._total_pages

    def poll_once(self) -> int:
        self.calls += 1
        return self._events


class FailingPoller:
    def __init__(self, exception: Exception) -> None:
        self._exception = exception

    def poll_once(self) -> int:
        raise self._exception


def _valid_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    cfg_path = tmp_path / "valid_config.yaml"
    cfg_path.write_text(_text(), encoding="utf-8")
    return cfg_path


def test_use_case_poll_single_source_success() -> None:
    poller = FakePoller(events_to_enqueue=2)
    pollers = {"corp-okta": poller, "corp-ad": FakePoller(0)}
    use_case = SourcePoll(pollers, FakeClock())

    results = use_case.poll_once("corp-okta")
    assert len(results) == 1
    assert results[0].source_name == "corp-okta"
    assert results[0].enqueued_count == 2
    assert results[0].error is None
    assert poller.calls == 1


def test_use_case_poll_all_sources_sorted_order() -> None:
    okta_poller = FakePoller(events_to_enqueue=3)
    ad_poller = FakePoller(events_to_enqueue=1)
    pollers = {"corp-okta": okta_poller, "corp-ad": ad_poller}
    use_case = SourcePoll(pollers, FakeClock())

    results = use_case.poll_once()
    assert len(results) == 2
    assert results[0].source_name == "corp-ad"
    assert results[0].enqueued_count == 1
    assert results[1].source_name == "corp-okta"
    assert results[1].enqueued_count == 3


def test_use_case_drains_multi_page_log_stream() -> None:
    multi_page_poller = FakePoller(events_to_enqueue=2, pages=3)
    pollers = {"corp-okta": multi_page_poller}
    use_case = SourcePoll(pollers, FakeClock())

    results = use_case.poll_once("corp-okta")
    assert len(results) == 1
    # 3 pages * 2 events = 6 events enqueued
    assert results[0].enqueued_count == 6
    assert multi_page_poller.calls == 3


def test_use_case_unknown_source_raises_not_found() -> None:
    pollers = {"corp-okta": FakePoller(1)}
    use_case = SourcePoll(pollers, FakeClock())

    with pytest.raises(SourceNotFoundError) as exc_info:
        use_case.poll_once("unknown-source")
    assert "unknown-source" in str(exc_info.value)


def test_use_case_records_poller_failure() -> None:
    failing = FailingPoller(RetryableError("Transient timeout connecting to directory"))
    pollers = {"corp-ad": failing}
    use_case = SourcePoll(pollers, FakeClock())

    results = use_case.poll_once("corp-ad")
    assert len(results) == 1
    assert results[0].source_name == "corp-ad"
    assert results[0].enqueued_count == 0
    assert results[0].error == "Transient timeout connecting to directory"
    assert isinstance(results[0].exception, RetryableError)


def test_cli_run_source_poll_once_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_file = _valid_config_file(tmp_path, monkeypatch)
    pollers = {
        "corp-okta": FakePoller(events_to_enqueue=2),
        "corp-ad": FakePoller(events_to_enqueue=0),
    }

    exit_code = cli._run_source_poll(
        config_file,
        "INFO",
        source_name="corp-okta",
        once=True,
        clock=FakeClock(),
        pollers_override=pollers,
    )

    assert exit_code == cli.ExitCode.SUCCESS
    out = capsys.readouterr().out
    assert "Polled 1 source(s):" in out
    assert "[OK] corp-okta: enqueued 2 event(s)" in out
    assert "Total enqueued: 2 event(s)" in out


def test_cli_run_source_poll_once_all_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_file = _valid_config_file(tmp_path, monkeypatch)
    pollers = {
        "corp-okta": FakePoller(events_to_enqueue=1),
        "corp-ad": FakePoller(events_to_enqueue=4),
    }

    exit_code = cli._run_source_poll(
        config_file,
        "INFO",
        source_name=None,
        once=True,
        clock=FakeClock(),
        pollers_override=pollers,
    )

    assert exit_code == cli.ExitCode.SUCCESS
    out = capsys.readouterr().out
    assert "Polled 2 source(s):" in out
    assert "[OK] corp-ad: enqueued 4 event(s)" in out
    assert "[OK] corp-okta: enqueued 1 event(s)" in out
    assert "Total enqueued: 5 event(s)" in out


def test_cli_run_source_poll_unknown_source_exits_permanent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_file = _valid_config_file(tmp_path, monkeypatch)
    pollers = {"corp-okta": FakePoller(1)}

    with pytest.raises(cli.PermanentError) as exc_info:
        cli._run_source_poll(
            config_file,
            "INFO",
            source_name="nonexistent",
            once=True,
            clock=FakeClock(),
            pollers_override=pollers,
        )
    assert "nonexistent" in str(exc_info.value)


def test_cli_run_source_poll_retryable_error_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _valid_config_file(tmp_path, monkeypatch)
    pollers = {"corp-ad": FailingPoller(RetryableError("Network partition"))}

    with pytest.raises(cli.RetryableError) as exc_info:
        cli._run_source_poll(
            config_file,
            "INFO",
            source_name="corp-ad",
            once=True,
            clock=FakeClock(),
            pollers_override=pollers,
        )
    assert "Network partition" in str(exc_info.value)


def test_cli_run_source_poll_continuous_max_cycles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _valid_config_file(tmp_path, monkeypatch)
    poller = FakePoller(events_to_enqueue=1)
    pollers = {"corp-okta": poller}

    # Setting once=False and max_cycles=1 to verify continuous loop execution and clean exit
    class MockUnitOfWork:
        def __enter__(self) -> MockUnitOfWork:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    exit_code = cli._run_source_poll(
        config_file,
        "INFO",
        source_name="corp-okta",
        once=False,
        clock=FakeClock(),
        unit_of_work_factory=lambda _: MockUnitOfWork(),  # type: ignore[arg-type,return-value]
        pollers_override=pollers,
    )
    assert exit_code == cli.ExitCode.SUCCESS


def test_main_cli_source_poll_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_file = _valid_config_file(tmp_path, monkeypatch)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    # When DATABASE_URL is missing and no unit_of_work override is provided,
    # running main (["source", "poll",...]) catches ConfigError and exits 2 (CONFIG_ERROR).
    exit_code = cli.main(
        [
            "source",
            "poll",
            "--config",
            str(config_file),
            "--source",
            "corp-okta",
            "--once",
        ]
    )
    assert exit_code == cli.ExitCode.CONFIG
    captured = capsys.readouterr()
    assert "DATABASE_URL" in captured.err
