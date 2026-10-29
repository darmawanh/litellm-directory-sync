"""Unit tests for the api CLI command and composition."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.config import Config, ConfigError, load_config
from tests.unit.test_config_loader import ENV, EXAMPLE

pytestmark = pytest.mark.unit


def test_build_api_returns_fastapi_app() -> None:
    config: Config = load_config(EXAMPLE, ENV)
    app = cli.build_api(
        config,
        lambda _source: None,  # type: ignore[arg-type]
        SystemClock(),
    )
    assert isinstance(app, FastAPI)


def test_run_api_requires_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(cli.DATABASE_URL_VARIABLE, raising=False)
    options = cli.ProcessOptions(config_path=EXAMPLE, log_level="INFO")

    with pytest.raises(ConfigError) as exc_info:
        cli._run_api(options)

    assert exc_info.value.key == cli.DATABASE_URL_VARIABLE
    assert exc_info.value.reason == "missing"


def test_run_api_starts_uvicorn_server(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    monkeypatch.setenv("API_PORT", "9999")

    # Mock engine and source dependencies so external servers are not contacted
    fake_engine = MagicMock()
    monkeypatch.setattr(cli, "build_engine", lambda _url: fake_engine)

    fake_source = MagicMock()
    fake_gateway = MagicMock()
    monkeypatch.setattr(cli, "build_gateway", lambda _config: fake_gateway)
    monkeypatch.setattr(
        cli, "_build_sources", lambda *args, **kwargs: ({"corp-ad": fake_source}, ())
    )

    import uvicorn

    server_runs = []

    def mock_run(self: uvicorn.Server) -> None:
        server_runs.append((self.config.host, self.config.port))

    monkeypatch.setattr(uvicorn.Server, "run", mock_run)

    options = cli.ProcessOptions(config_path=EXAMPLE, log_level="INFO")
    exit_code = cli._run_api(options)

    assert exit_code == cli.ExitCode.SUCCESS
    assert server_runs == [("127.0.0.1", 9999)]
    fake_engine.dispose.assert_called_once()
    fake_source.close.assert_called_once()
    fake_gateway.close.assert_called_once()


def test_run_api_fails_closed_when_dependency_construction_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")

    fake_engine = MagicMock()
    monkeypatch.setattr(cli, "build_engine", lambda _url: fake_engine)

    # Simulate dependency construction failure (e.g. source construction failure)
    def failing_build_sources(*args, **kwargs):
        raise ConfigError(
            key="identity_sources[0].ad",
            reason="invalid_certificate",
            detail="CA certificate verification failed",
        )

    monkeypatch.setattr(cli, "_build_sources", failing_build_sources)

    import uvicorn

    server_runs = []

    def mock_run(self: uvicorn.Server) -> None:
        server_runs.append((self.config.host, self.config.port))

    monkeypatch.setattr(uvicorn.Server, "run", mock_run)

    exit_code = cli.main(["api", "--config", str(EXAMPLE)])

    # Must exit 3, never bind or run server
    assert exit_code == cli.ExitCode.CONFIG
    assert server_runs == []
    captured = capsys.readouterr()
    assert "identity_sources[0].ad" in captured.err
    assert "placeholder-bind-password" not in captured.err


def test_run_api_fails_closed_when_admin_token_is_invalid(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(cli.DATABASE_URL_VARIABLE, "postgresql://user:pass@localhost:5432/db")
    monkeypatch.setenv("LIFECYCLE_MASTER_KEY", " ")

    fake_engine = MagicMock()
    monkeypatch.setattr(cli, "build_engine", lambda _url: fake_engine)
    fake_source = MagicMock()
    monkeypatch.setattr(cli, "build_gateway", lambda _config: MagicMock())
    monkeypatch.setattr(
        cli, "_build_sources", lambda *args, **kwargs: ({"corp-ad": fake_source}, ())
    )

    import uvicorn

    server_runs = []

    def mock_run(self: uvicorn.Server) -> None:
        server_runs.append((self.config.host, self.config.port))

    monkeypatch.setattr(uvicorn.Server, "run", mock_run)

    exit_code = cli.main(["api", "--config", str(EXAMPLE)])

    assert exit_code == cli.ExitCode.CONFIG
    assert server_runs == []
    captured = capsys.readouterr()
    assert "general_settings.master_key" in captured.err
