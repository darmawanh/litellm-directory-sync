"""Unit tests for the scheduler CLI command and composition."""

from __future__ import annotations

import pytest

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.config import Config, ConfigError, load_config
from identity_lifecycle.workers.scheduler import ReconciliationScheduler
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_client
from tests.fixtures.fakes import FakeGateway
from tests.fixtures.okta_http import FakeOktaHTTP
from tests.unit.test_config_loader import ENV, EXAMPLE

pytestmark = pytest.mark.unit


def test_build_scheduler_composes_sources_and_scheduler() -> None:
    config: Config = load_config(EXAMPLE, ENV)
    fake_conn = FakeADConnection()
    okta_server = FakeOktaHTTP()

    scheduler, sources = cli.build_scheduler(
        config,
        FakeGateway(),
        lambda _source: None,  # type: ignore[arg-type]
        SystemClock(),
        ad_client_factory=lambda _ad_config: create_fake_ad_client(fake_conn),
        client_factory=lambda _okta_config: okta_server.oauth_client(),
    )

    assert isinstance(scheduler, ReconciliationScheduler)
    assert len(sources) == 2
    assert {s.name() for s in sources} == {"corp-ad", "corp-okta"}


def test_run_scheduler_requires_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(cli.DATABASE_URL_VARIABLE, raising=False)
    options = cli.ProcessOptions(config_path=EXAMPLE, log_level="INFO")

    with pytest.raises(ConfigError) as exc_info:
        cli._run_scheduler(options)

    assert exc_info.value.key == cli.DATABASE_URL_VARIABLE
    assert exc_info.value.reason == "missing"
