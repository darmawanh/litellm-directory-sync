"""The worker's composition root resolves the configured gateway."""

from __future__ import annotations

from pathlib import Path

import pytest

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.litellm import LiteLLMGateway
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.config import Config, ConfigError, load_config
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_client
from tests.fixtures.fakes import FakeGateway
from tests.fixtures.okta_http import FakeOktaHTTP

from .test_config_loader import ENV, EXAMPLE, _text, _with_event_hook

pytestmark = pytest.mark.unit


def test_build_gateway_uses_configured_litellm_adapter() -> None:
    config: Config = load_config(EXAMPLE, ENV)

    gateway = cli.build_gateway(config)
    try:
        assert isinstance(gateway, LiteLLMGateway)
    finally:
        gateway.close()


def test_worker_uses_the_explicit_default_budget_policy() -> None:
    config: Config = load_config(EXAMPLE, ENV)

    assert len(config.budget_policies) > 1
    assert cli._default_budget_policy(config) == "standard"


def test_worker_composes_ad_source() -> None:
    config: Config = load_config(EXAMPLE, ENV)
    fake_conn = FakeADConnection()
    okta_server = FakeOktaHTTP()
    worker, sources = cli.build_worker(
        config,
        FakeGateway(),
        lambda _source: None,  # type: ignore[arg-type]
        lambda: 0,
        SystemClock(),
        ad_client_factory=lambda _ad_config: create_fake_ad_client(fake_conn),
        client_factory=lambda _okta_config: okta_server.oauth_client(),
    )
    assert any(s.name() == "corp-ad" for s in sources)
    for s in sources:
        s.close()


def test_worker_rejects_an_enabled_source_without_an_adapter() -> None:
    config = load_config(EXAMPLE, ENV)
    unsupported = config.identity_sources[0].model_copy(
        update={"source_type": "ping", "enabled": True}
    )
    bad_config = config.model_copy(update={"identity_sources": [unsupported]})
    with pytest.raises(ConfigError) as raised:
        cli.build_worker(
            bad_config,
            FakeGateway(),
            lambda _source: None,
            lambda: 0,
            SystemClock(),  # type: ignore[arg-type]
        )

    assert raised.value.key == "identity_sources[0].source_type"
    assert raised.value.reason == "unsupported"


def test_worker_accepts_event_hook_configuration_and_constructs_poller(
    tmp_path: Path,
) -> None:
    text = _with_event_hook(_text())
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path, ENV)
    fake_conn = FakeADConnection()
    okta_server = FakeOktaHTTP()

    worker, sources = cli.build_worker(
        config,
        FakeGateway(),
        lambda _source: None,  # type: ignore[arg-type]
        lambda: 0,
        SystemClock(),
        ad_client_factory=lambda _ad_config: create_fake_ad_client(fake_conn),
        client_factory=lambda _okta_config: okta_server.oauth_client(),
    )
    assert any(s.name() == "corp-okta" for s in sources)
    for s in sources:
        s.close()


def test_worker_rejects_unsupported_okta_change_feed() -> None:
    config = load_config(EXAMPLE, ENV)
    okta_source = config.identity_sources[1]
    assert okta_source.okta is not None
    bad_okta = okta_source.okta.model_copy(update={"change_feed": "invalid_feed"})  # type: ignore[arg-type]
    bad_source = okta_source.model_copy(update={"okta": bad_okta})
    bad_config = config.model_copy(
        update={"identity_sources": [config.identity_sources[0], bad_source]}
    )

    with pytest.raises(ConfigError) as raised:
        cli.build_worker(
            bad_config,
            FakeGateway(),
            lambda _source: None,
            lambda: 0,
            SystemClock(),
            ad_client_factory=lambda _ad: create_fake_ad_client(FakeADConnection()),
        )

    assert raised.value.key == "identity_sources[1].okta.change_feed"
    assert raised.value.reason == "unsupported"


def test_worker_requires_an_enabled_supported_source() -> None:
    config = load_config(EXAMPLE, ENV)
    all_disabled = config.model_copy(
        update={
            "identity_sources": [
                s.model_copy(update={"enabled": False}) for s in config.identity_sources
            ]
        }
    )

    with pytest.raises(ConfigError) as raised:
        cli.build_worker(
            all_disabled,
            FakeGateway(),
            lambda _source: None,  # type: ignore[arg-type]
            lambda: 0,
            SystemClock(),
        )

    assert raised.value.key == "identity_sources"
    assert raised.value.reason == "no_enabled_source"


def test_a_missing_database_url_is_a_typed_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Decision 1: a bare KeyError is not a startup diagnostic. The error names
    # the variable and is the config family, which exits 3 and is not restarted.
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(Exception) as raised:
        cli.database_url()

    assert type(raised.value).__name__ == "ConfigError"
    assert "DATABASE_URL" in str(raised.value)
    assert "reason=missing" in str(raised.value)
