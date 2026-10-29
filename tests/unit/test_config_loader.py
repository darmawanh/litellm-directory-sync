"""The config loader: YAML in, typed values out, fail fast and name the key.

These are the structural claims ADR-010 section 3 deferred to the loader, made with the
loader's own duplicate-rejecting parser rather than a line scan: how many sources there
are and which vendor block sits under which one, that retired keys are absent from the
schema, that the pinned values are the ones the ADRs name, and that the domain policy
types are the ones the decision code already takes.

Every failure test mutates the shipped example by one exact substring, so the file the
loader validates stays the file an operator copies.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from identity_lifecycle.config import AttributeBudgetMapping, Config, ConfigError, load_config
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping

pytestmark = pytest.mark.unit

EXAMPLE = Path(__file__).resolve().parents[2] / "config" / "config.example.yaml"

ENV = {
    "LIFECYCLE_MASTER_KEY": "placeholder-master-key",
    "AD_SERVER": "ldaps://dc01.example.com:636",
    "AD_BIND_DN": "CN=svc-identity-read,OU=Service Accounts,DC=example,DC=com",
    "AD_BIND_PASSWORD": "placeholder-bind-password",
    "AD_CA_CERT_PATH": "/etc/ssl/certs/example-ca.pem",
    "OKTA_ORG_URL": "https://example.okta.com",
    "OKTA_CLIENT_ID": "placeholder-client-id",
    "OKTA_KEY_ID": "placeholder-key-id",
    "OKTA_PRIVATE_KEY_PATH": "C:/keys/okta-test.pem",
    "OKTA_EVENT_HOOK_TOKEN": "placeholder-legacy-verification-token",
    "OKTA_EVENT_HOOK_SECRET": "placeholder-hook-secret",
    "OKTA_EVENT_HOOK_SECRET_PREVIOUS": "placeholder-previous-secret",
    "LITELLM_BASE_URL": "https://litellm.example.com",
    "LITELLM_MASTER_KEY": "placeholder-gateway-key",
}


def _text() -> str:
    return EXAMPLE.read_text(encoding="utf-8")


def _mutate(text: str, old: str, new: str) -> str:
    """Replace one exact substring; a mutation that matches nothing fails loudly."""
    assert text.count(old) == 1, f"expected exactly one {old!r} in the example"
    return text.replace(old, new)


def _with_event_hook(text: str, *, change_feed: str = "event_hook") -> str:
    """Add the optional hook config when a test needs to exercise that schema branch."""
    marker = "      change_feed: system_log\n"
    assert text.count(marker) == 1
    hook = (
        "      event_hook:\n"
        "        path: /api/v1/hooks/okta\n"
        "        auth_header: Authorization\n"
        "        auth_scheme: Bearer\n"
        "        shared_secret: os.environ/OKTA_EVENT_HOOK_SECRET\n"
        "        shared_secret_previous: os.environ/OKTA_EVENT_HOOK_SECRET_PREVIOUS\n"
        "        ip_allowlist:\n"
        "          - 203.0.113.0/24\n"
        "          - 198.51.100.0/24\n"
        "        trusted_proxies: []\n"
        "        client_ip_header: X-Forwarded-For\n"
        "        max_clock_skew_seconds: 300\n"
        "        max_body_bytes: 262144\n"
        "        verification_requests_per_minute: 5\n"
    )
    replacement = f"      change_feed: {change_feed}\n{hook}"
    return text.replace(marker, replacement)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _load(tmp_path: Path, text: str, environ: dict[str, str] | None = None) -> Config:
    return load_config(_write(tmp_path, text), ENV if environ is None else environ)


def _error(tmp_path: Path, text: str, environ: dict[str, str] | None = None) -> ConfigError:
    with pytest.raises(ConfigError) as raised:
        _load(tmp_path, text, environ)
    return raised.value


def test_config_example_parses_and_validates(tmp_path: Path) -> None:
    config = load_config(EXAMPLE, ENV)

    assert isinstance(config, Config)
    assert len(config.identity_sources) == 2
    assert config.identity_sources[0].enabled
    assert config.identity_sources[1].enabled
    assert set(config.budget_policies) == {"standard", "engineer"}
    assert config.default_budget_policy == "standard"
    assert set(config.teams) == {"ai-platform"}
    assert config.gateway.type == "litellm"
    assert config.event_bus.type == "postgres_outbox"


def test_identity_sources_pairing_and_vendor_block_placement() -> None:
    """Two sources, each carrying exactly the vendor block its ``source_type`` names.

       A line scan cannot see this: it cannot tell which block is a child of which item
    ("What a text scan can and cannot prove").
    """
    config = load_config(EXAMPLE, ENV)
    sources = config.identity_sources

    assert [(source.source_name, source.source_type) for source in sources] == [
        ("corp-ad", "ad"),
        ("corp-okta", "okta"),
    ]
    assert sources[0].ad is not None and sources[0].okta is None
    assert sources[1].okta is not None and sources[1].ad is None


def test_default_budget_policy_must_name_a_configured_policy(tmp_path: Path) -> None:
    text = _mutate(_text(), "default_budget_policy: standard\n", "default_budget_policy: unknown\n")

    error = _error(tmp_path, text)

    assert error.key == "default_budget_policy"
    assert error.reason == "unknown_policy"


def test_default_budget_policy_is_required(tmp_path: Path) -> None:
    text = _mutate(_text(), "default_budget_policy: standard\n", "")

    error = _error(tmp_path, text)

    assert error.key == "default_budget_policy"
    assert error.reason == "missing"


def test_a_vendor_block_under_the_wrong_source_is_rejected(tmp_path: Path) -> None:
    text = _mutate(_text(), "    source_type: okta\n", "    source_type: ad\n")

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1]"
    assert error.reason == "missing"


def test_duplicate_key_is_rejected(tmp_path: Path) -> None:
    """A second ``event_bus:`` would silently win under a plain ``SafeLoader``."""
    text = _text() + "\nevent_bus:\n  type: redis\n"

    error = _error(tmp_path, text)

    assert error.reason == "duplicate_key"
    assert error.key == "event_bus"


def test_a_merge_key_is_refused_with_its_own_reason(tmp_path: Path) -> None:
    """``<<`` is refused rather than expanded, so the duplicate rule stays total.

    ``yaml.safe_load`` accepts a merge key and lets the merged value override a key the
    file also spells; this loader fails closed with a reason instead (module docstring,
    ADR-001 section 7.3).
    """
    text = (
        "defaults: &defaults\n"
        "  table: identity_event_outbox\n"
        "event_bus:\n"
        "  <<: *defaults\n"
        "  type: postgres_outbox\n"
    )

    error = _error(tmp_path, text)

    assert error.reason == "merge_key"
    assert error.key == "<<"


def test_missing_credential_fails_fast_and_names_the_key(tmp_path: Path) -> None:
    text = _mutate(_text(), "        client_id: os.environ/OKTA_CLIENT_ID\n", "")

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta.oauth.client_id"
    assert error.reason == "missing"


def test_unresolved_environment_variable_names_the_variable(tmp_path: Path) -> None:
    environ = dict(ENV)
    del environ["OKTA_CLIENT_ID"]

    error = _error(tmp_path, _text(), environ)

    assert error.key == "identity_sources[1].okta.oauth.client_id"
    assert error.reason == "unresolved_env"
    assert "OKTA_CLIENT_ID" in error.detail


def test_generic_okta_api_tokens_are_not_a_supported_credential(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "      oauth:\n",
        "      api_token: os.environ/OKTA_API_TOKEN\n      oauth:\n",
    )

    error = _error(tmp_path, text)

    assert error.reason == "unknown_key"
    assert error.key == "identity_sources[1].okta.api_token"


def test_okta_org_url_must_use_https(tmp_path: Path) -> None:
    environ = dict(ENV)
    environ["OKTA_ORG_URL"] = "http://example.okta.com"

    error = _error(tmp_path, _text(), environ)

    assert error.key == "identity_sources[1].okta.org_url"
    assert error.reason == "invalid_value"


def test_literal_secret_is_rejected(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "      bind_password: os.environ/AD_BIND_PASSWORD\n",
        "      bind_password: hunter2\n",
    )

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[0].ad.bind_password"
    assert error.reason == "literal"
    # The value that leaked into the file must not leak into the diagnostic too.
    assert "hunter2" not in str(error)
    assert "hunter2" not in error.detail


def test_literal_operator_endpoint_is_rejected(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "      org_url: os.environ/OKTA_ORG_URL\n",
        "      org_url: https://acme.okta.com\n",
    )

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta.org_url"
    assert error.reason == "literal"


def test_group_mappings_become_domain_types(tmp_path: Path) -> None:
    """No second copy of ``GroupMapping``: the loader hands over the domain type."""
    config = load_config(EXAMPLE, ENV)

    assert all(type(mapping) is GroupMapping for mapping in config.group_mappings)
    ad_admin, ad_user, okta_user = config.group_mappings
    assert ad_admin.source_group_id.startswith("CN=AI-Platform-Admins")
    assert ad_user.role == "internal_user"
    assert okta_user.source_group_id == "00gEXAMPLE0000000000"
    assert (ad_admin.precedence, ad_user.precedence) == (100, 10)


def test_budget_policies_become_domain_types(tmp_path: Path) -> None:
    config = load_config(EXAMPLE, ENV)

    assert all(type(policy) is BudgetPolicy for policy in config.budget_policies.values())
    assert config.budget_policies["standard"] == BudgetPolicy(
        max_budget=50.0, budget_duration="30d"
    )


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    """Every block is ``extra="forbid"``."""
    text = _mutate(_text(), "  dry_run: true\n", "  dry_run: true\n  unexpected_setting: 1\n")

    error = _error(tmp_path, text)

    assert error.key == "reconciliation.unexpected_setting"
    assert error.reason == "unknown_key"


def test_the_retired_system_log_rate_key_is_an_unknown_key(tmp_path: Path) -> None:
    """ADR-009's losing home must fail startup rather than become a second bucket."""
    text = _mutate(
        _text(),
        "  worker:\n    concurrency: 4\n",
        "  okta_system_log:\n    requests_per_second: 2\n    burst: 4\n"
        "  worker:\n    concurrency: 4\n",
    )

    error = _error(tmp_path, text)

    assert error.key == "rate_limits.okta_system_log"
    assert error.reason == "unknown_key"


def test_the_system_log_budget_has_one_home_and_its_pinned_values(tmp_path: Path) -> None:
    config = load_config(EXAMPLE, ENV)
    system_log = config.identity_sources[1].okta.system_log

    assert (system_log.requests_per_second, system_log.burst) == (2, 4)
    assert system_log.retention_seconds == 604800
    assert not hasattr(config.rate_limits, "okta_system_log")


def test_system_log_retention_must_be_positive(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "        retention_seconds: 604800\n",
        "        retention_seconds: 0\n",
    )

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta.system_log.retention_seconds"
    assert error.reason == "invalid_value"


def test_system_log_overlap_may_be_zero(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "        overlap_seconds: 60\n",
        "        overlap_seconds: 0\n",
    )

    config = _load(tmp_path, text)

    assert config.identity_sources[1].okta.system_log.overlap_seconds == 0


def test_system_log_overlap_must_not_be_negative(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "        overlap_seconds: 60\n",
        "        overlap_seconds: -1\n",
    )

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta.system_log.overlap_seconds"
    assert error.reason == "invalid_value"


def test_trusted_proxies_stays_empty(tmp_path: Path) -> None:
    """The shipped worker config selects its implemented System Log feed only."""
    config = load_config(EXAMPLE, ENV)
    hook = config.identity_sources[1].okta.event_hook

    assert config.identity_sources[1].okta.change_feed == "system_log"
    assert hook is None


def test_an_empty_ip_allowlist_is_a_startup_failure(tmp_path: Path) -> None:
    text = _mutate(
        _with_event_hook(_text()),
        "        ip_allowlist:\n          - 203.0.113.0/24\n          - 198.51.100.0/24\n",
        "        ip_allowlist: []\n",
    )

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta.event_hook"
    assert error.reason == "invalid_value"


def test_two_empty_shared_secrets_are_a_startup_failure(tmp_path: Path) -> None:
    environ = dict(ENV)
    environ["OKTA_EVENT_HOOK_SECRET"] = ""
    environ["OKTA_EVENT_HOOK_SECRET_PREVIOUS"] = ""

    error = _error(tmp_path, _with_event_hook(_text()), environ)

    assert error.key == "identity_sources[1].okta.event_hook"
    assert error.reason == "invalid_value"


def test_the_shipped_example_carries_no_verification_token(tmp_path: Path) -> None:
    """The shipped worker config does not ask for credentials for an unimplemented hook route."""
    config = _load(tmp_path, _text())

    hook = config.identity_sources[1].okta.event_hook
    assert hook is None


def test_verification_token_is_rejected_as_unknown_key(tmp_path: Path) -> None:
    """T-067: verification_token was removed from the schema and is rejected as unknown."""
    replacement = (
        "        path: /api/v1/hooks/okta\n"
        "        verification_token: os.environ/OKTA_EVENT_HOOK_TOKEN\n"
    )
    text = _mutate(
        _with_event_hook(_text()),
        "        path: /api/v1/hooks/okta\n",
        replacement,
    )
    error = _error(tmp_path, text)
    assert "verification_token" in str(error)


def test_the_system_log_feed_rejects_a_hook_block(tmp_path: Path) -> None:
    """ADR-006 sections 5 and 8: system_log registers no hook, so the block is dead config."""
    text = _with_event_hook(_text(), change_feed="system_log")

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta"
    assert error.reason == "invalid_value"


def test_the_event_hook_feed_requires_the_hook_block(tmp_path: Path) -> None:
    """The other direction: the hook feed with no block is a startup failure."""
    text = _mutate(_text(), "      change_feed: system_log\n", "      change_feed: event_hook\n")

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[1].okta"
    assert error.reason == "missing"
    assert "event_hook" in error.detail


def test_event_bus_type_is_the_only_accepted_bus(tmp_path: Path) -> None:
    text = _mutate(_text(), "  type: postgres_outbox\n", "  type: redis\n")

    error = _error(tmp_path, text)

    assert error.key == "event_bus.type"
    assert error.reason == "invalid_value"


def test_source_name_charset_is_enforced(tmp_path: Path) -> None:
    text = _mutate(_text(), "  - source_name: corp-ad\n", "  - source_name: Corp AD\n")

    error = _error(tmp_path, text)

    assert error.key == "identity_sources[0].source_name"
    assert error.reason == "invalid_value"


def test_source_names_are_unique(tmp_path: Path) -> None:
    text = _mutate(_text(), "  - source_name: corp-okta\n", "  - source_name: corp-ad\n")

    error = _error(tmp_path, text)

    assert error.reason == "duplicate_source"


def test_group_mapping_names_a_configured_source(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "  - source: corp-ad\n    group: CN=AI-Platform-Admins",
        "  - source: ghost\n    group: CN=AI-Platform-Admins",
    )

    error = _error(tmp_path, text)

    assert error.reason == "unknown_source"


def test_budget_mapping_names_a_configured_policy(tmp_path: Path) -> None:
    text = _mutate(
        _text(),
        "    group: CN=AI-Platform-Users,OU=Groups,OU=AI Platform,DC=example,DC=com\n"
        "    policy: standard\n",
        "    group: CN=AI-Platform-Users,OU=Groups,OU=AI Platform,DC=example,DC=com\n"
        "    policy: missing\n",
    )

    error = _error(tmp_path, text)

    assert error.reason == "unknown_policy"


def test_the_loaded_config_is_frozen(tmp_path: Path) -> None:
    config = load_config(EXAMPLE, ENV)

    with pytest.raises(ValidationError):
        config.reconciliation.dry_run = False  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.group_mappings[0].role = "proxy_admin"  # type: ignore[misc]

    # ``frozen=True`` freezes the field, not the mapping it holds; the two mapping
    # fields and the attribute rule's map are read-only mappings in their own right.
    with pytest.raises(TypeError):
        config.teams["injected"] = None  # type: ignore[index]
    with pytest.raises(TypeError):
        config.budget_policies["injected"] = None  # type: ignore[index]
    attribute_rule = next(
        rule for rule in config.budget_mappings if isinstance(rule, AttributeBudgetMapping)
    )
    with pytest.raises(TypeError):
        attribute_rule.map["Engineering"] = "standard"  # type: ignore[index]


def test_the_loaded_config_serializes_to_json(tmp_path: Path) -> None:
    """A read-only mapping must still serialize as a dict.

    ``MappingProxyType`` makes the config immutable in flight, but Pydantic builds
    its serializer from the field annotation, so a proxy value raises
    ``PydanticSerializationError`` from ``model_dump (mode="json")`` and
    ``model_dump_json``. A field serializer that emits a plain dict restores the
    behavior the config had before the mappings were frozen.
    """
    config = load_config(EXAMPLE, ENV)

    plain = config.model_dump()
    assert isinstance(plain["teams"], dict)
    assert isinstance(plain["budget_policies"], dict)

    as_json = config.model_dump(mode="json")
    assert isinstance(as_json["teams"], dict)
    assert isinstance(as_json["budget_policies"], dict)

    attribute_rule = next(
        rule for rule in config.budget_mappings if isinstance(rule, AttributeBudgetMapping)
    )
    assert isinstance(attribute_rule.model_dump()["map"], dict)

    document = json.loads(config.model_dump_json())
    assert set(document["teams"]) == set(config.teams)


def test_a_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as raised:
        load_config(tmp_path / "absent.yaml", ENV)

    assert raised.value.reason == "unreadable"


def test_a_non_utf8_file_is_a_config_error(tmp_path: Path) -> None:
    """A UTF-16 file is not UTF-8; the failure names the file, not a codec traceback."""
    path = tmp_path / "config.yaml"
    path.write_bytes("general_settings:\n".encode("utf-16"))

    with pytest.raises(ConfigError) as raised:
        load_config(path, ENV)

    assert raised.value.reason == "invalid_encoding"
    assert raised.value.key == str(path)


def test_invalid_yaml_is_a_config_error(tmp_path: Path) -> None:
    error = _error(tmp_path, "general_settings: [unclosed\n")

    assert error.reason == "invalid_yaml"
    assert "line 2" in error.detail


def test_a_non_mapping_document_is_a_config_error(tmp_path: Path) -> None:
    error = _error(tmp_path, "- one\n- two\n")

    assert error.reason == "invalid_value"
    assert error.key == "<root>"


def test_the_process_environment_is_the_default_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)

    config = load_config(EXAMPLE)

    assert config.general_settings.master_key.get_secret_value() == "placeholder-master-key"
