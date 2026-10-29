"""The configuration loader

One file in, one typed object out. ``load_config`` reads ``config.yaml`` with a
duplicate-key-rejecting ``SafeLoader`` subclass, validates it with a
Pydantic model tree, and returns a frozen ``Config``. A value the schema does not
understand, a key it does not define, a duplicate key, and an unresolvable credential are
all startup failures that name the offending key.

Three rules are structural rather than documented:

- **Credentials and operator endpoints are references.** Every credential and the four
  endpoints ``org_url``, ``server``, ``base_url`` and ``bind_dn`` must be spelled
  ``os.environ/VAR``; a literal is rejected, so a secret cannot reach the repository or a
  log through this file.
- **``os.environ/VAR`` is resolved here, once.** The application receives values, never
  the reference syntax, and no resolved secret is stored on a model that a log or an
  exception can render: secrets are ``SecretStr`` and error details name the variable,
  never its value.
- **Every block forbids unknown keys**. A retired or misspelled key
  is a startup error, which is what makes a second home for a budget impossible rather
  than silently ignored.

The two policy types come from ``domain/policy.py`` and are not copied here: a
``group_mappings`` entry becomes a ``GroupMapping`` and a ``budget_policies`` entry
becomes a ``BudgetPolicy`` during validation, so a caller holds the domain types the
decision code already takes.

YAML 1.1 typing is a hazard, not a feature: the schema is strict,
so ``true`` is not an integer, ``12:30`` is not a string, and ``on`` is not an
identifier. The example quotes every value that could be coerced.

One construct is refused that ``yaml.safe_load`` accepts: a ``<<`` merge key. The
duplicate-key rule is checked on the keys the file spells, before ``flatten_mapping``
expands a merge, so a merge key would otherwise fail as an unhelpful constructor error.
It fails with its own reason instead. This is a deliberate, fail-closed divergence, not
an accident.
"""

from __future__ import annotations

import os
import re
from collections.abc import Hashable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from identity_lifecycle.domain.errors import PermanentError
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping

#: Every block is strict and closed: no coercion, no unknown key.
_BLOCK = ConfigDict(extra="forbid", frozen=True, strict=True)

#: The only accepted spelling of an environment reference.
_ENV_REFERENCE = re.compile(r"^os\.environ/([A-Z][A-Z0-9_]*)$")

#: a source name is a key, so its charset makes ``source:key`` injective.
_SOURCE_NAME = r"^[a-z0-9][a-z0-9_-]*$"

#: The tag PyYAML resolves ``<<`` to; it has no constructor and is expanded by flattening.
_MERGE_TAG = "tag:yaml.org,2002:merge"


class ConfigError(PermanentError):
    """The configuration cannot be used; startup must stop.

    Permanent, not retryable: the file and the environment do not change between two
    attempts. ``key`` is the dotted path of the offending value and ``reason`` is
    the stable machine-readable cause, which is what lets an operator find the line
    without reading a traceback.
    """

    def __init__(self, *, key: str, reason: str, detail: str = "") -> None:
        self.key = key
        self.reason = reason
        self.detail = detail
        message = f"config_error key={key} reason={reason}"
        if detail:
            message = f"{message} detail={detail}"
        super().__init__(message)


class _FieldProblem(ValueError):
    """A value the schema rejects, carrying the reason the startup line reports.

    Raised from a validator and read back from Pydantic's ``ctx.error``; a plain
    ``ValueError`` would still fail validation but would lose the reason vocabulary.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _resolve_reference(value: Any, info: ValidationInfo) -> str:
    """Resolve one required ``os.environ/VAR`` reference, or reject it.

    A literal is a startup error, not a warning: a credential in the file is a leak that
    already happened. The detail names the variable, never the value.
    """
    environ: Mapping[str, str] = (info.context or {}).get("environ", {})
    if not isinstance(value, str):
        raise _FieldProblem("invalid_type", "must be a string holding an os.environ/VAR reference")
    match = _ENV_REFERENCE.match(value)
    if match is None:
        raise _FieldProblem("literal", "must be an os.environ/VAR reference, never a literal")
    name = match.group(1)
    if name not in environ:
        raise _FieldProblem("unresolved_env", f"environment variable {name} is not set")
    return environ[name]


def _resolve_path(value: Any, info: ValidationInfo) -> str:
    """Resolve a filesystem path that may be a reference or a literal.

    ``ca_cert_path`` is an operator path, not a credential or a host name, so either
    spelling is legal; the example uses a reference so no host path is committed.
    """
    if isinstance(value, str) and _ENV_REFERENCE.match(value):
        return _resolve_reference(value, info)
    if not isinstance(value, str) or not value:
        raise _FieldProblem(
            "invalid_type", "must be a non-empty path or an os.environ/VAR reference"
        )
    return value


def _as_tuple(value: Any) -> Any:
    """Turn a YAML sequence into a tuple; strict mode refuses the list otherwise."""
    if isinstance(value, list):
        return tuple(value)
    return value


def _to_group_mapping(value: Any, info: ValidationInfo) -> GroupMapping:
    """Build the domain type from one ``group_mappings`` entry."""
    if isinstance(value, GroupMapping):
        return value
    try:
        entry = GroupMappingEntry.model_validate(value, context=info.context)
    except ValidationError as error:
        first = error.errors(include_url=False)[0]
        detail = f"{'.'.join(str(part) for part in first['loc'])}: {first['msg']}"
        raise _FieldProblem("invalid_value", detail) from None
    return GroupMapping(
        source=entry.source,
        source_group_id=entry.source_group_id,
        role=entry.role,
        team=entry.team,
        precedence=entry.precedence,
        enabled=entry.enabled,
    )


def _to_budget_policy(value: Any, info: ValidationInfo) -> BudgetPolicy:
    """Build the domain type from one ``budget_policies`` entry."""
    if isinstance(value, BudgetPolicy):
        return value
    try:
        entry = BudgetPolicyEntry.model_validate(value, context=info.context)
    except ValidationError as error:
        first = error.errors(include_url=False)[0]
        detail = f"{'.'.join(str(part) for part in first['loc'])}: {first['msg']}"
        raise _FieldProblem("invalid_value", detail) from None
    return BudgetPolicy(max_budget=float(entry.max_budget), budget_duration=entry.budget_duration)


class GroupMappingEntry(BaseModel):
    """One ``group_mappings`` entry as the file spells it.

    The two sources spell the group key differently (``group`` for AD, ``group_id`` for
    Okta); the domain type has one spelling, ``source_group_id``, and this model is the
    one place the normalization happens.
    """

    model_config = _BLOCK

    source: str
    group: str | None = None
    group_id: str | None = None
    role: str
    team: str
    precedence: int
    enabled: bool = True

    @model_validator(mode="after")
    def _exactly_one_group_key(self) -> Self:
        present = [value for value in (self.group, self.group_id) if value is not None]
        if len(present) != 1:
            raise _FieldProblem(
                "invalid_value", "exactly one of `group` (AD) or `group_id` (Okta) is required"
            )
        return self

    @property
    def source_group_id(self) -> str:
        value = self.group if self.group is not None else self.group_id
        assert value is not None  # the validator above guarantees it
        return value


class BudgetPolicyEntry(BaseModel):
    """One ``budget_policies`` entry as the file spells it.

        ``max_budget`` accepts an integer or a float because the example writes ``50``; the
        domain type is ``float`` and the window is stored as written, never parsed
    .
    """

    model_config = _BLOCK

    max_budget: int | float
    budget_duration: str


class GeneralSettingsConfig(BaseModel):
    """``general_settings``: the admin token"""

    model_config = _BLOCK

    master_key: Annotated[SecretStr, BeforeValidator(_resolve_reference)]


class AdConfig(BaseModel):
    """The ``ad`` block of one source.

    ``stable_id`` and ``cross_system_key`` are literals because ADR-005 sections 1-2 fix
    the attributes: ``objectGUID`` is the identity and ``employeeID`` the nullable link.
    ``change_feed`` is ``usn_poll`` only, because DirSync needs a replication right the
    read-only account must not have.
    """

    model_config = _BLOCK

    server: Annotated[str, BeforeValidator(_resolve_reference)]
    domain: str
    search_base: str
    group_dn: str
    bind_dn: Annotated[str, BeforeValidator(_resolve_reference)]
    bind_password: Annotated[SecretStr, BeforeValidator(_resolve_reference)]
    ca_cert_path: Annotated[str, BeforeValidator(_resolve_path)]
    stable_id: Literal["objectGUID"]
    cross_system_key: Literal["employeeID"]
    attributes: Annotated[tuple[str, ...], BeforeValidator(_as_tuple)]
    change_feed: Literal["usn_poll"]
    poll_interval_seconds: int


class EventHookConfig(BaseModel):
    """The ``okta.event_hook`` block.

    Two controls fail closed at startup: an empty ``ip_allowlist`` is never "allow all",
    and two empty shared secrets leave the endpoint unauthenticated. Both are startup
    errors, not warnings.
    """

    model_config = _BLOCK

    path: str
    auth_header: str
    auth_scheme: str
    shared_secret: Annotated[SecretStr, BeforeValidator(_resolve_reference)]
    shared_secret_previous: Annotated[SecretStr, BeforeValidator(_resolve_reference)]
    ip_allowlist: Annotated[tuple[str, ...], BeforeValidator(_as_tuple)]
    trusted_proxies: Annotated[tuple[str, ...], BeforeValidator(_as_tuple)]
    client_ip_header: str
    max_clock_skew_seconds: int
    max_body_bytes: int
    verification_requests_per_minute: int

    @model_validator(mode="after")
    def _two_fail_closed_controls(self) -> Self:
        if not self.ip_allowlist:
            raise _FieldProblem("invalid_value", "ip_allowlist must not be empty")
        current = self.shared_secret.get_secret_value()
        previous = self.shared_secret_previous.get_secret_value()
        if not current and not previous:
            raise _FieldProblem(
                "invalid_value",
                "shared_secret and shared_secret_previous must not both be empty",
            )
        return self


class SystemLogConfig(BaseModel):
    """The ``okta.system_log`` block, the sole home of the poller budget."""

    model_config = _BLOCK

    poll_interval_seconds: int
    overlap_seconds: int
    page_limit: int
    requests_per_second: int
    burst: int
    retention_seconds: int

    @field_validator("overlap_seconds")
    @classmethod
    def _nonnegative_overlap(cls, value: int) -> int:
        if value < 0:
            raise _FieldProblem("invalid_value", "must not be negative")
        return value

    @field_validator(
        "poll_interval_seconds",
        "page_limit",
        "requests_per_second",
        "burst",
        "retention_seconds",
    )
    @classmethod
    def _positive_poll_values(cls, value: int) -> int:
        if value <= 0:
            raise _FieldProblem("invalid_value", "must be a positive integer")
        return value


class OktaOAuthConfig(BaseModel):
    """Private-key JWT credentials for the Okta read-only service app."""

    model_config = _BLOCK

    client_id: Annotated[str, BeforeValidator(_resolve_reference)]
    key_id: Annotated[str, BeforeValidator(_resolve_reference)]
    private_key_path: Annotated[str, BeforeValidator(_resolve_reference)]


class OktaConfig(BaseModel):
    """The ``okta`` block of one source.

    ``change_feed: system_log`` means no hook is registered, so an ``event_hook`` block
    in that configuration is dead config and is rejected; ``event_hook`` means the hook is
    the primary feed and the block is required.
    """

    model_config = _BLOCK

    org_url: Annotated[str, BeforeValidator(_resolve_reference)]
    oauth: OktaOAuthConfig
    group_id: str
    stable_id: Literal["id"]
    cross_system_key: Literal["employeeNumber"]
    change_feed: Literal["event_hook", "system_log"]
    event_hook: EventHookConfig | None = None
    system_log: SystemLogConfig

    @field_validator("org_url")
    @classmethod
    def _org_url_is_https_origin(cls, value: str) -> str:
        origin = urlsplit(value)
        if (
            origin.scheme != "https"
            or not origin.netloc
            or origin.username is not None
            or origin.password is not None
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
        ):
            raise _FieldProblem("invalid_value", "must be an HTTPS Okta origin")
        return value

    @model_validator(mode="after")
    def _hook_matches_the_feed(self) -> Self:
        if self.change_feed == "event_hook" and self.event_hook is None:
            raise _FieldProblem("missing", "change_feed event_hook requires the event_hook block")
        if self.change_feed == "system_log" and self.event_hook is not None:
            raise _FieldProblem(
                "invalid_value", "change_feed system_log registers no hook; drop event_hook"
            )
        return self


class IdentitySourceConfig(BaseModel):
    """One ``identity_sources`` item, with the block its ``source_type`` names.

    Exactly one vendor block is legal and it must match ``source_type``; the other is an
    unknown key for that source. This is the placement rule
    a line scan cannot make and the loader makes structurally.
    """

    model_config = _BLOCK

    source_name: str = Field(pattern=_SOURCE_NAME)
    source_type: Literal["ad", "okta"]
    enabled: bool
    ad: AdConfig | None = None
    okta: OktaConfig | None = None

    @model_validator(mode="after")
    def _vendor_block_matches_the_type(self) -> Self:
        expected = self.ad if self.source_type == "ad" else self.okta
        unexpected = self.okta if self.source_type == "ad" else self.ad
        if expected is None:
            raise _FieldProblem(
                "missing", f"source_type {self.source_type} requires the {self.source_type} block"
            )
        if unexpected is not None:
            name = "okta" if self.source_type == "ad" else "ad"
            raise _FieldProblem(
                "invalid_value",
                f"the {name} block does not belong to a {self.source_type} source",
            )
        return self


class TeamConfig(BaseModel):
    """One ``teams`` entry."""

    model_config = _BLOCK

    create_if_missing: bool
    budget_duration: str


class BudgetPolicyOverridesConfig(BaseModel):
    """``budget_policy_overrides``: the table the override port reads."""

    model_config = _BLOCK

    source: Literal["postgres"]
    table: str


class GroupBudgetMapping(BaseModel):
    """A ``budget_mappings`` rule keyed on a group."""

    model_config = _BLOCK

    source: str
    group: str | None = None
    group_id: str | None = None
    policy: str

    @model_validator(mode="after")
    def _exactly_one_group_key(self) -> Self:
        present = [value for value in (self.group, self.group_id) if value is not None]
        if len(present) != 1:
            raise _FieldProblem(
                "invalid_value", "exactly one of `group` (AD) or `group_id` (Okta) is required"
            )
        return self


class AttributeBudgetMapping(BaseModel):
    """A ``budget_mappings`` rule keyed on an attribute."""

    model_config = _BLOCK

    source: Literal["any"]
    attribute: str
    map: Mapping[str, str]

    @field_validator("map", mode="after")
    @classmethod
    def _freeze_map(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        """``frozen=True`` freezes the field, not the dict inside it (N4)."""
        return MappingProxyType(dict(value))

    @field_serializer("map")
    def _serialize_map(self, value: Mapping[str, str]) -> dict[str, str]:
        """Emit a plain dict: the proxy is for immutability, not for the wire.

        Pydantic builds the serializer from the annotation, so a ``mappingproxy``
        value raises ``PydanticSerializationError`` from ``model_dump (mode="json")``
        and ``model_dump_json`` without this handler.
        """
        return dict(value)


BudgetMapping = Annotated[
    GroupBudgetMapping | AttributeBudgetMapping, Field(union_mode="left_to_right")
]


class GatewayConfig(BaseModel):
    """The ``gateway`` block; the adapter targets LiteLLM v1.105.0."""

    model_config = _BLOCK

    type: Literal["litellm"]
    base_url: Annotated[str, BeforeValidator(_resolve_reference)]
    api_key: Annotated[SecretStr, BeforeValidator(_resolve_reference)]


class EventBusConfig(BaseModel):
    """The ``event_bus`` block; the outbox is the only bus in v1."""

    model_config = _BLOCK

    type: Literal["postgres_outbox"]
    table: str
    consumer_group: str
    poll_interval_seconds: int
    batch_size: int


class ReconciliationConfig(BaseModel):
    """The ``reconciliation`` block."""

    model_config = _BLOCK

    schedule: str
    dry_run: bool
    grace_period_hours: int
    allowlist: Annotated[tuple[str, ...], BeforeValidator(_as_tuple)]
    two_miss_rule: bool
    miss_state_table: str
    batch_size: int


class RateLimitConfig(BaseModel):
    """A token bucket for a process-wide or per-adapter client."""

    model_config = _BLOCK

    requests_per_second: int
    burst: int


class AdRateLimitConfig(BaseModel):
    """The AD bucket uses the design's name, ``queries_per_second``."""

    model_config = _BLOCK

    queries_per_second: int
    burst: int


class WorkerLimitConfig(BaseModel):
    """The worker pool's concurrency, not a rate."""

    model_config = _BLOCK

    concurrency: int


class RateLimitsConfig(BaseModel):
    """``rate_limits``; the System Log budget is *not* here.

    An ``okta_system_log`` or ``system_log_requests_per_second`` key is an unknown key,
    so the retired second home fails startup instead of being silently ignored.
    """

    model_config = _BLOCK

    inbound: RateLimitConfig
    okta: RateLimitConfig
    ad: AdRateLimitConfig
    litellm: RateLimitConfig
    worker: WorkerLimitConfig


class Config(BaseModel):
    """The validated configuration handed to the application.

    Frozen, so a use case cannot edit the configuration in flight. ``group_mappings`` and
    ``budget_policies`` hold the domain types of ``domain/policy.py``, not a second copy.
    ``frozen=True`` freezes a field, not the dict inside it, so the two mapping fields are
    ``Mapping`` typed and wrapped in ``MappingProxyType`` by a validator.
    """

    model_config = _BLOCK

    general_settings: GeneralSettingsConfig
    identity_sources: Annotated[tuple[IdentitySourceConfig, ...], BeforeValidator(_as_tuple)]
    group_mappings: Annotated[
        tuple[Annotated[GroupMapping, BeforeValidator(_to_group_mapping)], ...],
        BeforeValidator(_as_tuple),
    ]
    teams: Mapping[str, TeamConfig]
    budget_policy_overrides: BudgetPolicyOverridesConfig
    budget_policies: Mapping[str, Annotated[BudgetPolicy, BeforeValidator(_to_budget_policy)]]
    default_budget_policy: str
    budget_mappings: Annotated[tuple[BudgetMapping, ...], BeforeValidator(_as_tuple)]
    gateway: GatewayConfig
    event_bus: EventBusConfig
    reconciliation: ReconciliationConfig
    rate_limits: RateLimitsConfig

    @field_validator("teams", "budget_policies", mode="after")
    @classmethod
    def _freeze_mappings(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        """Make the mapping itself read-only, not only the field that holds it."""
        return MappingProxyType(dict(value))

    @field_validator("default_budget_policy")
    @classmethod
    def _default_budget_policy_exists(cls, value: str, info: ValidationInfo) -> str:
        policies = info.data.get("budget_policies", {})
        if value not in policies:
            raise _FieldProblem(
                "unknown_policy",
                f"default_budget_policy names {value!r}, which is not a configured policy",
            )
        return value

    @field_serializer("teams", "budget_policies")
    def _serialize_mappings(self, value: Mapping[str, Any]) -> dict[str, Any]:
        """Emit a plain dict; see ``AttributeBudgetMapping._serialize_map``."""
        return dict(value)

    @model_validator(mode="after")
    def _references_resolve(self) -> Self:
        if not self.identity_sources:
            raise _FieldProblem("invalid_value", "at least one identity source is required")
        if not self.group_mappings:
            raise _FieldProblem("invalid_value", "group_mappings must not be empty")
        if not self.budget_policies:
            raise _FieldProblem("invalid_value", "budget_policies must not be empty")

        names = [source.source_name for source in self.identity_sources]
        if len(names) != len(set(names)):
            raise _FieldProblem("duplicate_source", "source_name must be unique")

        hook_paths = [
            source.okta.event_hook.path
            for source in self.identity_sources
            if source.okta is not None and source.okta.event_hook is not None
        ]
        if len(hook_paths) != len(set(hook_paths)):
            raise _FieldProblem("duplicate_hook_path", "two sources share one hook path")

        known_sources = set(names)
        for mapping in self.group_mappings:
            if mapping.source not in known_sources:
                raise _FieldProblem(
                    "unknown_source",
                    f"group_mappings names {mapping.source!r}, which is not a configured source",
                )
        for rule in self.budget_mappings:
            policies: tuple[str, ...]
            if isinstance(rule, GroupBudgetMapping):
                if rule.source not in known_sources:
                    raise _FieldProblem(
                        "unknown_source",
                        f"budget_mappings names {rule.source!r}, which is not a configured source",
                    )
                policies = (rule.policy,)
            else:
                policies = tuple(rule.map.values())
            for policy in policies:
                if policy not in self.budget_policies:
                    raise _FieldProblem(
                        "unknown_policy",
                        f"budget_mappings names {policy!r}, which is not a configured policy",
                    )
        return self


class _DuplicateKeyError(yaml.constructor.ConstructorError):
    """A mapping key appears twice; the second would silently replace the first."""

    def __init__(self, key: object, mark: yaml.error.Mark) -> None:
        super().__init__(
            context="while constructing a mapping",
            problem=f"found duplicate key {key!r}",
            problem_mark=mark,
        )
        self.key = key


class _MergeKeyError(yaml.constructor.ConstructorError):
    """A ``<<`` merge key; this loader refuses it instead of expanding it.

    Expanding a merge would let a value override a key the file also spells, so the
    duplicate rule could no longer be checked on the keys the file contains. Refusing the
    construct keeps the rule total and gives it a reason an operator can act on.
    """

    def __init__(self, mark: yaml.error.Mark) -> None:
        super().__init__(
            context="while constructing a mapping",
            problem="merge keys are not accepted; spell every key explicitly",
            problem_mark=mark,
        )


class UniqueKeySafeLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses a duplicate mapping key.

    PyYAML's ``SafeConstructor.construct_mapping`` assigns ``mapping[key] = value``, so a
    duplicated ``event_bus:`` silently overrides the earlier one. This subclass keeps every
    safe constructor and adds one check; it is the parser the structural tests use, which
    is why it is public.
    """


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    """Build one mapping, raising on a duplicate key before the later value can win."""
    seen: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == _MERGE_TAG:
            raise _MergeKeyError(key_node.start_mark)
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, Hashable):
            raise yaml.constructor.ConstructorError(
                context="while constructing a mapping",
                problem="found an unhashable key",
                problem_mark=key_node.start_mark,
            )
        if key in seen:
            raise _DuplicateKeyError(key, key_node.start_mark)
        seen.add(key)

    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, Hashable):
            raise yaml.constructor.ConstructorError(
                context="while constructing a mapping",
                problem="found an unhashable key",
                problem_mark=key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _read(path: Path) -> str:
    """Read the file as UTF-8, or stop with a reason an operator can act on.

    A file Notepad saved as "Unicode" is UTF-16 and raises ``UnicodeDecodeError``, which
    is a ``ValueError`` and would escape the loader's "every failure is a ``ConfigError``"
    contract. It gets its own reason, so a missing
    file (``unreadable``) and an undecodable one (``invalid_encoding``) are distinguishable.
    """
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ConfigError(
            key=str(path),
            reason="invalid_encoding",
            detail=f"the file is not UTF-8: {error.reason} at byte {error.start}",
        ) from None
    except OSError as error:
        raise ConfigError(key=str(path), reason="unreadable", detail=type(error).__name__) from None


def _parse(text: str) -> Mapping[Any, Any]:
    """Parse one document with the safe loader, and only the safe loader.

    ``UniqueKeySafeLoader`` subclasses ``yaml.SafeLoader``, and ``get_single_data`` is the
    body of ``yaml.safe_load`` itself, so this is the safe path spelled without
    ``yaml.load``. It also refuses a second document, which a
    ``safe_load_all`` caller would otherwise see as two configs.
    """
    loader = UniqueKeySafeLoader(text)
    try:
        data = loader.get_single_data()
    except _DuplicateKeyError as error:
        line = error.problem_mark.line + 1 if error.problem_mark is not None else 0
        raise ConfigError(
            key=str(error.key), reason="duplicate_key", detail=f"line {line}"
        ) from None
    except _MergeKeyError as error:
        line = error.problem_mark.line + 1 if error.problem_mark is not None else 0
        raise ConfigError(
            key="<<", reason="merge_key", detail=f"merge keys are not accepted; line {line}"
        ) from None
    except yaml.YAMLError as error:
        raise ConfigError(key="<file>", reason="invalid_yaml", detail=_yaml_detail(error)) from None
    if not isinstance(data, Mapping):
        raise ConfigError(key="<root>", reason="invalid_value", detail="the file is not a mapping")
    return data


def _yaml_detail(error: yaml.YAMLError) -> str:
    """Name the problem and its position; never echo the offending line.

    PyYAML's ``str (mark)`` includes the source line, which may hold a value; a startup
    diagnostic must not copy a credential into a log.
    """
    problem = getattr(error, "problem", None) or "the file is not valid YAML"
    mark = getattr(error, "problem_mark", None)
    if mark is None:
        return problem
    return f"{problem} at line {mark.line + 1}, column {mark.column + 1}"


def _format_key(location: tuple[int | str, ...]) -> str:
    """Render Pydantic's location tuple as ``identity_sources[1].okta.org_url``."""
    parts: list[str] = []
    for part in location:
        if isinstance(part, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{part}]"
            else:
                parts.append(f"[{part}]")
        else:
            parts.append(str(part))
    return ".".join(parts) or "<root>"


def _reason(error: Mapping[str, Any]) -> tuple[str, str]:
    """Map one Pydantic error to the startup reason vocabulary."""
    original = (error.get("ctx") or {}).get("error")
    if isinstance(original, _FieldProblem):
        return original.reason, original.detail
    kind = error["type"]
    if kind == "missing":
        return "missing", "the key is required"
    if kind == "extra_forbidden":
        return "unknown_key", "the key is not in the schema"
    if kind == "literal_error":
        return "invalid_value", str(error.get("msg", "unexpected value"))
    if kind.endswith("_type") or kind in {"model_type", "model_attributes_type"}:
        return "invalid_type", str(error.get("msg", "wrong type"))
    return "invalid_value", str(error.get("msg", "invalid value"))


def load_config(path: Path, environ: Mapping[str, str] | None = None) -> Config:
    """Read, parse, and validate ``path``; return the typed configuration.

    ``environ`` is the mapping ``os.environ/VAR`` references resolve against; it defaults
    to the process environment and is injectable so a test can prove resolution without
    setting real variables. Every failure is a ``ConfigError`` naming the key.
    """
    text = _read(path)
    mapping = _parse(text)
    context = {"environ": os.environ if environ is None else environ}
    try:
        return Config.model_validate(mapping, context=context)
    except ValidationError as error:
        first = error.errors(include_url=False)[0]
        reason, detail = _reason(first)
        raise ConfigError(key=_format_key(first["loc"]), reason=reason, detail=detail) from None
