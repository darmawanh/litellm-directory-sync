"""Command-line entry point for the identity lifecycle service."""

from __future__ import annotations

import argparse
import contextlib
import enum
import logging
import os
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from identity_lifecycle import __version__
from identity_lifecycle.adapters.ad.client import ADClient
from identity_lifecycle.adapters.ad.connector import ADIdentitySource
from identity_lifecycle.adapters.ad.poller import ADPoller
from identity_lifecycle.adapters.litellm import LiteLLMGateway
from identity_lifecycle.adapters.okta.client import OktaClient
from identity_lifecycle.adapters.okta.connector import OktaIdentitySource
from identity_lifecycle.adapters.okta.poller import OktaSystemLogPoller
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.outbox import reap_expired_leases
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.application.audit_export import AuditExport, AuditExportError
from identity_lifecycle.application.manual_sync import ManualSync
from identity_lifecycle.application.outbox_replay import OutboxReplay
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.application.source_check import (
    SourceCheck,
    SourceCheckResult,
)
from identity_lifecycle.application.source_poll import (
    PollCycleResult,
    SourceNotFoundError,
    SourcePoll,
)
from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.config import (
    AdConfig,
    Config,
    ConfigError,
    GroupBudgetMapping,
    OktaConfig,
    load_config,
)
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.observability.metrics import (
    record_equal_precedence_failure,
    record_event_processed,
    record_revocation_sla,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.gateway import Gateway
from identity_lifecycle.ports.identity_source import IdentitySource
from identity_lifecycle.workers.outbox_worker import OutboxWorker
from identity_lifecycle.workers.scheduler import ReconciliationScheduler

logger = logging.getLogger(__name__)
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: The environment variable the database URL comes from, the one
#: ``migrations/env.py:21`` already reads. Design section 6's config block has no
#: database field (its top-level keys are general_settings, identity_sources,
#: group_mappings, teams, budget_policy_overrides, budget_policies,
#: budget_mappings, gateway, event_bus, reconciliation, rate_limits), so this
#: follows the in-repo convention rather than adding a second home for a
#: credential. If section 6 ever gains a field, the wiring moves there.
DATABASE_URL_VARIABLE = "DATABASE_URL"


class ExitCode(enum.IntEnum):
    """The process exit table"""

    SUCCESS = 0
    INTERNAL = 1
    USAGE = 2
    CONFIG = 3
    PERMANENT = 4
    RETRYABLE = 5


@dataclass(frozen=True)
class ProcessOptions:
    """Everything a process runner receives from the command line."""

    config_path: Path
    log_level: str


@dataclass(frozen=True)
class ProcessNotImplemented(Exception):
    """A process command whose owning phase has not been implemented yet."""

    command: str
    phase: int


@dataclass(frozen=True)
class _ScheduledOktaPoller:
    """One source poller and its conservative System Log request schedule."""

    source_name: str
    poller: OktaSystemLogPoller
    poll_interval_seconds: float
    page_interval_seconds: float


@dataclass(frozen=True)
class _ScheduledADPoller:
    """One Active Directory source poller and its polling schedule."""

    source_name: str
    poller: ADPoller
    poll_interval_seconds: float


ScheduledPoller = _ScheduledOktaPoller | _ScheduledADPoller
SupportedIdentitySource = OktaIdentitySource | ADIdentitySource

ADClientFactory = Callable[[AdConfig], ADClient]
OktaClientFactory = Callable[[OktaConfig], OktaClient]


def build_gateway(config: Config) -> LiteLLMGateway:
    """Build the configured LiteLLM adapter at the process composition boundary."""
    return LiteLLMGateway(
        base_url=config.gateway.base_url,
        api_key=config.gateway.api_key.get_secret_value(),
    )


def _build_okta_client(config: OktaConfig) -> OktaClient:
    """Build the read-only Okta HTTP client from one validated source block."""
    return OktaClient(
        org_url=config.org_url,
        oauth_client_id=config.oauth.client_id,
        oauth_key_id=config.oauth.key_id,
        private_key_path=config.oauth.private_key_path,
    )


def _build_ad_client(config: AdConfig) -> ADClient:
    """Build the read-only LDAPS client from one validated source block."""
    return ADClient(
        server=config.server,
        bind_dn=config.bind_dn,
        bind_password=config.bind_password.get_secret_value(),
        ca_cert_path=config.ca_cert_path,
    )


def build_worker(
    config: Config,
    gateway: Gateway,
    unit_of_work: UnitOfWorkFactory,
    reap: Callable[[], int],
    clock: Clock,
    *,
    client_factory: OktaClientFactory | None = None,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[OutboxWorker, tuple[SupportedIdentitySource, ...]]:
    """Compose configured identity sources, pollers, use case, and the outbox loop."""
    resolved_okta_factory = okta_client_factory or client_factory
    identity_sources, schedules = _build_sources(
        config,
        unit_of_work,
        clock,
        okta_client_factory=resolved_okta_factory,
        ad_client_factory=ad_client_factory,
    )
    process = _process_event(
        config,
        gateway,
        unit_of_work,
        identity_sources=identity_sources,
        clock=clock,
    )
    worker = OutboxWorker(
        unit_of_work,
        process,
        reap,
        batch_size=config.event_bus.batch_size,
        poll_interval_seconds=float(config.event_bus.poll_interval_seconds),
        poll_sources=_poll_due_sources(schedules),
        sleep=sleep,
    )
    return worker, tuple(identity_sources.values())


def _build_sources(
    config: Config,
    unit_of_work: UnitOfWorkFactory | None,
    clock: Clock,
    *,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
    target_source: str | None = None,
) -> tuple[dict[str, SupportedIdentitySource], tuple[ScheduledPoller, ...]]:
    """Build every enabled source or fail before silently dropping configured input."""
    build_okta = _build_okta_client if okta_client_factory is None else okta_client_factory
    build_ad = _build_ad_client if ad_client_factory is None else ad_client_factory
    sources: dict[str, SupportedIdentitySource] = {}
    schedules: list[ScheduledPoller] = []

    try:
        for index, source_config in enumerate(config.identity_sources):
            if not source_config.enabled:
                continue
            if target_source is not None and source_config.source_name != target_source:
                continue

            if source_config.source_type == "okta":
                if source_config.okta is None:
                    raise ConfigError(
                        key=f"identity_sources[{index}].okta",
                        reason="missing",
                        detail="source_type okta requires the okta block",
                    )
                if source_config.okta.change_feed not in ("system_log", "event_hook"):
                    raise ConfigError(
                        key=f"identity_sources[{index}].okta.change_feed",
                        reason="unsupported",
                        detail="the v1 worker consumes Okta via system_log or event_hook",
                    )
                if (
                    source_config.okta.change_feed == "event_hook"
                    and source_config.okta.event_hook is None
                ):
                    raise ConfigError(
                        key=f"identity_sources[{index}].okta.event_hook",
                        reason="missing",
                        detail="change_feed event_hook requires the event_hook block",
                    )
                if source_config.okta.system_log is None:
                    raise ConfigError(
                        key=f"identity_sources[{index}].okta.system_log",
                        reason="missing",
                        detail="source_type okta requires the system_log block",
                    )
                client = build_okta(source_config.okta)
                okta_identity_source = OktaIdentitySource(
                    source_name=source_config.source_name,
                    group_id=source_config.okta.group_id,
                    client=client,
                    clock=clock,
                    log_page_limit=source_config.okta.system_log.page_limit,
                    log_overlap_seconds=source_config.okta.system_log.overlap_seconds,
                    log_retention_seconds=source_config.okta.system_log.retention_seconds,
                )
                sources[source_config.source_name] = okta_identity_source
                if unit_of_work is not None:
                    schedules.append(
                        _ScheduledOktaPoller(
                            source_name=source_config.source_name,
                            poller=OktaSystemLogPoller(
                                okta_identity_source,
                                unit_of_work,
                                overlap_seconds=source_config.okta.system_log.overlap_seconds,
                            ),
                            poll_interval_seconds=float(
                                source_config.okta.system_log.poll_interval_seconds
                            ),
                            page_interval_seconds=1.0
                            / source_config.okta.system_log.requests_per_second,
                        )
                    )

            elif source_config.source_type == "ad":
                if source_config.ad is None:
                    raise ConfigError(
                        key=f"identity_sources[{index}].ad",
                        reason="missing",
                        detail="source_type ad requires the ad block",
                    )
                if source_config.ad.change_feed != "usn_poll":
                    raise ConfigError(
                        key=f"identity_sources[{index}].ad.change_feed",
                        reason="unsupported",
                        detail="the v1 worker consumes Active Directory via usn_poll",
                    )
                ad_client = build_ad(source_config.ad)
                ad_identity_source = ADIdentitySource(
                    source_name=source_config.source_name,
                    group_dn=source_config.ad.group_dn,
                    search_base=source_config.ad.search_base,
                    client=ad_client,
                    clock=clock,
                    poll_interval_seconds=source_config.ad.poll_interval_seconds,
                )
                sources[source_config.source_name] = ad_identity_source
                if unit_of_work is not None:
                    schedules.append(
                        _ScheduledADPoller(
                            source_name=source_config.source_name,
                            poller=ADPoller(ad_identity_source, unit_of_work),
                            poll_interval_seconds=float(source_config.ad.poll_interval_seconds),
                        )
                    )

            else:
                raise ConfigError(
                    key=f"identity_sources[{index}].source_type",
                    reason="unsupported",
                    detail=f"unsupported source type: {source_config.source_type}",
                )

    except (PermanentError, RetryableError):
        for identity_source in sources.values():
            identity_source.close()
        raise

    if not sources:
        raise ConfigError(
            key="identity_sources",
            reason="no_enabled_source",
            detail="enable at least one supported source (Active Directory or Okta)",
        )

    return sources, tuple(schedules)


def _poll_due_sources(schedules: tuple[ScheduledPoller, ...]) -> Callable[[], None]:
    """Poll due pages before outbox claims, spacing pages under the configured rate."""
    next_poll_at = {schedule.source_name: 0.0 for schedule in schedules}

    def poll_due() -> None:
        for schedule in schedules:
            if time.monotonic() < next_poll_at[schedule.source_name]:
                continue
            if isinstance(schedule, _ScheduledOktaPoller):
                try:
                    enqueued = schedule.poller.poll_once()
                except RetryableError as error:
                    next_poll_at[schedule.source_name] = (
                        time.monotonic() + schedule.poll_interval_seconds
                    )
                    logger.warning(
                        "okta_system_log_poll_failed source=%s error=%s retry_in_seconds=%s",
                        schedule.source_name,
                        type(error).__name__,
                        schedule.poll_interval_seconds,
                    )
                    continue
                has_more_pages = schedule.poller.has_more_pages
                delay = (
                    schedule.page_interval_seconds
                    if has_more_pages
                    else schedule.poll_interval_seconds
                )
                next_poll_at[schedule.source_name] = time.monotonic() + delay
                logger.info(
                    "okta_system_log_page_committed source=%s enqueued=%s more_pages=%s",
                    schedule.source_name,
                    enqueued,
                    has_more_pages,
                )
            elif isinstance(schedule, _ScheduledADPoller):
                try:
                    enqueued = schedule.poller.poll_once()
                except RetryableError as error:
                    next_poll_at[schedule.source_name] = (
                        time.monotonic() + schedule.poll_interval_seconds
                    )
                    logger.warning(
                        "ad_poll_failed source=%s error=%s retry_in_seconds=%s",
                        schedule.source_name,
                        type(error).__name__,
                        schedule.poll_interval_seconds,
                    )
                    continue
                next_poll_at[schedule.source_name] = (
                    time.monotonic() + schedule.poll_interval_seconds
                )
                logger.info(
                    "ad_poll_committed source=%s enqueued=%s",
                    schedule.source_name,
                    enqueued,
                )

    return poll_due


def database_url() -> str:
    """Return the database URL, or stop with a typed error naming the variable.

    A bare ``KeyError`` from ``os.environ[...]`` is not a startup diagnostic: it
    has no message an operator can act on and it is not one's typed
    failures. ``ConfigError`` is permanent and carries the key and the reason.
    """
    value = os.environ.get(DATABASE_URL_VARIABLE)
    if not value:
        raise ConfigError(
            key=DATABASE_URL_VARIABLE,
            reason="missing",
            detail="the worker reads its connection string from the environment",
        )
    return value


def _run_api(options: ProcessOptions) -> int:
    """Run the inbound HTTP API server from the validated configuration."""
    config = load_config(options.config_path)
    engine = build_engine(database_url())
    try:
        clock = SystemClock()

        def unit_of_work(source: str) -> PostgresUnitOfWork:
            return PostgresUnitOfWork(engine, clock, source=source)

        gateway: LiteLLMGateway | None = None
        sources: dict[str, SupportedIdentitySource] = {}

        try:
            gateway = build_gateway(config)
            sources, _ = _build_sources(config, unit_of_work, clock)
            manual_sync = build_manual_sync(config, gateway, unit_of_work, sources, clock)
            reconcile = build_reconcile(config, gateway, unit_of_work, sources, clock)
            audit_export = AuditExport(unit_of_work, clock)
            app = build_api(
                config,
                unit_of_work,
                clock,
                manual_sync=manual_sync,
                reconcile=reconcile,
                audit_export=audit_export,
            )
            host = os.environ.get("API_HOST", os.environ.get("HOST", "0.0.0.0"))
            port = int(os.environ.get("API_PORT", os.environ.get("PORT", "8000")))

            import uvicorn

            uvicorn_config = uvicorn.Config(
                app,
                host=host,
                port=port,
                log_level=options.log_level.lower(),
            )
            server = uvicorn.Server(uvicorn_config)
            server.run()
            return ExitCode.SUCCESS
        finally:
            for source in sources.values():
                source.close()
            if gateway is not None:
                gateway.close()
    finally:
        engine.dispose()


def _run_worker(options: ProcessOptions) -> int:
    """Run the source pollers and outbox loop from the validated configuration.

    The gateway and Okta connection pools and database engine close when the
    worker exits.
    """
    config = load_config(options.config_path)
    gateway = build_gateway(config)
    try:
        engine = build_engine(database_url())
        try:
            clock = SystemClock()

            def unit_of_work(source: str) -> PostgresUnitOfWork:
                return PostgresUnitOfWork(engine, clock, source=source)

            worker, sources = build_worker(
                config,
                gateway,
                unit_of_work,
                _lease_reaper(engine, clock),
                clock,
            )
            try:
                logger.info(
                    "worker_started sources=%s outbox_poll_interval_seconds=%s",
                    tuple(source.name() for source in sources),
                    config.event_bus.poll_interval_seconds,
                )
                worker.run()
            finally:
                for source in sources:
                    source.close()
            return ExitCode.SUCCESS
        finally:
            engine.dispose()
    finally:
        gateway.close()


def build_api(
    config: Config,
    unit_of_work: UnitOfWorkFactory,
    clock: Clock,
    *,
    manual_sync: ManualSync | None = None,
    reconcile: Reconcile | None = None,
    audit_export: AuditExport | None = None,
) -> Any:
    """Build the inbound HTTP API application from validated configuration."""
    from identity_lifecycle.api.app import create_app

    return create_app(
        config,
        unit_of_work,
        clock,
        manual_sync=manual_sync,
        reconcile=reconcile,
        audit_export=audit_export,
    )


def build_reconcile(
    config: Config,
    gateway: Gateway,
    unit_of_work: UnitOfWorkFactory,
    identity_sources: Mapping[str, IdentitySource],
    clock: Clock,
) -> Reconcile:
    """Build the reconciliation use case from validated configuration."""
    return Reconcile(
        unit_of_work=unit_of_work,
        gateway=gateway,
        identity_sources=identity_sources,
        clock=clock,
        group_mappings=config.group_mappings,
        allowlist=config.reconciliation.allowlist,
        two_miss_rule=config.reconciliation.two_miss_rule,
        dry_run=config.reconciliation.dry_run,
        batch_size=config.reconciliation.batch_size,
        grace_period_hours=config.reconciliation.grace_period_hours,
    )


def build_scheduler(
    config: Config,
    gateway: Gateway,
    unit_of_work: UnitOfWorkFactory,
    clock: Clock,
    *,
    client_factory: OktaClientFactory | None = None,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
) -> tuple[ReconciliationScheduler, tuple[SupportedIdentitySource, ...]]:
    """Build the reconciliation scheduler process from validated configuration."""
    resolved_okta_factory = okta_client_factory or client_factory
    sources, _ = _build_sources(
        config,
        unit_of_work,
        clock,
        okta_client_factory=resolved_okta_factory,
        ad_client_factory=ad_client_factory,
    )
    reconcile = build_reconcile(
        config,
        gateway,
        unit_of_work,
        sources,
        clock,
    )
    scheduler = ReconciliationScheduler(
        reconcile,
        schedule=config.reconciliation.schedule,
    )
    return scheduler, tuple(sources.values())


def _run_scheduler(options: ProcessOptions) -> int:
    """Run the reconciliation scheduler process from the validated configuration.

    The gateway, identity source connections, and database engine close when the
    scheduler exits.
    """
    config = load_config(options.config_path)
    gateway = build_gateway(config)
    try:
        engine = build_engine(database_url())
        try:
            clock = SystemClock()

            def unit_of_work(source: str) -> PostgresUnitOfWork:
                return PostgresUnitOfWork(engine, clock, source=source)

            scheduler, sources = build_scheduler(
                config,
                gateway,
                unit_of_work,
                clock,
            )
            try:
                logger.info(
                    "scheduler_started sources=%s schedule=%s dry_run=%s",
                    tuple(source.name() for source in sources),
                    config.reconciliation.schedule,
                    config.reconciliation.dry_run,
                )
                scheduler.run()
            finally:
                for source in sources:
                    source.close()
            return ExitCode.SUCCESS
        finally:
            engine.dispose()
    finally:
        gateway.close()


def build_manual_sync(
    config: Config,
    gateway: Gateway,
    unit_of_work: UnitOfWorkFactory,
    identity_sources: Mapping[str, IdentitySource],
    clock: Clock,
) -> ManualSync:
    """Build the manual sync use case from validated configuration."""
    return ManualSync(
        unit_of_work=unit_of_work,
        gateway=gateway,
        identity_sources=identity_sources,
        clock=clock,
        group_mappings=config.group_mappings,
        enabled_sources=frozenset(identity_sources),
    )


def _run_config_validate(config_path: Path) -> int:
    """Validate configuration file and resolved environment references."""
    load_config(config_path)
    sys.stdout.buffer.write(f"Configuration is valid: {config_path}\n".encode())
    return ExitCode.SUCCESS


def _run_reconcile(
    config_path: Path,
    log_level: str,
    *,
    dry_run: bool = False,
    gateway_factory: Callable[[Config], Gateway] | None = None,
    engine_factory: Callable[[str], Any] | None = None,
    client_factory: OktaClientFactory | None = None,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
    clock: Clock | None = None,
) -> int:
    """Run one reconciliation pass across all enabled sources and LiteLLM."""
    config = load_config(config_path)
    build_gw = gateway_factory or build_gateway
    gateway = build_gw(config)
    try:
        build_eng = engine_factory or build_engine
        engine = build_eng(database_url())
        try:
            resolved_clock = clock or SystemClock()

            def unit_of_work(source: str) -> PostgresUnitOfWork:
                return PostgresUnitOfWork(engine, resolved_clock, source=source)

            resolved_okta_factory = okta_client_factory or client_factory
            sources, _ = _build_sources(
                config,
                unit_of_work,
                resolved_clock,
                okta_client_factory=resolved_okta_factory,
                ad_client_factory=ad_client_factory,
            )
            try:
                reconciler = build_reconcile(
                    config,
                    gateway,
                    unit_of_work,
                    sources,
                    resolved_clock,
                )
                result = reconciler.reconcile(dry_run=dry_run)
                summary_lines = [
                    f"Reconciliation completed (dry_run={result.dry_run}):",
                    f"  Drifts detected: {len(result.drifts)}",
                    f"  Misses recorded: {len(result.misses_recorded)}",
                    f"  Events enqueued: {len(result.events_emitted)}",
                ]
                for drift in result.drifts:
                    summary_lines.append(
                        f"  - [{drift.kind}] source={drift.source} "
                        f"user={drift.user_id}: {drift.detail}"
                    )
                sys.stdout.buffer.write(("\n".join(summary_lines) + "\n").encode())
                return ExitCode.SUCCESS
            finally:
                for source in sources.values():
                    if hasattr(source, "close"):
                        source.close()
        finally:
            if hasattr(engine, "dispose"):
                engine.dispose()
    finally:
        if hasattr(gateway, "close"):
            gateway.close()


def _run_sync(
    config_path: Path,
    log_level: str,
    *,
    employee_number: str | None = None,
    source_user_id: str | None = None,
    gateway_factory: Callable[[Config], Gateway] | None = None,
    engine_factory: Callable[[str], Any] | None = None,
    client_factory: OktaClientFactory | None = None,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
    clock: Clock | None = None,
) -> int:
    """Run manual targeted resynchronization for one employee or user."""
    config = load_config(config_path)
    build_gw = gateway_factory or build_gateway
    gateway = build_gw(config)
    try:
        build_eng = engine_factory or build_engine
        engine = build_eng(database_url())
        try:
            resolved_clock = clock or SystemClock()

            def unit_of_work(source: str) -> PostgresUnitOfWork:
                return PostgresUnitOfWork(engine, resolved_clock, source=source)

            resolved_okta_factory = okta_client_factory or client_factory
            sources, _ = _build_sources(
                config,
                unit_of_work,
                resolved_clock,
                okta_client_factory=resolved_okta_factory,
                ad_client_factory=ad_client_factory,
            )
            try:
                sync_use_case = build_manual_sync(
                    config,
                    gateway,
                    unit_of_work,
                    sources,
                    resolved_clock,
                )
                result = sync_use_case.sync(
                    employee_number=employee_number,
                    source_user_id=source_user_id,
                )
                target_desc = (
                    f"employee {employee_number}" if employee_number else f"user {source_user_id}"
                )
                lines = [
                    f"Manual sync completed for {target_desc} "
                    f"(source={result.source}, user={result.source_user_id}, "
                    f"person={result.person_id}):",
                    f"  Event enqueued: {result.event_enqueued.type.value} "
                    f"(id={result.event_enqueued.event_id})",
                    f"  Decision outcome: {result.decision.outcome.value} "
                    f"(reason={result.decision.reason})",
                    f"  Desired action: {result.desired.action.value}",
                ]
                sys.stdout.buffer.write(("\n".join(lines) + "\n").encode())
                return ExitCode.SUCCESS
            finally:
                for source in sources.values():
                    if hasattr(source, "close"):
                        source.close()
        finally:
            if hasattr(engine, "dispose"):
                engine.dispose()
    finally:
        if hasattr(gateway, "close"):
            gateway.close()


def parse_utc_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 string into an aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise AuditExportError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _run_audit_export(
    config_path: Path,
    log_level: str,
    *,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    employee_number: str | None = None,
    source_user_id: str | None = None,
    output_format: str = "csv",
    ndjson: bool = False,
    output_path: Path | None = None,
    engine_factory: Callable[[str], Any] | None = None,
    unit_of_work_factory: UnitOfWorkFactory | None = None,
    clock: Clock | None = None,
) -> int:
    """Export audit records matching date range and optional employee/user filters."""
    load_config(config_path)

    resolved_clock = clock or SystemClock()

    since: datetime | None = None
    if from_timestamp is not None:
        since = parse_utc_timestamp(from_timestamp)

    until = parse_utc_timestamp(to_timestamp) if to_timestamp is not None else resolved_clock.now()

    if since is not None and until is not None and since > until:
        raise AuditExportError(
            f"--from timestamp ({since.isoformat()}) must not be after "
            f"--to timestamp ({until.isoformat()})"
        )

    resolved_format = "ndjson" if (output_format == "json" and ndjson) else output_format

    if unit_of_work_factory is not None:
        use_case = AuditExport(unit_of_work_factory, resolved_clock)
        content = use_case.export(
            since=since,
            until=until,
            employee_number=employee_number,
            source_user_id=source_user_id,
            format=resolved_format,
            output=output_path,
        )
        if output_path is None:
            sys.stdout.buffer.write(content.encode("utf-8"))
        return ExitCode.SUCCESS

    build_eng = engine_factory or build_engine
    engine = build_eng(database_url())
    try:

        def uow_factory(source: str) -> PostgresUnitOfWork:
            return PostgresUnitOfWork(engine, resolved_clock, source=source)

        use_case = AuditExport(uow_factory, resolved_clock)
        content = use_case.export(
            since=since,
            until=until,
            employee_number=employee_number,
            source_user_id=source_user_id,
            format=resolved_format,
            output=output_path,
        )
        if output_path is None:
            sys.stdout.buffer.write(content.encode("utf-8"))
        return ExitCode.SUCCESS
    finally:
        if hasattr(engine, "dispose"):
            engine.dispose()


def _run_outbox_replay(
    config_path: Path,
    log_level: str,
    *,
    target_id: str,
    clock: Clock | None = None,
    engine_factory: Any = None,
    unit_of_work_factory: UnitOfWorkFactory | None = None,
) -> int:
    """Replay one dead or settled outbox event by ID or event ID."""
    load_config(config_path)
    logger.info(
        "identity_lifecycle_outbox_replay_started config=%s target_id=%s",
        config_path,
        target_id,
    )
    resolved_clock = clock or SystemClock()

    if unit_of_work_factory is not None:
        use_case = OutboxReplay(unit_of_work_factory, resolved_clock)
        outcome = use_case.replay(target_id)
        msg = (
            f"Replayed outbox event {outcome.event_id} (row {outcome.row_id}): "
            f"status reset from {outcome.previous_status!r} to 'pending'\n"
        )
        sys.stdout.buffer.write(msg.encode())
        return ExitCode.SUCCESS

    db_url = database_url()
    factory = engine_factory or build_engine
    engine = factory(db_url)
    try:

        def uow_factory(source: str = "lifecycle-service") -> PostgresUnitOfWork:
            return PostgresUnitOfWork(engine, resolved_clock, source=source)

        use_case = OutboxReplay(uow_factory, resolved_clock)
        outcome = use_case.replay(target_id)
        msg = (
            f"Replayed outbox event {outcome.event_id} (row {outcome.row_id}): "
            f"status reset from {outcome.previous_status!r} to 'pending'\n"
        )
        sys.stdout.buffer.write(msg.encode())
        return ExitCode.SUCCESS
    finally:
        if hasattr(engine, "dispose"):
            engine.dispose()


def _run_source_check(
    config_path: Path,
    log_level: str,
    *,
    source_name: str | None = None,
    clock: Clock | None = None,
    sources_override: Mapping[str, IdentitySource] | None = None,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
) -> int:
    """Check connectivity and read permissions for configured identity sources."""
    config = load_config(config_path)
    resolved_clock = clock or SystemClock()
    logger.info(
        "identity_lifecycle_source_check_started config=%s source=%s",
        config_path,
        source_name,
    )

    if sources_override is not None:
        sources: dict[str, Any] = dict(sources_override)
    else:
        enabled_sources = {s.source_name for s in config.identity_sources if s.enabled}
        if source_name is not None and source_name not in enabled_sources:
            raise SourceNotFoundError(f"source {source_name!r} is not configured or enabled")
        built_sources, _ = _build_sources(
            config,
            unit_of_work=None,
            clock=resolved_clock,
            okta_client_factory=okta_client_factory,
            ad_client_factory=ad_client_factory,
            target_source=source_name,
        )
        sources = dict(built_sources)

    try:
        use_case = SourceCheck(sources, resolved_clock)
        results = use_case.check(source_name)

        lines: list[str] = [f"Checked {len(results)} source(s):"]
        first_failure: SourceCheckResult | None = None

        for result in results:
            if result.status == "ok":
                lines.append(
                    f"  [OK] {result.source_name}: "
                    f"group={result.group_name!r} (id={result.group_id!r}), "
                    f"{result.member_count} member(s) ({result.duration_ms:.1f}ms)"
                )
            else:
                lines.append(
                    f"  [FAILED] {result.source_name}: {result.error} ({result.duration_ms:.1f}ms)"
                )
                if first_failure is None:
                    first_failure = result

        sys.stdout.buffer.write(("\n".join(lines) + "\n").encode())

        if first_failure is not None:
            if first_failure.exception is not None:
                raise first_failure.exception
            return ExitCode.PERMANENT

        return ExitCode.SUCCESS
    finally:
        for identity_source in sources.values():
            if hasattr(identity_source, "close"):
                identity_source.close()


def _run_source_poll(
    config_path: Path,
    log_level: str,
    *,
    source_name: str | None = None,
    once: bool = False,
    clock: Clock | None = None,
    unit_of_work_factory: UnitOfWorkFactory | None = None,
    engine_factory: Any | None = None,
    okta_client_factory: OktaClientFactory | None = None,
    ad_client_factory: ADClientFactory | None = None,
    pollers_override: Mapping[str, Any] | None = None,
    max_cycles: int | None = None,
) -> int:
    """Poll identity sources for changes on-demand or continuously."""
    config = load_config(config_path)
    resolved_clock = clock or SystemClock()
    logger.info(
        "identity_lifecycle_source_poll_started config=%s source=%s once=%s",
        config_path,
        source_name,
        once,
    )

    if pollers_override is not None:
        pollers: dict[str, Any] = dict(pollers_override)
        if source_name is not None and source_name not in pollers:
            raise SourceNotFoundError(f"source {source_name!r} is not configured or enabled")
        use_case = SourcePoll(pollers, resolved_clock)
        results = use_case.poll_once(source_name)
        lines = [f"Polled {len(results)} source(s):"]
        first_failure: PollCycleResult | None = None
        total_events = 0
        for res in results:
            if res.error is None:
                lines.append(
                    f"  [OK] {res.source_name}: enqueued {res.enqueued_count} event(s) "
                    f"({res.duration_ms:.1f}ms)"
                )
                total_events += res.enqueued_count
            else:
                lines.append(f"  [FAILED] {res.source_name}: {res.error} ({res.duration_ms:.1f}ms)")
                if first_failure is None:
                    first_failure = res

        lines.append(f"Total enqueued: {total_events} event(s)")
        sys.stdout.buffer.write(("\n".join(lines) + "\n").encode())

        if first_failure is not None:
            if first_failure.exception is not None:
                raise first_failure.exception
            return ExitCode.PERMANENT

        return ExitCode.SUCCESS

    engine = None
    if unit_of_work_factory is None:
        db_url = database_url()
        factory = engine_factory or build_engine
        engine = factory(db_url)

        def uow_factory(source: str = "source-poll") -> PostgresUnitOfWork:
            return PostgresUnitOfWork(engine, resolved_clock, source=source)

        active_uow: UnitOfWorkFactory = uow_factory
    else:
        active_uow = unit_of_work_factory

    built_sources: dict[str, Any] = {}
    try:
        enabled_sources = {s.source_name for s in config.identity_sources if s.enabled}
        if source_name is not None and source_name not in enabled_sources:
            raise SourceNotFoundError(f"source {source_name!r} is not configured or enabled")

        sources, schedules = _build_sources(
            config,
            unit_of_work=active_uow,
            clock=resolved_clock,
            okta_client_factory=okta_client_factory,
            ad_client_factory=ad_client_factory,
            target_source=source_name,
        )
        built_sources = dict(sources)
        pollers = {schedule.source_name: schedule.poller for schedule in schedules}

        if once:
            use_case = SourcePoll(pollers, resolved_clock)
            results = use_case.poll_once(source_name)
            lines = [f"Polled {len(results)} source(s):"]
            first_failure = None
            total_events = 0
            for res in results:
                if res.error is None:
                    lines.append(
                        f"  [OK] {res.source_name}: enqueued {res.enqueued_count} event(s) "
                        f"({res.duration_ms:.1f}ms)"
                    )
                    total_events += res.enqueued_count
                else:
                    lines.append(
                        f"  [FAILED] {res.source_name}: {res.error} ({res.duration_ms:.1f}ms)"
                    )
                    if first_failure is None:
                        first_failure = res

            lines.append(f"Total enqueued: {total_events} event(s)")
            sys.stdout.buffer.write(("\n".join(lines) + "\n").encode())

            if first_failure is not None:
                if first_failure.exception is not None:
                    raise first_failure.exception
                return ExitCode.PERMANENT

            return ExitCode.SUCCESS

        stopping = False

        def request_stop(signum: int, frame: Any) -> None:
            nonlocal stopping
            logger.info("source_poll_stop_requested signal=%s", signum)
            stopping = True

        previous_handlers: dict[signal.Signals, Any] = {}
        for signum in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(ValueError):
                previous_handlers[signum] = signal.signal(signum, request_stop)

        poll_due = _poll_due_sources(schedules)
        cycles = 0
        logger.info("source_poll_loop_started sources=%s", tuple(pollers.keys()))
        try:
            while not stopping:
                poll_due()
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    break
                time.sleep(0.5)
            return ExitCode.SUCCESS
        finally:
            for sig, handler in previous_handlers.items():
                with contextlib.suppress(ValueError):
                    signal.signal(sig, handler)

    finally:
        for source in built_sources.values():
            if hasattr(source, "close"):
                source.close()
        if engine is not None and hasattr(engine, "dispose"):
            engine.dispose()


def _process_event(
    config: Config,
    gateway: Gateway,
    unit_of_work: UnitOfWorkFactory,
    *,
    identity_sources: Mapping[str, IdentitySource],
    clock: Clock,
) -> ProcessEvent:
    """Build the use case the worker calls, from the typed configuration."""
    return ProcessEvent(
        unit_of_work,
        gateway,
        identity_sources=identity_sources,
        group_mappings=config.group_mappings,
        team_create_if_missing={
            name: team.create_if_missing for name, team in config.teams.items()
        },
        budget_policies=config.budget_policies,
        group_budget_policies=_group_budget_policies(config),
        default_budget_policy=_default_budget_policy(config),
        enabled_sources=frozenset(identity_sources),
        clock=clock,
        grace_period_hours=config.reconciliation.grace_period_hours,
        on_equal_precedence=record_equal_precedence_failure,
        on_revocation=record_revocation_sla,
        on_processed=record_event_processed,
    )


def _group_budget_policies(config: Config) -> Mapping[tuple[str, str], str]:
    """Return the ``budget_mappings`` rules that name a group, keyed by group."""
    rules: dict[tuple[str, str], str] = {}
    for rule in config.budget_mappings:
        if isinstance(rule, GroupBudgetMapping):
            group_id = rule.group if rule.group is not None else rule.group_id
            if group_id is not None:
                rules[(rule.source, group_id)] = rule.policy
    return rules


def _default_budget_policy(config: Config) -> str:
    """Return the policy explicitly selected for design 10.7's fourth level."""
    return config.default_budget_policy


def _lease_reaper(engine: Any, clock: SystemClock) -> Callable[[], int]:
    """Return the reaper the loop calls, in its own short transaction.

        ADR-002 section 7 makes lease recovery worker-level code over the outbox
        table, not a port method, so this binds the store's plain function to a
        connection instead of adding a repository method.

        ``engine`` is ``Any`` because the root layer may not name ``sqlalchemy``
    ; the value is whatever ``build_engine`` returned, and the
        only thing used here is its ``begin`` transaction.
    """

    def reap() -> int:
        with engine.begin() as connection:
            return reap_expired_leases(connection, now=clock.now())

    return reap


PROCESS_COMMANDS: Mapping[str, Callable[[ProcessOptions], int]] = {
    "api": _run_api,
    "worker": _run_worker,
    "scheduler": _run_scheduler,
}


def _add_process_options(parser: argparse.ArgumentParser) -> None:
    """Add the two shared options to one process parser."""
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/config.yaml"),
        metavar="PATH",
        help="Path to the configuration YAML file; the worker reads it at startup.",
    )
    parser.add_argument(
        "--log-level",
        choices=LOG_LEVELS,
        default=os.environ.get("LOG_LEVEL", "INFO"),
        metavar="LEVEL",
        help="Log verbosity; the flag wins over LOG_LEVEL, which defaults to INFO.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="identity-lifecycle",
        description="Identity lifecycle service command line.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    process_help = {
        "api": "Run the API process.",
        "worker": "Run the worker process.",
        "scheduler": "Run the scheduler process.",
    }
    for name in ("api", "worker", "scheduler"):
        process_parser = subparsers.add_parser(name, help=process_help[name])
        _add_process_options(process_parser)
    subparsers.add_parser("version", help="Print the package version.")

    config_parser = subparsers.add_parser("config", help="Configuration inspection and validation.")
    config_subparsers = config_parser.add_subparsers(dest="subcommand", required=True)
    validate_parser = config_subparsers.add_parser("validate", help="Validate configuration file.")
    validate_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/config.yaml"),
        metavar="PATH",
        help="Path to the configuration YAML file to validate.",
    )

    reconcile_parser = subparsers.add_parser(
        "reconcile", help="Run a one-shot reconciliation pass."
    )
    _add_process_options(reconcile_parser)
    reconcile_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Inspect detected drift without persisting changes or outbox events.",
    )

    sync_parser = subparsers.add_parser(
        "sync", help="Manually resynchronize a single employee or user."
    )
    _add_process_options(sync_parser)
    target_group = sync_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--employee",
        metavar="ID",
        help="Target employee number to resynchronize.",
    )
    target_group.add_argument(
        "--user",
        metavar="ID",
        help="Target source user ID to resynchronize.",
    )

    audit_parser = subparsers.add_parser("audit", help="Audit event logging and export operations.")
    audit_subparsers = audit_parser.add_subparsers(dest="subcommand", required=True)
    export_parser = audit_subparsers.add_parser(
        "export", help="Export audit events matching filters in CSV or JSON."
    )
    _add_process_options(export_parser)
    export_parser.add_argument(
        "--from",
        dest="from_timestamp",
        metavar="ISO_TIMESTAMP",
        help="Start of UTC date range (ISO-8601).",
    )
    export_parser.add_argument(
        "--to",
        dest="to_timestamp",
        metavar="ISO_TIMESTAMP",
        help="End of UTC date range (ISO-8601, defaults to current time).",
    )
    audit_target_group = export_parser.add_mutually_exclusive_group(required=False)
    audit_target_group.add_argument(
        "--employee",
        metavar="ID",
        help="Filter audit events by employee number.",
    )
    audit_target_group.add_argument(
        "--user",
        metavar="ID",
        help="Filter audit events by source user ID.",
    )
    export_parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format (csv or json; default: csv).",
    )
    export_parser.add_argument(
        "--ndjson",
        action="store_true",
        default=False,
        help="Format JSON output as newline-delimited JSON.",
    )
    export_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Output file path (default: stdout).",
    )

    outbox_parser = subparsers.add_parser(
        "outbox", help="Outbox queue inspection and replay operations."
    )
    outbox_subparsers = outbox_parser.add_subparsers(dest="subcommand", required=True)
    replay_parser = outbox_subparsers.add_parser(
        "replay", help="Replay a dead or settled outbox row by ID or event ID."
    )
    _add_process_options(replay_parser)
    replay_parser.add_argument(
        "--id",
        required=True,
        metavar="UUID",
        help="Outbox row ID or event UUID to replay.",
    )

    source_parser = subparsers.add_parser(
        "source", help="Identity source connectivity and polling operations."
    )
    source_subparsers = source_parser.add_subparsers(dest="subcommand", required=True)
    check_parser = source_subparsers.add_parser(
        "check", help="Check connectivity and read permissions for configured identity sources."
    )
    _add_process_options(check_parser)
    check_parser.add_argument(
        "--source",
        dest="source_name",
        default=None,
        metavar="NAME",
        help="Specific identity source name to check (checks all enabled sources if omitted).",
    )

    poll_parser = source_subparsers.add_parser(
        "poll", help="Poll identity sources for changes and enqueue outbox events."
    )
    _add_process_options(poll_parser)
    poll_parser.add_argument(
        "--source",
        dest="source_name",
        default=None,
        metavar="NAME",
        help="Specific identity source name to poll (polls all enabled sources if omitted).",
    )
    poll_parser.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Run a single polling cycle across changes/pages and exit.",
    )

    return parser


def _reject_invalid_environment_log_level(parser: argparse.ArgumentParser, resolved: str) -> None:
    """Reject an invalid ``LOG_LEVEL`` default, which ``argparse`` does not check.

    ``choices`` validates only a value written on the command line; a default is
    stored verbatim. The flag wins over the variable, so the variable is checked
    only when its value is the one that was resolved.
    """
    environment_level = os.environ.get("LOG_LEVEL", "INFO")
    if resolved == environment_level and environment_level not in LOG_LEVELS:
        parser.error(
            f"argument --log-level: invalid choice: {environment_level!r} "
            f"(choose from {', '.join(LOG_LEVELS)})"
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run one command and return its exit code; never call ``sys.exit``."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "version":
        # Write the bytes directly: a text stream translates "\n" to the platform
        # line ending, so `identity-lifecycle version` would not be the six bytes
        # "0.1.0\n" on Windows, which is what ADR-007 section 2 promises a script.
        sys.stdout.buffer.write(f"{__version__}\n".encode())
        return ExitCode.SUCCESS

    try:
        if args.command == "config" and args.subcommand == "validate":
            return _run_config_validate(args.config)

        assert hasattr(args, "log_level")
        _reject_invalid_environment_log_level(parser, args.log_level)
        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format="%(asctime)s %(levelname)s %(message)s",
        )

        if args.command == "reconcile":
            return _run_reconcile(args.config, args.log_level, dry_run=args.dry_run)

        if args.command == "sync":
            return _run_sync(
                args.config,
                args.log_level,
                employee_number=args.employee,
                source_user_id=args.user,
            )

        if args.command == "audit" and args.subcommand == "export":
            return _run_audit_export(
                args.config,
                args.log_level,
                from_timestamp=args.from_timestamp,
                to_timestamp=args.to_timestamp,
                employee_number=args.employee,
                source_user_id=args.user,
                output_format=args.format,
                ndjson=args.ndjson,
                output_path=args.output,
            )

        if args.command == "outbox" and args.subcommand == "replay":
            return _run_outbox_replay(
                args.config,
                args.log_level,
                target_id=args.id,
            )

        if args.command == "source" and args.subcommand == "check":
            return _run_source_check(
                args.config,
                args.log_level,
                source_name=args.source_name,
            )

        if args.command == "source" and args.subcommand == "poll":
            return _run_source_poll(
                args.config,
                args.log_level,
                source_name=args.source_name,
                once=args.once,
            )

        return PROCESS_COMMANDS[args.command](
            ProcessOptions(config_path=args.config, log_level=args.log_level)
        )
    except ProcessNotImplemented as error:
        # Bytes again, so the one diagnostic line is 79 bytes ending in "\n".
        sys.stderr.buffer.write(
            f"identity-lifecycle: error=permanent phase={error.phase} "
            f"command={error.command} detail=not_implemented\n".encode()
        )
        return ExitCode.PERMANENT
    except ConfigError as error:
        # a configuration failure is exit 3 and is not
        # restarted. ``ConfigError``'s own message names the key and the reason.
        sys.stderr.buffer.write(f"identity-lifecycle: {error}\n".encode())
        return ExitCode.CONFIG
    except PermanentError as error:
        sys.stderr.buffer.write(
            (
                f"identity-lifecycle: error=permanent type={type(error).__name__} "
                f"detail={error}\n"
            ).encode()
        )
        return ExitCode.PERMANENT
    except RetryableError as error:
        sys.stderr.buffer.write(
            (
                f"identity-lifecycle: error=retryable type={type(error).__name__} "
                f"detail={error}\n"
            ).encode()
        )
        return ExitCode.RETRYABLE
