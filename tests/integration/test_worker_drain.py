"""The worker drains a real outbox row against a migrated database.

Decision 3 of the ticket: while no vendor adapter exists, the honest reading of
"drains a row against a test database" is the real loop, the real
``PostgresUnitOfWork``, the real migrations, and the fake gateway. Every
component below the gateway seam is production code, so this proves the claim
and settle transactions against PostgreSQL rather than an in-memory dictionary.

The loop is stopped by the sleep hook: the first pass claims and processes the
row, the second finds nothing due and sleeps, and that sleep asks the worker to
stop. No thread, no signal, no wall-clock wait.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

import identity_lifecycle.main as cli
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.application.unit_of_work_factory import UnitOfWorkFactory
from identity_lifecycle.config import Config
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping
from identity_lifecycle.ports.gateway import Gateway
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome
from identity_lifecycle.workers.outbox_worker import OutboxWorker
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_client
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource
from tests.fixtures.okta_http import FakeOktaHTTP
from tests.unit.test_config_loader import ENV, EXAMPLE

pytestmark = pytest.mark.integration

SOURCE = "corp-ad"
GROUP = "group-ai-platform"
START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
BUDGET = BudgetPolicy(max_budget=50.0, budget_duration="30d")


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def _event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        source=SOURCE,
        source_event_id="source-event-1",
        type=EventType.GROUP_MEMBER_ADDED,
        occurred_at=START,
        person=EventPerson(source_user_id="object-guid-1", employee_number="E20002"),
        group=EventGroup(source_group_id=GROUP, name="AI-Platform-Users"),
    )


def _source() -> FakeIdentitySource:
    return FakeIdentitySource(
        source=SOURCE,
        users={
            "object-guid-1": IdentityUser(
                source_user_id="object-guid-1",
                employee_number="E20002",
                email="ada@example.com",
                display_name="Ada Lovelace",
                enabled=True,
            )
        },
        groups={GROUP: ["object-guid-1"]},
    )


def test_the_worker_command_drains_a_row_against_the_migrated_database(
    engine: Engine,
    migrated_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock(START)
    gateway = FakeGateway()
    okta_http = FakeOktaHTTP()
    okta_http.group_id = "00gEXAMPLE0000000000"

    def unit_of_work(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    event = _event()
    ingest = IngestEvent(unit_of_work, enabled_sources=frozenset({SOURCE}))
    assert ingest.ingest(event) is EnqueueOutcome.INSERTED

    config_path = tmp_path / "config.yaml"
    config_path.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("DATABASE_URL", migrated_database)
    monkeypatch.setenv("LOG_LEVEL", "INFO")

    monkeypatch.setattr(cli, "build_gateway", lambda config: gateway)
    monkeypatch.setattr(cli, "_build_okta_client", lambda _config: okta_http.oauth_client())
    fake_ad = FakeADConnection()
    fake_ad.group_dn = "CN=AI-Platform-Users,OU=Groups,OU=AI Platform,DC=example,DC=com"
    monkeypatch.setattr(cli, "_build_ad_client", lambda _config: create_fake_ad_client(fake_ad))

    def build_test_process(
        _config: Config,
        wired_gateway: Gateway,
        factory: UnitOfWorkFactory,
        *,
        identity_sources: object,
        clock: object,
    ) -> ProcessEvent:
        return ProcessEvent(
            factory,
            wired_gateway,
            {SOURCE: _source()},
            group_mappings=(
                GroupMapping(
                    source=SOURCE,
                    source_group_id=GROUP,
                    role="internal_user",
                    team="ai-platform",
                    precedence=10,
                ),
            ),
            team_create_if_missing={"ai-platform": True},
            budget_policies={"standard": BUDGET},
            group_budget_policies={(SOURCE, GROUP): "standard"},
            default_budget_policy="standard",
            enabled_sources=frozenset({SOURCE}),
            clock=clock,
        )

    monkeypatch.setattr(cli, "_process_event", build_test_process)

    worker_holder: list[OutboxWorker] = []
    real_worker = cli.OutboxWorker

    def build_worker(*args, **kwargs) -> OutboxWorker:
        kwargs["sleep"] = lambda _seconds: worker_holder[0].request_stop()
        worker = real_worker(
            *args,
            **kwargs,
        )
        worker_holder.append(worker)
        return worker

    monkeypatch.setattr(cli, "OutboxWorker", build_worker)

    assert cli.main(["worker", "--config", str(config_path)]) == cli.ExitCode.SUCCESS
    assert gateway.writes == ["ensure_team", "create_user"]
    assert gateway.closed

    with engine.connect() as connection:
        status = connection.execute(
            sqlalchemy.text("select status from identity_event_outbox where event_id = :id"),
            {"id": event.event_id},
        ).scalar_one()
        person_id = connection.execute(
            sqlalchemy.text("select person_id from persons")
        ).scalar_one()
        audit = (
            connection.execute(
                sqlalchemy.text(
                    "select source, actor, action, target, decision, reason from audit_events"
                )
            )
            .mappings()
            .one()
        )
        entitlement = (
            connection.execute(
                sqlalchemy.text(
                    "select person_id, role, team, budget_policy, source, effective_to"
                    " from entitlements"
                )
            )
            .mappings()
            .one()
        )

    assert status == "done"
    assert gateway.user_ids() == (person_id,)
    assert (audit["source"], audit["actor"], audit["action"]) == (SOURCE, SOURCE, "create")
    assert (audit["target"], audit["decision"], audit["reason"]) == (
        person_id,
        "granted",
        "highest_precedence",
    )
    assert (entitlement["person_id"], entitlement["role"], entitlement["team"]) == (
        person_id,
        "internal_user",
        "ai-platform",
    )
    assert (entitlement["budget_policy"], entitlement["source"]) == ("standard", SOURCE)
    assert entitlement["effective_to"] is None


def test_the_drained_row_is_not_claimed_again(engine: Engine) -> None:
    clock = FakeClock(START)

    def unit_of_work(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, clock, source=source)

    event = _event()
    IngestEvent(unit_of_work, enabled_sources=frozenset({SOURCE})).ingest(event)

    with unit_of_work(SOURCE) as uow:
        assert uow.outbox.claim(10) == (event,)
        uow.outbox.settle(event.event_id, outcome=_done())
        uow.commit()

    with unit_of_work(SOURCE) as uow:
        assert uow.outbox.claim(10) == ()


def _done() -> object:
    from identity_lifecycle.ports.unit_of_work import Settlement

    return Settlement.DONE
