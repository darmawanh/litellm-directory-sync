"""Integration tests for reconciliation against PostgreSQL."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.engine import Engine

from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.domain.events import EventType
from identity_lifecycle.domain.models import LiteLLMAccount, Person, SourceIdentity
from identity_lifecycle.domain.policy import GroupMapping
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import Settlement
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource

pytestmark = pytest.mark.integration

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SOURCE = "corp-idp"
MAPPED_GROUP = "cn=ai-platform,ou=groups,dc=example,dc=com"


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def test_reconciliation_miss_store_lifecycle_in_postgres(engine: Engine) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    # 1. Setup person to satisfy FK
    with PostgresUnitOfWork(engine, FakeClock(now), source=SOURCE) as uow:
        uow.persons.save(
            Person(
                person_id="p-reconcile-1",
                employee_number="E2001",
                email="user1@example.com",
                display_name="User One",
                status="active",
            )
        )
        uow.commit()

    # 2. Record first miss
    with PostgresUnitOfWork(engine, FakeClock(now), source=SOURCE) as uow:
        assert uow.misses.get("p-reconcile-1", SOURCE) is None
        miss1 = uow.misses.record_miss("p-reconcile-1", SOURCE, now)
        assert miss1.miss_count == 1
        uow.commit()

    with PostgresUnitOfWork(engine, FakeClock(now), source=SOURCE) as uow:
        read1 = uow.misses.get("p-reconcile-1", SOURCE)
        assert read1 is not None
        assert read1.miss_count == 1
        assert read1.person_id == "p-reconcile-1"
        assert read1.source == SOURCE

    # 3. Record second miss (increments counter)
    later = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
    with PostgresUnitOfWork(engine, FakeClock(later), source=SOURCE) as uow:
        miss2 = uow.misses.record_miss("p-reconcile-1", SOURCE, later)
        assert miss2.miss_count == 2
        uow.commit()

    with PostgresUnitOfWork(engine, FakeClock(later), source=SOURCE) as uow:
        read2 = uow.misses.get("p-reconcile-1", SOURCE)
        assert read2 is not None
        assert read2.miss_count == 2
        all_misses = uow.misses.list_all()
        assert len(all_misses) == 1
        assert all_misses[0].miss_count == 2

    # 4. Clear miss
    with PostgresUnitOfWork(engine, FakeClock(later), source=SOURCE) as uow:
        uow.misses.clear("p-reconcile-1", SOURCE)
        uow.commit()

    with PostgresUnitOfWork(engine, FakeClock(later), source=SOURCE) as uow:
        assert uow.misses.get("p-reconcile-1", SOURCE) is None
        assert len(uow.misses.list_all()) == 0


def test_reconcile_emits_outbox_events_and_persists_misses_in_postgres(engine: Engine) -> None:
    clock = FakeClock(START)
    gateway = FakeGateway()
    source = FakeIdentitySource(source=SOURCE)
    group_mappings = [
        GroupMapping(
            source=SOURCE,
            source_group_id=MAPPED_GROUP,
            role="internal_user",
            team="ai-platform",
            precedence=10,
        )
    ]

    # Pre-seed an existing person in DB whose directory account was removed
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.persons.save(
            Person(
                person_id="p-orphan",
                employee_number="E9999",
                email="orphan@example.com",
                display_name="Orphaned User",
                status="active",
            )
        )
        uow.identities.save(
            SourceIdentity(
                source=SOURCE,
                source_user_id="orphan-dir-id",
                person_id="p-orphan",
            )
        )
        uow.accounts.save(
            LiteLLMAccount(
                user_id="p-orphan",
                status="active",
                role="internal_user",
                team="ai-platform",
                budget=50.0,
                keys=(),
            )
        )
        uow.commit()

    # Directory has one new user Alice (missing pre-provisioning) and NOT orphan
    alice = IdentityUser(
        source_user_id="alice-dir-id",
        employee_number="E1001",
        email="alice@example.com",
        display_name="Alice Smith",
        enabled=True,
    )
    source.add_user(alice)
    source.add_to_group(MAPPED_GROUP, alice.source_user_id)

    reconcile = Reconcile(
        unit_of_work=lambda s: PostgresUnitOfWork(engine, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        two_miss_rule=True,
        dry_run=False,
    )

    # Run 1
    result1 = reconcile.reconcile()

    # Alice should trigger a GROUP_MEMBER_ADDED event in outbox
    add_events = [e for e in result1.events_emitted if e.type == EventType.GROUP_MEMBER_ADDED]
    assert len(add_events) == 1
    assert add_events[0].person is not None
    assert add_events[0].person.source_user_id == "alice-dir-id"

    # Orphan should have 1 miss recorded in PostgreSQL
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        miss1 = uow.misses.get("p-orphan", SOURCE)
        assert miss1 is not None
        assert miss1.miss_count == 1

        # Check outbox in PostgreSQL: Alice's event is claimed/present
        claimed = uow.outbox.claim(10)
        assert len(claimed) == 1
        assert claimed[0].type == EventType.GROUP_MEMBER_ADDED
        uow.outbox.settle(claimed[0].event_id, Settlement.DONE)
        uow.commit()

    # Alice is now active on gateway so she does not re-drift on Run 2
    gateway.accounts["alice-dir-id"] = LiteLLMAccount(
        user_id="alice-dir-id",
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=50.0,
        keys=(),
    )

    # Run 2
    clock.advance(3600)
    result2 = reconcile.reconcile()

    # Orphan now has 2 consecutive misses -> USER_DELETED event emitted into PostgreSQL outbox
    delete_events = [e for e in result2.events_emitted if e.type == EventType.USER_DELETED]
    assert len(delete_events) == 1
    assert delete_events[0].person is not None
    assert delete_events[0].person.source_user_id == "orphan-dir-id"

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        miss2 = uow.misses.get("p-orphan", SOURCE)
        assert miss2 is not None
        assert miss2.miss_count == 2

        claimed2 = uow.outbox.claim(10)
        assert len(claimed2) == 1
        assert claimed2[0].type == EventType.USER_DELETED
