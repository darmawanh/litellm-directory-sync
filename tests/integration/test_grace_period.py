"""Integration tests for grace-period lifecycle and sweeper in PostgreSQL."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.domain.models import LiteLLMAccount, Person, SourceIdentity
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource

pytestmark = pytest.mark.integration

SOURCE = "corp-ad"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def test_account_store_delete_after_persistence(engine: Engine) -> None:
    clock = FakeClock(NOW)
    user_id = f"user-{uuid4()}"
    delete_after = NOW + timedelta(hours=24)

    # 1. Save account with delete_after
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.accounts.save(
            LiteLLMAccount(
                user_id=user_id,
                status="blocked",
                role="internal_user",
                team="",
                budget=50.0,
                keys=(),
            ),
            delete_after=delete_after,
        )
        uow.commit()

    # 2. Read back delete_after and list pending deletions
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        stored_deadline = uow.accounts.get_delete_after(user_id)
        assert stored_deadline is not None
        assert stored_deadline.replace(tzinfo=UTC) == delete_after

        # Before deadline: empty
        pending_early = uow.accounts.list_pending_deletions(before=NOW)
        assert user_id not in pending_early

        # On/after deadline: includes user_id
        pending_due = uow.accounts.list_pending_deletions(before=delete_after)
        assert user_id in pending_due

    # 3. Update account with delete_after=None (rehire cancellation)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.accounts.save(
            LiteLLMAccount(
                user_id=user_id,
                status="active",
                role="internal_user",
                team="ai-platform",
                budget=100.0,
                keys=(),
            ),
            delete_after=None,
        )
        uow.commit()

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.accounts.get_delete_after(user_id) is None
        assert user_id not in uow.accounts.list_pending_deletions(before=delete_after)

    # 4. Delete account
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.accounts.delete(user_id)
        uow.commit()

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.accounts.get(user_id) is None


def test_reconcile_sweeps_expired_grace_period_in_postgres(engine: Engine) -> None:
    clock = FakeClock(NOW)
    gateway = FakeGateway()
    source = FakeIdentitySource(source=SOURCE)

    expired_pid = f"p-expired-{uuid4()}"
    active_pid = f"p-active-{uuid4()}"

    # Pre-seed gateway accounts
    gateway.accounts[expired_pid] = LiteLLMAccount(
        user_id=expired_pid,
        status="blocked",
        role="internal_user",
        team="",
        budget=50.0,
        keys=(),
    )
    gateway.accounts[active_pid] = LiteLLMAccount(
        user_id=active_pid,
        status="blocked",
        role="internal_user",
        team="",
        budget=50.0,
        keys=(),
    )

    # Pre-seed database with one expired deletion and one future deletion
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        # Expired account (delete_after was 1 hour ago)
        uow.persons.save(
            Person(
                person_id=expired_pid,
                employee_number="E9001",
                email="expired@example.com",
                display_name="Expired User",
                status="inactive",
            )
        )
        uow.identities.save(
            SourceIdentity(source=SOURCE, source_user_id="dir-exp-1", person_id=expired_pid)
        )
        uow.accounts.save(
            gateway.accounts[expired_pid],
            delete_after=NOW - timedelta(hours=1),
        )

        # Future account (delete_after is in 23 hours)
        uow.persons.save(
            Person(
                person_id=active_pid,
                employee_number="E9002",
                email="future@example.com",
                display_name="Future User",
                status="inactive",
            )
        )
        uow.identities.save(
            SourceIdentity(source=SOURCE, source_user_id="dir-fut-1", person_id=active_pid)
        )
        uow.accounts.save(
            gateway.accounts[active_pid],
            delete_after=NOW + timedelta(hours=23),
        )
        uow.commit()

    reconcile = Reconcile(
        unit_of_work=lambda s: PostgresUnitOfWork(engine, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=[],
        two_miss_rule=True,
    )

    # 1. Dry run: detects expired account without deleting
    result_dry = reconcile.reconcile(dry_run=True)
    expired_drifts = [d for d in result_dry.drifts if d.kind == "grace_period_expired"]
    assert len(expired_drifts) == 1
    assert expired_drifts[0].user_id == "dir-exp-1"
    assert expired_pid in gateway.accounts

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.accounts.get(expired_pid) is not None
        assert uow.accounts.get(active_pid) is not None

    # 2. Live run: deletes expired account from gateway and PostgreSQL
    result_live = reconcile.reconcile(dry_run=False)
    assert any(d.kind == "grace_period_expired" for d in result_live.drifts)

    # Gateway state
    assert expired_pid not in gateway.accounts
    assert active_pid in gateway.accounts
    assert "delete_user" in gateway.writes

    # Database state
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.accounts.get(expired_pid) is None
        assert uow.accounts.get(active_pid) is not None

        # Verify audit row in audit_events table
        audit_entries = uow.audit.query(employee_number="E9001")
        assert len(audit_entries) >= 1
        assert any(
            e.action == "delete_user" and e.reason == "grace_period_expired" for e in audit_entries
        )
