"""Grace-period account deletion and rehire cancellation.

Tests pin:
1. Revocation sets `delete_after` on `litellm_accounts` per `grace_period_hours`.
2. Rehire before expiration cancels pending deletion (`delete_after = None`), reactivates
   `person_id`, and issues current entitlements without duplicate accounts.
3. Reconcile in dry-run mode detects expired grace periods without deleting.
4. Reconcile in live mode deletes expired users from gateway and database and records audit events.
5. Non-expired accounts are preserved.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.models import ACTIVE, INACTIVE
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork

pytestmark = pytest.mark.unit

SOURCE = "corp-ad"
USERS_GROUP = "ai-platform-users"
TEAM = "ai-platform"

MAPPING = GroupMapping(
    source=SOURCE,
    source_group_id=USERS_GROUP,
    role="internal_user",
    team=TEAM,
    precedence=10,
)
BUDGET = BudgetPolicy(max_budget=100.0, budget_duration="30d")


def _event(event_type: EventType, *, source_user_id: str = "u-1") -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        source=SOURCE,
        source_event_id=f"src-{uuid4()}",
        type=event_type,
        occurred_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
        person=EventPerson(source_user_id=source_user_id, employee_number="E10001"),
        group=EventGroup(source_group_id=USERS_GROUP, name=USERS_GROUP),
    )


class Harness:
    """Wiring helper using the in-memory store and fakes."""

    def __init__(self, *, grace_period_hours: int = 24) -> None:
        self.clock = FakeClock(now=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC))
        self.store = InMemoryStore()
        self.gateway = FakeGateway()
        self.source = FakeIdentitySource(
            source=SOURCE,
            users={
                "u-1": IdentityUser(
                    source_user_id="u-1",
                    employee_number="E10001",
                    email="u1@example.com",
                    display_name="User One",
                    enabled=True,
                )
            },
            groups={USERS_GROUP: ["u-1"]},
        )

        def uow_factory(src: str) -> InMemoryUnitOfWork:
            return InMemoryUnitOfWork(self.store, self.clock, source=src)

        self.uow_factory = uow_factory
        self.grace_period_hours = grace_period_hours
        self.ingest = IngestEvent(uow_factory, enabled_sources=frozenset({SOURCE}))
        self.process = ProcessEvent(
            uow_factory,
            self.gateway,
            {SOURCE: self.source},
            group_mappings=[MAPPING],
            team_create_if_missing={TEAM: True},
            budget_policies={"standard": BUDGET},
            group_budget_policies={(SOURCE, USERS_GROUP): "standard"},
            default_budget_policy="standard",
            enabled_sources=frozenset({SOURCE}),
            clock=self.clock,
            grace_period_hours=grace_period_hours,
        )
        self.reconcile = Reconcile(
            unit_of_work=uow_factory,
            gateway=self.gateway,
            identity_sources={SOURCE: self.source},
            clock=self.clock,
            group_mappings=[MAPPING],
            grace_period_hours=grace_period_hours,
        )

    def run(self, event: CanonicalEvent) -> Settlement:
        outcome = self.ingest.ingest(event)
        assert outcome is EnqueueOutcome.INSERTED
        return self.process.process(event)


def test_revocation_sets_delete_after_deadline() -> None:
    harness = Harness(grace_period_hours=48)
    # Join first
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))
    assert harness.store.delete_after.get(person_id) is None

    # Leave: remove from group
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.run(_event(EventType.GROUP_MEMBER_REMOVED))

    expected_delete_after = harness.clock.now() + timedelta(hours=48)
    assert harness.store.delete_after.get(person_id) == expected_delete_after
    assert harness.store.audit[-1].action == "revoke"
    # User is not deleted from gateway yet
    assert person_id in harness.gateway.accounts
    # But keys were revoked
    assert harness.gateway.writes[-1] == "revoke_keys"


def test_rehire_cancels_pending_deletion_and_reactivates_account() -> None:
    harness = Harness(grace_period_hours=24)
    # Join
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))
    assert harness.store.delete_after.get(person_id) is not None
    assert harness.store.persons[person_id].status == INACTIVE

    # Advance clock by 10 hours (well within 24h grace period)
    harness.clock.advance(10 * 3600.0)

    # Rehire: enable user and re-add to group
    harness.source.enable_user("u-1")
    harness.source.add_to_group(USERS_GROUP, "u-1")
    harness.run(_event(EventType.USER_UPDATED))

    # Pending deletion cancelled
    assert harness.store.delete_after.get(person_id) is None
    # Person reactivated
    assert harness.store.persons[person_id].status == ACTIVE
    # Gateway updated
    assert harness.gateway.writes[-1] == "update_user"
    assert harness.store.audit[-1].action == "reactivate"


def test_no_change_preserves_pending_deletion() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.run(_event(EventType.GROUP_MEMBER_REMOVED))
    deadline = harness.store.delete_after[person_id]

    # Another remove event arrives: NO_CHANGE
    harness.run(_event(EventType.GROUP_MEMBER_REMOVED))
    assert harness.store.delete_after[person_id] == deadline


def test_reconciliation_dry_run_detects_expired_grace_period() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))

    # Advance clock past grace period (25 hours)
    harness.clock.advance(25 * 3600.0)

    result = harness.reconcile.reconcile(dry_run=True)
    expired_drifts = [d for d in result.drifts if d.kind == "grace_period_expired"]
    assert len(expired_drifts) == 1
    assert expired_drifts[0].user_id == "u-1"

    # Gateway and account row NOT touched in dry run
    assert person_id in harness.gateway.accounts
    assert person_id in harness.store.accounts
    assert person_id in harness.store.delete_after


def test_reconciliation_live_sweeper_deletes_expired_user() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))

    # Advance clock past grace period (25 hours)
    harness.clock.advance(25 * 3600.0)

    result = harness.reconcile.reconcile(dry_run=False)
    expired_drifts = [d for d in result.drifts if d.kind == "grace_period_expired"]
    assert len(expired_drifts) == 1

    # Gateway user deleted
    assert person_id not in harness.gateway.accounts
    assert "delete_user" in harness.gateway.writes

    # Stored account and pending deletion removed
    assert person_id not in harness.store.accounts
    assert person_id not in harness.store.delete_after

    # Audit row written
    expire_audits = [a for a in harness.store.audit if a.decision == "grace_period_expired"]
    assert len(expire_audits) == 1
    assert expire_audits[0].action == "delete_user"
    assert expire_audits[0].target == person_id


def test_non_expired_grace_period_is_not_swept() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))

    # Advance clock only 10 hours (grace period is 24h)
    harness.clock.advance(10 * 3600.0)

    result = harness.reconcile.reconcile(dry_run=False)
    expired_drifts = [d for d in result.drifts if d.kind == "grace_period_expired"]
    assert len(expired_drifts) == 0

    # User remains on gateway and store
    assert person_id in harness.gateway.accounts
    assert person_id in harness.store.accounts


def test_gateway_retryable_error_retains_row_and_reports_failure() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))

    # Advance clock past grace period
    harness.clock.advance(25 * 3600.0)

    # Queue retryable failure on delete_user
    def on_call(name: str) -> None:
        if name == "delete_user":
            raise RetryableError("LiteLLM gateway 503")

    harness.gateway.on_call = on_call

    result = harness.reconcile.reconcile(dry_run=False)

    # Row must be retained in litellm_accounts and delete_after
    assert person_id in harness.store.accounts
    assert person_id in harness.store.delete_after
    # Deletion failures reported in result
    assert len(result.deletion_failures) == 1
    assert result.deletion_failures[0].user_id == person_id
    # No success audit row written claiming delete_user
    expire_audits = [
        a
        for a in harness.store.audit
        if a.decision == "grace_period_expired" and a.action == "delete_user"
    ]
    assert len(expire_audits) == 0


def test_gateway_permanent_error_retains_row_and_audits_failure() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))

    # Advance clock past grace period
    harness.clock.advance(25 * 3600.0)

    # Queue permanent failure (not not-found) on delete_user
    def on_call(name: str) -> None:
        if name == "delete_user":
            raise PermanentError("LiteLLM 403 Forbidden")

    harness.gateway.on_call = on_call

    result = harness.reconcile.reconcile(dry_run=False)

    # Row retained
    assert person_id in harness.store.accounts
    # Deletion failure reported
    assert len(result.deletion_failures) == 1
    assert result.deletion_failures[0].user_id == person_id
    # No success audit row; failure audit written
    success_audits = [
        a
        for a in harness.store.audit
        if a.decision == "grace_period_expired" and a.action == "delete_user"
    ]
    assert len(success_audits) == 0
    failure_audits = [
        a
        for a in harness.store.audit
        if a.decision == "grace_period_expired" and a.action == "delete_user_failed"
    ]
    assert len(failure_audits) == 1


def test_gateway_not_found_removes_row_and_audits_already_absent() -> None:
    harness = Harness(grace_period_hours=24)
    harness.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(harness.store.persons.keys()))

    # Leave
    harness.source.remove_from_group(USERS_GROUP, "u-1")
    harness.source.disable_user("u-1")
    harness.run(_event(EventType.USER_DISABLED))

    # Advance clock past grace period
    harness.clock.advance(25 * 3600.0)

    # Simulate already deleted on gateway: remove from gateway.accounts
    del harness.gateway.accounts[person_id]

    result = harness.reconcile.reconcile(dry_run=False)

    # Row removed locally
    assert person_id not in harness.store.accounts
    assert person_id not in harness.store.delete_after
    # No deletion failure reported
    assert len(result.deletion_failures) == 0
    # Audit row written with reason="already_absent"
    expire_audits = [
        a
        for a in harness.store.audit
        if a.decision == "grace_period_expired" and a.action == "delete_user"
    ]
    assert len(expire_audits) == 1
    assert expire_audits[0].reason == "already_absent"
