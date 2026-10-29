"""Unit tests for the reconciliation use case."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from identity_lifecycle.application.reconcile import Reconcile
from identity_lifecycle.domain.events import EventType
from identity_lifecycle.domain.models import LiteLLMAccount, Person, SourceIdentity
from identity_lifecycle.domain.policy import GroupMapping
from identity_lifecycle.ports.identity_source import IdentityUser
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork

pytestmark = pytest.mark.unit

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SOURCE = "corp-idp"
MAPPED_GROUP = "cn=ai-platform,ou=groups,dc=example,dc=com"


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(START)


@pytest.fixture
def gateway() -> FakeGateway:
    return FakeGateway()


@pytest.fixture
def source() -> FakeIdentitySource:
    return FakeIdentitySource(source=SOURCE)


@pytest.fixture
def group_mappings() -> list[GroupMapping]:
    return [
        GroupMapping(
            source=SOURCE,
            source_group_id=MAPPED_GROUP,
            role="internal_user",
            team="ai-platform",
            precedence=10,
        )
    ]


def test_missing_member_preprovisioning_emits_group_member_added(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # Directory user Alice is active and in mapped group, but has no LiteLLM account
    alice = IdentityUser(
        source_user_id="alice-id",
        employee_number="E1001",
        email="alice@example.com",
        display_name="Alice Smith",
        enabled=True,
    )
    source.add_user(alice)
    source.add_to_group(MAPPED_GROUP, alice.source_user_id)

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        dry_run=False,
    )

    result = reconcile.reconcile()

    assert len(result.drifts) == 1
    assert result.drifts[0].kind == "missing_preprovisioned_member"
    assert result.drifts[0].user_id == "alice-id"

    assert len(result.events_emitted) == 1
    event = result.events_emitted[0]
    assert event.type == EventType.GROUP_MEMBER_ADDED
    assert event.person is not None
    assert event.person.source_user_id == "alice-id"
    assert event.group is not None
    assert event.group.source_group_id == MAPPED_GROUP

    # Outbox received the event
    assert len(store.outbox) == 1


def test_disabled_account_active_in_gateway_emits_user_disabled(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # Directory user Bob is disabled in directory, but gateway still has active account and keys
    bob = IdentityUser(
        source_user_id="bob-id",
        employee_number="E1002",
        email="bob@example.com",
        display_name="Bob Jones",
        enabled=False,
    )
    source.add_user(bob)
    source.add_to_group(MAPPED_GROUP, bob.source_user_id)

    # Store has person and identity
    person = Person(
        person_id="p-bob",
        employee_number="E1002",
        email="bob@example.com",
        display_name="Bob Jones",
        status="active",
    )
    store.persons["p-bob"] = person
    store.identities[(SOURCE, "bob-id")] = SourceIdentity(
        source=SOURCE,
        source_user_id="bob-id",
        person_id="p-bob",
    )

    # Gateway has active account with keys
    gateway.accounts["p-bob"] = LiteLLMAccount(
        user_id="p-bob",
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=100.0,
        keys=("key-bob-1",),
    )

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        dry_run=False,
    )

    result = reconcile.reconcile()

    assert any(d.kind == "disabled_account_active" for d in result.drifts)
    disabled_events = [e for e in result.events_emitted if e.type == EventType.USER_DISABLED]
    assert len(disabled_events) == 1
    assert disabled_events[0].person is not None
    assert disabled_events[0].person.source_user_id == "bob-id"


def test_unentitled_member_with_active_keys_emits_group_member_removed(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # Charlie is enabled in directory, but NOT in any mapped group
    charlie = IdentityUser(
        source_user_id="charlie-id",
        employee_number="E1003",
        email="charlie@example.com",
        display_name="Charlie Brown",
        enabled=True,
    )
    source.add_user(charlie)

    person = Person(
        person_id="p-charlie",
        employee_number="E1003",
        email="charlie@example.com",
        display_name="Charlie Brown",
        status="active",
    )
    store.persons["p-charlie"] = person
    store.identities[(SOURCE, "charlie-id")] = SourceIdentity(
        source=SOURCE,
        source_user_id="charlie-id",
        person_id="p-charlie",
    )
    gateway.accounts["p-charlie"] = LiteLLMAccount(
        user_id="p-charlie",
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=100.0,
        keys=("key-charlie-1",),
    )

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        dry_run=False,
    )

    result = reconcile.reconcile()

    assert any(d.kind == "unentitled_member_active" for d in result.drifts)
    removed_events = [e for e in result.events_emitted if e.type == EventType.GROUP_MEMBER_REMOVED]
    assert len(removed_events) == 1
    assert removed_events[0].person is not None
    assert removed_events[0].person.source_user_id == "charlie-id"


def test_orphaned_user_requires_two_consecutive_misses_before_deletion(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # Dave was previously provisioned in LiteLLM and stored in DB, but is now missing from directory
    person = Person(
        person_id="p-dave",
        employee_number="E1004",
        email="dave@example.com",
        display_name="Dave Miller",
        status="active",
    )
    store.persons["p-dave"] = person
    store.identities[(SOURCE, "dave-id")] = SourceIdentity(
        source=SOURCE,
        source_user_id="dave-id",
        person_id="p-dave",
    )
    gateway.accounts["p-dave"] = LiteLLMAccount(
        user_id="p-dave",
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=100.0,
        keys=(),
    )

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        two_miss_rule=True,
        dry_run=False,
    )

    # Run 1: First miss
    result1 = reconcile.reconcile()

    # Discrepancy recorded in miss table with count 1
    assert len(result1.misses_recorded) == 1
    assert result1.misses_recorded[0].person_id == "p-dave"
    assert result1.misses_recorded[0].miss_count == 1

    # NO delete event emitted on the first miss
    delete_events1 = [e for e in result1.events_emitted if e.type == EventType.USER_DELETED]
    assert len(delete_events1) == 0
    assert len(store.outbox) == 0

    # Stored miss table holds count 1
    assert store.misses[("p-dave", SOURCE)].miss_count == 1

    # Run 2: Second consecutive miss
    clock.advance(3600)  # Move time 1 hour
    result2 = reconcile.reconcile()

    # Miss incremented to 2
    assert len(result2.misses_recorded) == 1
    assert result2.misses_recorded[0].miss_count == 2
    assert store.misses[("p-dave", SOURCE)].miss_count == 2

    # Two-miss rule satisfied: USER_DELETED event emitted!
    delete_events2 = [e for e in result2.events_emitted if e.type == EventType.USER_DELETED]
    assert len(delete_events2) == 1
    assert delete_events2[0].person is not None
    assert delete_events2[0].person.source_user_id == "dave-id"
    assert len(store.outbox) == 1


def test_orphaned_user_reappearing_clears_miss_record(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # First, Dave had a miss
    person = Person(
        person_id="p-dave",
        employee_number="E1004",
        email="dave@example.com",
        display_name="Dave Miller",
        status="active",
    )
    store.persons["p-dave"] = person
    store.identities[(SOURCE, "dave-id")] = SourceIdentity(
        source=SOURCE,
        source_user_id="dave-id",
        person_id="p-dave",
    )

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        two_miss_rule=True,
        dry_run=False,
    )
    reconcile.reconcile()
    assert ("p-dave", SOURCE) in store.misses

    # Now Dave reappears in directory!
    dave = IdentityUser(
        source_user_id="dave-id",
        employee_number="E1004",
        email="dave@example.com",
        display_name="Dave Miller",
        enabled=True,
    )
    source.add_user(dave)
    source.add_to_group(MAPPED_GROUP, dave.source_user_id)

    # Reconcile again: Dave is active and in group
    result = reconcile.reconcile()

    # Dave's miss record is cleared
    assert "p-dave" in result.misses_cleared
    assert ("p-dave", SOURCE) not in store.misses


def test_allowlist_user_is_never_deleted_or_recorded_as_miss(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # svc-ci is an internal service account in LiteLLM not in directory
    gateway.accounts["svc-ci"] = LiteLLMAccount(
        user_id="svc-ci",
        status="active",
        role="internal_user",
        team="system",
        budget=0.0,
        keys=("key-ci",),
    )

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        allowlist=["svc-ci", "svc-monitoring"],
        dry_run=False,
    )

    result = reconcile.reconcile()

    # Never treated as drift or miss
    assert len(result.drifts) == 0
    assert len(result.events_emitted) == 0
    assert len(result.misses_recorded) == 0
    assert len(store.outbox) == 0


def test_dry_run_mode_emits_no_events_and_makes_no_database_changes(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    alice = IdentityUser(
        source_user_id="alice-id",
        employee_number="E1001",
        email="alice@example.com",
        display_name="Alice Smith",
        enabled=True,
    )
    source.add_user(alice)
    source.add_to_group(MAPPED_GROUP, alice.source_user_id)

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        dry_run=True,
    )

    result = reconcile.reconcile()

    assert result.dry_run is True
    assert len(result.drifts) == 1
    assert len(result.events_emitted) == 1

    # But outbox in store has ZERO rows because dry run did not commit
    assert len(store.outbox) == 0


def test_fake_gateway_user_with_no_local_account_is_not_deleted(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # A gateway user exists directly on LiteLLM gateway, but is NOT in store.accounts
    gateway.accounts["external-user-123"] = LiteLLMAccount(
        user_id="external-user-123",
        status="active",
        role="internal_user",
        team="external",
        budget=10.0,
        keys=("key-ext",),
    )

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        dry_run=False,
    )

    result = reconcile.reconcile()

    # Reconcile must NOT enumerate gateway users and must NOT delete external-user-123
    assert len(result.drifts) == 0
    assert len(result.events_emitted) == 0
    assert "external-user-123" in gateway.accounts


def test_orphaned_local_account_not_deleted_on_first_miss_deleted_on_second(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    # An account exists in store.accounts, but no Person row exists in store.persons
    orphan_id = "orphan-account-456"
    store.accounts[orphan_id] = LiteLLMAccount(
        user_id=orphan_id,
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=10.0,
        keys=(),
    )
    gateway.accounts[orphan_id] = store.accounts[orphan_id]

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        two_miss_rule=True,
        dry_run=False,
    )

    # First reconciliation pass: 1st miss recorded, NOT deleted
    result1 = reconcile.reconcile()
    assert len(result1.events_emitted) == 0
    assert len(result1.misses_recorded) == 1
    assert result1.misses_recorded[0].person_id == orphan_id
    assert result1.misses_recorded[0].miss_count == 1
    assert orphan_id in gateway.accounts

    # Advance clock
    clock.advance(3600.0)

    # Second reconciliation pass: 2nd miss recorded, deleted!
    result2 = reconcile.reconcile()
    assert len(result2.events_emitted) == 1
    assert result2.events_emitted[0].type == EventType.USER_DELETED
    assert result2.events_emitted[0].person.source_user_id == orphan_id


def test_returning_person_clears_miss(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    user_id = "user-temp-missing"
    person_id = "person-1"
    user = IdentityUser(
        source_user_id=user_id,
        employee_number="E-999",
        email="temp@example.com",
        display_name="Temp Missing",
        enabled=True,
    )
    store.persons[person_id] = Person(
        person_id=person_id,
        employee_number="E-999",
        email="temp@example.com",
        display_name="Temp Missing",
        status="active",
    )
    store.identities[(SOURCE, user_id)] = SourceIdentity(
        source=SOURCE,
        source_user_id=user_id,
        person_id=person_id,
    )
    store.accounts[person_id] = LiteLLMAccount(
        user_id=person_id,
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=10.0,
        keys=(),
    )
    gateway.accounts[person_id] = store.accounts[person_id]

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        two_miss_rule=True,
        dry_run=False,
    )

    result1 = reconcile.reconcile()
    assert len(result1.misses_recorded) == 1
    assert (person_id, SOURCE) in store.misses

    # Now user returns to directory in mapped group
    source.add_user(user)
    source.add_to_group(MAPPED_GROUP, user_id)

    result2 = reconcile.reconcile()
    assert person_id in result2.misses_cleared
    assert (person_id, SOURCE) not in store.misses


def test_allowlisted_account_with_missing_person_is_never_deleted(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    account_id = "allowlisted-admin"
    store.accounts[account_id] = LiteLLMAccount(
        user_id=account_id,
        status="active",
        role="admin",
        team="ops",
        budget=100.0,
        keys=(),
    )
    gateway.accounts[account_id] = store.accounts[account_id]

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        allowlist=[account_id],
        two_miss_rule=True,
        dry_run=False,
    )

    result = reconcile.reconcile()
    assert len(result.drifts) == 0
    assert len(result.misses_recorded) == 0
    assert len(result.events_emitted) == 0
    assert account_id in gateway.accounts


def test_dry_run_records_no_misses_and_emits_no_events(
    store: InMemoryStore,
    clock: FakeClock,
    gateway: FakeGateway,
    source: FakeIdentitySource,
    group_mappings: list[GroupMapping],
) -> None:
    person_id = "orphan-dry-run"
    store.accounts[person_id] = LiteLLMAccount(
        user_id=person_id,
        status="active",
        role="internal_user",
        team="ai-platform",
        budget=10.0,
        keys=(),
    )
    gateway.accounts[person_id] = store.accounts[person_id]

    reconcile = Reconcile(
        unit_of_work=lambda s: InMemoryUnitOfWork(store, clock, source=s),
        gateway=gateway,
        identity_sources={SOURCE: source},
        clock=clock,
        group_mappings=group_mappings,
        two_miss_rule=True,
        dry_run=True,
    )

    result = reconcile.reconcile()
    assert len(result.drifts) == 1
    assert len(result.events_emitted) == 0
    assert len(store.misses) == 0
    assert len(store.outbox) == 0
