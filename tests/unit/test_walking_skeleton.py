"""The walking skeleton end to end with fakes (10.1-10.3).

One fake event goes in, one gateway account and one audit row come out; a
duplicate produces neither a second account nor a second row; a leave revokes; a
move rewrites role and team; a retryable gateway failure retries; a permanent one
does not; and SIGTERM stops claiming while the batch in hand finishes.

Every test drives the real ``IngestEvent``, ``ProcessEvent``, and ``OutboxWorker``
over the in-memory unit of work, so the path under test is the production one
(design 15.4: fakes implement the ports, never a second implementation of a use
case). ``FakeGateway`` records what it wrote and reads its own state back, so an
echoing fake cannot make a broken write look applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest

from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement
from identity_lifecycle.workers.outbox_worker import OutboxWorker
from tests.fixtures.fakes import (
    FakeClock,
    FakeGateway,
    FakeIdentitySource,
    InMemoryStore,
    InMemoryUnitOfWork,
    event_rows,
)

pytestmark = pytest.mark.unit

SOURCE = "corp-ad"
USERS_GROUP = "group-users"
ADMINS_GROUP = "group-admins"
USER_MAPPING = GroupMapping(
    source=SOURCE,
    source_group_id=USERS_GROUP,
    role="internal_user",
    team="ai-platform",
    precedence=10,
)
ADMIN_MAPPING = GroupMapping(
    source=SOURCE,
    source_group_id=ADMINS_GROUP,
    role="proxy_admin",
    team="ai-platform",
    precedence=100,
)
BUDGET = BudgetPolicy(max_budget=50.0, budget_duration="30d")


def _user(enabled: bool = True, employee_number: str | None = "E20002") -> IdentityUser:
    return IdentityUser(
        source_user_id="ad-1",
        employee_number=employee_number,
        email="ada@example.com",
        display_name="Ada Lovelace",
        enabled=enabled,
    )


def _event(
    event_type: EventType,
    *,
    event_id: UUID | None = None,
    group_id: str = USERS_GROUP,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4() if event_id is None else event_id,
        source=SOURCE,
        source_event_id="source-event-1",
        type=event_type,
        occurred_at=FakeClock().now(),
        person=EventPerson(source_user_id="ad-1", employee_number="E20002"),
        group=EventGroup(source_group_id=group_id, name="AI-Platform-Users"),
    )


@dataclass
class Skeleton:
    """The wired walking skeleton: one store, one clock, one gateway, one source."""

    clock: FakeClock = field(default_factory=FakeClock)
    store: InMemoryStore = field(default_factory=InMemoryStore)
    gateway: FakeGateway = field(default_factory=FakeGateway)
    source: FakeIdentitySource = field(
        default_factory=lambda: FakeIdentitySource(
            source=SOURCE,
            users={"ad-1": _user()},
            groups={USERS_GROUP: ["ad-1"]},
        )
    )

    def __post_init__(self) -> None:
        def unit_of_work(source_name: str) -> InMemoryUnitOfWork:
            return InMemoryUnitOfWork(self.store, self.clock, source=source_name)

        self.unit_of_work = unit_of_work
        self.ingest = IngestEvent(unit_of_work, enabled_sources=frozenset({SOURCE}))
        self.process = ProcessEvent(
            unit_of_work,
            self.gateway,
            {SOURCE: self.source},
            group_mappings=(USER_MAPPING, ADMIN_MAPPING),
            team_create_if_missing={"ai-platform": True},
            budget_policies={"standard": BUDGET},
            group_budget_policies={(SOURCE, USERS_GROUP): "standard"},
            default_budget_policy="standard",
            enabled_sources=frozenset({SOURCE}),
            clock=self.clock,
        )

    def run(self, event: CanonicalEvent) -> Settlement:
        """Ingest then process, the way the hook route and the worker do."""
        assert self.ingest.ingest(event) is EnqueueOutcome.INSERTED
        return self.process.process(event)

    def worker(self, *, batch_size: int = 10, sleep: object = None) -> OutboxWorker:
        return OutboxWorker(
            self.unit_of_work,
            self.process,
            lambda: 0,
            batch_size=batch_size,
            poll_interval_seconds=0.01,
            sleep=sleep or (lambda seconds: None),  # type: ignore[arg-type]
        )


def test_join_creates_user_and_audit_row() -> None:
    skeleton = Skeleton()
    event = _event(EventType.GROUP_MEMBER_ADDED)

    settlement = skeleton.run(event)

    assert settlement is Settlement.DONE
    assert len(skeleton.store.persons) == 1
    person_id = next(iter(skeleton.store.persons))
    assert skeleton.gateway.user_ids() == (person_id,)
    account = skeleton.gateway.accounts[person_id]
    assert (account.role, account.team, account.status) == (
        "internal_user",
        "ai-platform",
        "active",
    )
    assert account.budget == 50.0
    assert [row.decision for row in skeleton.store.audit] == ["granted"]
    assert [row.action for row in skeleton.store.audit] == ["create"]
    assert skeleton.store.audit[0].target == person_id
    assert skeleton.store.audit[0].actor == SOURCE
    assert skeleton.store.audit[0].event_id == event.event_id
    assert len(skeleton.store.processed) == 1


def test_duplicate_event_produces_no_second_effect() -> None:
    skeleton = Skeleton()
    event = _event(EventType.GROUP_MEMBER_ADDED)
    skeleton.run(event)

    # The same envelope arrives again: ingest is a duplicate outcome, and the
    # worker's second pass is DONE with no write.
    assert skeleton.ingest.ingest(event) is EnqueueOutcome.DUPLICATE
    assert skeleton.process.process(event) is Settlement.DONE

    assert skeleton.gateway.writes.count("create_user") == 1
    assert len(skeleton.store.accounts) == 1
    assert len(skeleton.store.audit) == 1
    assert skeleton.source.calls.count("get_user") == 1


def test_leave_revokes_access() -> None:
    skeleton = Skeleton()
    skeleton.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(skeleton.store.persons))

    skeleton.source.remove_from_group(USERS_GROUP, "ad-1")
    settlement = skeleton.run(_event(EventType.GROUP_MEMBER_REMOVED))

    assert settlement is Settlement.DONE
    assert "revoke_keys" in skeleton.gateway.writes
    assert skeleton.gateway.accounts[person_id].team == ""
    assert skeleton.store.audit[-1].action == "revoke"
    assert skeleton.store.audit[-1].decision == "not_entitled"


def test_move_updates_role_and_team() -> None:
    skeleton = Skeleton()
    skeleton.run(_event(EventType.GROUP_MEMBER_ADDED))
    person_id = next(iter(skeleton.store.persons))

    skeleton.source.remove_from_group(USERS_GROUP, "ad-1")
    skeleton.source.add_to_group(ADMINS_GROUP, "ad-1")
    settlement = skeleton.run(_event(EventType.GROUP_MEMBER_ADDED, group_id=ADMINS_GROUP))

    assert settlement is Settlement.DONE
    account = skeleton.gateway.accounts[person_id]
    assert (account.role, account.team) == ("proxy_admin", "ai-platform")
    assert skeleton.store.audit[-1].action == "update"
    assert skeleton.store.audit[-1].reason == "highest_precedence"


def test_retryable_gateway_failure_is_retried() -> None:
    skeleton = Skeleton()
    skeleton.gateway.fail_next(RetryableError("gateway is warming up"))
    event = _event(EventType.GROUP_MEMBER_ADDED)

    assert skeleton.run(event) is Settlement.RETRYABLE
    row = event_rows(skeleton.store)[event.event_id]
    assert (row.status, row.attempts) == ("pending", 1)
    assert skeleton.store.audit == []
    assert skeleton.store.accounts == {}

    skeleton.clock.advance(5.0)
    assert skeleton.process.process(event) is Settlement.DONE
    assert event_rows(skeleton.store)[event.event_id].status == "done"
    assert len(skeleton.store.accounts) == 1
    assert len(skeleton.store.audit) == 1


def test_permanent_gateway_failure_is_not_retried() -> None:
    skeleton = Skeleton()
    skeleton.gateway.fail_next(PermanentError("team does not exist and may not be created"))
    event = _event(EventType.GROUP_MEMBER_ADDED)

    assert skeleton.run(event) is Settlement.PERMANENT
    row = event_rows(skeleton.store)[event.event_id]
    assert (row.status, row.attempts) == ("dead", 0)
    assert skeleton.store.accounts == {}

    skeleton.clock.advance(3600.0)
    with InMemoryUnitOfWork(skeleton.store, skeleton.clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (), "a dead row is never claimed again"


def test_sigterm_stops_claiming_and_finishes_in_flight() -> None:
    skeleton = Skeleton()
    first = _event(EventType.GROUP_MEMBER_ADDED)
    second = _event(EventType.GROUP_MEMBER_ADDED)
    skeleton.ingest.ingest(first)
    skeleton.ingest.ingest(second)
    worker = skeleton.worker(batch_size=1)
    skeleton.gateway.on_call = lambda name: (
        worker.request_stop() if name == "create_user" else None
    )

    worker.run()

    statuses = sorted(row.status for row in event_rows(skeleton.store).values())
    assert statuses == ["done", "pending"], "the in-flight row settles; the next is never claimed"
    assert len(skeleton.store.audit) == 1
    assert len(skeleton.store.accounts) == 1
