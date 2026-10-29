"""Unit tests for ProcessEvent membership pagination and precedence."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.domain.events import (
    CanonicalEvent,
    EventGroup,
    EventPerson,
    EventType,
)
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement
from tests.fixtures.fakes import FakeClock, FakeGateway, FakeIdentitySource
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork

pytestmark = pytest.mark.unit

SOURCE = "corp-ad"
GROUP_A = "group-a"
GROUP_B = "group-b"
TEAM_A = "team-a"
TEAM_B = "team-b"

MAPPING_A = GroupMapping(
    source=SOURCE,
    source_group_id=GROUP_A,
    role="user",
    team=TEAM_A,
    precedence=10,
)
MAPPING_B = GroupMapping(
    source=SOURCE,
    source_group_id=GROUP_B,
    role="admin",
    team=TEAM_B,
    precedence=20,
)
BUDGET = BudgetPolicy(max_budget=100.0, budget_duration="30d")


def _event(*, source_user_id: str, group_id: str) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        source=SOURCE,
        source_event_id=f"src-{uuid4()}",
        type=EventType.GROUP_MEMBER_ADDED,
        occurred_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
        person=EventPerson(source_user_id=source_user_id, employee_number=f"E-{source_user_id}"),
        group=EventGroup(source_group_id=group_id, name=group_id),
    )


class Harness:
    def __init__(
        self,
        *,
        users: list[IdentityUser],
        groups: dict[str, list[str]],
        group_members_page_size: int | None = None,
        group_mappings: list[GroupMapping] | None = None,
    ) -> None:
        self.clock = FakeClock(now=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC))
        self.store = InMemoryStore()
        self.gateway = FakeGateway()
        self.source = FakeIdentitySource(
            source=SOURCE,
            users={u.source_user_id: u for u in users},
            groups=groups,
            group_members_page_size=group_members_page_size,
        )
        mappings = group_mappings or [MAPPING_A]

        def uow_factory(src: str) -> InMemoryUnitOfWork:
            return InMemoryUnitOfWork(self.store, self.clock, source=src)

        self.uow_factory = uow_factory
        self.ingest = IngestEvent(uow_factory, enabled_sources=frozenset({SOURCE}))
        self.process = ProcessEvent(
            uow_factory,
            self.gateway,
            {SOURCE: self.source},
            group_mappings=mappings,
            team_create_if_missing={TEAM_A: True, TEAM_B: True},
            budget_policies={"standard": BUDGET},
            group_budget_policies={
                (SOURCE, GROUP_A): "standard",
                (SOURCE, GROUP_B): "standard",
            },
            default_budget_policy="standard",
            enabled_sources=frozenset({SOURCE}),
            clock=self.clock,
            grace_period_hours=24,
        )

    def run(self, event: CanonicalEvent) -> Settlement:
        outcome = self.ingest.ingest(event)
        assert outcome is EnqueueOutcome.INSERTED
        return self.process.process(event)


def test_user_on_page_2_of_mapped_group_stays_entitled() -> None:
    # GROUP_A has ["u-1", "u-2"]. With page_size=1, u-2 is on page 2.
    u1 = IdentityUser(
        source_user_id="u-1",
        employee_number="E-u-1",
        email="u1@example.com",
        display_name="U1",
        enabled=True,
    )
    u2 = IdentityUser(
        source_user_id="u-2",
        employee_number="E-u-2",
        email="u2@example.com",
        display_name="U2",
        enabled=True,
    )

    harness = Harness(
        users=[u1, u2],
        groups={GROUP_A: ["u-1", "u-2"]},
        group_members_page_size=1,
        group_mappings=[MAPPING_A],
    )

    event = _event(source_user_id="u-2", group_id=GROUP_A)
    settlement = harness.run(event)

    assert settlement == Settlement.DONE
    ident = harness.store.identities.get((SOURCE, "u-2"))
    assert ident is not None
    account = harness.gateway.accounts.get(ident.person_id)
    assert account is not None
    assert account.team == TEAM_A


def test_user_absent_from_all_pages_is_unentitled() -> None:
    u1 = IdentityUser(
        source_user_id="u-1",
        employee_number="E-u-1",
        email="u1@example.com",
        display_name="U1",
        enabled=True,
    )
    u2 = IdentityUser(
        source_user_id="u-2",
        employee_number="E-u-2",
        email="u2@example.com",
        display_name="U2",
        enabled=True,
    )
    u3 = IdentityUser(
        source_user_id="u-3",
        employee_number="E-u-3",
        email="u3@example.com",
        display_name="U3",
        enabled=True,
    )

    harness = Harness(
        users=[u1, u2, u3],
        groups={GROUP_A: ["u-1", "u-2"]},
        group_members_page_size=1,
        group_mappings=[MAPPING_A],
    )

    event = _event(source_user_id="u-3", group_id=GROUP_A)
    settlement = harness.run(event)

    assert settlement == Settlement.DONE
    ident = harness.store.identities.get((SOURCE, "u-3"))
    if ident is not None:
        assert harness.gateway.accounts.get(ident.person_id) is None
    else:
        assert len(harness.gateway.accounts) == 0


def test_paging_stops_after_match_and_continues_to_next_mapping() -> None:
    # GROUP_A has ["u-1", "u-other-1", "u-other-2"]. u-1 is on page 1 of 3.
    # GROUP_B has ["u-other-3", "u-1"]. u-1 is on page 2 of 2.
    u1 = IdentityUser(
        source_user_id="u-1",
        employee_number="E-u-1",
        email="u1@example.com",
        display_name="U1",
        enabled=True,
    )
    other1 = IdentityUser(
        source_user_id="u-other-1",
        employee_number="E-o1",
        email="o1@example.com",
        display_name="O1",
        enabled=True,
    )
    other2 = IdentityUser(
        source_user_id="u-other-2",
        employee_number="E-o2",
        email="o2@example.com",
        display_name="O2",
        enabled=True,
    )
    other3 = IdentityUser(
        source_user_id="u-other-3",
        employee_number="E-o3",
        email="o3@example.com",
        display_name="O3",
        enabled=True,
    )

    harness = Harness(
        users=[u1, other1, other2, other3],
        groups={
            GROUP_A: ["u-1", "u-other-1", "u-other-2"],
            GROUP_B: ["u-other-3", "u-1"],
        },
        group_members_page_size=1,
        group_mappings=[MAPPING_A, MAPPING_B],
    )

    event = _event(source_user_id="u-1", group_id=GROUP_A)
    settlement = harness.run(event)

    assert settlement == Settlement.DONE
    # For GROUP_A, u-1 is on page 1, so it should stop paging after 1 call for GROUP_A.
    # For GROUP_B, u-1 is on page 2, so it takes 2 calls. Total calls = 1 + 2 = 3 (not 3 + 2 = 5).
    get_member_calls = [c for c in harness.source.calls if c == "get_group_members"]
    assert len(get_member_calls) == 3


def test_winning_group_on_later_page_resolves_precedence_correctly() -> None:
    # GROUP_A has precedence 10. u-1 is on page 1.
    # GROUP_B has precedence 20. u-1 is on page 2.
    u1 = IdentityUser(
        source_user_id="u-1",
        employee_number="E-u-1",
        email="u1@example.com",
        display_name="U1",
        enabled=True,
    )
    other = IdentityUser(
        source_user_id="u-other",
        employee_number="E-o",
        email="o@example.com",
        display_name="O",
        enabled=True,
    )

    harness = Harness(
        users=[u1, other],
        groups={
            GROUP_A: ["u-1"],
            GROUP_B: ["u-other", "u-1"],
        },
        group_members_page_size=1,
        group_mappings=[MAPPING_A, MAPPING_B],
    )

    event = _event(source_user_id="u-1", group_id=GROUP_B)
    settlement = harness.run(event)

    assert settlement == Settlement.DONE
    ident = harness.store.identities.get((SOURCE, "u-1"))
    assert ident is not None
    account = harness.gateway.accounts.get(ident.person_id)
    assert account is not None
    # Precedence 20 (TEAM_B) must win over Precedence 10 (TEAM_A)
    assert account.team == TEAM_B
