"""A move rewrites the role and team the selected mapping names.

A move is a grant whose account already exists. The decision has already picked
the winning mapping, so ``desired_access`` only has to carry that mapping's role
and team onto the existing account and leave the person's ``person_id`` alone.
These tests pin the update, the team's source — the mapping, never the old
account or a constant — the role-only change, and the case
where the mapping already describes the account.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from identity_lifecycle.domain.models import (
    ACTIVE,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceGroup,
)
from identity_lifecycle.domain.policy import (
    AccessAction,
    AccessDecision,
    GroupMapping,
    decide_access,
    desired_access,
)

pytestmark = pytest.mark.unit

ADMIN = GroupMapping(
    source="corp-ad",
    source_group_id="group-admins",
    role="proxy_admin",
    team="ai-platform",
    precedence=100,
)
USER = GroupMapping(
    source="corp-ad",
    source_group_id="group-users",
    role="internal_user",
    team="ai-platform",
    precedence=10,
)
RESEARCH = GroupMapping(
    source="corp-okta",
    source_group_id="group-research",
    role="internal_user_viewer",
    team="research",
    precedence=50,
)
ENABLED_SOURCES = frozenset({"corp-ad", "corp-okta"})

PERSON = Person(
    person_id="person-1",
    employee_number="E10001",
    email="ada@example.com",
    display_name="Ada Lovelace",
    status=ACTIVE,
)


def _member(mapping: GroupMapping) -> SourceGroup:
    """The membership a person holds when they are in ``mapping``'s group."""
    return SourceGroup(
        source=mapping.source,
        source_group_id=mapping.source_group_id,
        name="membership",
    )


def _decision(*mappings: GroupMapping) -> AccessDecision:
    """The grant the policy returns when the person is in exactly these groups."""
    return decide_access(
        mappings=list(mappings),
        memberships=[_member(mapping) for mapping in mappings],
        enabled_sources=ENABLED_SOURCES,
    )


def _account(role: str = "internal_user", team: str = "ai-platform") -> LiteLLMAccount:
    """The gateway state as last read back, before the move."""
    return LiteLLMAccount(
        user_id="user-1",
        status="active",
        role=role,
        team=team,
        budget=50.0,
        keys=("key-1",),
    )


def _entitlement(role: str = "internal_user", team: str = "ai-platform") -> Entitlement:
    """The entitlement in force, which the caller audits as the old access."""
    return Entitlement(
        person_id=PERSON.person_id,
        role=role,
        team=team,
        budget_policy="standard",
        source="corp-ad",
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
    )


def test_a_move_between_groups_changes_role_and_team() -> None:
    decision = _decision(ADMIN)

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=_account(role="internal_user", team="ai-platform"),
        previous=_entitlement(role="internal_user", team="ai-platform"),
    )

    assert result.action is AccessAction.UPDATE
    assert result.role == "proxy_admin"
    assert result.team == "ai-platform"
    assert result.person_id == PERSON.person_id
    assert result.reason == "highest_precedence"


def test_the_team_comes_from_the_selected_mapping() -> None:
    # The person is in both groups, the account's team matches the loser, and
    # the winner names a different team: only the mapping can supply "research".
    decision = _decision(RESEARCH, USER)
    account = _account(role="internal_user", team="ai-platform")

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=account,
        previous=_entitlement(),
    )

    assert decision.selected == RESEARCH
    assert result.team == RESEARCH.team == "research"
    assert result.team != account.team
    assert result.team != USER.team


def test_a_move_that_keeps_the_team_still_updates_the_role() -> None:
    decision = _decision(ADMIN)

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=_account(role="internal_user", team="ai-platform"),
        previous=_entitlement(),
    )

    assert result.action is AccessAction.UPDATE
    assert result.role == "proxy_admin"
    assert result.team == "ai-platform"


def test_a_move_that_changes_nothing_is_no_change() -> None:
    decision = _decision(USER)

    result = desired_access(
        decision=decision,
        person=PERSON,
        account=_account(role="internal_user", team="ai-platform"),
        previous=_entitlement(),
    )

    assert result.action is AccessAction.NO_CHANGE
    assert result.role is None
    assert result.team is None
    assert result.person_id == PERSON.person_id
    assert result.reason == decision.reason != ""
