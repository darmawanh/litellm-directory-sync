"""A rehire reactivates the same person and applies the current entitlement.

Design 10.5 step 2: "If the person exists and is inactive, reactivate the same
``person_id``." A rehire is therefore a grant for an inactive person whose
account exists, not a create and not a new person. These tests pin the action,
the reused id (never the account's ``user_id``), the current mapping's role and
team rather than the stale values on the old account, and the ADR-005 section 2
case where the person carries no ``employee_number``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from identity_lifecycle.domain.models import (
    INACTIVE,
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
ENABLED_SOURCES = frozenset({"corp-ad", "corp-okta"})


def _member(mapping: GroupMapping) -> SourceGroup:
    """The membership a person holds when they are in ``mapping``'s group."""
    return SourceGroup(
        source=mapping.source,
        source_group_id=mapping.source_group_id,
        name="membership",
    )


def _decision(mapping: GroupMapping) -> AccessDecision:
    """The grant the policy returns when the person is in ``mapping``'s group."""
    return decide_access([mapping], [_member(mapping)], ENABLED_SOURCES)


def _person(status: str = INACTIVE, employee_number: str | None = "E10001") -> Person:
    """The person row as the store holds it after a leave."""
    return Person(
        person_id="person-1",
        employee_number=employee_number,
        email="ada@example.com",
        display_name="Ada Lovelace",
        status=status,
    )


def _blocked_account(role: str = "internal_user", team: str = "ai-platform") -> LiteLLMAccount:
    """The gateway state a leave left behind: blocked, with its keys revoked."""
    return LiteLLMAccount(
        user_id="user-1",
        status="blocked",
        role=role,
        team=team,
        budget=50.0,
        keys=(),
    )


def _previous(role: str = "internal_user", team: str = "ai-platform") -> Entitlement:
    """The entitlement the leave closed."""
    return Entitlement(
        person_id="person-1",
        role=role,
        team=team,
        budget_policy="standard",
        source="corp-ad",
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=datetime(2026, 6, 1, tzinfo=UTC),
    )


def test_a_rehire_reactivates_the_same_person_id() -> None:
    person = _person()

    result = desired_access(
        decision=_decision(USER),
        person=person,
        account=_blocked_account(),
        previous=_previous(),
    )

    assert result.action is AccessAction.REACTIVATE
    assert result.person_id == person.person_id
    assert result.role == "internal_user"
    assert result.team == "ai-platform"


def test_a_rehire_applies_the_current_entitlement() -> None:
    # The old account carries a stale role and team; the decision carries the
    # mapping that applies now. Only the decision's values may reach the result.
    account = _blocked_account(role="internal_user_viewer", team="legacy-team")
    decision = _decision(ADMIN)

    result = desired_access(
        decision=decision,
        person=_person(),
        account=account,
        previous=_previous(role="internal_user_viewer", team="legacy-team"),
    )

    assert result.action is AccessAction.REACTIVATE
    assert result.role == decision.role == "proxy_admin"
    assert result.team == decision.team == "ai-platform"
    assert result.role != account.role
    assert result.team != account.team


def test_a_rehire_without_an_employee_number_still_reactivates() -> None:
    # the cross-system link is optional, never an identity.
    person = _person(employee_number=None)

    result = desired_access(
        decision=_decision(USER),
        person=person,
        account=_blocked_account(),
        previous=_previous(),
    )

    assert person.employee_number is None
    assert result.action is AccessAction.REACTIVATE
    assert result.person_id == person.person_id


def test_the_rehire_names_the_person_id_not_the_account_user_id() -> None:
    person = _person()
    account = _blocked_account()

    result = desired_access(
        decision=_decision(USER),
        person=person,
        account=account,
        previous=_previous(),
    )

    assert result.person_id == person.person_id
    assert result.person_id != account.user_id
