"""Two mappings at the highest precedence fail the event, and never guess.

A tie is a decision result, not an exception from ``decide_access``: ADR-003
section 3 has the caller audit it and then raise ``EqualPrecedenceError``. These
tests pin the failure, the absence of a fallback to the next level, the error's
family and payload, and the legal case of two mappings sharing a lower value
 (the shipped example has two at 10).
"""

from __future__ import annotations

import pytest

from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.models import SourceGroup
from identity_lifecycle.domain.policy import (
    AccessDecision,
    DecisionOutcome,
    EqualPrecedenceError,
    GroupMapping,
    decide_access,
)

pytestmark = pytest.mark.unit

ADMIN_AD = GroupMapping(
    source="corp-ad",
    source_group_id="group-admins",
    role="proxy_admin",
    team="ai-platform",
    precedence=100,
)
ADMIN_OKTA = GroupMapping(
    source="corp-okta",
    source_group_id="group-okta-admins",
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
OKTA_USER = GroupMapping(
    source="corp-okta",
    source_group_id="group-okta-users",
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


def _tied_decision() -> AccessDecision:
    """A person in two groups mapped at precedence 100, and one mapped at 10."""
    return decide_access(
        mappings=[ADMIN_AD, ADMIN_OKTA, USER],
        memberships=[_member(ADMIN_AD), _member(ADMIN_OKTA), _member(USER)],
        enabled_sources=ENABLED_SOURCES,
    )


def test_equal_highest_precedence_fails_the_event() -> None:
    decision = _tied_decision()

    assert decision.outcome is DecisionOutcome.FAILED
    assert decision.reason == "equal_precedence"
    assert decision.selected is None
    assert (decision.role, decision.team, decision.precedence) == (None, None, None)
    tied = [candidate for candidate in decision.candidates if candidate.mapping.precedence == 100]
    assert [candidate.mapping for candidate in tied] == [ADMIN_AD, ADMIN_OKTA]
    assert not any(candidate.selected for candidate in decision.candidates)


def test_a_tie_never_falls_back_to_the_next_level() -> None:
    decision = _tied_decision()

    assert decision.outcome is DecisionOutcome.FAILED
    assert decision.selected is None
    assert decision.role is None
    # The 10 is still recorded as a candidate, and it is not selected.
    assert [candidate.mapping for candidate in decision.candidates] == [
        ADMIN_AD,
        ADMIN_OKTA,
        USER,
    ]
    assert [candidate.selected for candidate in decision.candidates] == [False, False, False]


def test_two_mappings_at_a_lower_precedence_do_not_fail_the_event() -> None:
    decision = decide_access(
        mappings=[ADMIN_AD, USER, OKTA_USER],
        memberships=[_member(ADMIN_AD), _member(USER), _member(OKTA_USER)],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert decision.selected == ADMIN_AD
    assert decision.precedence == 100


def test_the_tie_is_a_permanent_typed_error() -> None:
    decision = _tied_decision()

    error = EqualPrecedenceError(decision)

    assert isinstance(error, PermanentError)
    assert not isinstance(error, RetryableError)
    # A direct subclass, not a family cousin: the retry policy branches
    # on the family, so the base must be PermanentError itself.
    assert EqualPrecedenceError.__bases__ == (PermanentError,)
    assert error.decision is decision
    assert "100" in str(error)


def test_a_tie_returns_a_decision_rather_than_raising() -> None:
    decision = decide_access(
        mappings=[ADMIN_AD, ADMIN_OKTA],
        memberships=[_member(ADMIN_AD), _member(ADMIN_OKTA)],
        enabled_sources=ENABLED_SOURCES,
    )

    # Returning is the point: the caller writes the audit row before it raises.
    assert decision.outcome is DecisionOutcome.FAILED
    with pytest.raises(EqualPrecedenceError):
        raise EqualPrecedenceError(decision)
