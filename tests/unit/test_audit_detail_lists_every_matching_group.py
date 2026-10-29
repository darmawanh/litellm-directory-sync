"""The decision lists every matching group, not only the winner.

The audit record has to explain a denial and a surprise grant, so the decision
carries every candidate with its role, team, precedence and selected flag, plus
the selected result and the reason. These tests pin that detail and its stable
order.
"""

from __future__ import annotations

import pytest

from identity_lifecycle.domain.models import SourceGroup
from identity_lifecycle.domain.policy import (
    DecisionOutcome,
    GroupMapping,
    decide_access,
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
TRIAL = GroupMapping(
    source="corp-okta",
    source_group_id="group-trial",
    role="internal_user_viewer",
    team="ai-platform",
    precedence=1,
)
ENABLED_SOURCES = frozenset({"corp-ad", "corp-okta"})


def _member(mapping: GroupMapping) -> SourceGroup:
    """The membership a person holds when they are in ``mapping``'s group."""
    return SourceGroup(
        source=mapping.source,
        source_group_id=mapping.source_group_id,
        name="membership",
    )


def test_every_matching_group_appears_in_the_decision() -> None:
    decision = decide_access(
        mappings=[TRIAL, USER, ADMIN],
        memberships=[_member(TRIAL), _member(USER), _member(ADMIN)],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert [
        (candidate.mapping.role, candidate.mapping.team, candidate.mapping.precedence)
        for candidate in decision.candidates
    ] == [
        ("proxy_admin", "ai-platform", 100),
        ("internal_user", "ai-platform", 10),
        ("internal_user_viewer", "ai-platform", 1),
    ]
    assert [candidate.selected for candidate in decision.candidates] == [True, False, False]
    assert decision.role == "proxy_admin"
    assert decision.team == "ai-platform"
    assert decision.precedence == 100
    assert decision.reason == "highest_precedence"


def test_a_tie_lists_every_tied_candidate() -> None:
    okta_admin = GroupMapping(
        source="corp-okta",
        source_group_id="group-okta-admins",
        role="proxy_admin",
        team="ai-platform",
        precedence=100,
    )

    decision = decide_access(
        mappings=[ADMIN, okta_admin, USER],
        memberships=[_member(ADMIN), _member(okta_admin), _member(USER)],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.FAILED
    tied = [candidate for candidate in decision.candidates if candidate.mapping.precedence == 100]
    assert {candidate.mapping.source for candidate in tied} == {"corp-ad", "corp-okta"}
    assert len(decision.candidates) == 3
    assert [candidate.selected for candidate in decision.candidates] == [False, False, False]
