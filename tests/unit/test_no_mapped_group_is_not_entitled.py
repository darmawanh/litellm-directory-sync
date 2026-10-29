"""No mapped group after a complete read is a decision, not an error.

ADR-003 section 4 makes "no match" a not-entitled decision and makes a failed
read something else entirely: it never reaches ``decide_access``. These tests
pin the decision's shape, that it is returned rather than raised, and that a
mapping which is disabled cannot stand in for a match.
"""

from __future__ import annotations

import dataclasses

import pytest

from identity_lifecycle.domain.models import SourceGroup
from identity_lifecycle.domain.policy import (
    AccessDecision,
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
ENABLED_SOURCES = frozenset({"corp-ad", "corp-okta"})


def _member(mapping: GroupMapping) -> SourceGroup:
    """The membership a person holds when they are in ``mapping``'s group."""
    return SourceGroup(
        source=mapping.source,
        source_group_id=mapping.source_group_id,
        name="membership",
    )


def test_no_mapped_group_is_not_entitled() -> None:
    # The read succeeded and returned nothing: that is the complete-read case
    # ADR-003 section 4 calls not entitled.
    decision = decide_access([ADMIN], [], ENABLED_SOURCES)

    assert decision.outcome is DecisionOutcome.NOT_ENTITLED
    assert decision.reason == "no_mapped_group"
    assert decision.selected is None
    assert (decision.role, decision.team, decision.precedence) == (None, None, None)
    assert decision.candidates == ()


def test_a_membership_outside_every_mapping_is_not_entitled() -> None:
    unmapped = SourceGroup(source="corp-ad", source_group_id="group-unmapped", name="unmapped")

    decision = decide_access([ADMIN], [unmapped], ENABLED_SOURCES)

    assert decision.outcome is DecisionOutcome.NOT_ENTITLED
    assert decision.reason == "no_mapped_group"
    assert decision.candidates == ()


def test_not_entitled_is_a_decision_not_an_error() -> None:
    decision = decide_access([ADMIN], [], ENABLED_SOURCES)

    # Returned, and not an exception instance: only the tie has an error type.
    assert isinstance(decision, AccessDecision)
    assert not isinstance(decision, Exception)
    assert decision.outcome is DecisionOutcome.NOT_ENTITLED


def test_a_disabled_mapping_alone_is_not_entitled() -> None:
    disabled_admin = dataclasses.replace(ADMIN, enabled=False)

    decision = decide_access([disabled_admin], [_member(disabled_admin)], ENABLED_SOURCES)

    assert decision.outcome is DecisionOutcome.NOT_ENTITLED
    assert decision.reason == "no_mapped_group"
    assert decision.candidates == ()
