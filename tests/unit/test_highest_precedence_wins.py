"""The highest precedence mapping wins, globally across sources.

``decide_access`` is a pure function over the mappings and the memberships the
caller read. These tests pin the winner, the two ways a mapping stops being a
candidate (``enabled: false`` and a disabled source), the membership match, and
the fact that input order cannot change the decision.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from dataclasses import FrozenInstanceError
from enum import StrEnum
from pathlib import Path

import pytest

from identity_lifecycle.domain.models import SourceGroup
from identity_lifecycle.domain.policy import (
    AccessDecision,
    Candidate,
    DecisionOutcome,
    GroupMapping,
    decide_access,
)

pytestmark = pytest.mark.unit

POLICY_MODULE = (
    Path(__file__).resolve().parents[2] / "src" / "identity_lifecycle" / "domain" / "policy.py"
)

#: The module's whole import set: the standard library plus the two domain
#: modules design 15.2 names. A new import needs a review that widens this
#: literal. ADR-012's engine rejects the ten database/socket names
#: mechanically; this pin is the review trigger for the stdlib names ADR-012
#: section 4 still leaves admitted in `domain` (os, pathlib, io, ssl).
#: T-021 widened it by `INACTIVE`, `Entitlement`, `LiteLLMAccount` and `Person`
#: because `desired_access`'s signature names those three models and the status
#: vocabulary lives in `models.py`; D-116 approved exactly those four names.
EXPECTED_IMPORTS = {
    "__future__.annotations",
    "collections.abc.Sequence",
    "dataclasses.dataclass",
    "enum.StrEnum",
    "identity_lifecycle.domain.errors.PermanentError",
    "identity_lifecycle.domain.models.INACTIVE",
    "identity_lifecycle.domain.models.Entitlement",
    "identity_lifecycle.domain.models.LiteLLMAccount",
    "identity_lifecycle.domain.models.Person",
    "identity_lifecycle.domain.models.SourceGroup",
}

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
OKTA_USER = GroupMapping(
    source="corp-okta",
    source_group_id="group-okta-users",
    role="internal_user",
    team="ai-platform",
    precedence=10,
)
TRIAL = GroupMapping(
    source="corp-ad",
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


def _import_targets(source: str) -> set[str]:
    """Return every absolute import target in ``source`` as ``module.name``."""
    targets: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "policy.py uses absolute imports only"
            targets.update(f"{node.module}.{alias.name}" for alias in node.names)
    return targets


def test_the_highest_precedence_mapping_wins() -> None:
    decision = decide_access(
        mappings=[USER, ADMIN],
        memberships=[_member(USER), _member(ADMIN)],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert decision.selected == ADMIN
    assert decision.role == "proxy_admin"
    assert decision.team == "ai-platform"
    assert decision.precedence == 100
    assert decision.reason == "highest_precedence"
    assert [candidate.mapping for candidate in decision.candidates] == [ADMIN, USER]
    assert [candidate.selected for candidate in decision.candidates] == [True, False]


def test_precedence_is_global_across_sources() -> None:
    okta_admin = dataclasses.replace(ADMIN, source="corp-okta", source_group_id="group-okta-admins")

    decision = decide_access(
        mappings=[USER, okta_admin],
        memberships=[_member(USER), _member(okta_admin)],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert decision.selected is not None
    assert decision.selected.source == "corp-okta"
    assert decision.selected.role == "proxy_admin"
    assert decision.precedence == 100


def test_a_disabled_mapping_is_ignored() -> None:
    disabled_admin = dataclasses.replace(ADMIN, enabled=False)

    decision = decide_access(
        mappings=[disabled_admin, USER],
        memberships=[_member(disabled_admin), _member(USER)],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert decision.selected == USER
    assert decision.precedence == 10
    assert decision.candidates == (Candidate(mapping=USER, selected=True),)


def test_a_mapping_from_a_disabled_source_is_not_a_candidate() -> None:
    decision = decide_access(
        mappings=[ADMIN, OKTA_USER],
        memberships=[_member(ADMIN), _member(OKTA_USER)],
        enabled_sources=frozenset({"corp-okta"}),
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert decision.selected == OKTA_USER
    assert decision.precedence == 10
    assert [candidate.mapping for candidate in decision.candidates] == [OKTA_USER]


def test_only_current_memberships_are_candidates() -> None:
    unheld = GroupMapping(
        source="corp-ad",
        source_group_id="group-retired",
        role="internal_user",
        team="ai-platform",
        precedence=50,
    )
    unmapped = SourceGroup(source="corp-ad", source_group_id="group-unmapped", name="unmapped")

    decision = decide_access(
        mappings=[ADMIN, USER, unheld],
        memberships=[_member(ADMIN), unmapped],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.GRANTED
    assert decision.selected == ADMIN
    assert decision.candidates == (Candidate(mapping=ADMIN, selected=True),)


def test_a_membership_matches_only_its_own_source() -> None:
    okta_mapping = GroupMapping(
        source="corp-okta",
        source_group_id="group-users",
        role="internal_user",
        team="ai-platform",
        precedence=10,
    )
    ad_membership = SourceGroup(source="corp-ad", source_group_id="group-users", name="users")

    decision = decide_access(
        mappings=[okta_mapping],
        memberships=[ad_membership],
        enabled_sources=ENABLED_SOURCES,
    )

    assert decision.outcome is DecisionOutcome.NOT_ENTITLED
    assert decision.candidates == ()


def test_the_decision_does_not_depend_on_input_order() -> None:
    mappings = [ADMIN, USER, TRIAL]
    memberships = [_member(ADMIN), _member(USER), _member(TRIAL)]

    forward = decide_access(mappings, memberships, ENABLED_SOURCES)
    backward = decide_access(list(reversed(mappings)), list(reversed(memberships)), ENABLED_SOURCES)

    assert dataclasses.asdict(forward) == dataclasses.asdict(backward)
    assert [candidate.mapping.precedence for candidate in forward.candidates] == [100, 10, 1]


def test_a_decision_cannot_be_mutated_after_it_is_made() -> None:
    decision = decide_access([ADMIN], [_member(ADMIN)], ENABLED_SOURCES)
    assert decision.selected is not None

    with pytest.raises(FrozenInstanceError):
        decision.reason = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        decision.candidates[0].selected = False  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        decision.selected.role = "changed"  # type: ignore[misc]


def test_the_three_outcomes_are_the_only_outcomes() -> None:
    assert issubclass(DecisionOutcome, StrEnum)
    assert {outcome.value for outcome in DecisionOutcome} == {
        "granted",
        "not_entitled",
        "failed",
    }
    # ADR-003 section 3 writes the audit decision as `failed`, so the enum's
    # value is the audit vocabulary, not a second spelling.
    assert DecisionOutcome.FAILED == "failed"
    with pytest.raises(ValueError):
        DecisionOutcome("denied")


#: The field sets of the ticket's "Types this ticket introduces", as literals.
#: ``AccessDecision`` has no ``budget`` field: T-020 returns its own resolution
#: type, and the decision stays an access policy.
DECISION_TYPE_FIELDS = {
    "GroupMapping": {"source", "source_group_id", "role", "team", "precedence", "enabled"},
    "Candidate": {"mapping", "selected"},
    "AccessDecision": {
        "outcome",
        "selected",
        "role",
        "team",
        "precedence",
        "reason",
        "candidates",
    },
}

DECISION_TYPES = {
    "GroupMapping": GroupMapping,
    "Candidate": Candidate,
    "AccessDecision": AccessDecision,
}


@pytest.mark.parametrize("name", sorted(DECISION_TYPE_FIELDS))
def test_each_decision_type_carries_exactly_its_documented_fields(name: str) -> None:
    model = DECISION_TYPES[name]

    assert dataclasses.is_dataclass(model)
    # `is_dataclass` is inherited by an undecorated subclass, so require the
    # decorator's own namespace as well.
    assert "__dataclass_fields__" in vars(model)
    assert model.__dataclass_params__.frozen
    assert {field.name for field in dataclasses.fields(model)} == DECISION_TYPE_FIELDS[name]


def test_the_decision_takes_no_event_and_no_read_complete_flag() -> None:
    # the candidate set comes from the memberships the caller
    # read, so there is no event parameter to read a payload from. Section 4: an
    # incomplete read never reaches this function, so there is no flag either.
    assert list(inspect.signature(decide_access).parameters) == [
        "mappings",
        "memberships",
        "enabled_sources",
    ]


def test_the_policy_module_imports_only_the_standard_library_and_domain() -> None:
    assert _import_targets(POLICY_MODULE.read_text(encoding="utf-8")) == EXPECTED_IMPORTS


def test_the_import_scanner_sees_an_import_it_must_reject() -> None:
    # Negative control: a scanner that finds nothing would pass the test above
    # forever, including on a module that imports json.
    source = "import json\nfrom identity_lifecycle.domain.models import SourceGroup\n"

    assert _import_targets(source) == {
        "json",
        "identity_lifecycle.domain.models.SourceGroup",
    }
