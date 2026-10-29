"""The override levels beat the config levels's order.

``resolve_budget`` takes four candidates the caller already looked up and returns
the first that exists: the person override, the group override, the
``budget_mappings`` rule, then the default. These tests pin that order, the audit
``reason`` each level writes, and the shape of the two types the ticket adds.
They also pin what the function must *not* have: no ``AccessDecision`` parameter,
because a group is an access decision, not a budget value (P-009, ADR-003
section 6), and four keyword-only candidates, so the two overrides cannot be
transposed.
"""

from __future__ import annotations

import dataclasses
import inspect
from enum import StrEnum

import pytest

from identity_lifecycle.domain.policy import (
    BudgetPolicy,
    BudgetResolution,
    BudgetSource,
    resolve_budget,
)

pytestmark = pytest.mark.unit

PERSON = BudgetPolicy(max_budget=500.0, budget_duration="30d")
GROUP = BudgetPolicy(max_budget=250.0, budget_duration="30d")
MAPPING = BudgetPolicy(max_budget=100.0, budget_duration="30d")
DEFAULT = BudgetPolicy(max_budget=50.0, budget_duration="30d")


def test_a_person_override_beats_every_other_source() -> None:
    resolution = resolve_budget(
        person_override=PERSON,
        group_override=GROUP,
        config_mapping=MAPPING,
        default=DEFAULT,
    )

    assert resolution.source is BudgetSource.PERSON_OVERRIDE
    assert resolution.policy == PERSON
    assert resolution.policy.max_budget == 500.0
    assert resolution.reason == "person_override"


def test_a_group_override_beats_the_config_mapping() -> None:
    resolution = resolve_budget(
        person_override=None,
        group_override=GROUP,
        config_mapping=MAPPING,
        default=DEFAULT,
    )

    assert resolution.source is BudgetSource.GROUP_OVERRIDE
    assert resolution.policy == GROUP
    assert resolution.policy.max_budget == 250.0
    assert resolution.reason == "group_override"


def test_the_config_mapping_beats_the_default() -> None:
    resolution = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=MAPPING,
        default=DEFAULT,
    )

    assert resolution.source is BudgetSource.CONFIG_MAPPING
    assert resolution.policy == MAPPING
    assert resolution.reason == "config_mapping"


def test_the_order_is_the_designs_order_not_the_budget_size() -> None:
    # Design 10.7 fixes a sequence, not a maximum: the first level present wins
    # whatever it is worth, so a generous default cannot displace a mapping.
    generous_default = BudgetPolicy(max_budget=1000.0, budget_duration="30d")
    modest_mapping = BudgetPolicy(max_budget=10.0, budget_duration="30d")

    resolution = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=modest_mapping,
        default=generous_default,
    )

    assert resolution.source is BudgetSource.CONFIG_MAPPING
    assert resolution.policy.max_budget == 10.0
    assert resolution.policy == modest_mapping


def test_a_zero_budget_person_override_is_still_an_override() -> None:
    # `0.0` is a policy, not an absence: a truthiness check would let the group
    # override win and silently raise the person's budget.
    zero = BudgetPolicy(max_budget=0.0, budget_duration="30d")

    resolution = resolve_budget(
        person_override=zero,
        group_override=GROUP,
        config_mapping=MAPPING,
        default=DEFAULT,
    )

    assert resolution.source is BudgetSource.PERSON_OVERRIDE
    assert resolution.policy.max_budget == 0.0


@pytest.mark.parametrize(
    ("person_override", "group_override", "config_mapping", "expected"),
    [
        (PERSON, GROUP, MAPPING, BudgetSource.PERSON_OVERRIDE),
        (None, GROUP, MAPPING, BudgetSource.GROUP_OVERRIDE),
        (None, None, MAPPING, BudgetSource.CONFIG_MAPPING),
        (None, None, None, BudgetSource.DEFAULT),
    ],
)
def test_every_resolution_names_the_level_that_won(
    person_override: BudgetPolicy | None,
    group_override: BudgetPolicy | None,
    config_mapping: BudgetPolicy | None,
    expected: BudgetSource,
) -> None:
    resolution = resolve_budget(
        person_override=person_override,
        group_override=group_override,
        config_mapping=config_mapping,
        default=DEFAULT,
    )

    assert resolution.source is expected
    assert resolution.reason == expected.value
    assert resolution.reason != ""


def test_the_reason_matches_the_selected_source() -> None:
    group = resolve_budget(
        person_override=None,
        group_override=GROUP,
        config_mapping=MAPPING,
        default=DEFAULT,
    )
    fallback = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=None,
        default=DEFAULT,
    )

    assert group.reason == group.source.value == "group_override"
    assert fallback.reason == fallback.source.value == "default"
    assert group.reason != BudgetSource.PERSON_OVERRIDE.value


def test_the_four_levels_are_the_only_levels() -> None:
    assert issubclass(BudgetSource, StrEnum)
    assert {source.value for source in BudgetSource} == {
        "person_override",
        "group_override",
        "config_mapping",
        "default",
    }
    # The value is the audit vocabulary, so a StrEnum comparison needs no.value.
    assert BudgetSource.PERSON_OVERRIDE == "person_override"
    with pytest.raises(ValueError):
        # A precedence reason is not a budget level.
        BudgetSource("highest_precedence")


def test_a_policy_holds_the_two_fields_fr7_names() -> None:
    assert dataclasses.is_dataclass(BudgetPolicy)
    # `is_dataclass` is inherited by an undecorated subclass, so require the
    # decorator's own namespace as well.
    assert "__dataclass_fields__" in vars(BudgetPolicy)
    assert BudgetPolicy.__dataclass_params__.frozen
    assert {field.name for field in dataclasses.fields(BudgetPolicy)} == {
        "max_budget",
        "budget_duration",
    }
    # No validator runs: the config loader owns the startup checks, and this
    # dataclass is the type.
    odd = BudgetPolicy(max_budget=-1.0, budget_duration="")
    assert (odd.max_budget, odd.budget_duration) == (-1.0, "")


def test_a_resolution_carries_the_policy_the_source_and_the_reason() -> None:
    assert dataclasses.is_dataclass(BudgetResolution)
    assert "__dataclass_fields__" in vars(BudgetResolution)
    assert BudgetResolution.__dataclass_params__.frozen
    assert {field.name for field in dataclasses.fields(BudgetResolution)} == {
        "policy",
        "source",
        "reason",
    }


def test_a_resolution_cannot_be_changed_after_it_is_made() -> None:
    resolution = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=MAPPING,
        default=DEFAULT,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        resolution.reason = "changed"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        resolution.source = BudgetSource.DEFAULT  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        resolution.policy.max_budget = 0.0  # type: ignore[misc]


def test_the_resolution_takes_four_keyword_only_candidates_and_no_decision() -> None:
    # P-009 and ADR-003 section 6: the budget is not read from an AccessDecision,
    # and the two overrides cannot be transposed because every argument is
    # keyword-only. `default` is required: a missing default is a startup
    # configuration error, not a runtime branch.
    signature = inspect.signature(resolve_budget)

    assert list(signature.parameters) == [
        "person_override",
        "group_override",
        "config_mapping",
        "default",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert signature.parameters["default"].default is inspect.Parameter.empty


def test_resolution_is_deterministic() -> None:
    first = resolve_budget(
        person_override=None,
        group_override=GROUP,
        config_mapping=MAPPING,
        default=DEFAULT,
    )
    second = resolve_budget(
        person_override=None,
        group_override=GROUP,
        config_mapping=MAPPING,
        default=DEFAULT,
    )

    assert first == second
    # Equal but distinct: the function reads no module-level cache either.
    assert first is not second
