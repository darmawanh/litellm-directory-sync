"""With no override and no mapping the default policy applies.

Design 10.7's fourth step always supplies a default, so the fallback is a
resolution, not an error and not ``None``. A default of ``max_budget=0.0`` is
still a policy that won: a truthiness check would turn a deliberate zero into a
missing value.
"""

from __future__ import annotations

import pytest

from identity_lifecycle.domain.policy import (
    BudgetPolicy,
    BudgetResolution,
    BudgetSource,
    resolve_budget,
)

pytestmark = pytest.mark.unit

DEFAULT = BudgetPolicy(max_budget=50.0, budget_duration="30d")


def test_the_default_policy_applies_when_no_override_or_mapping_exists() -> None:
    resolution = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=None,
        default=DEFAULT,
    )

    assert resolution.source is BudgetSource.DEFAULT
    assert resolution.policy == DEFAULT
    assert resolution.policy.max_budget == 50.0
    assert resolution.policy.budget_duration == "30d"
    assert resolution.reason == "default"


def test_a_zero_budget_default_is_a_resolution_not_an_absence() -> None:
    zero = BudgetPolicy(max_budget=0.0, budget_duration="30d")

    resolution = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=None,
        default=zero,
    )

    assert isinstance(resolution, BudgetResolution)
    assert resolution.source is BudgetSource.DEFAULT
    assert resolution.policy.max_budget == 0.0
    assert resolution.reason == "default"


def test_the_default_policy_is_carried_not_reconstructed() -> None:
    default = BudgetPolicy(max_budget=50.0, budget_duration="30d")

    resolution = resolve_budget(
        person_override=None,
        group_override=None,
        config_mapping=None,
        default=default,
    )

    # The caller's policy object is the one recorded, so an audit write cannot
    # disagree with the object the loader holds.
    assert resolution.policy is default
