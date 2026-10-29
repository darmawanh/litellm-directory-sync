"""Shared behavioral contract for every ``Gateway`` implementation."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace

import pytest

from identity_lifecycle.adapters.litellm import LiteLLMGateway
from identity_lifecycle.domain.policy import BudgetPolicy
from identity_lifecycle.ports.gateway import Gateway
from tests.fixtures.fakes import FakeGateway
from tests.fixtures.litellm_http import FakeLiteLLMHTTP

pytestmark = pytest.mark.contract


@dataclass
class GatewayHarness:
    gateway: Gateway
    seed_keys: Callable[[str], tuple[str, ...]]
    keys_are_blocked: Callable[[str], bool]


@pytest.fixture(params=("fake", "litellm"))
def gateway_harness(request: pytest.FixtureRequest) -> Iterator[GatewayHarness]:
    if request.param == "fake":
        gateway = FakeGateway()

        def seed(user_id: str) -> tuple[str, ...]:
            key_ids = (f"key-{user_id}-1", f"key-{user_id}-2")
            account = gateway.accounts[user_id]
            gateway.accounts[user_id] = replace(account, keys=key_ids)
            return key_ids

        yield GatewayHarness(
            gateway=gateway,
            seed_keys=seed,
            keys_are_blocked=lambda user_id: all(
                key in gateway.blocked_keys for key in gateway.accounts[user_id].keys
            ),
        )
        return

    server = FakeLiteLLMHTTP()
    client = server.client()
    gateway = LiteLLMGateway(
        base_url="https://litellm.example.invalid",
        api_key="test-management-key",
        client=client,
    )
    try:
        yield GatewayHarness(
            gateway=gateway,
            seed_keys=lambda user_id: server.seed_keys(user_id),
            keys_are_blocked=server.keys_are_blocked,
        )
    finally:
        client.close()


_BUDGET = BudgetPolicy(max_budget=52.5, budget_duration="30d")


def test_gateway_ensures_and_returns_existing_team(gateway_harness: GatewayHarness) -> None:
    gateway = gateway_harness.gateway

    first = gateway.ensure_team(name="platform-users", create_if_missing=True)
    second = gateway.ensure_team(name="platform-users", create_if_missing=False)

    assert first == second


def test_gateway_create_sets_user_membership_and_reads_account_back(
    gateway_harness: GatewayHarness,
) -> None:
    gateway = gateway_harness.gateway
    team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)

    created = gateway.create_user(
        user_id="person-1",
        email="person@example.com",
        display_name="Example Person",
        role="internal_user",
        team_id=team_id,
        budget=_BUDGET,
    )

    assert created == gateway.get_user(user_id="person-1")
    assert created is not None
    assert created.user_id == "person-1"
    assert created.role == "internal_user"
    assert created.team == team_id
    assert created.budget == 52.5
    assert all(not key.startswith("sk-") for key in created.keys)


def test_gateway_update_moves_role_team_and_budget(gateway_harness: GatewayHarness) -> None:
    gateway = gateway_harness.gateway
    old_team = gateway.ensure_team(name="platform-users", create_if_missing=True)
    new_team = gateway.ensure_team(name="platform-admins", create_if_missing=True)
    gateway.create_user(
        user_id="person-2",
        email="person@example.com",
        display_name="Example Person",
        role="internal_user",
        team_id=old_team,
        budget=_BUDGET,
    )
    next_budget = BudgetPolicy(max_budget=125.0, budget_duration="30d")

    updated = gateway.update_user(
        user_id="person-2",
        role="proxy_admin",
        team_id=new_team,
        budget=next_budget,
    )

    assert (updated.role, updated.team, updated.budget) == ("proxy_admin", new_team, 125.0)


def test_gateway_remove_from_team_reads_membership_back(gateway_harness: GatewayHarness) -> None:
    gateway = gateway_harness.gateway
    team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)
    gateway.create_user(
        user_id="person-3",
        email="person@example.com",
        display_name="Example Person",
        role="internal_user",
        team_id=team_id,
        budget=_BUDGET,
    )

    account = gateway.remove_from_team(user_id="person-3", team_id=team_id)

    assert account.team == ""


def test_gateway_revokes_every_key_and_reads_account_back(gateway_harness: GatewayHarness) -> None:
    gateway = gateway_harness.gateway
    team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)
    gateway.create_user(
        user_id="person-4",
        email="person@example.com",
        display_name="Example Person",
        role="internal_user",
        team_id=team_id,
        budget=_BUDGET,
    )
    expected_keys = gateway_harness.seed_keys("person-4")

    revoked = gateway.revoke_keys(user_id="person-4")

    assert revoked.keys == tuple(sorted(expected_keys))
    assert gateway_harness.keys_are_blocked("person-4")


def test_gateway_delete_is_confirmed_by_absence(gateway_harness: GatewayHarness) -> None:
    gateway = gateway_harness.gateway
    team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)
    gateway.create_user(
        user_id="person-5",
        email="person@example.com",
        display_name="Example Person",
        role="internal_user",
        team_id=team_id,
        budget=_BUDGET,
    )

    gateway.delete_user(user_id="person-5")

    assert gateway.get_user(user_id="person-5") is None


def test_gateway_get_user_returns_none_for_missing_user(gateway_harness: GatewayHarness) -> None:
    assert gateway_harness.gateway.get_user(user_id="missing") is None
