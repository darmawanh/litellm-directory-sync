"""LiteLLM API mapping and read-back assertions."""

from __future__ import annotations

from collections import Counter

import httpx
import pytest

from identity_lifecycle.adapters.litellm import LiteLLMGateway
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.policy import BudgetPolicy
from tests.fixtures.litellm_http import FakeLiteLLMHTTP

pytestmark = pytest.mark.unit

_BUDGET = BudgetPolicy(max_budget=52.5, budget_duration="30d")


@pytest.fixture
def gateway_and_server() -> tuple[LiteLLMGateway, FakeLiteLLMHTTP, httpx.Client]:
    server = FakeLiteLLMHTTP()
    client = server.client()
    gateway = LiteLLMGateway(
        base_url="https://litellm.example.invalid",
        api_key="test-management-key",
        client=client,
    )
    return gateway, server, client


def test_membership_is_set_through_the_user(
    gateway_and_server: tuple[LiteLLMGateway, FakeLiteLLMHTTP, httpx.Client],
) -> None:
    gateway, server, client = gateway_and_server
    try:
        team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)
        gateway.create_user(
            user_id="person-1",
            email="person@example.com",
            display_name="Example Person",
            role="internal_user",
            team_id=team_id,
            budget=_BUDGET,
        )

        create = next(call for call in server.calls if call[1] == "/user/new")
        assert create[2]["teams"] == [team_id]
        assert not any(path == "/team/member_add" for _, path, _ in server.calls)
    finally:
        client.close()


def test_write_is_read_back_before_it_is_treated_as_applied(
    gateway_and_server: tuple[LiteLLMGateway, FakeLiteLLMHTTP, httpx.Client],
) -> None:
    gateway, server, client = gateway_and_server
    server.post_response_overrides["/user/new"] = {
        "user_id": "write-response-user",
        "user_role": "wrong-role",
        "key": "sk-response-secret-must-not-escape",
    }
    try:
        team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)
        account = gateway.create_user(
            user_id="person-2",
            email="person@example.com",
            display_name="Example Person",
            role="internal_user",
            team_id=team_id,
            budget=_BUDGET,
        )

        assert account.user_id == "person-2"
        assert account.role == "internal_user"
        assert account.team == team_id
        assert all("sk-" not in key for key in account.keys)
    finally:
        client.close()


def test_nonconfirming_readback_is_retryable_without_an_extra_read(
    gateway_and_server: tuple[LiteLLMGateway, FakeLiteLLMHTTP, httpx.Client],
) -> None:
    gateway, server, client = gateway_and_server
    server.user_info_overrides["person-3"] = {
        "user_id": "person-3",
        "user_email": "person@example.com",
        "user_alias": "Example Person",
        "user_role": "wrong-role",
        "teams": ["requested-team"],
        "max_budget": 52.5,
    }
    try:
        with pytest.raises(RetryableError):
            gateway.create_user(
                user_id="person-3",
                email="person@example.com",
                display_name="Example Person",
                role="internal_user",
                team_id="requested-team",
                budget=_BUDGET,
            )

        calls = Counter(path for _, path, _ in server.calls)
        assert calls["/user/info"] == 1
        assert calls["/key/list"] == 1
    finally:
        client.close()


def test_400_is_permanent_and_429_is_retryable() -> None:
    for status, error in ((400, PermanentError), (429, RetryableError)):
        client = httpx.Client(
            base_url="https://litellm.example.invalid",
            transport=httpx.MockTransport(
                lambda _, response_status=status: httpx.Response(
                    response_status, json={"error": "x"}
                )
            ),
        )
        gateway = LiteLLMGateway(
            base_url="https://litellm.example.invalid",
            api_key="test-management-key",
            client=client,
        )
        try:
            with pytest.raises(error):
                gateway.ensure_team(name="platform-users", create_if_missing=False)
        finally:
            client.close()


def test_key_listing_reads_every_page_before_revocation(
    gateway_and_server: tuple[LiteLLMGateway, FakeLiteLLMHTTP, httpx.Client],
) -> None:
    gateway, server, client = gateway_and_server
    try:
        team_id = gateway.ensure_team(name="platform-users", create_if_missing=True)
        gateway.create_user(
            user_id="person-4",
            email="person@example.com",
            display_name="Example Person",
            role="internal_user",
            team_id=team_id,
            budget=_BUDGET,
        )
        server.seed_keys("person-4", count=101)

        gateway.revoke_keys(user_id="person-4")

        page_numbers = {
            server.queries[index].get("page")
            for index, (method, path, _) in enumerate(server.calls)
            if method == "GET" and path == "/key/list"
        }
        assert server.keys_are_blocked("person-4")
        assert len([call for call in server.calls if call[1] == "/key/block"]) == 101
        assert {"1", "2"}.issubset(page_numbers)
        assert all(
            server.queries[index].get("size") == "100"
            for index, (method, path, _) in enumerate(server.calls)
            if method == "GET" and path == "/key/list"
        )
    finally:
        client.close()
