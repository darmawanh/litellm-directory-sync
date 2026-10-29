"""Optional T-045 acceptance test against an explicitly configured local gateway."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import pytest

from identity_lifecycle.adapters.litellm import LiteLLMGateway
from identity_lifecycle.application.ingest_event import IngestEvent
from identity_lifecycle.application.process_event import ProcessEvent
from identity_lifecycle.domain.events import CanonicalEvent, EventGroup, EventPerson, EventType
from identity_lifecycle.domain.policy import BudgetPolicy, GroupMapping
from identity_lifecycle.ports.identity_source import IdentityUser
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement
from tests.fixtures.fakes import FakeClock, FakeIdentitySource, InMemoryStore, InMemoryUnitOfWork

pytestmark = pytest.mark.integration


def test_revoked_key_returns_401() -> None:
    """A fake source join and leave create a LiteLLM user, then revoke its key."""
    base_url = os.environ.get("LITELLM_BASE_URL")
    management_key = os.environ.get("LITELLM_MASTER_KEY")
    if not base_url or not management_key:
        pytest.skip("local LiteLLM URL and management key are not both configured")
    if urlsplit(base_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
        pytest.skip("live acceptance test is restricted to a local nonproduction gateway")

    source_name = f"codex-t045-{uuid4().hex}"
    source_user_id = "source-user-1"
    group_id = "demo-group-1"
    team_alias = f"codex-t045-team-{uuid4().hex}"
    user_ids: list[str] = []
    team_ids: list[str] = []
    user_keys: list[str] = []

    def capture_response(response: httpx.Response) -> None:
        """Capture temporary ids and the one-time user key in test memory only."""
        response.read()
        if response.request.url.path == "/user/new":
            body = response.json()
            key = body.get("key") if isinstance(body, dict) else None
            if isinstance(key, str):
                user_keys.append(key)
            request_body = response.request.content
            if request_body:
                payload = json.loads(request_body)
                user_id = payload.get("user_id") if isinstance(payload, dict) else None
                if isinstance(user_id, str):
                    user_ids.append(user_id)
        elif response.request.url.path == "/team/new":
            body = response.json()
            team_id = body.get("team_id") if isinstance(body, dict) else None
            if isinstance(team_id, str):
                team_ids.append(team_id)

    management_client = httpx.Client(
        base_url=base_url.rstrip("/"),
        timeout=10.0,
        event_hooks={"response": [capture_response]},
    )
    gateway = LiteLLMGateway(
        base_url=base_url,
        api_key=management_key,
        client=management_client,
    )
    admin = httpx.Client(
        base_url=base_url.rstrip("/"),
        headers={"Authorization": f"Bearer {management_key}"},
        timeout=10.0,
    )

    clock = FakeClock()
    store = InMemoryStore()
    source = FakeIdentitySource(
        source=source_name,
        users={
            source_user_id: IdentityUser(
                source_user_id=source_user_id,
                employee_number="E-T045",
                email=f"t045-{uuid4().hex[:8]}@example.invalid",
                display_name="T-045 Acceptance User",
                enabled=True,
            )
        },
        groups={group_id: (source_user_id,)},
    )

    def unit_of_work(name: str) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(store, clock, source=name)

    budget = BudgetPolicy(max_budget=1.0, budget_duration="30d")
    process = ProcessEvent(
        unit_of_work,
        gateway,
        {source_name: source},
        group_mappings=(
            GroupMapping(
                source=source_name,
                source_group_id=group_id,
                role="internal_user",
                team=team_alias,
                precedence=1,
            ),
        ),
        team_create_if_missing={team_alias: True},
        budget_policies={"standard": budget},
        group_budget_policies={(source_name, group_id): "standard"},
        default_budget_policy="standard",
        enabled_sources=frozenset({source_name}),
        clock=clock,
    )
    ingest = IngestEvent(unit_of_work, enabled_sources=frozenset({source_name}))

    def event(event_type: EventType) -> CanonicalEvent:
        return CanonicalEvent(
            event_id=uuid4(),
            source=source_name,
            source_event_id=str(uuid4()),
            type=event_type,
            occurred_at=datetime.now(UTC),
            person=EventPerson(source_user_id=source_user_id, employee_number="E-T045"),
            group=EventGroup(source_group_id=group_id, name="T-045 demo group"),
        )

    try:
        join = event(EventType.GROUP_MEMBER_ADDED)
        assert ingest.ingest(join) is EnqueueOutcome.INSERTED
        assert process.process(join) is Settlement.DONE

        source.remove_from_group(group_id, source_user_id)
        leave = event(EventType.GROUP_MEMBER_REMOVED)
        assert ingest.ingest(leave) is EnqueueOutcome.INSERTED
        assert process.process(leave) is Settlement.DONE

        if len(user_keys) != 1:
            pytest.fail("LiteLLM did not return one temporary user key")
        key_response = httpx.get(
            f"{base_url.rstrip('/')}/v1/models",
            headers={"Authorization": f"Bearer {user_keys[0]}"},
            timeout=10.0,
        )
        assert key_response.status_code == 401
    finally:
        for user_id in user_ids:
            if gateway.get_user(user_id=user_id) is not None:
                gateway.delete_user(user_id=user_id)
        if team_ids:
            admin.post("/team/delete", json={"team_ids": team_ids})
        gateway.close()
        management_client.close()
        admin.close()
