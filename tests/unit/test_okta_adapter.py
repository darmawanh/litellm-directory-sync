"""Okta source adapter mapping, pagination, and read-only HTTP behavior."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from identity_lifecycle.adapters.okta.client import OktaClient
from identity_lifecycle.adapters.okta.connector import OktaIdentitySource
from identity_lifecycle.adapters.okta.cursor import seeded_cursor
from identity_lifecycle.adapters.okta.mapping import mapped_event_types
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import CanonicalEvent, EventType
from identity_lifecycle.ports.identity_source import EventCondition
from tests.fixtures.fakes import FakeClock
from tests.fixtures.okta import event_hook_payloads
from tests.fixtures.okta_http import SOURCE_NAME, FakeOktaHTTP, user

ROOT = Path(__file__).resolve().parents[2]
GROUP_ID = event_hook_payloads.GROUP_ID
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _source(server: FakeOktaHTTP) -> OktaIdentitySource:
    return OktaIdentitySource(
        source_name=SOURCE_NAME,
        group_id=GROUP_ID,
        client=server.oauth_client(),
        clock=FakeClock(START),
        log_page_limit=20,
        log_overlap_seconds=60,
        log_retention_seconds=604800,
    )


@pytest.mark.unit
def test_user_and_group_reads_follow_opaque_pagination() -> None:
    server = FakeOktaHTTP()
    server.add_user(
        user(
            event_hook_payloads.ALICE_USER_ID, employee_number="E10001", email="alice@example.com"
        ),
        member=True,
    )
    server.add_user(
        user(
            event_hook_payloads.BOB_USER_ID,
            employee_number=None,
            email="bob@example.com",
            name="Bob Brown",
        ),
        member=True,
    )
    source = _source(server)

    users_first = source.list_users(None)
    users_second = source.list_users(users_first.next_cursor)
    members = source.group_members()

    assert users_first.next_cursor == "users-1"
    assert tuple(person.source_user_id for person in users_second.items) == (
        event_hook_payloads.BOB_USER_ID,
    )
    assert tuple(person.source_user_id for person in members) == (
        event_hook_payloads.ALICE_USER_ID,
        event_hook_payloads.BOB_USER_ID,
    )
    assert members[1].employee_number is None
    assert sum(request.url.path.endswith("/users") for request in server.requests) == 4
    source.close()


@pytest.mark.unit
def test_system_log_filter_covers_every_mapped_type_and_rebuilds_next_request() -> None:
    server = FakeOktaHTTP()
    first_event = event_hook_payloads.membership_add()
    unrelated = event_hook_payloads.membership_add()
    unrelated["uuid"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    unrelated["target"][1]["id"] = "00gOTHERGROUP00001"
    server.log_pages = {None: ([first_event, unrelated], "Mg=="), "Mg==": ([], None)}
    source = _source(server)
    token = seeded_cursor(START, 60)

    first = source.poll_changes(token)
    second = source.poll_changes(first.next_cursor)

    assert len(first.items) == 1
    assert isinstance(first.items[0], CanonicalEvent)
    assert first.items[0].type == EventType.GROUP_MEMBER_ADDED
    assert second.items == ()
    log_requests = [request for request in server.requests if request.url.path == "/api/v1/logs"]
    assert len(log_requests) == 2
    first_query = log_requests[0].url.params
    second_query = log_requests[1].url.params
    assert set(mapped_event_types()) <= set(
        first_query["filter"].replace('"', "").replace("eventType eq ", "").split(" or ")
    )
    assert second_query["after"] == "Mg=="
    assert second_query["filter"] == first_query["filter"]
    assert second_query["since"] == first_query["since"]
    source.close()


@pytest.mark.unit
def test_hook_mapping_returns_typed_conditions_and_shared_canonical_events() -> None:
    server = FakeOktaHTTP()
    source = _source(server)

    normalized = source.normalize(event_hook_payloads.membership_add())
    missing_employee = source.normalize(
        event_hook_payloads.membership_add_without_employee_number()
    )
    unsupported = source.normalize({"eventType": "user.lifecycle.create"})

    assert isinstance(normalized, CanonicalEvent)
    assert isinstance(missing_employee, EventCondition)
    assert missing_employee.code == "missing_employee_number"
    assert isinstance(unsupported, EventCondition)
    source.close()


@pytest.mark.unit
def test_okta_client_maps_429_to_retryable_and_auth_failure_to_permanent() -> None:
    server = FakeOktaHTTP()
    server.status_overrides["/api/v1/users"] = 429
    client = server.oauth_client()
    with pytest.raises(RetryableError):
        client.get("/api/v1/users")

    server.status_overrides["/api/v1/users"] = 401
    with pytest.raises(PermanentError):
        client.get("/api/v1/users")
    client.close()


@pytest.mark.unit
@pytest.mark.parametrize(
    "org_url",
    (
        "http://example.okta.com",
        "https://user:password@example.okta.com",
        "https://example.okta.com/path",
    ),
)
def test_okta_client_rejects_non_https_or_credentialed_org_urls(org_url: str) -> None:
    with pytest.raises(PermanentError, match="HTTPS origin"):
        OktaClient(
            org_url=org_url,
            oauth_client_id="synthetic-client-id",
            oauth_key_id="synthetic-key-id",
            private_key_path="/missing-test-key.pem",
        )


@pytest.mark.unit
def test_identity_http_surface_has_no_write_verb() -> None:
    source_file = ROOT / "src" / "identity_lifecycle" / "adapters" / "okta" / "client.py"
    tree = ast.parse(source_file.read_text(encoding="utf-8"))
    verbs = {
        node.func.attr.upper()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "_client"
    }
    assert verbs == {"GET", "CLOSE"}

    oauth_file = source_file.with_name("oauth.py")
    oauth_tree = ast.parse(oauth_file.read_text(encoding="utf-8"))
    oauth_calls = [
        node
        for node in ast.walk(oauth_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "_client"
    ]
    assert len(oauth_calls) == 1
    assert oauth_calls[0].func.attr == "post"
    assert isinstance(oauth_calls[0].args[0], ast.Constant)
    assert oauth_calls[0].args[0].value == "/oauth2/v1/token"
