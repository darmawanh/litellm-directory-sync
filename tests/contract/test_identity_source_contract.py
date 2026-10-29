"""The shared read-only source contract, exercised by fake, Okta, and AD adapters."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from identity_lifecycle.adapters.ad.mapping import objectguid_to_uuid
from identity_lifecycle.adapters.okta.connector import OktaIdentitySource
from identity_lifecycle.adapters.okta.cursor import seeded_cursor
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.ports.identity_source import EventCondition, IdentitySource, IdentityUser
from tests.fixtures.ad import ldap_responses
from tests.fixtures.ad_ldap import FakeADConnection, create_fake_ad_source
from tests.fixtures.fakes import FakeClock, FakeIdentitySource
from tests.fixtures.okta import event_hook_payloads
from tests.fixtures.okta_http import SOURCE_NAME, FakeOktaHTTP, user

GROUP_ID = event_hook_payloads.GROUP_ID
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
AD_ALICE_USER_ID = str(objectguid_to_uuid(ldap_responses.ALICE_GUID)).lower()


def _build_sources() -> tuple[tuple[str, Callable[[], IdentitySource], str, str], ...]:
    identity = IdentityUser(
        source_user_id=event_hook_payloads.ALICE_USER_ID,
        employee_number="E10001",
        email="alice@example.com",
        display_name="Alice Example",
        enabled=True,
    )

    def fake() -> IdentitySource:
        return FakeIdentitySource(
            source=SOURCE_NAME,
            users={identity.source_user_id: identity},
            groups={GROUP_ID: [identity.source_user_id]},
        )

    def okta() -> IdentitySource:
        server = FakeOktaHTTP()
        server.add_user(
            user(identity.source_user_id, email=identity.email, name=identity.display_name),
            member=True,
        )
        return OktaIdentitySource(
            source_name=SOURCE_NAME,
            group_id=GROUP_ID,
            client=server.oauth_client(),
            clock=FakeClock(START),
            log_page_limit=20,
            log_overlap_seconds=60,
            log_retention_seconds=604800,
        )

    def ad() -> IdentitySource:
        group_with_alice = ldap_responses.search_res_entry(
            ldap_responses.GROUP_DN,
            {
                "objectClass": [b"top", b"group"],
                "cn": [b"AI-Platform-Users"],
                "distinguishedName": [ldap_responses.GROUP_DN.encode("utf-8")],
                "objectGUID": [ldap_responses.GROUP_GUID],
                "uSNChanged": [b"19042"],
                "whenChanged": [b"20260101120000.0Z"],
                "member": [ldap_responses.ALICE_DN.encode("utf-8")],
            },
        )
        fake_conn = FakeADConnection(
            group_entry=group_with_alice,
            users=[ldap_responses.alice_entry()],
        )
        return create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)

    return (
        ("fake", fake, event_hook_payloads.ALICE_USER_ID, GROUP_ID),
        ("okta", okta, event_hook_payloads.ALICE_USER_ID, GROUP_ID),
        ("ad", ad, AD_ALICE_USER_ID, ldap_responses.GROUP_DN),
    )


@pytest.mark.contract
@pytest.mark.parametrize(
    ("adapter_name", "build_source", "expected_user_id", "expected_group_id"),
    _build_sources(),
)
def test_identity_source_read_contract(
    adapter_name: str,
    build_source: Callable[[], IdentitySource],
    expected_user_id: str,
    expected_group_id: str,
) -> None:
    source = build_source()
    try:
        assert source.name() == SOURCE_NAME
        capabilities = source.capabilities()
        assert capabilities.incremental_changes
        assert capabilities.full_snapshot
        assert capabilities.group_membership

        users = source.list_users(None)
        assert users.items[0].source_user_id == expected_user_id
        assert source.get_user(expected_user_id) == users.items[0]
        assert source.get_user("missing-user") is None

        groups = source.list_groups(None)
        assert [group.source_group_id for group in groups.items] == [expected_group_id]
        members = source.get_group_members(expected_group_id, None)
        assert tuple(member.source_user_id for member in members.items) == (expected_user_id,)

        normalized = source.normalize(event_hook_payloads.membership_add())
        assert isinstance(normalized, CanonicalEvent | EventCondition), adapter_name
        if isinstance(normalized, CanonicalEvent):
            assert normalized.person is not None
            assert normalized.person.source_user_id == expected_user_id

        polled = source.poll_changes(seeded_cursor(START, 60))
        assert all(isinstance(item, CanonicalEvent | EventCondition) for item in polled.items)
    finally:
        close = getattr(source, "close", None)
        if close is not None:
            close()
