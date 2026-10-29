"""Active Directory adapter unit tests: client, mapping, cursor, poller."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from identity_lifecycle.adapters.ad.client import ADClient, escape_ldap_filter
from identity_lifecycle.adapters.ad.cursor import ADCursor, format_cursor, parse_cursor
from identity_lifecycle.adapters.ad.mapping import (
    MalformedObjectGuid,
    is_account_enabled,
    map_group_entry,
    map_user_entry,
    objectguid_to_uuid,
    uuid_to_ldap_filter_value,
)
from identity_lifecycle.adapters.ad.poller import ADPoller
from identity_lifecycle.domain.errors import PermanentError, RetryableError
from identity_lifecycle.domain.events import EventType
from identity_lifecycle.ports.identity_source import EventCondition
from tests.fixtures.ad import ldap_responses
from tests.fixtures.ad.objectguid_samples import SAMPLES, ObjectGuidSample
from tests.fixtures.ad_ldap import (
    AD_GROUP_DN,
    AD_SEARCH_BASE,
    AD_SOURCE_NAME,
    FakeADConnection,
    create_fake_ad_client,
    create_fake_ad_source,
)
from tests.fixtures.fakes import FakeClock
from tests.fixtures.in_memory_unit_of_work import InMemoryStore, InMemoryUnitOfWork

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


# 1. Mapping Tests


@pytest.mark.unit
@pytest.mark.parametrize("sample", SAMPLES, ids=[s.name for s in SAMPLES])
def test_mixed_endian_objectguid_to_uuid_matches_samples(sample: ObjectGuidSample) -> None:
    guid = objectguid_to_uuid(sample.raw)
    assert str(guid).lower() == sample.expected


@pytest.mark.unit
def test_objectguid_conversion_matches_bytes_le_layout() -> None:
    raw = bytes.fromhex("4a3b2c1d5e6f47a8b9c0d1e2f3a4b5c6")
    guid = objectguid_to_uuid(raw)
    assert str(guid).lower() == "1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6"
    assert str(guid).lower() != "4a3b2c1d-5e6f-47a8-b9c0-d1e2f3a4b5c6"


@pytest.mark.unit
@pytest.mark.parametrize("length", [0, 15, 17])
def test_invalid_length_objectguid_raises_malformed_object_guid(length: int) -> None:
    with pytest.raises(MalformedObjectGuid):
        objectguid_to_uuid(b"\x00" * length)


@pytest.mark.unit
def test_braced_string_objectguid_conversion() -> None:
    braced = "{1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6}"
    guid = objectguid_to_uuid(braced)
    assert str(guid).lower() == "1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6"


@pytest.mark.unit
@pytest.mark.parametrize(
    "invalid",
    [
        "1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6",  # missing braces
        "{1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c}",  # short
        12345,  # wrong type
    ],
)
def test_invalid_string_or_type_raises_malformed_object_guid(invalid: object) -> None:
    with pytest.raises(MalformedObjectGuid):
        objectguid_to_uuid(invalid)  # type: ignore[arg-type]


@pytest.mark.unit
def test_uuid_to_ldap_filter_value() -> None:
    guid = objectguid_to_uuid(ldap_responses.ALICE_GUID)
    filter_val = uuid_to_ldap_filter_value(guid)
    assert filter_val == r"\4a\3b\2c\1d\5e\6f\47\a8\b9\c0\d1\e2\f3\a4\b5\c6"


@pytest.mark.unit
def test_user_account_control_account_disable_bit_mapping() -> None:
    assert is_account_enabled(512) is True
    assert is_account_enabled(514) is False  # 512 | 2
    assert is_account_enabled(b"512") is True
    assert is_account_enabled(b"514") is False
    assert is_account_enabled(66048) is True  # 65536 | 512
    assert is_account_enabled(66050) is False  # 65536 | 512 | 2
    assert is_account_enabled(None) is True


@pytest.mark.unit
def test_map_user_entry_alice() -> None:
    alice = map_user_entry(ldap_responses.alice_entry())
    assert alice.source_user_id == "1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6"
    assert alice.employee_number == "E10001"
    assert alice.email == "alice.adams@example.com"
    assert alice.display_name == "Alice Adams"
    assert alice.enabled is True


@pytest.mark.unit
def test_map_user_entry_bob_missing_employee_id() -> None:
    bob = map_user_entry(ldap_responses.bob_entry())
    assert bob.source_user_id == "33221100-5544-7766-8899-aabbccddeeff"
    assert bob.employee_number is None
    assert bob.enabled is True


@pytest.mark.unit
def test_map_user_entry_carol_and_dave_duplicate_employee_id_and_disabled() -> None:
    carol = map_user_entry(ldap_responses.carol_entry())
    dave = map_user_entry(ldap_responses.dave_entry())

    assert carol.employee_number == "E20002"
    assert dave.employee_number == "E20002"
    assert carol.source_user_id != dave.source_user_id
    assert carol.enabled is True
    assert dave.enabled is False  # UAC 514 has ACCOUNTDISABLE bit set


@pytest.mark.unit
def test_map_group_entry() -> None:
    group, members = map_group_entry(ldap_responses.group_entry())
    assert group.source_group_id == ldap_responses.GROUP_DN
    assert group.name == "AI-Platform-Users"
    assert len(members) == 4
    assert ldap_responses.ALICE_DN in members


# 2. Cursor Tests


@pytest.mark.unit
def test_cursor_serialization_and_parsing() -> None:
    token = format_cursor("dc-invoc-123", 10000)
    assert token == '{"v": 1, "dc": "dc-invoc-123", "usn": 10000}'

    parsed, reason = parse_cursor(token, connected_dc="dc-invoc-123")
    assert reason is None
    assert parsed == ADCursor(dc="dc-invoc-123", usn=10000)


@pytest.mark.unit
def test_cursor_detects_lexicographic_ordering_trap() -> None:
    before = ldap_responses.USN_BEFORE.decode()
    after = ldap_responses.USN_AFTER.decode()

    # Lexicographically, "9999" > "10000"
    assert before > after

    # As parsed ADCursor integers, ordering is strictly correct
    token_before = format_cursor("dc1", int(before))
    token_after = format_cursor("dc1", int(after))
    c_before, _ = parse_cursor(token_before)
    c_after, _ = parse_cursor(token_after)
    assert c_before is not None and c_after is not None
    assert c_before.usn < c_after.usn


@pytest.mark.unit
@pytest.mark.parametrize(
    ("token", "connected_dc", "expected_reason"),
    [
        (None, "dc1", "cursor_unusable"),
        ("invalid-json", "dc1", "cursor_unusable"),
        ('{"v": 2, "dc": "dc1", "usn": 100}', "dc1", "cursor_unusable"),
        ('{"v": 1, "dc": "dc1", "usn": "100"}', "dc1", "cursor_unusable"),
        ('{"v": 1, "dc": "dc1", "usn": -5}', "dc1", "cursor_unusable"),
        ('{"v": 1, "dc": "dc1", "usn": true}', "dc1", "cursor_unusable"),
        ('{"v": 1, "dc": "", "usn": 100}', "dc1", "cursor_unusable"),
        ('{"v": 1, "dc": "dc-old", "usn": 100}', "dc-new", "dc_changed"),
    ],
)
def test_cursor_rejection_reasons(
    token: str | None, connected_dc: str, expected_reason: str
) -> None:
    parsed, reason = parse_cursor(token, connected_dc=connected_dc)
    assert parsed is None
    assert reason == expected_reason


# 3. Client & Security Tests


@pytest.mark.unit
def test_ad_client_surface_has_no_write_verb() -> None:
    client_file = ROOT / "src" / "identity_lifecycle" / "adapters" / "ad" / "client.py"
    tree = ast.parse(client_file.read_text(encoding="utf-8"))

    # Verify no add, modify, delete calls are invoked on _connection
    connection_calls = {
        node.func.attr.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "_connection"
    }
    forbidden = {"add", "modify", "delete", "modify_dn", "rename", "write"}
    found_forbidden = connection_calls & forbidden
    assert not found_forbidden, f"Found forbidden write calls: {found_forbidden}"
    assert connection_calls <= {"search", "bind", "unbind"}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("server", "port", "ca_cert_path"),
    [
        ("", 636, "ca.pem"),
        ("http://ad.example.com", 636, "ca.pem"),
        ("ldap://ad.example.com", 636, "ca.pem"),
        ("ad.example.com", 389, "ca.pem"),
        ("ad.example.com", 636, ""),
        ("ldaps://user:pass@ad.example.com", 636, "ca.pem"),
    ],
)
def test_ad_client_rejects_insecure_or_invalid_configuration(
    server: str, port: int, ca_cert_path: str
) -> None:
    with pytest.raises(PermanentError):
        ADClient(
            server=server,
            bind_dn="CN=read-only,DC=example,DC=com",
            bind_password="password",
            ca_cert_path=ca_cert_path,
            port=port,
            connection=FakeADConnection(),
        )


@pytest.mark.unit
def test_escape_ldap_filter() -> None:
    special = r"foo*bar(baz)\test" + "\x00"
    escaped = escape_ldap_filter(special)
    assert escaped == r"foo\2abar\28baz\29\5ctest\00"


@pytest.mark.unit
def test_client_search_and_root_dse() -> None:
    fake_conn = FakeADConnection()
    client = create_fake_ad_client(fake_conn)

    root_dse = client.read_root_dse()
    assert root_dse["dnsHostName"] == "dc1.corp.example.com"
    assert root_dse["invocationID"] == "44332211-6655-8877-9900-aabbccddeeff"
    assert root_dse["highestCommittedUSN"] == 25000

    entries, cookie = client.search(
        search_base=AD_SEARCH_BASE,
        search_filter="(&(objectCategory=person)(objectClass=user))",
    )
    assert len(entries) == 4
    assert cookie is None
    client.close()


@pytest.mark.unit
def test_client_error_mapping() -> None:
    fake_conn = FakeADConnection()
    fake_conn.bind_error_code = 49  # invalid credentials
    fake_conn.bound = False
    client = create_fake_ad_client(fake_conn)
    with pytest.raises(PermanentError, match="invalid credentials"):
        client.search(AD_SEARCH_BASE, "(objectClass=*)")

    fake_conn.bind_error_code = 81  # server down
    fake_conn.bound = False
    with pytest.raises(RetryableError, match="server unavailable"):
        client.search(AD_SEARCH_BASE, "(objectClass=*)")


@pytest.mark.unit
def test_client_search_empty_result_returns_empty_tuple() -> None:
    fake_conn = FakeADConnection()
    fake_conn.users = []
    fake_conn.status_override = (0, "success")
    client = create_fake_ad_client(fake_conn)
    entries, cookie = client.search(AD_SEARCH_BASE, "(objectClass=*)")
    assert entries == ()
    assert cookie is None
    client.close()


@pytest.mark.unit
def test_client_root_dse_falls_back_to_ds_service_name_invocation_id() -> None:
    fake_conn = FakeADConnection()
    ntds_dn = (
        "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,"
        "CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com"
    )
    fake_conn.root_dse = ldap_responses.search_res_entry(
        "",
        {
            "dnsHostName": [b"dc1.corp.example.com"],
            "dsServiceName": [ntds_dn.encode("utf-8")],
            "highestCommittedUSN": [b"25000"],
            "supportedControl": [b"1.2.840.113556.1.4.319"],
        },
    )
    ntds_guid = bytes.fromhex("11223344556677889900aabbccddeeff")
    fake_conn.users.append(
        ldap_responses.search_res_entry(
            ntds_dn,
            {
                "invocationId": [ntds_guid],
                "objectGUID": [ntds_guid],
            },
        )
    )
    client = create_fake_ad_client(fake_conn)
    root_dse = client.read_root_dse()
    assert root_dse["dnsHostName"] == "dc1.corp.example.com"
    assert root_dse["highestCommittedUSN"] == 25000
    assert root_dse["invocationID"] == str(objectguid_to_uuid(ntds_guid)).lower()
    client.close()


# 4. Connector Tests


@pytest.mark.unit
def test_ad_identity_source_get_user_and_members() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)

    alice = source.get_user("1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6")
    assert alice is not None
    assert alice.display_name == "Alice Adams"

    missing = source.get_user("00000000-0000-0000-0000-000000000000")
    assert missing is None

    invalid_uuid = source.get_user("not-a-uuid")
    assert invalid_uuid is None

    members_page = source.get_group_members(AD_GROUP_DN, None)
    assert len(members_page.items) == 4
    assert {u.display_name for u in members_page.items} == {
        "Alice Adams",
        "Bob Brown",
        "Carol Clark",
        "Dave Davis",
    }


@pytest.mark.unit
def test_ad_identity_source_normalize_returns_condition() -> None:
    fake_conn = FakeADConnection()
    source = create_fake_ad_source(fake_conn, FakeClock(START))

    result = source.normalize({"some": "event"})
    assert isinstance(result, EventCondition)
    assert result.code == "unsupported_source_event"


# 5. Poller Tests: Full Sync, Removals, and Disables


def _uow_factory(store: InMemoryStore, clock: FakeClock):
    def factory(source: str):
        return InMemoryUnitOfWork(store, clock, source=source)

    return factory


@pytest.mark.unit
def test_poller_full_sync_on_empty_cursor() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)
    store = InMemoryStore()
    uow_fact = _uow_factory(store, clock)

    poller = ADPoller(source, uow_fact)
    enqueued = poller.poll_once()

    # 4 member_added events + 1 user.disabled for Dave = 5 events
    assert enqueued == 5
    outbox_events = [row.event for row in store.outbox.values()]
    event_types = [e.type for e in outbox_events]
    assert event_types.count(EventType.GROUP_MEMBER_ADDED) == 4
    assert event_types.count(EventType.USER_DISABLED) == 1

    # Snapshot and cursor were persisted
    snapshot = store.group_members.get((AD_SOURCE_NAME, AD_GROUP_DN))
    assert snapshot is not None
    assert len(snapshot) == 4

    cursor_token = store.cursors.get((AD_SOURCE_NAME, "usn_poll"))
    assert cursor_token is not None
    parsed, _ = parse_cursor(cursor_token)
    assert parsed is not None
    assert parsed.usn >= 25000


@pytest.mark.unit
def test_poller_detects_member_removal_via_group_snapshot_diff() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)
    store = InMemoryStore()
    uow_fact = _uow_factory(store, clock)

    poller = ADPoller(source, uow_fact)
    # First cycle: initial full sync
    poller.poll_once()

    # Clear outbox for next cycle assertion
    store.outbox.clear()

    # Simulate Bob removed from group: group entry changes, Bob's does not (F4)
    fake_conn.current_group_entry = ldap_responses.group_entry_after_removal()

    # Next poll cycle
    enqueued = poller.poll_once()
    assert enqueued >= 1

    outbox_events = [row.event for row in store.outbox.values()]
    removal_events = [e for e in outbox_events if e.type == EventType.GROUP_MEMBER_REMOVED]
    assert len(removal_events) == 1

    bob_guid_str = str(objectguid_to_uuid(ldap_responses.BOB_GUID)).lower()
    assert removal_events[0].person is not None
    assert removal_events[0].person.source_user_id == bob_guid_str
    assert removal_events[0].group is not None
    assert removal_events[0].group.source_group_id == AD_GROUP_DN

    # Verified group snapshot now has 3 members (Alice, Carol, Dave)
    snapshot = store.group_members[(AD_SOURCE_NAME, AD_GROUP_DN)]
    assert len(snapshot) == 3
    assert bob_guid_str not in snapshot


@pytest.mark.unit
def test_poller_resets_on_dc_invocation_id_change() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)
    store = InMemoryStore()
    uow_fact = _uow_factory(store, clock)

    poller = ADPoller(source, uow_fact)
    poller.poll_once()

    # Simulate DC restore from backup: invocationID changes
    new_invoc = bytes.fromhex("99887766554433221100aabbccddeeff")
    fake_conn.root_dse = ldap_responses.root_dse_entry(invocation_id=new_invoc)

    store.outbox.clear()
    enqueued = poller.poll_once()

    # Triggers full sync: disabled Dave is enqueued, and cursor is re-seeded to new DC
    assert enqueued == 1
    new_token = store.cursors[(AD_SOURCE_NAME, "usn_poll")]
    parsed, _ = parse_cursor(new_token)
    assert parsed is not None
    assert parsed.dc == str(objectguid_to_uuid(new_invoc)).lower()


# 6. Fail-Safe Read Failure Tests


@pytest.mark.unit
def test_malformed_user_entry_raises_permanent_error() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    # Alice's entry has malformed objectGUID that fails mapping
    malformed_alice = ldap_responses.search_res_entry(
        "CN=Alice Adams," + ldap_responses.USERS_BASE,
        {
            "objectGUID": [b"short_guid"],
            "sAMAccountName": [b"aadams"],
            "userAccountControl": [b"512"],
        },
    )
    fake_conn.override_response = [malformed_alice]
    source = create_fake_ad_source(fake_conn, clock)

    with pytest.raises(PermanentError):
        source.get_user("1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6")


@pytest.mark.unit
def test_member_mapping_failure_aborts_snapshot_read_no_diff_emitted() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)
    store = InMemoryStore()
    uow_fact = _uow_factory(store, clock)

    poller = ADPoller(source, uow_fact)
    poller.poll_once()  # Initial full sync succeeds with 4 members

    # Now make Bob's entry malformed
    for i, u in enumerate(fake_conn.users):
        if "Bob" in u["dn"]:
            fake_conn.users[i] = ldap_responses.search_res_entry(
                u["dn"],
                {
                    "objectGUID": [b"invalid_guid"],
                    "sAMAccountName": [b"bbrown"],
                    "userAccountControl": [b"512"],
                },
            )

    store.outbox.clear()
    initial_snapshot = store.group_members[(AD_SOURCE_NAME, AD_GROUP_DN)]
    initial_cursor = store.cursors[(AD_SOURCE_NAME, "usn_poll")]

    # Next poll must raise an error and abort diff; no removals enqueued,
    # cursor and snapshot untouched
    with pytest.raises(PermanentError):
        poller.poll_once()

    assert len(store.outbox) == 0
    assert store.group_members[(AD_SOURCE_NAME, AD_GROUP_DN)] == initial_snapshot
    assert store.cursors[(AD_SOURCE_NAME, "usn_poll")] == initial_cursor


@pytest.mark.unit
def test_group_removed_raises_typed_error_no_mass_removal() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)
    store = InMemoryStore()
    uow_fact = _uow_factory(store, clock)

    poller = ADPoller(source, uow_fact)
    poller.poll_once()  # Initial sync

    # Simulate group removed in directory
    fake_conn.current_group_entry = None

    store.outbox.clear()
    initial_snapshot = store.group_members[(AD_SOURCE_NAME, AD_GROUP_DN)]
    initial_cursor = store.cursors[(AD_SOURCE_NAME, "usn_poll")]

    with pytest.raises(PermanentError):
        poller.poll_once()

    assert len(store.outbox) == 0
    assert store.group_members[(AD_SOURCE_NAME, AD_GROUP_DN)] == initial_snapshot
    assert store.cursors[(AD_SOURCE_NAME, "usn_poll")] == initial_cursor


@pytest.mark.unit
def test_genuine_absence_returns_none() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)

    # Valid UUID that does not exist in fake directory
    absent = source.get_user("00000000-0000-0000-0000-000000000000")
    assert absent is None


@pytest.mark.unit
def test_transport_failure_raises_retryable_error() -> None:
    fake_conn = FakeADConnection()
    clock = FakeClock(START)
    source = create_fake_ad_source(fake_conn, clock)

    # Server down (LDAP result code 81)
    fake_conn.status_override = (81, "serverDown")

    with pytest.raises(RetryableError):
        source.get_user("1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6")

    with pytest.raises(RetryableError):
        source.read_group_entry()
