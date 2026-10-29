"""Hand-built ``ldap3`` response shapes for the T-007 AD spike.

These dictionaries mirror what ``ldap3`` puts on ``Connection.response`` for a
synchronous search: a list of ``searchResEntry`` mappings, each with ``dn``,
``raw_dn``, ``attributes`` (decoded where the bytes are valid UTF-8) and
``raw_attributes`` (always the raw bytes). The values were built from the
documented AD schema and the ``ldap3`` 2.9 source, **not captured from a live
domain controller**. No test connects anywhere; this module is data only.

Why the shapes matter for ADR-005:

- ``objectGUID`` arrives as ``bytes`` in ``raw_attributes`` and stays bytes in
  ``attributes`` because it is not UTF-8. The adapter must convert it, and the
  reference converter in ``tests/fixtures/ad/objectguid.py`` shows the byte
  order.
- ``uSNChanged`` and ``userAccountControl`` arrive as numeric strings; they are
  parsed, never compared as text. ``USN_LEXICOGRAPHIC_TRAP`` shows why.
- ``whenChanged`` arrives as a generalized-time string. It is a wall-clock
  timestamp with one-second resolution and is not a cursor.
- ``member`` holds full DNs, so the poller must resolve each DN to a user entry
  and cannot assume the member value is a key.
- The entries below include a missing ``employeeID``, a duplicated
  ``employeeID``, and a disabled account, so the identity-policy question has
  concrete fixture evidence.
- ``group_entry_after_removal`` shows the membership-removal case: the
  group's own ``uSNChanged`` moves while the removed user's does not, so a
  poller that reads only user objects never sees the removal.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

GROUP_DN = "CN=AI-Platform-Users,OU=Groups,OU=AI Platform,DC=corp,DC=example,DC=com"
USERS_BASE = "OU=AI Platform,DC=corp,DC=example,DC=com"

ALICE_DN = f"CN=Alice Adams,{USERS_BASE}"
BOB_DN = f"CN=Bob Brown,{USERS_BASE}"
CAROL_DN = f"CN=Carol Clark,{USERS_BASE}"
DAVE_DN = f"CN=Dave Davis,{USERS_BASE}"

# Alice, Bob, Carol and Dave each have a distinct objectGUID. Carol and Dave
# share employeeID "E20002": the duplicate that D-010 must handle.
ALICE_GUID = bytes.fromhex("4a3b2c1d5e6f47a8b9c0d1e2f3a4b5c6")
BOB_GUID = bytes.fromhex("00112233445566778899aabbccddeeff")
CAROL_GUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
DAVE_GUID = bytes.fromhex("d3a1f0b24c8e4f6a9b7c5d3e1f2a4b6c")

GROUP_GUID = bytes.fromhex("0180a1b2c3d4e5f60718293a4b5c6d7e")

# AD's default for a normal enabled account; 514 is ACCOUNTDISABLE (0x0002)
# plus NORMAL_ACCOUNT (0x0200).
UAC_NORMAL_ACCOUNT = b"512"
UAC_DISABLED_ACCOUNT = b"514"

# ``uSNChanged`` is a signed 64-bit counter that increments per domain
# controller. These two values are adjacent in counter order but sort the
# other way round as text, which is why the cursor must be an integer.
USN_BEFORE = b"9999"
USN_AFTER = b"10000"

# Removed-from-group state: the group's USN moved, Bob's did not.
GROUP_USN_AFTER_REMOVAL = b"19055"
GROUP_WHEN_CHANGED_AFTER_REMOVAL = b"20260101120500.0Z"


def decode_like_ldap3(raw_attributes: Mapping[str, Sequence[bytes]]) -> dict[str, list[Any]]:
    """Decode attribute values the way ``ldap3`` does on the fast path.

    Textual attributes become ``str``; a value that is not valid UTF-8 (such as
    ``objectGUID``) stays ``bytes``. A missing or empty attribute stays absent,
    matching ``ldap3``'s behaviour without ``empty_attributes``.
    """
    decoded: dict[str, list[Any]] = {}
    for name, values in raw_attributes.items():
        decoded_values: list[Any] = []
        for value in values:
            try:
                decoded_values.append(value.decode("utf-8"))
            except UnicodeDecodeError:
                decoded_values.append(value)
        decoded[name] = decoded_values
    return decoded


def search_res_entry(dn: str, raw_attributes: Mapping[str, Sequence[bytes]]) -> dict[str, Any]:
    """Build one ``searchResEntry`` mapping in the shape ``ldap3`` returns."""
    raw = {name: list(values) for name, values in raw_attributes.items()}
    return {
        "type": "searchResEntry",
        "dn": dn,
        "raw_dn": dn.encode("utf-8"),
        "attributes": decode_like_ldap3(raw),
        "raw_attributes": raw,
    }


def search_res_done(
    result: int = 0,
    description: str = "success",
    message: str = "",
    controls: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the ``searchResDone`` result mapping, including paging controls."""
    done: dict[str, Any] = {
        "type": "searchResDone",
        "result": result,
        "description": description,
        "message": message,
        "dn": "",
        "referrals": None,
    }
    if controls is not None:
        done["controls"] = dict(controls)
    return done


def _group(members: Sequence[str], usn: bytes, when_changed: bytes) -> dict[str, Any]:
    return search_res_entry(
        GROUP_DN,
        {
            "objectClass": [b"top", b"group"],
            "cn": [b"AI-Platform-Users"],
            "distinguishedName": [GROUP_DN.encode("utf-8")],
            "objectGUID": [GROUP_GUID],
            "uSNChanged": [usn],
            "whenChanged": [when_changed],
            "member": [member.encode() for member in members],
        },
    )


def group_entry(
    members: Sequence[str] | None = None,
    usn: bytes = b"19042",
    when_changed: bytes = b"20260101120000.0Z",
) -> dict[str, Any]:
    """The access group before any change: four members, GUID binary.

    Dave is still a member even though his account is disabled: disabling a
    user in AD does not remove the group membership, so a poller that trusts
    ``member`` alone would keep a disabled person entitled.
    """
    if members is None:
        members = [ALICE_DN, BOB_DN, CAROL_DN, DAVE_DN]
    return _group(
        members,
        usn=usn,
        when_changed=when_changed,
    )


def group_entry_after_removal() -> dict[str, Any]:
    """The same group after Bob is removed: Bob's DN is gone, the group's USN moved."""
    return _group(
        [ALICE_DN, CAROL_DN, DAVE_DN],
        usn=GROUP_USN_AFTER_REMOVAL,
        when_changed=GROUP_WHEN_CHANGED_AFTER_REMOVAL,
    )


def alice_entry(
    user_account_control: bytes = UAC_NORMAL_ACCOUNT,
) -> dict[str, Any]:
    """A complete user: employeeID present, enabled account."""
    return search_res_entry(
        ALICE_DN,
        {
            "objectClass": [b"top", b"person", b"organizationalPerson", b"user"],
            "sAMAccountName": [b"aadams"],
            "displayName": [b"Alice Adams"],
            "mail": [b"alice.adams@example.com"],
            "employeeID": [b"E10001"],
            "objectGUID": [ALICE_GUID],
            "uSNChanged": [b"19031"],
            "whenChanged": [b"20260101115900.0Z"],
            "userAccountControl": [user_account_control],
        },
    )


def bob_entry() -> dict[str, Any]:
    """A user with no employeeID at all: only objectGUID can identify them.

    Bob's ``uSNChanged`` is unchanged after he is removed from the group, which
    is the point of ``group_entry_after_removal``.
    """
    return search_res_entry(
        BOB_DN,
        {
            "objectClass": [b"top", b"person", b"organizationalPerson", b"user"],
            "sAMAccountName": [b"bbrown"],
            "displayName": [b"Bob Brown"],
            "mail": [b"bob.brown@example.com"],
            "objectGUID": [BOB_GUID],
            "uSNChanged": [b"19035"],
            "whenChanged": [b"20260101120000.0Z"],
            "userAccountControl": [UAC_NORMAL_ACCOUNT],
        },
    )


def carol_entry() -> dict[str, Any]:
    """A user sharing employeeID E20002 with Dave: a duplicate value."""
    return search_res_entry(
        CAROL_DN,
        {
            "objectClass": [b"top", b"person", b"organizationalPerson", b"user"],
            "sAMAccountName": [b"cclark"],
            "displayName": [b"Carol Clark"],
            "mail": [b"carol.clark@example.com"],
            "employeeID": [b"E20002"],
            "objectGUID": [CAROL_GUID],
            "uSNChanged": [b"19038"],
            "whenChanged": [b"20260101120100.0Z"],
            "userAccountControl": [UAC_NORMAL_ACCOUNT],
        },
    )


def dave_entry() -> dict[str, Any]:
    """A disabled user sharing employeeID E20002 with Carol."""
    return search_res_entry(
        DAVE_DN,
        {
            "objectClass": [b"top", b"person", b"organizationalPerson", b"user"],
            "sAMAccountName": [b"ddavis"],
            "displayName": [b"Dave Davis"],
            "mail": [b"dave.davis@example.com"],
            "employeeID": [b"E20002"],
            "objectGUID": [DAVE_GUID],
            "uSNChanged": [b"19040"],
            "whenChanged": [b"20260101120200.0Z"],
            "userAccountControl": [UAC_DISABLED_ACCOUNT],
        },
    )


def group_search_response() -> list[dict[str, Any]]:
    """``ldap3`` response for the group lookup: the group object and its members."""
    return [group_entry(), search_res_done()]


def member_search_response() -> list[dict[str, Any]]:
    """``ldap3`` response for resolving the group's member DNs to user entries."""
    return [alice_entry(), bob_entry(), carol_entry(), dave_entry(), search_res_done()]


def usn_search_response() -> list[dict[str, Any]]:
    """``ldap3`` response for `` (uSNChanged>=<cursor>)``: group plus users.

    The group is included because a membership change updates the group's
    ``member`` attribute and the group's own ``uSNChanged``, not the removed
    user's. A poller that reads only user objects misses removals.
    """
    return [
        group_entry(),
        alice_entry(),
        bob_entry(),
        carol_entry(),
        dave_entry(),
        search_res_done(),
    ]


def usn_search_response_after_removal() -> list[dict[str, Any]]:
    """The same query one poll later: only the group entry comes back.

    Bob's entry is absent because his ``uSNChanged`` did not change. The group
    entry carries the new ``member`` list, and diffing it against the previous
    group read is what produces ``group.member_removed``.
    """
    return [group_entry_after_removal(), search_res_done()]


def paged_search_response() -> list[dict[str, Any]]:
    """A page that ends with a paging cookie, as a real paged search would.

    ``ldap3`` surfaces the server control in ``result['controls']``; the
    adapter must pass the cookie back until it is empty.
    """
    cookie = {"1.2.840.113556.1.4.319": {"value": {"cookie": b"opaque-page-2"}}}
    return [alice_entry(), bob_entry(), search_res_done(controls=cookie)]


def empty_search_response() -> list[dict[str, Any]]:
    """A search with no matching entries: only the done message."""
    return [search_res_done()]


ROOT_DSE_INVOCATION_ID = bytes.fromhex("11223344556677889900aabbccddeeff")


def root_dse_entry(
    dns_host_name: str = "dc1.corp.example.com",
    invocation_id: bytes = ROOT_DSE_INVOCATION_ID,
    highest_committed_usn: bytes = b"25000",
) -> dict[str, Any]:
    """RootDSE searchResEntry mapping in the shape ldap3 returns."""
    return search_res_entry(
        "",
        {
            "dnsHostName": [dns_host_name.encode("utf-8")],
            "invocationID": [invocation_id],
            "highestCommittedUSN": [highest_committed_usn],
            "supportedControl": [
                b"1.2.840.113556.1.4.319",
            ],
        },
    )


def root_dse_search_response() -> list[dict[str, Any]]:
    """ldap3 response for RootDSE lookup."""
    return [root_dse_entry(), search_res_done()]
