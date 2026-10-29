"""Map Active Directory LDAP entries and binary attributes to domain types."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from identity_lifecycle.ports.identity_source import IdentityGroup, IdentityUser

OBJECTGUID_LENGTH = 16
ACCOUNTDISABLE_BIT = 0x0002


class MalformedObjectGuid(ValueError):
    """Raised when an Active Directory objectGUID is not a valid 16-byte binary value."""


def objectguid_to_uuid(raw: bytes | str) -> uuid.UUID:
    """Convert raw Active Directory ``objectGUID`` bytes to canonical UUID.

       AD sends ``objectGUID`` as 16 raw bytes in mixed-endian order:
       ``time_low``, ``time_mid``, and ``time_hi_and_version`` are little-endian on
       the wire, while ``clock_seq`` and ``node`` are big-endian.
       ``uuid.UUID (bytes_le=raw)`` implements this layout directly.

       If a string is supplied, only the 38-character braced form is accepted
    (e.g. ``{1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6}``).
    """
    if isinstance(raw, bytes):
        if len(raw) != OBJECTGUID_LENGTH:
            raise MalformedObjectGuid(
                f"objectGUID must be {OBJECTGUID_LENGTH} bytes, got {len(raw)}"
            )
        return uuid.UUID(bytes_le=raw)

    if isinstance(raw, str):
        cleaned = raw.strip()
        if len(cleaned) == 38 and cleaned.startswith("{") and cleaned.endswith("}"):
            try:
                return uuid.UUID(cleaned[1:-1])
            except ValueError as error:
                raise MalformedObjectGuid(f"Invalid braced objectGUID string: {raw}") from error
        raise MalformedObjectGuid(
            f"String objectGUID must be 38-character braced format, got: {raw!r}"
        )

    raise MalformedObjectGuid(f"objectGUID must be bytes or braced str, got {type(raw).__name__}")


def uuid_to_ldap_filter_value(guid: uuid.UUID) -> str:
    """Format a UUID as an RFC 4515 hex-escaped octet string for LDAP search filters."""
    return "".join(f"\\{byte:02x}" for byte in guid.bytes_le)


def is_account_enabled(uac: int | str | bytes | None) -> bool:
    """Return whether userAccountControl indicates an enabled account (F7).

    Account disable is indicated by bit 0x0002 (ACCOUNTDISABLE).
    """
    if uac is None:
        return True
    try:
        val = int(uac.decode("utf-8")) if isinstance(uac, bytes) else int(uac)
    except (ValueError, TypeError):
        return True
    return not bool(val & ACCOUNTDISABLE_BIT)


def map_user_entry(entry: Mapping[str, Any]) -> IdentityUser:
    """Map one AD searchResEntry mapping into an IdentityUser."""
    raw_attrs: Mapping[str, Sequence[bytes]] = entry.get("raw_attributes", {})
    attrs: Mapping[str, Sequence[Any]] = entry.get("attributes", {})

    guid_raw: bytes | None = None
    raw_guid_list = raw_attrs.get("objectGUID")
    if raw_guid_list:
        guid_raw = raw_guid_list[0]
    else:
        attr_guid_list = attrs.get("objectGUID")
        if attr_guid_list and isinstance(attr_guid_list[0], bytes):
            guid_raw = attr_guid_list[0]

    if guid_raw is None:
        raise MalformedObjectGuid(f"Missing objectGUID in entry: {entry.get('dn')}")

    source_user_id = str(objectguid_to_uuid(guid_raw)).lower()

    emp_id_list = attrs.get("employeeID", [])
    employee_number: str | None = None
    if emp_id_list and emp_id_list[0] is not None:
        emp_str = str(emp_id_list[0]).strip()
        if emp_str:
            employee_number = emp_str

    mail_list = attrs.get("mail", [])
    if mail_list and mail_list[0]:
        email = str(mail_list[0]).strip()
    else:
        upn_list = attrs.get("userPrincipalName", [])
        email = str(upn_list[0]).strip() if upn_list and upn_list[0] else ""

    display_name_list = attrs.get("displayName", [])
    if display_name_list and display_name_list[0]:
        display_name = str(display_name_list[0]).strip()
    else:
        sam_list = attrs.get("sAMAccountName", [])
        display_name = str(sam_list[0]).strip() if sam_list and sam_list[0] else ""

    uac_list = attrs.get("userAccountControl", [])
    uac_val = uac_list[0] if uac_list else 512
    enabled = is_account_enabled(uac_val)

    return IdentityUser(
        source_user_id=source_user_id,
        employee_number=employee_number,
        email=email,
        display_name=display_name,
        enabled=enabled,
    )


def map_group_entry(entry: Mapping[str, Any]) -> tuple[IdentityGroup, tuple[str, ...]]:
    """Map one AD group entry to IdentityGroup and its member DNs."""
    attrs: Mapping[str, Sequence[Any]] = entry.get("attributes", {})
    group_dn = str(entry.get("dn", ""))

    cn_list = attrs.get("cn", [])
    group_name = str(cn_list[0]) if cn_list and cn_list[0] else group_dn

    members: list[str] = []
    for member_dn in attrs.get("member", []):
        if member_dn:
            members.append(str(member_dn))

    return IdentityGroup(source_group_id=group_dn, name=group_name), tuple(members)
