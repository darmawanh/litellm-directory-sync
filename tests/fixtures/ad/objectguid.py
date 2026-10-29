"""Reference converter for the AD ``objectGUID`` attribute.

Active Directory returns ``objectGUID`` as a 16-byte binary value in
*mixed-endian* order: ``time_low``, ``time_mid``, and ``time_hi_and_version``
are little-endian on the wire, while ``clock_seq`` and ``node`` are
big-endian. ``uuid.UUID (bytes_le=...)`` implements exactly that layout, so the
wire bytes ``4a3b2c1d5e6f47a8b9c0d1e2f3a4b5c6`` become the canonical string
``1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6``. Reading the same bytes with
``uuid.UUID (bytes=...)`` would reverse the first three fields and produce the
wrong person's identifier.

This module is the spike's *reference* converter. It proves the byte order and
gives ADR-005 a checkable example; it is not the adapter. Phase 6 must
reimplement the conversion in ``src/identity_lifecycle/adapters/ad/mapping.py``
and cover it with the adapter contract suite. Nothing under ``src/`` may
import this module.
"""

from __future__ import annotations

import uuid

OBJECTGUID_LENGTH = 16


class MalformedObjectGuid(ValueError):
    """A value is not a 16-byte binary AD ``objectGUID``."""


def objectguid_to_uuid(raw: bytes) -> uuid.UUID:
    """Convert raw AD ``objectGUID`` bytes to the canonical UUID.

    The first three UUID fields are little-endian and the last two are
    big-endian, which is what ``bytes_le`` means.
    """
    if not isinstance(raw, bytes):
        raise MalformedObjectGuid(f"objectGUID must be bytes, got {type(raw).__name__}")
    if len(raw) != OBJECTGUID_LENGTH:
        raise MalformedObjectGuid(f"objectGUID must be {OBJECTGUID_LENGTH} bytes, got {len(raw)}")
    return uuid.UUID(bytes_le=raw)
