"""Per-DC integer USN cursor tracking for Active Directory."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

_CURSOR_KEYS = frozenset({"v", "dc", "usn"})


@dataclass(frozen=True)
class ADCursor:
    """Parsed internal AD cursor state: invocationID and integer USN counter."""

    dc: str
    usn: int


def parse_cursor(
    token: str | None,
    *,
    connected_dc: str | None = None,
) -> tuple[ADCursor | None, str | None]:
    """Parse the accepted v1 AD cursor shape, returning (state, reason) instead of raising.

    The AD cursor token is strictly `{"v": 1, "dc": "<invocationID>", "usn": <integer>}`.
    USN must be a JSON integer number, never a string or boolean.
    """
    if token is None:
        return None, "cursor_unusable"

    try:
        value: Any = json.loads(token)
    except (ValueError, TypeError):
        return None, "cursor_unusable"

    if not isinstance(value, dict) or frozenset(value) != _CURSOR_KEYS:
        return None, "cursor_unusable"

    if (
        isinstance(value["v"], bool)
        or value["v"] != 1
        or not isinstance(value["dc"], str)
        or not value["dc"]
        or isinstance(value["usn"], bool)
        or not isinstance(value["usn"], int)
        or value["usn"] < 0
    ):
        return None, "cursor_unusable"

    dc = value["dc"]
    usn = value["usn"]

    if connected_dc is not None and dc != connected_dc:
        return None, "dc_changed"

    return ADCursor(dc=dc, usn=usn), None


def format_cursor(dc: str, usn: int) -> str:
    """Serialize the AD cursor to the canonical JSON token format."""
    if not isinstance(dc, str) or not dc:
        raise ValueError("DC invocationID must be a non-empty string")
    if isinstance(usn, bool) or not isinstance(usn, int) or usn < 0:
        raise ValueError("USN must be a non-negative integer")
    return json.dumps({"v": 1, "dc": dc, "usn": usn})
