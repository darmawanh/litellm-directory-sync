"""Version-2 opaque System Log cursor functions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

_CURSOR_KEYS = frozenset({"v", "since", "covered_through", "after", "pages"})


@dataclass(frozen=True)
class SystemLogCursor:
    """Parsed internal state; only serialized text crosses the port boundary."""

    since: datetime
    covered_through: datetime
    after: str | None
    pages: int


def parse_cursor(token: str | None) -> tuple[SystemLogCursor | None, str | None]:
    """Parse exactly the accepted v2 shape, returning a reason instead of raising."""
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
        or value["v"] != 2
        or not isinstance(value["since"], str)
        or not isinstance(value["covered_through"], str)
        or (
            value["after"] is not None
            and (not isinstance(value["after"], str) or not value["after"])
        )
        or isinstance(value["pages"], bool)
        or not isinstance(value["pages"], int)
        or value["pages"] < 0
    ):
        return None, "cursor_unusable"
    since = _parse_instant(value["since"])
    covered_through = _parse_instant(value["covered_through"])
    if since is None or covered_through is None:
        return None, "cursor_unusable"
    return (
        SystemLogCursor(
            since=since,
            covered_through=covered_through,
            after=value["after"],
            pages=value["pages"],
        ),
        None,
    )


def gap_reason(
    cursor: SystemLogCursor | None,
    *,
    now: datetime,
    overlap_seconds: int,
    retention_seconds: int,
    parse_reason: str | None = None,
) -> str | None:
    """Apply ADR-008's ordered check once, using the response Date as ``now``."""
    if cursor is None:
        return parse_reason or "cursor_unusable"
    overlap = timedelta(seconds=overlap_seconds)
    if now < cursor.covered_through - overlap:
        return "clock_backwards"
    if cursor.since > cursor.covered_through:
        return "window_ahead_of_coverage"
    if cursor.since < now - timedelta(seconds=retention_seconds):
        return "aged_out"
    return None


def initial_since(now: datetime, overlap_seconds: int) -> str:
    """Build the first query's window start before the server watermark is known."""
    return _format_instant(now - timedelta(seconds=overlap_seconds))


def seeded_cursor(now: datetime, overlap_seconds: int) -> str:
    """Seed a clean cursor after a full group sync."""
    state = SystemLogCursor(
        since=now - timedelta(seconds=overlap_seconds),
        covered_through=now,
        after=None,
        pages=0,
    )
    return encode_cursor(state)


def page_cursor(cursor: SystemLogCursor, *, after: str) -> str:
    """Persist the next page token without advancing completed coverage."""
    return encode_cursor(
        SystemLogCursor(
            since=cursor.since,
            covered_through=cursor.covered_through,
            after=after,
            pages=cursor.pages + 1,
        )
    )


def completed_cursor(cursor: SystemLogCursor, *, now: datetime, overlap_seconds: int) -> str:
    """Advance coverage only after the final page has been read."""
    covered_through = max(cursor.covered_through, now)
    return encode_cursor(
        SystemLogCursor(
            since=covered_through - timedelta(seconds=overlap_seconds),
            covered_through=covered_through,
            after=None,
            pages=0,
        )
    )


def encode_cursor(cursor: SystemLogCursor) -> str:
    """Serialize the exact five-key opaque token from ADR-008 §1."""
    return json.dumps(
        {
            "v": 2,
            "since": _format_instant(cursor.since),
            "covered_through": _format_instant(cursor.covered_through),
            "after": cursor.after,
            "pages": cursor.pages,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _parse_instant(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _format_instant(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.") + f"{normalized.microsecond // 1000:03d}Z"
