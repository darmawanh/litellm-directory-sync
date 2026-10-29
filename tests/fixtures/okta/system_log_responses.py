"""Hand-built Okta System Log responses for the T-008 spike.

Written from Okta's documented System Log API shape, **not captured from a live
org**. No request is sent; this module is data only.

``PAGES`` models cursor pagination: the body is a bare JSON array and the next
page is reached through the ``Link`` header's ``rel="next"`` URL. The cursor is
that URL's ``after`` parameter and is **not** an integer, which is why the port's
cursor is an opaque string. ``empty_page`` has no ``Link`` header:
that, not an empty array alone, is the documented end signal. ``rate_limited`` is
the 429 shape, whose ``X-RateLimit-Reset`` design 9.2 says to honour.
``query_params`` separates ``since`` (the resume window) from ``after`` (the page
cursor). ``cursor``, ``seeded``, ``gap_reason``, ``advance``, and ``drain``
encode ADR-008: the cursor is version 2, its watermark is the instant the last
completed drain issued its first request, and a gap is a window start ahead of
that watermark rather than a window that has merely outlived the last event.
Every gap runs a full sync and re-seeds the token.

The first entry deliberately carries an ``employeeNumber`` so the cross-feed
``event_id`` equality F10 is executable: its ``uuid`` matches the hook
fixture's ``ADD_EVENT_UUID``. The remaining entries keep ``detailEntry: null``,
which is the shape F4 records.

Every host is ``example.com`` and every id is synthetic. No token appears here.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

LOGS_URL = "https://example.okta.com/api/v1/logs"
GROUP_ID = "00gPLACEHOLDERGRP01"

# Opaque base64 cursors, as Okta returns them inside the Link URL.
CURSOR_PAGE_2 = "Mg=="
CURSOR_PAGE_3 = "Mw=="

RATE_LIMIT_RESET_EPOCH = "1767272400"

# ADR-008 §1-§2: the token is version 2, and its ``covered_through`` watermark
# advances to the drain start whether or not events were read. The overlap is a
# re-read margin around that watermark, not a term that makes a predicate
# sufficient: ``since = covered_through - overlap`` is always strictly below
# ``covered_through``, so this service's own advance can never report a gap.
CURSOR_VERSION = 2
DEFAULT_POLL_SECONDS = 60
DEFAULT_OVERLAP_SECONDS = 60
# a conservative floor, not the org's real retention.
DEFAULT_RETENTION_SECONDS = 604_800

# An event timestamp: not a watermark and not a window start.
# ``test_system_log_query_separates_since_from_after`` uses it as query input
# only; no gap rule may compare against it.
LAST_CONSUMED_PUBLISHED = "2026-01-01T12:00:05.000Z"

# The first entry's uuid matches ``event_hook_payloads.ADD_EVENT_UUID`` so the
# two feeds dedupe on one canonical ``event_id``.
SHARED_EVENT_UUID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"


def _parse_instant(instant: str) -> datetime:
    """Parse an ISO-8601 instant, accepting Okta's trailing ``Z``."""
    return datetime.fromisoformat(instant.replace("Z", "+00:00"))


def _format_instant(instant: datetime) -> str:
    """Render an aware UTC instant in the token's ``...mmmZ`` shape."""
    return instant.strftime("%Y-%m-%dT%H:%M:%S.") + f"{instant.microsecond // 1000:03d}Z"


def _entry(
    event_type: str,
    uuid: str,
    published: str,
    user_id: str,
    email: str,
    employee_number: str | None = None,
) -> dict[str, Any]:
    detail = {"employeeNumber": employee_number} if employee_number else None
    return {
        "eventType": event_type,
        "version": "0",
        "severity": "INFO",
        "displayMessage": "Add user to group membership",
        "actor": {"id": "00uPLACEHOLDERADMIN1", "type": "User", "detailEntry": None},
        "client": {"ipAddress": "203.0.113.10", "geographicalContext": None},
        "outcome": {"result": "SUCCESS", "reason": None},
        "published": published,
        "target": [
            {
                "id": user_id,
                "type": "User",
                "alternateId": email,
                "displayName": "Placeholder",
                "detailEntry": detail,
            },
            {
                "id": GROUP_ID,
                "type": "UserGroup",
                "alternateId": "AI-Platform-Users",
                "displayName": "AI-Platform-Users",
                "detailEntry": None,
            },
        ],
        "uuid": uuid,
    }


def link_header(after: str | None) -> str | None:
    """The ``Link`` header for a page, or ``None`` for the last page.

       Okta puts the next cursor in a URL, not in a header of its own.

       Deliberately incomplete: this URL carries only ``limit`` and ``after``, with
       no ``filter`` and no ``since``. That absence is the evidence for ADR-006 F8
    ("never fetch the ``Link`` URL verbatim"). Do not copy it as a request
       builder.
    """
    if after is None:
        return None
    encoded = after.replace("=", "%3D")
    return (
        f'<{LOGS_URL}?limit=2&after={encoded}>; rel="next", '
        f'<{LOGS_URL}?limit=2&after={encoded}>; rel="self"'
    )


def next_cursor(headers: Mapping[str, str]) -> str | None:
    """Read the next cursor from a ``Link`` header; ``None`` means stop."""
    link = headers.get("Link")
    if link is None:
        return None
    for part in link.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        target = section.split(";", 1)[0].strip().strip("<>")
        for pair in target.partition("?")[2].split("&"):
            key, _, value = pair.partition("=")
            if key == "after":
                return value.replace("%3D", "=")
    return None


def filter_for_group() -> str:
    """The ``filter`` a group-scoped poll sends; the group id is stable, the name is not.

       Deliberately incomplete: this covers only the two membership event types,
       while ``reference_mapping.EVENT_TYPE_MAP`` also maps
       ``user.lifecycle.deactivate``. That mismatch is the evidence for ADR-006 F11
    (a poller built from this filter never sees a disable). Do not copy it; the
       Phase 5 poller must filter over every mapped type.
    """
    return 'eventType eq "group.user_membership.add" or eventType eq "group.user_membership.remove"'


def query_params(since: str | None = None, after: str | None = None) -> dict[str, str]:
    """The query the poller sends to ``/api/v1/logs``.

    ``limit`` is capped by the org and is unverified. The group is matched in
    memory from ``target``, because the documented filter has no membership
    clause for this endpoint.
    """
    params = {"limit": "200", "filter": filter_for_group()}
    if since is not None:
        params["since"] = since
    if after is not None:
        params["after"] = after
    return params


def cursor(
    since: str, covered_through: str, after: str | None = None, pages: int = 0
) -> dict[str, Any]:
    """The version-2 cursor token; ``consumed_through`` is gone."""
    return {
        "v": CURSOR_VERSION,
        "since": since,
        "covered_through": covered_through,
        "after": after,
        "pages": pages,
    }


def seeded(now: str, overlap: int = DEFAULT_OVERLAP_SECONDS) -> dict[str, Any]:
    """The post-full-sync seed: ``covered_through = now``."""
    since = _parse_instant(now) - timedelta(seconds=overlap)
    return cursor(_format_instant(since), now)


def gap_reason(
    token: Any,
    now: str,
    overlap: int = DEFAULT_OVERLAP_SECONDS,
    retention_seconds: int = DEFAULT_RETENTION_SECONDS,
) -> str | None:
    """Evaluate ADR-008 §3 once, in its branch order, and name the reason.

    The reason strings are literals: ADR-008's fixture surface names no
    constant for them, and the Phase 5 metric label is the literal anyway.
    """
    if not isinstance(token, Mapping):
        return "cursor_unusable"
    since = token.get("since")
    covered_through = token.get("covered_through")
    after = token.get("after")
    pages = token.get("pages")
    if (
        token.get("v") != CURSOR_VERSION
        or not isinstance(since, str)
        or not isinstance(covered_through, str)
        or not isinstance(pages, int)
        or not (after is None or isinstance(after, str))
    ):
        return "cursor_unusable"
    try:
        since_instant = _parse_instant(since)
        covered_instant = _parse_instant(covered_through)
    except ValueError:
        return "cursor_unusable"

    now_instant = _parse_instant(now)
    if now_instant < covered_instant - timedelta(seconds=overlap):
        return "clock_backwards"
    if since_instant > covered_instant:
        return "window_ahead_of_coverage"
    if since_instant < now_instant - timedelta(seconds=retention_seconds):
        return "aged_out"
    return None


def advance(
    token: dict[str, Any], drain_start: str, overlap: int = DEFAULT_OVERLAP_SECONDS
) -> dict[str, Any]:
    """ADR-008 §2: advance the watermark to the drain start, never backwards."""
    covered_through = max(_parse_instant(token["covered_through"]), _parse_instant(drain_start))
    since = covered_through - timedelta(seconds=overlap)
    return cursor(_format_instant(since), _format_instant(covered_through))


def drain(
    token: Any,
    now: str,
    published: tuple[dict[str, Any], ...] = (),
    overlap: int = DEFAULT_OVERLAP_SECONDS,
    retention_seconds: int = DEFAULT_RETENTION_SECONDS,
) -> tuple[dict[str, Any], str | None]:
    """One iteration of the real loop: check once, then re-seed or advance.

    ``published`` is accepted and deliberately not read for state: the
    watermark is the drain start, never the last event.
    """
    reason = gap_reason(token, now, overlap, retention_seconds)
    if reason is not None:
        return seeded(now, overlap), reason
    return advance(token, drain_start=now, overlap=overlap), None


def _response(status: int, body: Any, headers: Mapping[str, str]) -> dict[str, Any]:
    return {"status": status, "headers": dict(headers), "body": body}


def _headers(link: str | None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "X-RateLimit-Limit": "2",
        "X-RateLimit-Remaining": "1",
        "X-RateLimit-Reset": RATE_LIMIT_RESET_EPOCH,
    }
    if link is not None:
        headers["Link"] = link
    return headers


def first_page() -> dict[str, Any]:
    """Page one: two entries and a ``rel="next"`` link carrying ``after=Mg==``.

    The first entry carries ``employeeNumber`` so it normalizes to a
    :class:`CanonicalEvent` and the F10 cross-feed equality can be asserted.
    """
    return _response(
        200,
        [
            _entry(
                "group.user_membership.add",
                SHARED_EVENT_UUID,
                "2026-01-01T12:00:00.000Z",
                "00uPLACEHOLDERUSER01",
                "alice.adams@example.com",
                employee_number="E10001",
            ),
            _entry(
                "group.user_membership.add",
                "3a4b5c6d-7e8f-4a9b-9c0d-1e2f3a4b5c6d",
                "2026-01-01T12:00:05.000Z",
                "00uPLACEHOLDERUSER02",
                "bob.brown@example.com",
            ),
        ],
        _headers(link_header(CURSOR_PAGE_2)),
    )


def second_page() -> dict[str, Any]:
    """Page two: one entry that still links onward, then the empty page.

    The short page with a ``rel="next"`` is deliberate: ADR-006 F7 says
    termination is the absence of the link, not a short body.
    """
    return _response(
        200,
        [
            _entry(
                "group.user_membership.remove",
                "1a2b3c4d-5e6f-4a7b-9c8d-0e1f2a3b4c5d",
                "2026-01-01T12:05:00.000Z",
                "00uPLACEHOLDERUSER01",
                "alice.adams@example.com",
            )
        ],
        _headers(link_header(CURSOR_PAGE_3)),
    )


def empty_page() -> dict[str, Any]:
    """The terminal page: an empty array and no ``Link`` header."""
    return _response(200, [], _headers(None))


def rate_limited() -> dict[str, Any]:
    """A 429 with Okta's error envelope and the reset epoch the client must honour."""
    headers = _headers(None)
    headers["X-RateLimit-Remaining"] = "0"
    return _response(
        429,
        {
            "errorCode": "E0000047",
            "errorSummary": "API call exceeded rate limit due to too many requests.",
            "errorLink": "E0000047",
            "errorId": "oaePLACEHOLDERERRORID",
            "errorCauses": [],
        },
        headers,
    )


# The walk a fallback poller performs: first page -> second page -> empty page.
# Keys are the cursor the *request* carried; ``None`` is the first request.
PAGES: dict[str | None, dict[str, Any]] = {
    None: first_page(),
    CURSOR_PAGE_2: second_page(),
    CURSOR_PAGE_3: empty_page(),
}
