"""The adapter's opaque cursor parser and ADR-008's gap rule."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from identity_lifecycle.adapters.okta.cursor import (
    SystemLogCursor,
    completed_cursor,
    gap_reason,
    page_cursor,
    parse_cursor,
    seeded_cursor,
)

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@pytest.mark.unit
def test_v2_cursor_has_exact_keys_and_pages_resume_without_advancing_coverage() -> None:
    seeded, reason = parse_cursor(seeded_cursor(START, 60))
    assert reason is None
    assert seeded == SystemLogCursor(
        since=START - timedelta(seconds=60),
        covered_through=START,
        after=None,
        pages=0,
    )
    assert seeded is not None

    resumed, reason = parse_cursor(page_cursor(seeded, after="opaque-cursor"))
    assert reason is None
    assert resumed == SystemLogCursor(
        since=seeded.since,
        covered_through=seeded.covered_through,
        after="opaque-cursor",
        pages=1,
    )


@pytest.mark.unit
def test_completed_cursor_uses_the_drain_start_and_overlap() -> None:
    token = seeded_cursor(START, 60)
    state, reason = parse_cursor(token)
    assert reason is None and state is not None

    completed, reason = parse_cursor(
        completed_cursor(state, now=START + timedelta(seconds=30), overlap_seconds=60)
    )

    assert reason is None and completed is not None
    assert completed.covered_through == START + timedelta(seconds=30)
    assert completed.since == START - timedelta(seconds=30)
    assert completed.after is None and completed.pages == 0


@pytest.mark.unit
@pytest.mark.parametrize(
    ("token", "now", "expected"),
    [
        (None, START, "cursor_unusable"),
        ('{"v":1}', START, "cursor_unusable"),
        (
            json.dumps(
                {
                    "v": 2,
                    "since": "2026-01-01T12:00:01Z",
                    "covered_through": "2026-01-01T12:00:00Z",
                    "after": None,
                    "pages": 0,
                }
            ),
            START,
            "window_ahead_of_coverage",
        ),
        (
            json.dumps(
                {
                    "v": 2,
                    "since": "2026-01-01T11:58:59Z",
                    "covered_through": "2026-01-01T12:00:00Z",
                    "after": None,
                    "pages": 0,
                }
            ),
            START - timedelta(seconds=61),
            "clock_backwards",
        ),
        (
            json.dumps(
                {
                    "v": 2,
                    "since": "2025-12-20T00:00:00Z",
                    "covered_through": "2025-12-20T00:01:00Z",
                    "after": None,
                    "pages": 0,
                }
            ),
            START,
            "aged_out",
        ),
    ],
)
def test_adr008_gap_reasons(token: str | None, now: datetime, expected: str) -> None:
    state, parse_reason = parse_cursor(token)

    assert (
        gap_reason(
            state,
            now=now,
            overlap_seconds=60,
            retention_seconds=604800,
            parse_reason=parse_reason,
        )
        == expected
    )


@pytest.mark.unit
def test_cursor_parser_rejects_unknown_keys_boolean_versions_and_empty_after() -> None:
    base = {
        "v": 2,
        "since": "2026-01-01T11:59:00Z",
        "covered_through": "2026-01-01T12:00:00Z",
        "after": None,
        "pages": 0,
    }
    malformed = (
        {**base, "extra": "no"},
        {**base, "v": True},
        {**base, "after": ""},
    )
    for payload in malformed:
        state, reason = parse_cursor(json.dumps(payload))
        assert state is None
        assert reason == "cursor_unusable"
