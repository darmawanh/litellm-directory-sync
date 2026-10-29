"""Evidence tests for the T-008 Okta spike: hook shape and System Log pagination.

Hand-built fixtures only. No socket, no org, no write. The ``tests.fixtures``
import ban for ``src/`` is already enforced tree-wide by
``tests/unit/test_objectguid_conversion.py``.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.okta import event_hook_payloads, reference_mapping, system_log_responses
from tests.fixtures.okta.reference_mapping import (
    CODE_MALFORMED_CHALLENGE,
    CODE_MALFORMED_EVENT,
    CODE_MISSING_EMPLOYEE_NUMBER,
    CODE_UNSUCCESSFUL_OUTCOME,
    CODE_VERIFICATION_CHALLENGE,
    CanonicalEvent,
    PermanentCondition,
)

FIXTURE_ROOT = Path(reference_mapping.__file__).resolve().parent

# Vendor field names that must not survive into the canonical envelope.
VENDOR_FIELD_NAMES = {
    "eventType",
    "target",
    "detailEntry",
    "alternateId",
    "displayMessage",
    "published",
    "uuid",
    "actor",
    "client",
    "outcome",
    "employeeNumber",
}


def _canonical(payload: dict[str, Any]) -> CanonicalEvent:
    result = reference_mapping.normalize_event(payload)
    assert isinstance(result, CanonicalEvent), f"expected a canonical event, got {result!r}"
    return result


def _all_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.add(str(key))
            keys |= _all_keys(nested)
    elif isinstance(value, list):
        for item in value:
            keys |= _all_keys(item)
    return keys


def _client_reads(source: str) -> list[str]:
    """Every place the normalizer reads a ``client`` key, as ``line: form``.

    ADR-006 §2 forbids using the body-supplied ``client.ipAddress`` for the
    allowlist, so the normalizer must never read ``client`` at all. A source-text
    search for the field name cannot prove that: a comment mentioning the field
    fails it, and a read through the ``client`` mapping passes it. The AST can
    tell the two apart, and the whole module is walked because no function here
    has a legitimate reason to read ``client``.
    """
    found: list[str] = []
    for node in ast.walk(ast.parse(source, filename="reference_mapping.py")):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "client"
        ):
            found.append(f"line {node.lineno}: subscript {ast.unparse(node)}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "client"
        ):
            found.append(f"line {node.lineno}: {ast.unparse(node)}")
    return found


@pytest.mark.unit
def test_membership_events_map_to_canonical_types() -> None:
    add = _canonical(event_hook_payloads.membership_add())
    remove = _canonical(event_hook_payloads.membership_remove())
    deactivate = _canonical(event_hook_payloads.user_deactivate())

    assert add.type == "group.member_added"
    assert remove.type == "group.member_removed"
    assert deactivate.type == "user.disabled"

    # Identity comes from the immutable ids, not from names.
    assert add.person_source_user_id == event_hook_payloads.ALICE_USER_ID
    assert add.group_source_group_id == event_hook_payloads.GROUP_ID
    assert remove.person_source_user_id == event_hook_payloads.ALICE_USER_ID
    assert deactivate.person_source_user_id == event_hook_payloads.DAVE_USER_ID
    assert deactivate.group_source_group_id is None

    for event in (add, remove, deactivate):
        payload = event.as_dict()
        assert payload["source"] == "okta"
        assert payload["schema_version"] == 1
        leaked = _all_keys(payload) & VENDOR_FIELD_NAMES
        assert not leaked, f"vendor field name leaked into the envelope: {sorted(leaked)}"


@pytest.mark.unit
def test_event_without_employee_number_is_flagged() -> None:
    result = reference_mapping.normalize_event(
        event_hook_payloads.membership_add_without_employee_number()
    )

    assert isinstance(result, PermanentCondition)
    assert result.code == CODE_MISSING_EMPLOYEE_NUMBER
    assert result.permanent is True
    # The condition names the person, so an operator can act on it.
    assert event_hook_payloads.BOB_USER_ID in result.detail


@pytest.mark.unit
def test_failed_outcome_is_not_mapped_as_an_applied_event() -> None:
    # ADR-006 F13: a non-SUCCESS outcome means the change did not happen.
    payload = event_hook_payloads.membership_add_failed_outcome()

    result = reference_mapping.normalize_event(payload)

    assert isinstance(result, PermanentCondition)
    assert result.code == CODE_UNSUCCESSFUL_OUTCOME
    assert "DENY" in result.detail

    # A present SUCCESS is still an applied change: the outcome split must not
    # route every result to a condition.
    assert _canonical(event_hook_payloads.membership_add()).type == "group.member_added"


@pytest.mark.unit
def test_missing_or_malformed_outcome_is_a_malformed_event() -> None:
    # a malformed body is a 400, while a present non-SUCCESS outcome
    # is a 200 "ignored". An absent or shapeless outcome is the former.
    base = event_hook_payloads.membership_add()

    absent = {key: value for key, value in base.items() if key != "outcome"}
    null_outcome = {**base, "outcome": None}
    empty_outcome = {**base, "outcome": {}}
    non_string_result = {**base, "outcome": {"result": 1}}
    string_outcome = {**base, "outcome": "SUCCESS"}

    for payload in (absent, null_outcome, empty_outcome, non_string_result, string_outcome):
        result = reference_mapping.normalize_event(payload)
        assert isinstance(result, PermanentCondition), f"expected a condition, got {result!r}"
        assert result.code == CODE_MALFORMED_EVENT
        assert result.permanent is True

    # The three shapes are distinguishable on one payload: absent is malformed,
    # DENY is a business outcome, SUCCESS is an applied event.
    assert _canonical({**base, "outcome": {"result": "SUCCESS"}}).type == "group.member_added"
    denied = reference_mapping.normalize_event({**base, "outcome": {"result": "DENY"}})
    assert isinstance(denied, PermanentCondition)
    assert denied.code == CODE_UNSUCCESSFUL_OUTCOME


@pytest.mark.unit
def test_non_string_challenge_is_a_typed_condition_not_an_exception() -> None:
    # The body is attacker-controlled: ``{"verification": 123}`` passes the
    # predicate and must be a typed 400 condition, not an AttributeError/TypeError
    # surfacing as a 500 on a public endpoint.
    secret = event_hook_payloads.VERIFICATION_SECRET

    for challenge, type_name in (
        (123, "int"),
        (None, "NoneType"),
        (["x"], "list"),
    ):
        body = {"verification": challenge}
        assert reference_mapping.is_verification_request(body)

        result = reference_mapping.verification_response(body["verification"], secret)

        assert isinstance(result, PermanentCondition), f"expected a condition, got {result!r}"
        assert result.code == CODE_MALFORMED_CHALLENGE
        assert result.permanent is True
        assert type_name in result.detail, f"detail must name the received type: {result.detail!r}"


@pytest.mark.unit
def test_verification_challenge_is_not_an_event() -> None:
    challenge = event_hook_payloads.VERIFICATION_REQUEST

    result = reference_mapping.normalize_event(challenge)

    assert isinstance(result, PermanentCondition)
    assert result.code == CODE_VERIFICATION_CHALLENGE
    assert reference_mapping.is_verification_request(challenge)

    # The challenge is answered once, by the verification path: a deterministic
    # HMAC of the challenge under the shared secret.
    answer = reference_mapping.verification_response(
        event_hook_payloads.VERIFICATION_CHALLENGE, event_hook_payloads.VERIFICATION_SECRET
    )
    expected = base64.b64encode(
        hmac.new(
            event_hook_payloads.VERIFICATION_SECRET.encode(),
            event_hook_payloads.VERIFICATION_CHALLENGE.encode(),
            hashlib.sha256,
        ).digest()
    ).decode("ascii")
    assert answer == expected


@pytest.mark.unit
def test_challenge_body_must_have_exactly_the_verification_key() -> None:
    # exactly one key. An extra key is a 400, not a challenge.
    challenge = event_hook_payloads.VERIFICATION_CHALLENGE

    assert reference_mapping.is_verification_request({"verification": challenge})
    assert not reference_mapping.is_verification_request(
        {"verification": challenge, "extra": "value"}
    )
    assert not reference_mapping.is_verification_request(
        {"verification": challenge, "eventType": "x"}
    )
    assert not reference_mapping.is_verification_request({})

    # The predicate alone is not enough: the normalizer must reject it too. The
    # eventType-only body is also malformed for a second reason (no outcome), so
    # the assertion that proves the key rejection is an otherwise complete event.
    for body in (
        {"verification": challenge, "eventType": "group.user_membership.add"},
        {**event_hook_payloads.membership_add(), "verification": challenge},
    ):
        result = reference_mapping.normalize_event(body)
        assert not isinstance(result, CanonicalEvent), f"mapped to an event: {result!r}"
        assert isinstance(result, PermanentCondition)
        assert result.code == CODE_MALFORMED_EVENT


@pytest.mark.unit
def test_extra_key_verification_body_is_rejected_by_the_normalizer() -> None:
    # "a later body containing verification is not an event", and a
    # body with any other key is a 400. Before the tightening, the predicate was
    # right while the normalizer mapped the body to an event.
    challenge = event_hook_payloads.VERIFICATION_CHALLENGE
    # Otherwise a complete, valid event: without the key rejection this body
    # would map to a CanonicalEvent, so it is the case that proves the check.
    complete_event = {**event_hook_payloads.membership_add(), "verification": challenge}

    bodies = (
        {"verification": challenge, "eventType": "group.user_membership.add"},
        {
            "verification": challenge,
            "uuid": event_hook_payloads.ADD_EVENT_UUID,
            "published": "2026-01-01T12:00:00.000Z",
        },
        complete_event,
    )

    for body in bodies:
        result = reference_mapping.normalize_event(body)
        assert not isinstance(result, CanonicalEvent), f"mapped to an event: {result!r}"
        assert isinstance(result, PermanentCondition)
        assert result.code == CODE_MALFORMED_EVENT


@pytest.mark.unit
def test_non_ascii_challenge_is_a_typed_condition_not_an_exception() -> None:
    # A non-ASCII challenge cannot be the base64 text the exchange sends. It must
    # be a typed 400 condition, not a UnicodeEncodeError surfacing as a 500. The
    # non-str guard must not absorb this case.
    result = reference_mapping.verification_response(
        "not-ascii-é", event_hook_payloads.VERIFICATION_SECRET
    )

    assert isinstance(result, PermanentCondition)
    assert result.code == CODE_MALFORMED_CHALLENGE
    assert result.permanent is True
    assert "ASCII" in result.detail


@pytest.mark.unit
def test_system_log_pagination_reads_the_link_header() -> None:
    pages = system_log_responses.PAGES
    cursor: str | None = None
    seen: list[dict[str, Any]] = []
    requests = 0

    while True:
        page = pages[cursor]
        requests += 1
        body = page["body"]
        assert isinstance(body, list)
        seen.extend(body)
        cursor = system_log_responses.next_cursor(page["headers"])
        if cursor is None:
            break
        assert cursor in pages, f"walk followed a cursor with no fixture page: {cursor}"

    assert requests == 3
    assert [entry["eventType"] for entry in seen] == [
        "group.user_membership.add",
        "group.user_membership.add",
        "group.user_membership.remove",
    ]
    # The terminal page is reached through the second page's Link header and is
    # empty, with no Link of its own.
    assert system_log_responses.PAGES[system_log_responses.CURSOR_PAGE_3]["body"] == []


@pytest.mark.unit
def test_system_log_cursor_is_not_an_integer() -> None:
    # The port's cursor is opaque because this cannot be a number.
    cursor = system_log_responses.next_cursor(system_log_responses.first_page()["headers"])

    assert cursor == system_log_responses.CURSOR_PAGE_2
    with pytest.raises(ValueError):
        int(cursor)  # type: ignore[arg-type]


@pytest.mark.unit
def test_system_log_query_separates_since_from_after() -> None:
    # ``since`` bounds the window and ``after`` pages inside it; treating one as
    # the other either re-reads the feed or silently skips a page.
    since = system_log_responses.LAST_CONSUMED_PUBLISHED
    first = system_log_responses.query_params(since=since)
    second = system_log_responses.query_params(
        since=since, after=system_log_responses.CURSOR_PAGE_2
    )

    assert first["since"] == since
    assert "after" not in first
    assert second["after"] == system_log_responses.CURSOR_PAGE_2
    assert second["since"] == since
    assert second["filter"] == system_log_responses.filter_for_group()


@pytest.mark.unit
def test_idle_drains_never_report_a_gap() -> None:
    # ADR-008 §4 row 1: `since` and `covered_through` advance together, so a
    # quiet org never looks like a hole. Driving the loop, not a fixed pair,
    # is what M-040 says a boundary table cannot do.
    token: dict[str, Any] = system_log_responses.seeded("2026-01-01T12:00:00.000Z")
    reasons: list[str | None] = []
    for now in (
        "2026-01-01T12:01:00.000Z",
        "2026-01-01T12:02:00.000Z",
        "2026-01-01T12:03:00.000Z",
    ):
        token, reason = system_log_responses.drain(token, now, published=())
        reasons.append(reason)

    assert reasons == [None, None, None]
    assert token["since"] == "2026-01-01T12:02:00.000Z"
    assert token["covered_through"] == "2026-01-01T12:03:00.000Z"
    assert token["since"] < token["covered_through"]
    assert token["v"] == 2
    assert token["after"] is None
    assert token["pages"] == 0


@pytest.mark.unit
def test_a_long_idle_run_still_reports_no_gap() -> None:
    # ADR-008 §4 row 1, driven for 60 drains: the old rule latched on the fourth
    # and never recovered, so one instance of silence is not enough.
    start = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    token: dict[str, Any] = system_log_responses.seeded("2026-01-01T12:00:00.000Z")

    for minute in range(1, 61):
        now = (start + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        token, reason = system_log_responses.drain(token, now)
        assert reason is None, f"idle drain at {now} reported a gap"

    assert token["covered_through"] == "2026-01-01T13:00:00.000Z"
    assert token["since"] == "2026-01-01T12:59:00.000Z"


@pytest.mark.unit
def test_a_window_ahead_of_its_coverage_is_a_gap() -> None:
    # the comparison is strict, so `since == covered_through` is
    # covered. The equality case comes first so the strictness is what the
    # test proves before it proves the ahead case.
    equal = system_log_responses.cursor(
        since="2026-01-01T12:00:00.000Z", covered_through="2026-01-01T12:00:00.000Z"
    )
    assert system_log_responses.gap_reason(equal, "2026-01-01T12:01:00.000Z") is None

    ahead = system_log_responses.cursor(
        since="2026-01-01T12:30:00.000Z", covered_through="2026-01-01T12:00:00.000Z"
    )
    token, reason = system_log_responses.drain(ahead, "2026-01-01T12:31:00.000Z")

    assert reason == "window_ahead_of_coverage"
    # The gap path re-seeds, so the returned token is seeded (12:31), not the
    # token advanced from its stale watermark.
    assert token["since"] == "2026-01-01T12:30:00.000Z"
    assert token["covered_through"] == "2026-01-01T12:31:00.000Z"

    token, reason = system_log_responses.drain(token, "2026-01-01T12:32:00.000Z")
    assert reason is None
    assert token["since"] == "2026-01-01T12:31:00.000Z"
    assert token["covered_through"] == "2026-01-01T12:32:00.000Z"


@pytest.mark.unit
def test_a_backwards_clock_is_a_gap() -> None:
    # ADR-008 §4 row 7: stored coverage is in the future, so time moved
    # backwards. The gap path re-seeds from `now`; it does not advance, which
    # would keep the future watermark.
    behind = system_log_responses.cursor(
        since="2026-01-01T12:00:00.000Z", covered_through="2026-01-01T12:10:00.000Z"
    )
    token, reason = system_log_responses.drain(behind, "2026-01-01T12:01:00.000Z")

    assert reason == "clock_backwards"
    assert token["covered_through"] == "2026-01-01T12:01:00.000Z"
    assert token["since"] == "2026-01-01T12:00:00.000Z"

    # Both conditions hold here: the clock is behind and the window is ahead of
    # its coverage. ADR-008 §3 orders the branches, and clock_backwards wins.
    both = system_log_responses.cursor(
        since="2026-01-01T12:30:00.000Z", covered_through="2026-01-01T12:10:00.000Z"
    )
    both_reason = system_log_responses.gap_reason(both, "2026-01-01T12:01:00.000Z")
    assert both_reason == "clock_backwards"

    # A forward jump skips nothing: the drain still queries from the old
    # `since`, so it is a catch-up, not a gap.
    forward = system_log_responses.cursor(
        since="2026-01-01T11:59:00.000Z", covered_through="2026-01-01T12:00:00.000Z"
    )
    assert system_log_responses.gap_reason(forward, "2026-01-01T12:10:00.000Z") is None


@pytest.mark.unit
def test_a_window_older_than_retention_is_a_gap() -> None:
    # a window older than retention cannot be recovered from the
    # cursor. One second on either side of the boundary, with retention passed
    # explicitly so this measures the comparison rather than the constant.
    now = "2026-01-01T12:00:00.000Z"
    outside = system_log_responses.cursor(
        since="2025-12-25T11:59:59.000Z", covered_through="2025-12-25T12:00:00.000Z"
    )
    token, reason = system_log_responses.drain(outside, now, retention_seconds=604_800)

    assert reason == "aged_out"
    # Literal instants, not a comparison against seeded (now): a comparison
    # against the helper would move with it and prove nothing.
    assert token["covered_through"] == "2026-01-01T12:00:00.000Z"
    assert token["since"] == "2026-01-01T11:59:00.000Z"

    inside = system_log_responses.cursor(
        since="2025-12-25T12:00:01.000Z", covered_through="2025-12-25T12:00:02.000Z"
    )
    assert system_log_responses.gap_reason(inside, now, retention_seconds=604_800) is None


@pytest.mark.unit
def test_a_pause_is_a_catch_up_not_a_gap() -> None:
    # ADR-008 §4 row 2: `since` did not move while the poller was down, so the
    # next drain reads the whole interval. Duplicates dedupe.
    token, first = system_log_responses.drain(
        system_log_responses.seeded("2026-01-01T12:00:00.000Z"),
        "2026-01-01T12:01:00.000Z",
    )
    assert first is None
    # The token entering the paused check still carries the pre-pause `since`.
    assert token["since"] == "2026-01-01T12:00:00.000Z"

    token, reason = system_log_responses.drain(token, "2026-01-01T12:11:00.000Z")

    assert reason is None
    assert token["since"] == "2026-01-01T12:10:00.000Z"
    assert token["covered_through"] == "2026-01-01T12:11:00.000Z"


@pytest.mark.unit
def test_the_watermark_is_the_drain_start_not_the_last_event() -> None:
    # ADR-008 §1-§2: `covered_through` is the drain start, never the last
    # event. An event inside the window must not move it, and `published` is
    # accepted only to prove that.
    token = system_log_responses.cursor(
        since="2026-01-01T11:59:00.000Z",
        covered_through="2026-01-01T12:00:00.000Z",
        after=system_log_responses.CURSOR_PAGE_2,
        pages=1,
    )
    published = ({"published": "2026-01-01T12:00:05.000Z"},)

    token, reason = system_log_responses.drain(token, "2026-01-01T12:01:00.000Z", published)

    assert reason is None
    assert token["covered_through"] == "2026-01-01T12:01:00.000Z"
    assert token["covered_through"] != "2026-01-01T12:00:05.000Z"
    assert token["since"] == "2026-01-01T12:00:00.000Z"
    # A completed drain resets the page cursor.
    assert token["after"] is None
    assert token["pages"] == 0
    # No last-event field exists in cursor state.
    assert set(token) == {"v", "since", "covered_through", "after", "pages"}

    # The watermark never moves backwards when the drain start is behind it.
    ahead = system_log_responses.cursor(
        since="2026-01-01T12:04:00.000Z", covered_through="2026-01-01T12:05:00.000Z"
    )
    advanced = system_log_responses.advance(ahead, drain_start="2026-01-01T12:01:00.000Z")
    assert advanced["covered_through"] == "2026-01-01T12:05:00.000Z"


@pytest.mark.unit
@pytest.mark.parametrize(
    "token",
    [
        None,
        # The real v1 shape: `consumed_through` and no `covered_through`.
        {
            "v": 1,
            "since": "2026-01-01T11:59:05.000Z",
            "after": None,
            "consumed_through": "2026-01-01T12:05:00.000Z",
            "pages": 3,
        },
        # v1-shaped version on an otherwise v2 body: only the version check
        # rejects this one, which is why the real v1 shape alone is not enough.
        {
            "v": 1,
            "since": "2026-01-01T12:00:00.000Z",
            "covered_through": "2026-01-01T12:01:00.000Z",
            "after": None,
            "pages": 0,
        },
        {
            "v": 2,
            "since": "not-an-instant",
            "covered_through": "2026-01-01T12:01:00.000Z",
            "after": None,
            "pages": 0,
        },
        "Mg==",
        {
            "v": 2,
            "since": "2026-01-01T12:00:00.000Z",
            "after": None,
            "pages": 0,
        },
    ],
)
def test_a_v1_cursor_is_unusable(token: Any) -> None:
    # ADR-008 §1 removes `consumed_through` rather than redefining it, so a v1
    # token must run a full sync and seed v2, never parse as v2. The six cases
    # are the parametrization: absent, the real v1 shape, a v2-shaped v1 token,
    # a malformed instant, a bare string, and a missing `covered_through`.
    now = "2026-01-01T12:01:00.000Z"

    assert system_log_responses.gap_reason(token, now) == "cursor_unusable"
    _, reason = system_log_responses.drain(token, now)
    assert reason == "cursor_unusable"


@pytest.mark.unit
def test_both_feeds_produce_the_same_event_id() -> None:
    # ADR-006 F10: one underlying event carries the same uuid in the hook body
    # and the System Log, so the two feeds dedupe on one canonical event_id.
    hook_event = _canonical(event_hook_payloads.membership_add())

    first_entry = system_log_responses.first_page()["body"][0]
    assert first_entry["uuid"] == event_hook_payloads.ADD_EVENT_UUID
    log_result = reference_mapping.normalize_system_log_entry(first_entry)
    assert isinstance(log_result, CanonicalEvent)

    assert log_result.event_id == hook_event.event_id
    assert log_result.source_event_id == hook_event.source_event_id
    assert log_result.event_id == reference_mapping.canonical_event_id(
        "okta", system_log_responses.SHARED_EVENT_UUID
    )


@pytest.mark.unit
def test_rate_limit_fixture_carries_the_reset_header() -> None:
    response = system_log_responses.rate_limited()

    assert response["status"] == 429
    assert response["headers"]["X-RateLimit-Reset"].isdigit()
    assert response["body"]["errorCode"] == "E0000047"


@pytest.mark.unit
def test_shared_secret_comparison_is_constant_time_and_exact() -> None:
    secret = event_hook_payloads.VERIFICATION_SECRET
    header = event_hook_payloads.HOOK_REQUEST_HEADERS["Authorization"]

    assert reference_mapping.verify_shared_secret(header, secret)
    assert not reference_mapping.verify_shared_secret(header, secret + "x")
    assert not reference_mapping.verify_shared_secret("Bearer wrong", secret)
    assert not reference_mapping.verify_shared_secret("", secret)


@pytest.mark.unit
def test_fixture_has_no_signature_field_or_header() -> None:
    # Names what the fixture shows, not what Okta does: an absence in hand-built
    # data. ADR-006 Unverified item 1 keeps the real answer open.
    signature_keys = {"signature", "signaturev1", "digest", "hmac", "x-okta-signature"}

    for payload in event_hook_payloads.EVENT_PAYLOADS:
        keys = {key.lower() for key in _all_keys(payload)}
        assert not keys & signature_keys, f"signed shape: {sorted(keys & signature_keys)}"

    header_names = {name.lower() for name in event_hook_payloads.HOOK_REQUEST_HEADERS}
    assert not header_names & signature_keys


@pytest.mark.unit
def test_client_ip_field_is_body_data_only() -> None:
    # Documents the field: ``client.ipAddress`` is present and is sender-written.
    # Nothing in the reference mapping reads it, so it cannot feed an allowlist
    # . The negative half is an AST check, not a source-text search:
    # a comment naming the field must not fail it, and a read through ``client``
    # must. The positive half gives the absence assertion a subject.
    payload = event_hook_payloads.membership_add()

    assert payload["client"]["ipAddress"] == "203.0.113.10"

    source = Path(reference_mapping.__file__).read_text(encoding="utf-8")
    reads = _client_reads(source)
    assert not reads, "the mapping must not read the body-supplied client: " + "; ".join(reads)

    # The helper is not vacuous: a read it must catch is caught.
    planted = 'def f(raw):\n    return raw["client"]["ipAddress"]\n'
    assert _client_reads(planted)
    planted_get = 'def f(raw):\n    return raw.get("client")\n'
    assert _client_reads(planted_get)


@pytest.mark.unit
def test_fixtures_are_data_only_and_read_only() -> None:
    # "Read only" is a claim about the fixtures' behavior, not just their
    # absence: the walk rejects a network import, an HTTP mutating verb, and a
    # file written through ``open ("w")`` or ``Path.write_text``.
    forbidden_imports = {"socket", "ssl", "http", "httpx", "requests", "urllib", "aiohttp"}
    forbidden_methods = {"post", "put", "patch", "delete", "write_text", "write_bytes"}

    offenders: list[str] = []
    for module in sorted(FIXTURE_ROOT.glob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                names = [node.module.split(".")[0]]
            offenders.extend(
                f"{module.name}:{node.lineno} imports {name}"
                for name in names
                if name in forbidden_imports
            )
            if isinstance(node, ast.Attribute) and node.attr in forbidden_methods:
                offenders.append(f"{module.name}:{node.lineno} uses .{node.attr}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"
                and len(node.args) > 1
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and any(flag in node.args[1].value for flag in "wax+")
            ):
                offenders.append(
                    f"{module.name}:{node.lineno} opens a file for writing: {ast.unparse(node)}"
                )

    assert not offenders, "fixtures must be inert and read-only: " + "; ".join(offenders)
