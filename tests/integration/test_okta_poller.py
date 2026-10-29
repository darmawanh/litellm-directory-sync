"""The Okta poller against real PostgreSQL, including atomic cursor/outbox writes."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

from identity_lifecycle.adapters.okta.connector import OktaIdentitySource
from identity_lifecycle.adapters.okta.cursor import parse_cursor, seeded_cursor
from identity_lifecycle.adapters.okta.poller import FEED_SCOPE, OktaSystemLogPoller
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.domain.errors import RetryableError
from identity_lifecycle.domain.events import EventType
from tests.fixtures.okta import event_hook_payloads
from tests.fixtures.okta_http import SOURCE_NAME, FakeOktaHTTP, user

pytestmark = pytest.mark.integration

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
GROUP_ID = event_hook_payloads.GROUP_ID


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def _source(server: FakeOktaHTTP) -> OktaIdentitySource:
    return OktaIdentitySource(
        source_name=SOURCE_NAME,
        group_id=GROUP_ID,
        client=server.oauth_client(),
        clock=SystemClock(),
        log_page_limit=20,
        log_overlap_seconds=60,
        log_retention_seconds=604800,
    )


def _factory(engine: Engine):
    def unit_of_work(source: str) -> PostgresUnitOfWork:
        return PostgresUnitOfWork(engine, SystemClock(), source=source)

    return unit_of_work


def _write_cursor(engine: Engine, token: str) -> None:
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE_NAME) as uow:
        uow.cursors.write(SOURCE_NAME, FEED_SCOPE, token)
        uow.commit()


def _cursor(engine: Engine) -> str | None:
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE_NAME) as uow:
        return uow.cursors.read(SOURCE_NAME, FEED_SCOPE)


def _counts(engine: Engine) -> tuple[int, int, int]:
    with engine.connect() as connection:
        outbox = connection.execute(
            sqlalchemy.text("select count(*) from identity_event_outbox")
        ).scalar_one()
        members = connection.execute(
            sqlalchemy.text("select count(*) from source_group_members")
        ).scalar_one()
        cursor = connection.execute(
            sqlalchemy.text(
                "select count(*) from source_cursors where source = :source and feed_scope = :scope"
            ),
            {"source": SOURCE_NAME, "scope": FEED_SCOPE},
        ).scalar_one()
    return int(outbox), int(members), int(cursor)


def test_poller_resumes_from_cursor_after_restart(engine: Engine) -> None:
    server = FakeOktaHTTP()
    server.log_pages = {
        None: ([event_hook_payloads.membership_add()], "Mg=="),
        "Mg==": ([event_hook_payloads.membership_remove()], None),
    }
    _write_cursor(engine, seeded_cursor(START, 60))
    factory = _factory(engine)
    first_source = _source(server)
    first_poller = OktaSystemLogPoller(first_source, factory, overlap_seconds=60)

    assert first_poller.poll_once() == 1
    assert first_poller.has_more_pages
    stored_after_first = _cursor(engine)
    first_state, first_reason = parse_cursor(stored_after_first)
    assert first_reason is None and first_state is not None
    assert first_state.after == "Mg=="
    first_source.close()

    resumed_source = _source(server)
    resumed_poller = OktaSystemLogPoller(resumed_source, factory, overlap_seconds=60)
    assert resumed_poller.poll_once() == 1
    stored_after_resume = _cursor(engine)
    final_state, final_reason = parse_cursor(stored_after_resume)

    assert final_reason is None and final_state is not None
    assert final_state.after is None
    assert final_state.pages == 0
    assert not resumed_poller.has_more_pages
    assert final_state.since == START - timedelta(seconds=60)
    assert (
        len(server.requests) == 4
    )  # one OAuth exchange and one GET per page plus token exchange cache
    log_requests = [request for request in server.requests if request.url.path == "/api/v1/logs"]
    assert [request.url.params.get("after") for request in log_requests] == [None, "Mg=="]
    assert log_requests[0].url.params["since"] == log_requests[1].url.params["since"]
    assert _counts(engine) == (2, 0, 1)
    resumed_source.close()


def test_gap_runs_full_sync_and_reseeds_cursor(engine: Engine) -> None:
    server = FakeOktaHTTP()
    server.add_user(user("00uSYNTHETIC0001", employee_number="E30001"), member=True)
    server.log_pages = {None: ([], None)}
    old_v1_token = '{"v":1,"since":"2026-01-01T11:59:00.000Z"}'
    _write_cursor(engine, old_v1_token)
    source = _source(server)
    poller = OktaSystemLogPoller(source, _factory(engine), overlap_seconds=60)

    assert poller.poll_once() == 1

    stored = _cursor(engine)
    state, reason = parse_cursor(stored)
    assert reason is None and state is not None
    assert state.after is None and state.pages == 0
    assert state.covered_through == START
    assert state.since == START - timedelta(seconds=60)
    assert _counts(engine) == (1, 1, 1)
    source.close()


def test_gap_full_sync_emits_a_disable_for_an_inactive_group_member(engine: Engine) -> None:
    server = FakeOktaHTTP()
    server.add_user(
        user("00uSYNTHETIC0002", employee_number="E30002", status="SUSPENDED"),
        member=True,
    )
    server.log_pages = {None: ([], None)}
    _write_cursor(engine, '{"v":1}')
    source = _source(server)
    poller = OktaSystemLogPoller(source, _factory(engine), overlap_seconds=60)

    assert poller.poll_once() == 2
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE_NAME) as uow:
        events = uow.outbox.claim(10)

    assert {event.type for event in events} == {
        EventType.GROUP_MEMBER_ADDED,
        EventType.USER_DISABLED,
    }
    source.close()


def test_cursor_and_outbox_commit_together(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = FakeOktaHTTP()
    server.log_pages = {None: ([event_hook_payloads.membership_add()], None)}
    original_token = seeded_cursor(START, 60)
    _write_cursor(engine, original_token)
    source = _source(server)

    original_write = PostgresUnitOfWork.__enter__

    def raise_after_cursor_write(uow: PostgresUnitOfWork) -> PostgresUnitOfWork:
        entered = original_write(uow)
        cursor_store: Any = entered.cursors
        original_store_write = cursor_store.write

        def write_then_fail(source_name: str, feed_scope: str, cursor: str) -> None:
            original_store_write(source_name, feed_scope, cursor)
            raise RetryableError("injected cursor write failure")

        cursor_store.write = write_then_fail
        return entered

    monkeypatch.setattr(PostgresUnitOfWork, "__enter__", raise_after_cursor_write)
    poller = OktaSystemLogPoller(source, _factory(engine), overlap_seconds=60)

    with pytest.raises(RetryableError, match="injected cursor write failure"):
        poller.poll_once()

    monkeypatch.setattr(PostgresUnitOfWork, "__enter__", original_write)
    assert _counts(engine) == (0, 0, 1)
    assert _cursor(engine) == original_token
    source.close()
