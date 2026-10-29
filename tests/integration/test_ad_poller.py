"""The Active Directory poller against PostgreSQL, including atomic cursor/outbox writes."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

from identity_lifecycle.adapters.ad.cursor import format_cursor, parse_cursor
from identity_lifecycle.adapters.ad.mapping import objectguid_to_uuid
from identity_lifecycle.adapters.ad.poller import FEED_SCOPE, ADPoller
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.engine import build_engine
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.domain.errors import RetryableError
from identity_lifecycle.domain.events import EventType
from tests.fixtures.ad import ldap_responses
from tests.fixtures.ad_ldap import (
    AD_SOURCE_NAME,
    FakeADConnection,
    create_fake_ad_source,
)
from tests.fixtures.fakes import FakeClock

pytestmark = pytest.mark.integration

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SOURCE_NAME = AD_SOURCE_NAME
GROUP_DN = ldap_responses.GROUP_DN
ALICE_ID = str(objectguid_to_uuid(ldap_responses.ALICE_GUID)).lower()
BOB_ID = str(objectguid_to_uuid(ldap_responses.BOB_GUID)).lower()


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = build_engine(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


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


def test_poller_initial_sync_and_resume_after_restart(engine: Engine) -> None:
    fake_conn = FakeADConnection(
        group_entry=ldap_responses.group_entry(
            members=[ldap_responses.ALICE_DN],
            usn=b"20000",
        ),
        users=[ldap_responses.alice_entry()],
    )
    factory = _factory(engine)
    source = create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)
    poller = ADPoller(source, factory)

    # Initial poll without cursor runs full sync and seeds cursor
    assert poller.poll_once() == 1
    stored = _cursor(engine)
    state, reason = parse_cursor(stored)
    assert reason is None and state is not None
    assert state.usn >= 20000
    assert _counts(engine) == (1, 1, 1)
    source.close()

    # Restart poller: resumes from committed cursor, no new changes
    resumed_source = create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)
    resumed_poller = ADPoller(resumed_source, factory)
    assert resumed_poller.poll_once() == 0
    assert _counts(engine) == (1, 1, 1)

    # Add Bob to AD group
    fake_conn.current_group_entry = ldap_responses.group_entry(
        members=[ldap_responses.ALICE_DN, ldap_responses.BOB_DN],
        usn=b"26000",
    )
    fake_conn.users.append(ldap_responses.bob_entry())

    assert resumed_poller.poll_once() == 1
    assert _counts(engine) == (2, 2, 1)
    stored_after_bob = _cursor(engine)
    state_after_bob, _ = parse_cursor(stored_after_bob)
    assert state_after_bob is not None and state_after_bob.usn >= 26000
    resumed_source.close()


def test_poller_detects_member_removal_via_snapshot_diff(engine: Engine) -> None:
    fake_conn = FakeADConnection(
        group_entry=ldap_responses.group_entry(
            members=[ldap_responses.ALICE_DN, ldap_responses.BOB_DN],
            usn=b"20000",
        ),
        users=[ldap_responses.alice_entry(), ldap_responses.bob_entry()],
    )
    source = create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)
    poller = ADPoller(source, _factory(engine))

    # Initial sync enqueues Alice and Bob
    assert poller.poll_once() == 2
    assert _counts(engine) == (2, 2, 1)

    # Remove Bob from group in AD
    fake_conn.current_group_entry = ldap_responses.group_entry(
        members=[ldap_responses.ALICE_DN],
        usn=b"22000",
    )
    assert poller.poll_once() == 1
    assert _counts(engine) == (3, 1, 1)

    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE_NAME) as uow:
        events = uow.outbox.claim(10)
    removal_events = [e for e in events if e.type == EventType.GROUP_MEMBER_REMOVED]
    assert len(removal_events) == 1
    assert removal_events[0].person is not None
    assert removal_events[0].person.source_user_id == BOB_ID
    source.close()


def test_gap_or_dc_change_runs_full_sync_and_reseeds_cursor(engine: Engine) -> None:
    old_dc_token = format_cursor("00000000-0000-0000-0000-000000000001", 10000)
    _write_cursor(engine, old_dc_token)

    fake_conn = FakeADConnection(
        group_entry=ldap_responses.group_entry(
            members=[ldap_responses.ALICE_DN],
            usn=b"25000",
        ),
        users=[ldap_responses.alice_entry()],
    )
    source = create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)
    poller = ADPoller(source, _factory(engine))

    assert poller.poll_once() == 1
    stored = _cursor(engine)
    state, reason = parse_cursor(stored)
    assert reason is None and state is not None
    expected_dc = str(objectguid_to_uuid(ldap_responses.ROOT_DSE_INVOCATION_ID)).lower()
    assert state.dc == expected_dc
    assert state.usn >= 25000
    assert _counts(engine) == (1, 1, 1)
    source.close()


def test_gap_full_sync_emits_a_disable_for_an_inactive_group_member(engine: Engine) -> None:
    disabled_alice = ldap_responses.alice_entry(user_account_control=b"514")
    fake_conn = FakeADConnection(
        group_entry=ldap_responses.group_entry(
            members=[ldap_responses.ALICE_DN],
            usn=b"20000",
        ),
        users=[disabled_alice],
    )
    source = create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)
    poller = ADPoller(source, _factory(engine))

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
    connected_dc = str(objectguid_to_uuid(ldap_responses.ROOT_DSE_INVOCATION_ID)).lower()
    original_token = format_cursor(connected_dc, 15000)
    _write_cursor(engine, original_token)

    fake_conn = FakeADConnection(
        group_entry=ldap_responses.group_entry(
            members=[ldap_responses.ALICE_DN],
            usn=b"20000",
        ),
        users=[ldap_responses.alice_entry()],
    )
    source = create_fake_ad_source(fake_conn, FakeClock(START), source_name=SOURCE_NAME)

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
    poller = ADPoller(source, _factory(engine))

    with pytest.raises(RetryableError, match="injected cursor write failure"):
        poller.poll_once()

    monkeypatch.setattr(PostgresUnitOfWork, "__enter__", original_write)
    assert _counts(engine) == (0, 0, 1)
    assert _cursor(engine) == original_token
    source.close()
