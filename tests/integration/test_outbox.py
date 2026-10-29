"""The outbox state machine, against real PostgreSQL.

Every test here uses two connections where the behavior is about isolation, so
what is proven is the table's semantics rather than one session's view of them.
The clock is the injected ``FakeClock``: a lease expires and a retry becomes due
by moving time, never by sleeping.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine, RowMapping

from identity_lifecycle.adapters.persistence.advisory import identity_key
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.errors import StoreError
from identity_lifecycle.adapters.persistence.outbox import (
    DEFAULT_LEASE_SECONDS,
    reap_expired_leases,
)
from identity_lifecycle.adapters.persistence.payload import event_to_payload, person_key
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.domain.events import CanonicalEvent, EventGroup, EventType
from identity_lifecycle.ports.unit_of_work import EnqueueOutcome, Settlement

from .persistence_support import START, FakeClock, FixedRandom, engine_for, member_added

pytestmark = pytest.mark.integration

SOURCE = "corp-ad"


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = engine_for(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def _row(engine: Engine, event_id: UUID) -> RowMapping:
    """Read the outbox columns a state assertion needs, from a fresh connection."""
    with engine.connect() as connection:
        return (
            connection.execute(
                sqlalchemy.text(
                    "select status, attempts, next_attempt_at, locked_until, last_error,"
                    " person_key from identity_event_outbox where event_id = :event_id"
                ),
                {"event_id": event_id},
            )
            .mappings()
            .one()
        )


def _enqueue(engine: Engine, clock: FakeClock, event: CanonicalEvent) -> None:
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.enqueue(event) is EnqueueOutcome.INSERTED
        uow.commit()


# claim


def test_claim_commits_before_returning(engine: Engine) -> None:
    """ADR-002 section 4: the claim commits, so no transaction spans a vendor call.

    The row is read from a second connection *before* the claiming unit of work
    calls ``commit``. If the claim had left its transaction open, that reader
    would see ``pending`` (or block); it sees ``processing``.
    """
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (event,)
        assert _row(engine, event.event_id)["status"] == "processing"
        # The unit of work has not committed; the claim already did.
    assert _row(engine, event.event_id)["status"] == "processing"


def test_claim_sets_the_lease_and_the_person_key(engine: Engine) -> None:
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)

    with PostgresUnitOfWork(engine, clock, source=SOURCE, lease_seconds=30.0) as uow:
        uow.outbox.claim(1)

    row = _row(engine, event.event_id)
    assert row["locked_until"] == clock.now() + timedelta(seconds=30)
    assert row["person_key"] == "corp-ad:object-guid-1"


def test_claim_returns_nothing_when_no_row_is_due(engine: Engine) -> None:
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.claim(1)

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == ()


def test_claim_honours_the_batch_limit(engine: Engine) -> None:
    clock = FakeClock()
    events = tuple(member_added() for _ in range(3))
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        for event in events:
            uow.outbox.enqueue(event)
        uow.commit()

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        first = uow.outbox.claim(2)
        second = uow.outbox.claim(2)

    assert len(first) == 2
    assert len(second) == 1
    assert {event.event_id for event in (*first, *second)} == {e.event_id for e in events}


def test_two_workers_do_not_claim_the_same_row(engine: Engine) -> None:
    """NFR13: a row one worker holds is skipped, not handed out twice.

    Worker A holds the row lock inside its claim window and has not committed.
    Worker B, on a different connection, runs the same claim query and gets
    nothing, because ``FOR UPDATE SKIP LOCKED`` skips the locked row. When A
    releases, B claims it.
    """
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)

    with engine.connect() as worker_a:
        worker_a.execute(
            sqlalchemy.text(
                "select id from identity_event_outbox"
                " where status = 'pending' for update skip locked"
            )
        ).all()
        with PostgresUnitOfWork(engine, clock, source=SOURCE) as worker_b:
            assert worker_b.outbox.claim(10) == (), "B must not claim A's locked row"
            worker_b.commit()
        worker_a.rollback()

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as worker_b:
        assert worker_b.outbox.claim(10) == (event,)


def test_two_claims_never_return_one_event_twice(engine: Engine) -> None:
    clock = FakeClock()
    events = tuple(member_added() for _ in range(6))
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        for event in events:
            uow.outbox.enqueue(event)
        uow.commit()

    claimed: list[UUID] = []
    for _ in range(3):
        with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
            claimed.extend(event.event_id for event in uow.outbox.claim(2))

    assert sorted(claimed) == sorted(event.event_id for event in events)
    assert len(set(claimed)) == len(claimed)


def test_a_poison_payload_goes_dead_without_blocking_the_batch(engine: Engine) -> None:
    """Design 9.1's poison-event path: an unreadable payload dies, the batch proceeds.

    A payload that cannot describe a legal event fails identically on every
    retry, so it is dead-lettered at claim. The dead-letter must not
    abort the claim: the readable row in the same batch is still returned, and
    the poison row is not re-selected.
    """
    clock = FakeClock()
    good = member_added()
    _enqueue(engine, clock, good)
    poison_id = uuid4()
    # ``next_attempt_at`` is written explicitly: its column default is the real
    # ``now``, while this test's clock is pinned at 2026-01-01, so a defaulted
    # row would never be due and the claim would not select it.
    with engine.begin() as connection:
        connection.execute(
            sqlalchemy.text(
                "insert into identity_event_outbox"
                " (event_id, source, event_type, payload, next_attempt_at)"
                " values (:event_id, 'corp-ad', 'group.member_added', '{\"type\": 7}'::jsonb, :now)"
            ),
            {"event_id": poison_id, "now": clock.now()},
        )

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        claimed = uow.outbox.claim(10)
        uow.commit()

    assert claimed == (good,), "the readable event is returned; the poison row does not abort it"
    assert _row(engine, poison_id)["status"] == "dead"
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (), "the poison row is not re-selected"


def test_a_poison_person_payload_goes_dead_without_blocking_the_batch(engine: Engine) -> None:
    """T-047: a non-mapping ``person`` is a permanent parse failure, not a crash.

        The payload is otherwise legal, so parsing reaches ``person``; a string there
        used to raise ``AttributeError``, which the claim path does not catch, and the
        whole batch stayed pending. The parser must reject it as an
        ``EventValidationError`` so the row dies and the readable one is returned
    .
    """
    clock = FakeClock()
    good = member_added()
    _enqueue(engine, clock, good)
    poison_id = uuid4()
    poison_payload = event_to_payload(good)
    poison_payload["event_id"] = str(poison_id)
    poison_payload["person"] = "x"
    # ``next_attempt_at`` is written explicitly: its column default is the real
    # ``now``, while this test's clock is pinned at 2026-01-01, so a defaulted
    # row would never be due and the claim would not select it.
    with engine.begin() as connection:
        connection.execute(
            sqlalchemy.text(
                "insert into identity_event_outbox"
                " (event_id, source, event_type, payload, next_attempt_at)"
                " values (:event_id, 'corp-ad', 'group.member_added',"
                " cast(:payload as jsonb), :now)"
            ),
            {
                "event_id": poison_id,
                "payload": json.dumps(poison_payload),
                "now": clock.now(),
            },
        )

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        claimed = uow.outbox.claim(10)
        uow.commit()

    assert claimed == (good,), "the readable event is returned; the poison row does not abort it"
    assert _row(engine, poison_id)["status"] == "dead"
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (), "the poison row is not re-selected"


# enqueue


def test_duplicate_event_id_is_rejected(engine: Engine) -> None:
    """The unique ``event_id`` is the enqueue guard.

    The port reports the duplicate as an outcome, not an exception, so the
    sender is told to stop retrying. The constraint is still
    the authority: a direct second insert raises.
    """
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.enqueue(event) is EnqueueOutcome.DUPLICATE
        uow.commit()

    with engine.connect() as connection:
        count = connection.execute(
            sqlalchemy.text("select count(*) from identity_event_outbox")
        ).scalar_one()
    assert count == 1

    with (
        pytest.raises(sqlalchemy.exc.IntegrityError, match="uq_identity_event_outbox_event_id"),
        engine.begin() as connection,
    ):
        connection.execute(
            sqlalchemy.text(
                "insert into identity_event_outbox (event_id, source, event_type, payload)"
                " values (:event_id, 'corp-ad', 'group.member_added', '{}'::jsonb)"
            ),
            {"event_id": event.event_id},
        )


def test_person_key_is_null_when_the_event_names_no_person(engine: Engine) -> None:
    clock = FakeClock()
    group_only = CanonicalEvent(
        event_id=uuid4(),
        source=SOURCE,
        source_event_id="s-1",
        type=EventType.GROUP_UPDATED,
        occurred_at=START,
        person=None,
        group=EventGroup(source_group_id="group-1", name="AI-Platform-Users"),
    )
    _enqueue(engine, clock, group_only)

    assert _row(engine, group_only.event_id)["person_key"] is None
    assert person_key(group_only) is None


# settle: done


def test_done_settlement_marks_the_row_done(engine: Engine) -> None:
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.claim(1)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.settle(event.event_id, Settlement.DONE)
        uow.commit()

    row = _row(engine, event.event_id)
    assert (row["status"], row["attempts"], row["locked_until"]) == ("done", 0, None)


# settle: retryable


def test_retryable_failure_backs_off(engine: Engine) -> None:
    """ADR-002 section 6: base 1 s, doubling, cap 60 s, full jitter, 8 attempts.

    ``FixedRandom`` draws the midpoint, so each delay is exactly half the
    ceiling and the test can assert a number instead of a range.
    """
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.claim(1)

    expected = [(1, 0.5), (2, 1.0), (3, 2.0), (4, 4.0), (5, 8.0), (6, 16.0), (7, 30.0)]
    for attempt, delay in expected:
        with PostgresUnitOfWork(engine, clock, source=SOURCE, rng=FixedRandom()) as uow:
            uow.outbox.settle(event.event_id, Settlement.RETRYABLE)
            uow.commit()
        row = _row(engine, event.event_id)
        assert row["status"] == "pending", attempt
        assert row["attempts"] == attempt
        assert row["locked_until"] is None
        assert row["next_attempt_at"] == clock.now() + timedelta(seconds=delay), attempt
        assert row["last_error"] is None

    # The eighth failure is the limit: the row goes dead rather than retrying.
    with PostgresUnitOfWork(engine, clock, source=SOURCE, rng=FixedRandom()) as uow:
        uow.outbox.settle(event.event_id, Settlement.RETRYABLE)
        uow.commit()

    row = _row(engine, event.event_id)
    assert (row["status"], row["attempts"], row["last_error"]) == ("dead", 7, "retry_limit")


def test_a_retry_is_not_claimed_before_its_next_attempt(engine: Engine) -> None:
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE, rng=FixedRandom()) as uow:
        uow.outbox.claim(1)
    with PostgresUnitOfWork(engine, clock, source=SOURCE, rng=FixedRandom()) as uow:
        uow.outbox.settle(event.event_id, Settlement.RETRYABLE)
        uow.commit()

    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (), "the backoff has not elapsed"

    clock.advance(0.5)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (event,)


# settle: permanent


def test_permanent_failure_is_dead_immediately(engine: Engine) -> None:
    """P-007: a permanent error does not use the retry ladder."""
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.claim(1)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.settle(event.event_id, Settlement.PERMANENT)
        uow.commit()

    row = _row(engine, event.event_id)
    assert (row["status"], row["attempts"], row["last_error"]) == ("dead", 0, "permanent")
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == ()


def test_settling_an_unknown_event_is_a_permanent_store_error(engine: Engine) -> None:
    clock = FakeClock()
    with (
        PostgresUnitOfWork(engine, clock, source=SOURCE) as uow,
        pytest.raises(StoreError, match="found no outbox row"),
    ):
        uow.outbox.settle(uuid4(), Settlement.DONE)


# the reaper


def test_expired_lease_is_reclaimed(engine: Engine) -> None:
    """FR19: a crashed worker's row returns to ``pending`` after the lease."""
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE, lease_seconds=30.0) as uow:
        uow.outbox.claim(1)
    assert _row(engine, event.event_id)["status"] == "processing"

    # A live lease is not reaped.
    with engine.begin() as connection:
        assert reap_expired_leases(connection, now=clock.now()) == 0

    clock.advance(31.0)
    with engine.begin() as connection:
        assert reap_expired_leases(connection, now=clock.now()) == 1

    row = _row(engine, event.event_id)
    assert (row["status"], row["locked_until"]) == ("pending", None)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == (event,)


def test_the_reaper_leaves_a_done_row_alone(engine: Engine) -> None:
    clock = FakeClock()
    event = member_added()
    _enqueue(engine, clock, event)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.claim(1)
    with PostgresUnitOfWork(engine, clock, source=SOURCE) as uow:
        uow.outbox.settle(event.event_id, Settlement.DONE)
        uow.commit()

    clock.advance(DEFAULT_LEASE_SECONDS * 10)
    with engine.begin() as connection:
        assert reap_expired_leases(connection, now=clock.now()) == 0
    assert _row(engine, event.event_id)["status"] == "done"


# per-person serialization


def test_same_person_events_do_not_run_concurrently(engine: Engine) -> None:
    """ADR-015 section 3: a session lock, not a transaction lock.

    Two envelopes for one source identity compute one key. While the first unit
    of work holds it — and after it commits, which is exactly the claim boundary
    ADR-002 section 4 introduces — a second session cannot take the same key.
    ``pg_advisory_xact_lock`` would have been released at that commit and this
    probe would succeed.
    """
    first = member_added()
    second = member_added()
    key = identity_key(person_key(second))

    with (
        PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as holder,
        holder.hold_person_locks(first),
        engine.connect() as other,
    ):
        holder.commit()  # the claim boundary; a xact lock would end here
        held = other.execute(
            sqlalchemy.text("select pg_try_advisory_lock(hashtextextended(:key, 0))"),
            {"key": key},
        ).scalar_one()
        assert held is False, "the second session must not hold the same key"

    with engine.connect() as other:
        acquired = other.execute(
            sqlalchemy.text("select pg_try_advisory_lock(hashtextextended(:key, 0))"),
            {"key": key},
        ).scalar_one()
        assert acquired is True, "the key is free after the holder exits"
        other.execute(
            sqlalchemy.text("select pg_advisory_unlock(hashtextextended(:key, 0))"),
            {"key": key},
        )
        other.commit()


def test_the_person_lock_is_released_when_the_body_raises(engine: Engine) -> None:
    event = member_added()
    key = identity_key(person_key(event))
    with (
        PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as holder,
        pytest.raises(RuntimeError),
        holder.hold_person_locks(event),
    ):
        raise RuntimeError("vendor call failed")

    with engine.connect() as other:
        acquired = other.execute(
            sqlalchemy.text("select pg_try_advisory_lock(hashtextextended(:key, 0))"),
            {"key": key},
        ).scalar_one()
        assert acquired is True
        other.execute(
            sqlalchemy.text("select pg_advisory_unlock(hashtextextended(:key, 0))"),
            {"key": key},
        )
        other.commit()


def test_the_default_lease_outlives_the_shutdown_window() -> None:
    # Design 10.6 finishes in-flight rows within 30 seconds; a shorter lease
    # would let the reaper hand a row to a second worker mid-processing.
    assert DEFAULT_LEASE_SECONDS > 30.0
