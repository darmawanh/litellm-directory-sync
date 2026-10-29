"""A crashed worker's row is recovered and retried.

The demo's third step, as a test. A worker claims a row and dies before it settles,
so the row is left ``processing`` with a lease. Nothing about that state is
recoverable by the row itself: ``claim`` committed, so the
effect never happened and the row will not be claimed again until its lease
passes. The reaper is what makes it claimable, and it is a plain function over the
outbox, not a port method.

The row is then drained by the real loop and reaches ``done`` with one effect and
one audit row, which is the at-least-once guarantee the fake proves without a
database.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from identity_lifecycle.domain.events import EventType
from identity_lifecycle.ports.unit_of_work import Settlement
from tests.fixtures.fakes import InMemoryUnitOfWork, event_rows, reap_expired

from .test_walking_skeleton import SOURCE, Skeleton, _event

pytestmark = pytest.mark.unit


def test_a_crashed_worker_row_is_reaped_and_retried() -> None:
    skeleton = Skeleton()
    event = _event(EventType.GROUP_MEMBER_ADDED)
    skeleton.ingest.ingest(event)

    # The claim commits and the process dies before any settle: no effect, no
    # audit row, and a lease that has not yet expired.
    with InMemoryUnitOfWork(skeleton.store, skeleton.clock, source=SOURCE) as uow:
        assert uow.outbox.claim(1) == (event,)
    row = event_rows(skeleton.store)[event.event_id]
    assert (row.status, row.attempts) == ("processing", 0)
    assert skeleton.store.accounts == {}
    assert skeleton.store.audit == []

    # Before the lease passes the row is invisible to a claim, which is the point
    # of the lease: a worker still processing must not be duplicated.
    with InMemoryUnitOfWork(skeleton.store, skeleton.clock, source=SOURCE) as uow:
        assert uow.outbox.claim(10) == ()

    skeleton.clock.advance(301.0)
    assert reap_expired(skeleton.store, skeleton.clock.now()) == 1
    assert event_rows(skeleton.store)[event.event_id].status == "pending"

    worker = skeleton.worker()
    skeleton.gateway.on_call = lambda name: (
        worker.request_stop() if name == "ensure_team" else None
    )
    worker.run()

    assert event_rows(skeleton.store)[event.event_id].status == "done"
    assert skeleton.gateway.writes.count("create_user") == 1
    assert len(skeleton.store.audit) == 1


def test_the_reaper_leaves_a_live_lease_alone() -> None:
    skeleton = Skeleton()
    event = _event(EventType.GROUP_MEMBER_ADDED)
    skeleton.ingest.ingest(event)
    with InMemoryUnitOfWork(skeleton.store, skeleton.clock, source=SOURCE) as uow:
        uow.outbox.claim(1)

    assert reap_expired(skeleton.store, skeleton.clock.now() + timedelta(seconds=1)) == 0
    assert event_rows(skeleton.store)[event.event_id].status == "processing"


def test_a_retried_row_settles_done_not_retryable() -> None:
    # The second pass is a first attempt from the use case's point of view: the
    # attempt counter moved only because the settle path moved it, and the effect
    # succeeded this time.
    skeleton = Skeleton()
    event = _event(EventType.GROUP_MEMBER_ADDED)
    skeleton.ingest.ingest(event)
    with InMemoryUnitOfWork(skeleton.store, skeleton.clock, source=SOURCE) as uow:
        uow.outbox.claim(1)
    skeleton.clock.advance(301.0)
    reap_expired(skeleton.store, skeleton.clock.now())

    assert skeleton.process.process(event) is Settlement.DONE
    assert event_rows(skeleton.store)[event.event_id].status == "done"
