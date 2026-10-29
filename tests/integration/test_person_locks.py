"""The three advisory keys, observed as the database sees them.

Each test holds a person's locks through ``hold_person_locks`` and probes from a
second session whether this one holds a given key. The key list itself is not
read from the adapter: the defect these tests pin was the predicate that built
it, not the builder, so the probe is what has to be observed.

F3 (round 2): the ``link:`` key is taken when the link is **present and
unambiguous**, and zero matches is unambiguous. A brand-new employee is the case
the key exists for — two sources can arrive with the same link and no person
yet — so ``len (found) <= 1`` is the executable predicate, not ``== 1``.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import sqlalchemy
from sqlalchemy.engine import Engine

from identity_lifecycle.adapters.persistence.advisory import identity_key, link_key
from identity_lifecycle.adapters.persistence.clock import SystemClock
from identity_lifecycle.adapters.persistence.payload import person_key
from identity_lifecycle.adapters.persistence.unit_of_work import PostgresUnitOfWork
from identity_lifecycle.domain.models import Person

from .persistence_support import engine_for, member_added

pytestmark = pytest.mark.integration

SOURCE = "corp-ad"


@pytest.fixture
def engine(migrated_database: str) -> Iterator[Engine]:
    built = engine_for(migrated_database)
    try:
        yield built
    finally:
        built.dispose()


def _holder_holds(engine: Engine, key: str) -> bool:
    """Probe whether another session is excluded from ``key``.

    ``pg_try_advisory_lock`` succeeds only when no other session holds the key,
    so a failed probe means the holder holds it. The probe releases what it took,
    because a leaked key would make the next assertion lie.
    """
    with engine.connect() as other:
        taken = other.execute(
            sqlalchemy.text("select pg_try_advisory_lock(hashtextextended(:key, 0))"),
            {"key": key},
        ).scalar_one()
        if taken:
            other.execute(
                sqlalchemy.text("select pg_advisory_unlock(hashtextextended(:key, 0))"),
                {"key": key},
            )
        other.commit()
    return not bool(taken)


def test_a_brand_new_link_takes_the_link_lock(engine: Engine) -> None:
    """Zero matches is unambiguous, and it is the case the link key exists for.

    No person carries ``E20002`` yet, so both sources resolving the same new
    employee take ``link:E20002`` and serialize. Under the earlier ``== 1``
    predicate this test's probe would find the key free.
    """
    event = member_added(employee_number="E20002")

    with (
        PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow,
        uow.hold_person_locks(event),
    ):
        assert _holder_holds(engine, link_key("E20002")) is True
        assert _holder_holds(engine, identity_key(person_key(event))) is True


def test_an_ambiguous_link_takes_no_link_lock(engine: Engine) -> None:
    """Two matches is ambiguity: nothing is unified through the link, so it excludes nothing."""
    with PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow:
        for person_id in ("p-1", "p-2"):
            uow.persons.save(
                Person(
                    person_id=person_id,
                    employee_number="E20002",
                    email=f"{person_id}@example.com",
                    display_name="Shared Link",
                    status="active",
                )
            )
        uow.commit()

    event = member_added(employee_number="E20002")
    with (
        PostgresUnitOfWork(engine, SystemClock(), source=SOURCE) as uow,
        uow.hold_person_locks(event),
    ):
        assert _holder_holds(engine, link_key("E20002")) is False
        assert _holder_holds(engine, identity_key(person_key(event))) is True
