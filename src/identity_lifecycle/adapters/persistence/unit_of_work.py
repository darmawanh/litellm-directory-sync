"""The concrete unit of work: one connection, one transaction, one commit.

``PostgresUnitOfWork`` implements all nine repository protocols of
``ports/unit_of_work.py`` over one SQLAlchemy Core connection. The connection is
acquired on entry and returned on exit; ``commit`` and ``rollback`` are the only
transaction control here, and no repository has either.

Two constructor arguments are wiring, not discovery, because a port may not gain
a method:

- ``clock`` — the one source of "now" for the outbox lease and the retry
  schedule, so a test moves time instead of sleeping.
- ``source`` — the canonical event's source, stored on every audit row.
  ``audit_events.source`` is ``not null`` because FR14 names the source in the
  record, and migration 0002 says the writer supplies it from the event; the
  domain's ``AuditEvent`` has no such field and ``AuditRepository.append`` takes
  only that record.

``hold_person_locks`` is the third piece of wiring and is deliberately **not** on
the port: ADR-015 section 3 is a worker-level lock protocol, and ``workers`` may
not import ``sqlalchemy``, so the context manager is typed in
``CanonicalEvent`` terms and owns the connection itself.

``claim`` commits inside itself. That is the one place a
transaction ends without the caller asking, and it is why a claim never spans a
vendor call.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.engine import Connection, Engine

from identity_lifecycle.adapters.persistence.access import (
    AccountStore,
    AuditStore,
    EntitlementStore,
    ReconciliationMissStore,
)
from identity_lifecycle.adapters.persistence.advisory import hold_locks, lock_keys
from identity_lifecycle.adapters.persistence.cursors import CursorStore
from identity_lifecycle.adapters.persistence.group_members import GroupMemberStore
from identity_lifecycle.adapters.persistence.outbox import DEFAULT_LEASE_SECONDS, OutboxStore
from identity_lifecycle.adapters.persistence.payload import person_key as compute_person_key
from identity_lifecycle.adapters.persistence.persons import PersonStore, SourceIdentityStore
from identity_lifecycle.adapters.persistence.processed_events import ProcessedEventStore
from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import (
    AccountRepository,
    AuditRepository,
    CursorRepository,
    EntitlementRepository,
    GroupMemberRepository,
    OutboxRepository,
    PersonRepository,
    ProcessedEventRepository,
    ReconciliationMissRepository,
    SourceIdentityRepository,
)


class PostgresUnitOfWork:
    """One use case's transaction over PostgreSQL (10.1-10.3).

    Used as a context manager so the connection is always returned::

        with PostgresUnitOfWork (engine, clock, source="corp-ad") as uow:
            uow.persons.save (person)
            uow.outbox.enqueue (event)
            uow.commit

    The attribute annotations are the port's protocol types, not the concrete
    classes, so ``mypy`` proves the class satisfies ``UnitOfWork`` structurally
    rather than by intent.
    """

    persons: PersonRepository
    identities: SourceIdentityRepository
    entitlements: EntitlementRepository
    accounts: AccountRepository
    audit: AuditRepository
    group_members: GroupMemberRepository
    processed_events: ProcessedEventRepository
    cursors: CursorRepository
    outbox: OutboxRepository
    misses: ReconciliationMissRepository

    def __init__(
        self,
        engine: Engine,
        clock: Clock,
        *,
        source: str,
        rng: random.Random | None = None,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self._engine = engine
        self._connection: Connection | None = None
        self._clock = clock
        self._source = source
        self._rng = rng
        self._lease_seconds = lease_seconds

    def __enter__(self) -> PostgresUnitOfWork:
        connection = self._engine.connect()
        self._connection = connection
        self.persons = PersonStore(connection)
        self.identities = SourceIdentityStore(connection)
        self.entitlements = EntitlementStore(connection)
        self.accounts = AccountStore(connection)
        self.audit = AuditStore(connection, source=self._source)
        self.group_members = GroupMemberStore(connection)
        self.processed_events = ProcessedEventStore(connection)
        self.cursors = CursorStore(connection)
        self.outbox = OutboxStore(
            connection,
            self._clock,
            rng=self._rng,
            lease_seconds=self._lease_seconds,
        )
        self.misses = ReconciliationMissStore(connection)
        return self

    def __exit__(self, *exc_info: object) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            # Closing returns the connection to the pool and discards any open
            # transaction, so an uncommitted write leaves no row.
            connection.close()

    @property
    def connection(self) -> Connection:
        """The live connection, for the lock context manager and for tests."""
        if self._connection is None:
            raise RuntimeError("the unit of work is not open; use it as a context manager")
        return self._connection

    def commit(self) -> None:
        """Commit everything written in this unit of work, once."""
        self.connection.commit()

    def rollback(self) -> None:
        """Discard everything written in this unit of work, leaving no row."""
        self.connection.rollback()

    @contextmanager
    def hold_person_locks(self, event: CanonicalEvent) -> Iterator[None]:
        """Serialize this event against others for the same person.

        The keys are computed from the envelope and from two reads the caller
        would make anyway: the link lookup decides whether the link is
        unambiguous, and the identity row decides whether a person is already
        resolved. A read failure propagates; it is never treated as "no lock".
        """
        employee_number = None if event.person is None else event.person.employee_number
        resolved: str | None = None
        if employee_number is not None:
            matches = self.persons.find_all_by_employee_number(employee_number)
            if len(matches) > 1:
                # Ambiguous: no unification happens, so ``link:`` excludes
                # nothing and is not taken.
                employee_number = None
            elif len(matches) == 1:
                resolved = matches[0].person_id
            # ``len (matches) == 0`` keeps the link and its lock: a brand-new
            # employee is exactly the case ``link:`` exists for, because two
            # sources can arrive with the same link and no person yet. ADR-015
            # section 3 says "present and unambiguous", and zero matches is not
            # ambiguity, so the executable predicate is ``len (found) <= 1``
            # (correction appended to section 1).
        if resolved is None and event.person is not None:
            identity = self.identities.find(event.source, event.person.source_user_id)
            resolved = None if identity is None else identity.person_id
        keys = lock_keys(
            person_key=compute_person_key(event),
            employee_number=employee_number,
            person_id=resolved,
        )
        with hold_locks(self.connection, keys):
            yield
