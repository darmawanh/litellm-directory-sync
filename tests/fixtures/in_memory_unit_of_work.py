"""An in-memory ``UnitOfWork`` for the walking skeleton.

The nine repository protocols of ``ports/unit_of_work.py`` over dictionaries, so
the real use cases take the same path a test database would give them: the same
``claim``/``settle`` state machine, the same "every match" link lookup
, and the same ``None`` for a group that has no rows.

Two behaviours are deliberately faithful rather than convenient:

- ``commit`` is the only way a write survives. ``__enter__`` snapshots the store
  and ``__exit__`` restores it unless ``commit`` ran, so a failed gateway call
  leaves no audit row, no account row, and no ``processed_events`` record.
- ``claim`` marks the rows ``processing`` and returns them; it does not settle
  anything. The lease is the adapter's 300 seconds, so a test that wants a lease
  to expire moves the injected clock instead of sleeping.

This module is test code and is never imported by production code.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import (
    AuditEvent,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceIdentity,
)
from identity_lifecycle.ports.clock import Clock
from identity_lifecycle.ports.unit_of_work import (
    AuditEntry,
    EnqueueOutcome,
    GroupMemberSnapshot,
    ReconciliationMiss,
    ReplayOutcome,
    Settlement,
)

#: The adapter's lease and retry numbers, copied so the fake expires like the
#: real store (``adapters/persistence/outbox.py``, ``retry.py``).
LEASE_SECONDS = 300.0
MAX_ATTEMPTS = 8
MAX_BACKOFF_SECONDS = 60.0


@dataclass
class OutboxRow:
    """One in-memory outbox row, with the columns ``claim`` and ``settle`` use."""

    event: CanonicalEvent
    next_attempt_at: datetime
    status: str = "pending"
    attempts: int = 0
    locked_until: datetime | None = None
    last_error: str | None = None
    row_id: UUID = field(default_factory=uuid4)


@dataclass
class InMemoryStore:
    """Everything one unit of work can read or write, shared by its repositories."""

    persons: dict[str, Person] = field(default_factory=dict)
    identities: dict[tuple[str, str], SourceIdentity] = field(default_factory=dict)
    entitlements: list[Entitlement] = field(default_factory=list)
    accounts: dict[str, LiteLLMAccount] = field(default_factory=dict)
    delete_after: dict[str, datetime] = field(default_factory=dict)
    audit: list[AuditEvent] = field(default_factory=list)
    audit_records: list[tuple[AuditEvent, str]] = field(default_factory=list)
    group_members: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    processed: set[UUID] = field(default_factory=set)
    cursors: dict[tuple[str, str], str] = field(default_factory=dict)
    outbox: dict[UUID, OutboxRow] = field(default_factory=dict)
    misses: dict[tuple[str, str], ReconciliationMiss] = field(default_factory=dict)

    def snapshot(self) -> InMemoryStore:
        """Return a deep copy, so ``rollback`` can restore every collection."""
        return copy.deepcopy(self)

    def restore(self, snapshot: InMemoryStore) -> None:
        """Put every collection back as the snapshot left it."""
        self.persons = snapshot.persons
        self.identities = snapshot.identities
        self.entitlements = snapshot.entitlements
        self.accounts = snapshot.accounts
        self.delete_after = snapshot.delete_after
        self.audit = snapshot.audit
        self.audit_records = snapshot.audit_records
        self.group_members = snapshot.group_members
        self.processed = snapshot.processed
        self.cursors = snapshot.cursors
        self.outbox = snapshot.outbox
        self.misses = snapshot.misses


class PersonRepository:
    """``persons`` over a dictionary."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def get(self, person_id: str) -> Person | None:
        person = self._store.persons.get(person_id)
        return None if person is None else copy.deepcopy(person)

    def find_all_by_employee_number(self, employee_number: str) -> tuple[Person, ...]:
        """Return every match, ordered by ``person_id`` like the SQL store."""
        matches = [
            copy.deepcopy(person)
            for person in self._store.persons.values()
            if person.employee_number == employee_number
        ]
        return tuple(sorted(matches, key=lambda person: person.person_id))

    def save(self, person: Person) -> None:
        self._store.persons[person.person_id] = copy.deepcopy(person)

    def list_all(self) -> tuple[Person, ...]:
        return tuple(
            sorted(
                [copy.deepcopy(p) for p in self._store.persons.values()],
                key=lambda p: p.person_id,
            )
        )


class SourceIdentityRepository:
    """``source_identities`` keyed by `` (source, source_user_id)``."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def find(self, source: str, source_user_id: str) -> SourceIdentity | None:
        identity = self._store.identities.get((source, source_user_id))
        return None if identity is None else copy.deepcopy(identity)

    def save(self, identity: SourceIdentity) -> None:
        self._store.identities[(identity.source, identity.source_user_id)] = copy.deepcopy(identity)

    def list_for_source(self, source: str) -> tuple[SourceIdentity, ...]:
        return tuple(
            sorted(
                [copy.deepcopy(i) for (s, _), i in self._store.identities.items() if s == source],
                key=lambda i: i.source_user_id,
            )
        )


class EntitlementRepository:
    """``entitlements`` with the store's close-then-insert rule."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def current_for(self, person_id: str) -> Entitlement | None:
        open_rows = [
            row
            for row in self._store.entitlements
            if row.person_id == person_id and row.effective_to is None
        ]
        if not open_rows:
            return None
        return copy.deepcopy(max(open_rows, key=lambda row: row.effective_from))

    def save(self, entitlement: Entitlement) -> None:
        for row in self._store.entitlements:
            if (
                row.person_id == entitlement.person_id
                and row.effective_to is None
                and row.effective_from < entitlement.effective_from
            ):
                row.effective_to = entitlement.effective_from
        duplicate = any(
            row.person_id == entitlement.person_id
            and row.effective_from == entitlement.effective_from
            for row in self._store.entitlements
        )
        if not duplicate:
            self._store.entitlements.append(copy.deepcopy(entitlement))


class AccountRepository:
    """``litellm_accounts`` keyed by ``user_id``."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def get(self, user_id: str) -> LiteLLMAccount | None:
        account = self._store.accounts.get(user_id)
        return None if account is None else copy.deepcopy(account)

    def save(self, account: LiteLLMAccount, delete_after: datetime | None = None) -> None:
        self._store.accounts[account.user_id] = copy.deepcopy(account)
        if delete_after is not None:
            self._store.delete_after[account.user_id] = delete_after
        else:
            self._store.delete_after.pop(account.user_id, None)

    def list_all(self) -> tuple[LiteLLMAccount, ...]:
        return tuple(
            sorted(
                [copy.deepcopy(a) for a in self._store.accounts.values()],
                key=lambda a: a.user_id,
            )
        )

    def list_pending_deletions(self, before: datetime) -> tuple[str, ...]:
        before_utc = before if before.tzinfo is not None else before.replace(tzinfo=UTC)
        matches = [
            user_id
            for user_id, dt in self._store.delete_after.items()
            if (dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)) <= before_utc
        ]
        return tuple(sorted(matches, key=lambda uid: (self._store.delete_after[uid], uid)))

    def delete(self, user_id: str) -> None:
        self._store.accounts.pop(user_id, None)
        self._store.delete_after.pop(user_id, None)

    def get_delete_after(self, user_id: str) -> datetime | None:
        return self._store.delete_after.get(user_id)


class AuditRepository:
    """``audit_events``: append-only."""

    def __init__(self, store: InMemoryStore, *, source: str = "memory") -> None:
        self._store = store
        self._source = source

    def append(self, record: AuditEvent) -> None:
        self._store.audit.append(copy.deepcopy(record))
        self._store.audit_records.append((copy.deepcopy(record), self._source))

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        employee_number: str | None = None,
        source_user_id: str | None = None,
    ) -> tuple[AuditEntry, ...]:
        matching_person_ids_for_user: set[str] = set()
        if source_user_id is not None:
            for ident in self._store.identities.values():
                if ident.source_user_id == source_user_id:
                    matching_person_ids_for_user.add(ident.person_id)

        records = self._store.audit_records
        if len(records) != len(self._store.audit):
            records = [(rec, getattr(self, "_source", "memory")) for rec in self._store.audit]

        results: list[AuditEntry] = []
        for event, source in records:
            ts = (
                event.timestamp.replace(tzinfo=UTC)
                if event.timestamp.tzinfo is None
                else event.timestamp.astimezone(UTC)
            )

            if since is not None:
                since_utc = since if since.tzinfo is not None else since.replace(tzinfo=UTC)
                if ts < since_utc:
                    continue
            if until is not None:
                until_utc = until if until.tzinfo is not None else until.replace(tzinfo=UTC)
                if ts > until_utc:
                    continue

            person = self._store.persons.get(event.target)
            emp_no = person.employee_number if person else None
            email = person.email if person else None

            if (
                employee_number is not None
                and emp_no != employee_number
                and event.target != employee_number
            ):
                continue

            if source_user_id is not None and (
                event.target not in matching_person_ids_for_user and event.target != source_user_id
            ):
                continue

            results.append(
                AuditEntry(
                    event_id=event.event_id,
                    occurred_at=ts,
                    actor=event.actor,
                    action=event.action,
                    source=source,
                    person_id=event.target,
                    employee_number=emp_no,
                    email=email,
                    reason=event.reason,
                    decision=event.decision,
                    details=event.source_event_id,
                )
            )
        results.sort(key=lambda r: (r.occurred_at, r.event_id))
        return tuple(results)


class GroupMemberRepository:
    """``source_group_members``: ``None`` when the group has no rows."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def read(self, source: str, source_group_id: str) -> GroupMemberSnapshot | None:
        members = self._store.group_members.get((source, source_group_id))
        if members is None:
            return None
        return GroupMemberSnapshot(
            source=source,
            source_group_id=source_group_id,
            source_user_ids=members,
        )

    def replace(self, snapshot: GroupMemberSnapshot) -> None:
        self._store.group_members[(snapshot.source, snapshot.source_group_id)] = (
            snapshot.source_user_ids
        )


class ProcessedEventRepository:
    """``processed_events``: the idempotency set."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def is_processed(self, event_id: UUID) -> bool:
        return event_id in self._store.processed

    def mark_processed(self, event_id: UUID) -> None:
        self._store.processed.add(event_id)


class CursorRepository:
    """``source_cursors``: one opaque token per `` (source, feed_scope)``."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def read(self, source: str, feed_scope: str) -> str | None:
        return self._store.cursors.get((source, feed_scope))

    def write(self, source: str, feed_scope: str, cursor: str) -> None:
        self._store.cursors[(source, feed_scope)] = cursor


class OutboxRepository:
    """The outbox state machine over ``InMemoryStore.outbox``."""

    def __init__(self, store: InMemoryStore, clock: Clock, checkpoint: Callable[[], None]) -> None:
        self._store = store
        self._clock = clock
        self._checkpoint = checkpoint

    def enqueue(self, event: CanonicalEvent) -> EnqueueOutcome:
        if event.event_id in self._store.outbox:
            return EnqueueOutcome.DUPLICATE
        self._store.outbox[event.event_id] = OutboxRow(
            event=event,
            next_attempt_at=self._clock.now(),
        )
        return EnqueueOutcome.INSERTED

    def claim(self, limit: int) -> tuple[CanonicalEvent, ...]:
        if limit < 1:
            return ()
        now = self._clock.now()
        due = sorted(
            (
                row
                for row in self._store.outbox.values()
                if row.status == "pending" and row.next_attempt_at <= now
            ),
            key=lambda row: (row.next_attempt_at, row.event.event_id),
        )[:limit]
        for row in due:
            row.status = "processing"
            row.locked_until = now + timedelta(seconds=LEASE_SECONDS)
        # ``claim`` commits inside itself in the adapter, so
        # the fake moves its rollback point here: a worker that claims and then
        # never settles must leave the rows ``processing``, not restore them.
        self._checkpoint()
        return tuple(row.event for row in due)

    def settle(self, event_id: UUID, outcome: Settlement) -> None:
        row = self._store.outbox[event_id]
        now = self._clock.now()
        if outcome == Settlement.DONE:
            row.status = "done"
            row.locked_until = None
            return
        if outcome == Settlement.PERMANENT:
            row.status = "dead"
            row.locked_until = None
            row.last_error = "permanent"
            return
        row.attempts += 1
        row.locked_until = None
        if row.attempts >= MAX_ATTEMPTS:
            row.status = "dead"
            row.last_error = "retry_limit"
            return
        row.status = "pending"
        ceiling = min(MAX_BACKOFF_SECONDS, 2.0 ** (row.attempts - 1))
        row.next_attempt_at = now + timedelta(seconds=ceiling)

    def replay(self, target_id: UUID) -> ReplayOutcome | None:
        """Reset an outbox row to 'pending' with 0 attempts and clear errors."""
        now = self._clock.now()
        target_row: OutboxRow | None = None
        for row in self._store.outbox.values():
            if row.row_id == target_id or row.event.event_id == target_id:
                target_row = row
                break
        if target_row is None:
            return None

        current_status = target_row.status
        locked_until = target_row.locked_until
        if current_status == "processing" and locked_until is not None and locked_until > now:
            raise RuntimeError(
                f"cannot replay outbox row {target_id}: row is currently processing"
                f" (locked until {locked_until})"
            )

        target_row.status = "pending"
        target_row.attempts = 0
        target_row.next_attempt_at = now
        target_row.locked_until = None
        target_row.last_error = None
        return ReplayOutcome(
            row_id=target_row.row_id,
            event_id=target_row.event.event_id,
            previous_status=current_status,
            event_type=target_row.event.type.value,
        )


class ReconciliationMissRepository:
    """``reconciliation_misses`` keyed by `` (person_id, source)``."""

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def get(self, person_id: str, source: str) -> ReconciliationMiss | None:
        miss = self._store.misses.get((person_id, source))
        return None if miss is None else copy.deepcopy(miss)

    def record_miss(self, person_id: str, source: str, seen_at: datetime) -> ReconciliationMiss:
        key = (person_id, source)
        existing = self._store.misses.get(key)
        new_count = 1 if existing is None else existing.miss_count + 1
        record = ReconciliationMiss(
            person_id=person_id,
            source=source,
            miss_count=new_count,
            last_seen_at=seen_at,
        )
        self._store.misses[key] = record
        return record

    def clear(self, person_id: str, source: str) -> None:
        self._store.misses.pop((person_id, source), None)

    def list_all(self) -> tuple[ReconciliationMiss, ...]:
        return tuple(
            sorted(
                [copy.deepcopy(m) for m in self._store.misses.values()],
                key=lambda m: (m.person_id, m.source),
            )
        )


class InMemoryUnitOfWork:
    """One use case's in-memory transaction."""

    def __init__(self, store: InMemoryStore, clock: Clock, *, source: str) -> None:
        self._store = store
        self._snapshot = store.snapshot()
        self._committed = False
        self._source = source
        self.persons = PersonRepository(store)
        self.identities = SourceIdentityRepository(store)
        self.entitlements = EntitlementRepository(store)
        self.accounts = AccountRepository(store)
        self.audit = AuditRepository(store, source=source)
        self.group_members = GroupMemberRepository(store)
        self.processed_events = ProcessedEventRepository(store)
        self.cursors = CursorRepository(store)
        self.outbox = OutboxRepository(store, clock, self._checkpoint)
        self.misses = ReconciliationMissRepository(store)

    def __enter__(self) -> InMemoryUnitOfWork:
        return self

    def _checkpoint(self) -> None:
        """Move the rollback point forward, the way the adapter's claim commits."""
        self._snapshot = self._store.snapshot()

    def __exit__(self, *exc_info: object) -> None:
        if not self._committed:
            self._store.restore(self._snapshot)

    @property
    def source(self) -> str:
        """The configured source this unit of work would write into an audit row."""
        return self._source

    def commit(self) -> None:
        self._committed = True

    def rollback(self) -> None:
        self._store.restore(self._snapshot)


def reap_expired(store: InMemoryStore, now: datetime) -> int:
    """Return expired ``processing`` rows to ``pending``, as the adapter's reaper does.

    ADR-002 section 7 makes the reaper worker-level code over the outbox table, so
    the fake needs the same plain function for a test or a demo to prove that a
    killed worker's row is retried after its lease.
    """
    reaped = 0
    for row in store.outbox.values():
        expired = row.locked_until is not None and row.locked_until < now
        if row.status == "processing" and expired:
            row.status = "pending"
            row.locked_until = None
            reaped += 1
    return reaped


def event_rows(store: InMemoryStore) -> Mapping[UUID, OutboxRow]:
    """Expose the rows read-only, for a test that asserts a status or attempt count."""
    return dict(store.outbox)
