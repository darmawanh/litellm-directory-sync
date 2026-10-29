"""One transaction per use case: the store and the queue commit together.

A use case opens one unit of work, writes every row it needs through the
repositories below, and calls :meth:`UnitOfWork.commit` once. The state change
and the outbox row therefore commit together or not at all (design 9.1 step 1,
ADR-002 section 3). No repository has a ``commit`` of its own — ``outbox.claim``
is the one exception, and its own docstring says why —
because a repository that could commit would make a half-applied use case
representable, which is the failure ER6 exists to forbid.

Every method speaks in the domain's values. A repository returns a
``domain.models`` dataclass, a ``CanonicalEvent``, or this module's
``GroupMemberSnapshot``, or ``None`` when the record is absent; it never returns
a row, a mapping, a DB-API cursor, or a SQLAlchemy object. A
"no such row" read is an outcome, not an exception.

A read whose answer is a set returns a tuple and never ``None``: the empty tuple
is the set-valued form of "nothing to return", and the caller sees every match
rather than one guess.

The two enums below,
``bool``, and ``str | None`` are the only other return types, and each is a
vocabulary the caller already needs: whether an enqueue inserted or hit the
unique ``event_id``, and which's three settle paths applies.

The method sets are the minimum each use case, 10.1-10.3, and 10.6
needs, and no more:

- **ingest** needs ``outbox.enqueue`` and ``cursors.write``.
- **process** needs the person, identity, entitlement, account, and audit
  repositories, plus ``processed_events`` and ``outbox.settle`` (design 9.1
  processing rules 1-7).
- **the poller** needs ``cursors.read``, ``cursors.write``, ``group_members.read``,
  and ``group_members.replace``.

One thing is deliberately absent. The lease reaper is a maintenance process, not
a use case, so it is not a method here; it is worker-level code over the outbox
table. The membership snapshot *is* here, because ADR-005
section 8 makes it not an *identity source* port concept — that sentence is about
``IdentitySource``, not about the store. It is a store concern, so the poller
writes it through ``group_members`` in the same transaction as the page's outbox
rows and the advanced cursor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from identity_lifecycle.domain.events import CanonicalEvent
from identity_lifecycle.domain.models import (
    AuditEvent,
    Entitlement,
    LiteLLMAccount,
    Person,
    SourceIdentity,
)


class PersonRepository(Protocol):
    """The ``persons`` rows, as ``Person`` values."""

    def get(self, person_id: str) -> Person | None:
        """Return the person, or ``None`` when no such row exists."""
        ...

    def find_all_by_employee_number(self, employee_number: str) -> tuple[Person, ...]:
        """Return every person carrying the link: none, one, or several.

                ``employee_number`` is a nullable link, not a key: two live persons may
                share one value and both rows store it (ADR-017 section 1, ADR-005
                section 3). The cardinality is therefore the answer, and the caller acts
                on it rather than on the first element:

                - ```` — no person carries the link; this is a first join.
                - `` (person)`` — the link is unambiguous and may resolve to that person
        .
                - two or more — the link is ambiguous. It resolves to nobody: the caller
                  does not unify through it, does not guess, and does not fail
                  the event. It records the ambiguity in the audit
                  row and the alert and still provisions the object
                  as its own person.

                This is the only read that can answer the question. The identity rows are
                keyed by `` (source, source_user_id)``, so a caller that holds only a link
                — a source object not yet linked, or FR17's operator-supplied number —
                cannot count the persons behind it any other way.
        """
        ...

    def save(self, person: Person) -> None:
        """Insert or update the person, keyed by ``person_id``."""
        ...

    def list_all(self) -> tuple[Person, ...]:
        """Return every stored person."""
        ...


class SourceIdentityRepository(Protocol):
    """The ``source_identities`` link rows."""

    def find(self, source: str, source_user_id: str) -> SourceIdentity | None:
        """Return the link for one source object, or ``None``."""
        ...

    def save(self, identity: SourceIdentity) -> None:
        """Insert or update the link; `` (source, source_user_id)`` is unique."""
        ...

    def list_for_source(self, source: str) -> tuple[SourceIdentity, ...]:
        """Return every stored identity link for one source."""
        ...


class EntitlementRepository(Protocol):
    """The ``entitlements`` rows: the access decision in force."""

    def current_for(self, person_id: str) -> Entitlement | None:
        """Return the open entitlement (``effective_to`` null), or ``None``."""
        ...

    def save(self, entitlement: Entitlement) -> None:
        """Insert the new entitlement or close the old one."""
        ...


class AccountRepository(Protocol):
    """The ``litellm_accounts`` rows: what the gateway held at the last read."""

    def get(self, user_id: str) -> LiteLLMAccount | None:
        """Return the stored account for one gateway user id, or ``None``."""
        ...

    def save(self, account: LiteLLMAccount, delete_after: datetime | None = None) -> None:
        """Record the account exactly as the gateway's read-back returned it."""
        ...

    def list_all(self) -> tuple[LiteLLMAccount, ...]:
        """Return every stored account."""
        ...

    def list_pending_deletions(self, before: datetime) -> tuple[str, ...]:
        """Return user_ids of accounts whose grace period has expired on or before ``before``."""
        ...

    def delete(self, user_id: str) -> None:
        """Remove an account record after gateway deletion."""
        ...

    def get_delete_after(self, user_id: str) -> datetime | None:
        """Return the scheduled deletion instant for an account, or ``None``."""
        ...


@dataclass(frozen=True)
class AuditEntry:
    """An audit log row joined with person identity for export."""

    event_id: UUID
    occurred_at: datetime
    actor: str
    action: str
    source: str
    person_id: str
    employee_number: str | None
    email: str | None
    reason: str
    decision: str
    details: str


class AuditRepository(Protocol):
    """The ``audit_events`` rows: one per decision."""

    def append(self, record: AuditEvent) -> None:
        """Append the record; an audit row is never updated or deleted."""
        ...

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        employee_number: str | None = None,
        source_user_id: str | None = None,
    ) -> tuple[AuditEntry, ...]:
        """Query audit records matching date range and optional employee/user filters."""
        ...


@dataclass(frozen=True)
class GroupMemberSnapshot:
    """One group's member set as the last completed poll left it.

    This is the diff input for the poller: it reads the group object, compares the
    source's ``member`` list against this set, and emits ``group.member_added`` and
    ``group.member_removed`` from the difference. ``source_user_ids`` holds source
    identities, not person ids, because a member that never resolved to a person is
    still a member.

    ``None`` means the store holds no member rows for the group, and the schema
    cannot tell the never-read case from the read-and-empty case: the table stores
    member rows only, so an empty group leaves no row behind. The empty case is
    still safe because the poll that observes emptiness calls ``replace`` with the
    empty set in the same transaction, which emits a removal for every member the
    previous snapshot held. The cost is one redundant full
    sync per poll while a group is empty. A per-group marker row would restore the
    distinction and is deferred; the earlier claim here that the distinction was
    load-bearing described a behavior this schema does not deliver.
    """

    source: str
    source_group_id: str
    source_user_ids: frozenset[str]


class GroupMemberRepository(Protocol):
    """The ``source_group_members`` snapshot, one member set per group."""

    def read(self, source: str, source_group_id: str) -> GroupMemberSnapshot | None:
        """Return the snapshot for one group, or ``None`` when it holds no member rows.

        ``None`` covers both "never read" and "read, empty", because the table stores
        member rows and nothing else. It forces a full sync, and
        the empty case stays safe: the poll that found the group empty has already
        written the empty set through ``replace`` in the same transaction, so the
        removals were emitted there. A per-group marker row would tell the two apart
        and is deferred.
        """
        ...

    def replace(self, snapshot: GroupMemberSnapshot) -> None:
        """Replace one group's whole snapshot in the caller's transaction.

        Every stored row for `` (source, source_group_id)`` becomes
        ``snapshot.source_user_ids``, so a repeated call with the same set leaves the
        same rows. The replace, the page's outbox rows, and the advanced cursor commit
        together or not at all.
        """
        ...


class ProcessedEventRepository(Protocol):
    """The idempotency table: which ``event_id`` values already took effect."""

    def is_processed(self, event_id: UUID) -> bool:
        """Return whether this event has already been applied."""
        ...

    def mark_processed(self, event_id: UUID) -> None:
        """Record the event as applied in the use case's transaction."""
        ...


class CursorRepository(Protocol):
    """The ``source_cursors`` rows: one opaque token per `` (source, feed_scope)``."""

    def read(self, source: str, feed_scope: str) -> str | None:
        """Return the stored token, or ``None`` when the feed has never run.

        The token is opaque: this module never parses it, and neither does the
        use case. Its form belongs to the adapter (ADR-005 section 8, ADR-008
        section 1).
        """
        ...

    def write(self, source: str, feed_scope: str, cursor: str) -> None:
        """Store the advanced token in the transaction that writes the page's events."""
        ...


class EnqueueOutcome(StrEnum):
    """What an enqueue did, which the hook route reports as 202 or 200.

    ``DUPLICATE`` is the unique ``event_id`` firing: the event already has a row,
    so there is no second effect and the sender is told to stop retrying.
    """

    INSERTED = "inserted"
    DUPLICATE = "duplicate"


class Settlement(StrEnum):
    """The three settle paths, named once.

        The adapter owns the retry ladder (attempts, backoff, the limit); the caller
        only says which path this attempt took, so no HTTP code is inspected here
    .
    """

    DONE = "done"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"


class OutboxRepository(Protocol):
    """The ``identity_event_outbox`` state machine, in ``CanonicalEvent`` terms."""

    def enqueue(self, event: CanonicalEvent) -> EnqueueOutcome:
        """Write the event in the caller's transaction.

        The adapter derives ``person_key`` from the envelope
        and stores the envelope as the row's payload. The unique ``event_id`` is
        the enqueue guard, so a replay returns ``DUPLICATE`` rather than raising.
        """
        ...

    def claim(self, limit: int) -> tuple[CanonicalEvent, ...]:
        """Claim up to ``limit`` due events and return their envelopes.

                The adapter marks the rows ``processing``, sets ``locked_until``, and
                commits before returning; a claim transaction never spans a vendor call
        . An empty tuple means nothing is due.
        """
        ...

    def settle(self, event_id: UUID, outcome: Settlement) -> None:
        """Record one attempt's result for the event.

        ``DONE`` marks the row done, ``RETRYABLE`` increments ``attempts`` and
        moves ``next_attempt_at``, and ``PERMANENT`` marks it dead at once. The
        adapter applies the ladder; the caller never inspects a status code.
        """
        ...

    def replay(self, target_id: UUID) -> ReplayOutcome | None:
        """Reset an outbox row to ``pending`` with zero attempts.

        Matches either row ``id`` or canonical ``event_id``. Returns ``None`` if
        no row matches.
        """
        ...


@dataclass(frozen=True)
class ReplayOutcome:
    """The result of an outbox row replay operation."""

    row_id: UUID
    event_id: UUID
    previous_status: str
    event_type: str


@dataclass(frozen=True)
class ReconciliationMiss:
    """One recorded reconciliation miss (migration 0003)."""

    person_id: str
    source: str
    miss_count: int
    last_seen_at: datetime


class ReconciliationMissRepository(Protocol):
    """The ``reconciliation_misses`` rows (migration 0003)."""

    def get(self, person_id: str, source: str) -> ReconciliationMiss | None:
        """Return the miss record for one person and source, or ``None``."""
        ...

    def record_miss(self, person_id: str, source: str, seen_at: datetime) -> ReconciliationMiss:
        """Increment or insert the miss count for one person and source."""
        ...

    def clear(self, person_id: str, source: str) -> None:
        """Clear the miss record when the person is found in the source."""
        ...

    def list_all(self) -> tuple[ReconciliationMiss, ...]:
        """Return every stored miss record."""
        ...


class UnitOfWork(Protocol):
    """One use case's transaction, with the repositories it may write."""

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

    def commit(self) -> None:
        """Commit everything written in this unit of work, once."""
        ...

    def rollback(self) -> None:
        """Discard everything written in this unit of work, leaving no row."""
        ...
