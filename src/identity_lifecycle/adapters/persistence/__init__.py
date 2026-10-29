"""PostgreSQL persistence: the store and the outbox, over SQLAlchemy Core.

This package implements the nine repositories of ``ports/unit_of_work.py`` with
explicit SQL. There are no declarative models and no ``Session``: the migration
is the schema authority, so a table's shape is read from
``migrations/versions/``, never restated here as a mapped class. A repository
returns a ``domain.models`` dataclass, a ``CanonicalEvent``, or this package's
``GroupMemberSnapshot``; a ``Row``, a ``RowMapping``, a DB-API cursor and a
SQLAlchemy object all stop at this boundary.

Two things are wired rather than discovered, and both are constructor
arguments because a port may not gain a method:

- **The clock.** ``settle`` writes ``next_attempt_at`` and the claim writes
  ``locked_until``; both read one injected ``Clock`` so a test moves time
  instead of sleeping (no global mutable state).
- **The source.** ``audit_events.source`` is ``not null`` because FR14 names the
  source in the record, and migration 0002's docstring says "the writer supplies
  it from the canonical event". ``domain.models.AuditEvent`` carries no such
  field and ``AuditRepository.append`` takes only that record, so the unit of
  work is opened for one event's source and hands it to the audit repository.
"""
