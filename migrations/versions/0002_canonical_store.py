"""Canonical store, idempotency, and cursors.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-22 00:00:00.000000

Eight tables: the five canonical entities that are stored, the group
membership snapshot, the idempotency record (design 9.1
step 7), and the poller cursor.

Storage names settled here, all of them carried from Phase 1:

- ``audit_events.occurred_at`` stores design 8's ``AuditEvent.timestamp``. The
  domain field keeps the design's name; ``occurred_at`` is the storage name
  ``domain/models.py`` already documents for it.
- ``litellm_accounts.budget`` is ``numeric not null``. Design 8's
  ``LiteLLMAccount.budget`` is a non-optional ``float``, FR5 requires the budget
  before the first login, and design 10.7 always resolves one of four levels
  with a required default, so the value exists before the account row is
  written. A stored NULL could not be read back into the domain type
.
- ``audit_events.source`` exists because FR14 names the source in the record,
  although design 8's ``AuditEvent`` has no ``source`` field. The writer
  supplies it from the canonical event.
- ``source_cursors.cursor`` is the opaque token. ADR-005 section 7, ADR-006
  section 6 and ADR-008 section 1 all name the column ``cursor``; design 10.6
  calls the value a token, which is what it holds. ``cursor`` is an unreserved
  word in PostgreSQL, so no statement needs to quote it.

One constraint deliberately absent, because a reader will look for it:

- **No UNIQUE on ``persons.employee_number``.** ADR-005 section 3 says two live
  objects may share an ``employeeID``, are provisioned independently, and are
  never unified through that value. A UNIQUE constraint would reject the second
  person's row, which is the outcome the ADR forbids. Ambiguity is resolved in
  the application (``employee_number`` is used only when unambiguous) and
  recorded in the audit row and the alert; it is not a table constraint.

Two deliberate omissions, so a reader does not look for them:

- **No ``source_groups`` table.** Design 8's ``SourceGroup`` names
  ``source_group_id`` and ``name``; the identifier lives in
  ``source_group_members`` and in the ``group_mappings`` config, and the display
  name is not persisted because design 7.2 and ``domain/models.py`` record that
  a group's name is not stable. Nothing reads a stored name.
- **No ``created_at``/``updated_at`` on the canonical tables.** Design 8 does
  not name them, and the tables are rewritten from the source on every event.
  The outbox's timestamps are design 9.1's and live in revision 0003.

Personal data stored by this revision:

- ``persons.employee_number``, ``persons.email``, ``persons.display_name``
- ``audit_events.target`` and ``audit_events.actor``, which may name a person
  or an account
- ``source_identities.source_user_id`` and ``source_group_members.source_user_id``,
  pseudonymous source identifiers that resolve to a person
- ``litellm_accounts.user_id``, the gateway account key, which names a person
  through ``source_identities``

Every timestamp is ``timestamptz``. All timestamps are UTC.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the canonical store, the membership snapshot, idempotency, and cursors."""
    op.create_table(
        "persons",
        sa.Column("person_id", sa.Text(), nullable=False),
        # Nullable by ADR-005 section 2: a person without an employee number is
        # valid. Deliberately NOT unique: ADR-005 section 3 says two live
        # objects may carry the same employeeID, are provisioned independently,
        # and are not unified through it. A UNIQUE constraint would make the
        # second of those people unstorable. Uniqueness is a resolution rule in
        # the application (unambiguous link only), not a table constraint.
        sa.Column("employee_number", sa.Text(), nullable=True),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("person_id", name="pk_persons"),
    )

    op.create_table(
        "source_identities",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_user_id", sa.Text(), nullable=False),
        sa.Column("person_id", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("source", "source_user_id", name="pk_source_identities"),
        sa.ForeignKeyConstraint(
            ["person_id"],
            ["persons.person_id"],
            name="fk_source_identities_person_id",
        ),
    )
    op.create_index(
        "ix_source_identities_person_id",
        "source_identities",
        ["person_id"],
    )

    op.create_table(
        "entitlements",
        # A surrogate key design 8 does not name: a person accumulates one row
        # per decision, and ``effective_from`` alone is not guaranteed unique.
        sa.Column(
            "entitlement_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_id", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("team", sa.Text(), nullable=False),
        sa.Column("budget_policy", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("entitlement_id", name="pk_entitlements"),
        sa.ForeignKeyConstraint(
            ["person_id"],
            ["persons.person_id"],
            name="fk_entitlements_person_id",
        ),
    )
    op.create_index("ix_entitlements_person_id", "entitlements", ["person_id"])

    op.create_table(
        "litellm_accounts",
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("team", sa.Text(), nullable=False),
        # Required, not nullable: LiteLLMAccount.budget is a non-optional float
        # and the value is always resolved before the row is written
        # .
        sa.Column("budget", sa.Numeric(precision=12, scale=2), nullable=False),
        # Key identifiers only, never a key secret.
        sa.Column(
            "keys",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        # FR31's grace period needs the instant. Design 8's LiteLLMAccount does
        # not model it; the column stores a gateway-side deadline, not state.
        sa.Column("delete_after", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("user_id", name="pk_litellm_accounts"),
    )

    op.create_table(
        "audit_events",
        # A surrogate key: one event can produce more than one audit row, so
        # the canonical event id cannot be the primary key.
        sa.Column(
            "audit_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        # Design 8's ``AuditEvent.timestamp``; see the module docstring.
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("audit_id", name="pk_audit_events"),
    )
    op.create_index("ix_audit_events_event_id", "audit_events", ["event_id"])
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"])

    op.create_table(
        "source_group_members",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_group_id", sa.Text(), nullable=False),
        sa.Column("source_user_id", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "source",
            "source_group_id",
            "source_user_id",
            name="pk_source_group_members",
        ),
    )

    op.create_table(
        "processed_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("event_id", name="pk_processed_events"),
    )

    op.create_table(
        "source_cursors",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("feed_scope", sa.Text(), nullable=False),
        # Opaque to the store: the AD token and the v2 System Log token both fit
        # . Nothing parses it in SQL.
        sa.Column("cursor", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("source", "feed_scope", name="pk_source_cursors"),
    )


def downgrade() -> None:
    """Drop the eight tables of revision 0002, dependents first."""
    op.drop_table("source_cursors")
    op.drop_table("processed_events")
    op.drop_table("source_group_members")
    op.drop_table("audit_events")
    op.drop_table("litellm_accounts")
    op.drop_table("entitlements")
    op.drop_table("source_identities")
    op.drop_table("persons")
