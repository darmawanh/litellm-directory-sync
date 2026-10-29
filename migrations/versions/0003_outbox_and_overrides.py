"""The outbox, its satellites, and the person key.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-22 00:00:00.000000

Three tables: design 9.1's queue with ADR-002's and ADR-015's deltas, the
reconciliation miss counter, and the budget override
.

``identity_event_outbox`` is design 9.1's DDL plus two deltas, both cited in
the column list below:

- ADR-002 section 2's ``check (status in ('pending', 'processing', 'done', 'dead'))``
  and the `` (status, next_attempt_at)`` index. A ``CHECK`` is used rather than a
  PostgreSQL enum because adding a value to an enum is migration friction.
- ADR-015 section 2's ``person_key text``: nullable exactly when the event names
  no person, not unique, **no index**, no check, not generated. The per-person
  lock is a session-scoped advisory lock computed from this value (ADR-015
  section 3); it does not read the table, which is why the column carries no
  index in v1. The ingest writer computes it as ``source + ":" +
  source_user_id``; a generated expression would carry a ``payload`` JSON path
  whose meaning depends on ``schema_version``.

Two names worth stating, because design 10.6 and the ADRs word them differently:

- ``source_cursors`` (revision 0002) calls its scope ``feed_scope``, not
  ``group_id``, because two of the three feeds are not groups.
- ``budget_policy_overrides.key`` holds the person_id or the source_group_id,
  depending on ``scope``. ``key`` is an unreserved word in PostgreSQL, so no
  statement this schema's readers write needs to quote it.

Personal data stored by this revision:

- ``identity_event_outbox.payload`` carries the canonical envelope, including
  the event's person fields: ``source_user_id``, ``employee_number``,
  ``display_name`` and ``email`` where the adapter supplies them.
- ``reconciliation_misses.person_id`` is a pseudonymous person identifier.
- ``budget_policy_overrides.key`` is a ``person_id`` when ``scope`` is
  ``person``, so a person-scoped override row names a person.
- ``identity_event_outbox.last_error`` may quote a vendor message that names a
  person or an account.

Every timestamp is ``timestamptz``. All timestamps are UTC.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the outbox, the miss counter, and the budget override."""
    op.create_table(
        "identity_event_outbox",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # The enqueue guard: a duplicate event cannot take a second row
        # .
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=True),
        # ADR-015 section 2. Immediately after source_event_id, where the ADR
        # places it. See the module docstring for the five properties.
        sa.Column("person_key", sa.Text(), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        # Design 8's envelope, including schema_version.
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_identity_event_outbox"),
        sa.UniqueConstraint("event_id", name="uq_identity_event_outbox_event_id"),
        # ADR-002 section 2's status CHECK: the first of its two deltas from
        # design 9.1. The second is ADR-015 section 2's ``person_key`` above.
        sa.CheckConstraint(
            "status in ('pending', 'processing', 'done', 'dead')",
            name="ck_identity_event_outbox_status",
        ),
    )
    # Design 9.1's claim index. The only index on the table: person_key gets
    # none in v1.
    op.create_index(
        "ix_identity_event_outbox_claim",
        "identity_event_outbox",
        ["status", "next_attempt_at"],
    )

    op.create_table(
        "reconciliation_misses",
        sa.Column("person_id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column(
            "miss_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        # One row per person per source: the second consecutive miss increments
        # the row instead of adding one.
        sa.PrimaryKeyConstraint("person_id", "source", name="pk_reconciliation_misses"),
        sa.ForeignKeyConstraint(
            ["person_id"],
            ["persons.person_id"],
            name="fk_reconciliation_misses_person_id",
        ),
    )

    op.create_table(
        "budget_policy_overrides",
        # Design 10.7 steps 1-2: a person override and a group override, the two
        # levels between the config mapping and the default.
        sa.Column("scope", sa.Text(), nullable=False),
        # The person_id or the source_group_id, depending on the scope.
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("policy", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("scope", "key", name="pk_budget_policy_overrides"),
        sa.CheckConstraint(
            "scope in ('person', 'group')",
            name="ck_budget_policy_overrides_scope",
        ),
    )


def downgrade() -> None:
    """Drop the three tables of revision 0003, dependents first."""
    op.drop_table("budget_policy_overrides")
    op.drop_table("reconciliation_misses")
    op.drop_index("ix_identity_event_outbox_claim", table_name="identity_event_outbox")
    op.drop_table("identity_event_outbox")
