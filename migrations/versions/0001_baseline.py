"""Baseline: no schema objects.

Revision ID: 0001
Revises:
Create Date: 2026-10-19 00:00:00.000000

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create no schema objects; tables arrive with the Phase 2 tickets."""


def downgrade() -> None:
    """Drop no schema objects; the baseline is empty."""
