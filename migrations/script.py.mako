"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""

<%!
import json


def quoted(value):
    """Render a revision identifier as a double-quoted literal, or None."""
    return json.dumps(value) if value else "None"
%>from collections.abc import Sequence
${"import sqlalchemy as sa\nfrom alembic import op\n" if upgrades or downgrades else ""}
# revision identifiers, used by Alembic.
revision: str = ${quoted(up_revision)}
down_revision: str | None = ${quoted(down_revision)}
branch_labels: str | Sequence[str] | None = ${quoted(branch_labels)}
depends_on: str | Sequence[str] | None = ${quoted(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
