"""The ``persons`` and ``source_identities`` repositories.

Both are upserts keyed by their own key: ``person_id`` and the pair
`` (source, source_user_id)``. The link lookup returns every match, never
``limit 1`` and never a first row.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

from identity_lifecycle.adapters.persistence.rows import identity_from_row, person_from_row
from identity_lifecycle.domain.models import Person, SourceIdentity


class PersonStore:
    """The ``persons`` rows, as ``Person`` values."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get(self, person_id: str) -> Person | None:
        """Return the person, or ``None`` when no such row exists."""
        row = (
            self._connection.execute(
                text(
                    "select person_id, employee_number, email, display_name, status"
                    " from persons where person_id = :person_id"
                ),
                {"person_id": person_id},
            )
            .mappings()
            .first()
        )
        return None if row is None else person_from_row(row)

    def find_all_by_employee_number(self, employee_number: str) -> tuple[Person, ...]:
        """Return every person carrying the link: none, one, or several.

        The cardinality is the answer. There is no ``limit`` and no ordering by
        preference: the rows are ordered by ``person_id`` only so a test and a
        log read the same tuple twice.
        """
        rows = (
            self._connection.execute(
                text(
                    "select person_id, employee_number, email, display_name, status"
                    " from persons where employee_number = :employee_number"
                    " order by person_id"
                ),
                {"employee_number": employee_number},
            )
            .mappings()
            .all()
        )
        return tuple(person_from_row(row) for row in rows)

    def save(self, person: Person) -> None:
        """Insert or update the person, keyed by ``person_id``."""
        self._connection.execute(
            text(
                "insert into persons"
                " (person_id, employee_number, email, display_name, status)"
                " values (:person_id, :employee_number, :email, :display_name, :status)"
                " on conflict (person_id) do update set"
                " employee_number = excluded.employee_number,"
                " email = excluded.email,"
                " display_name = excluded.display_name,"
                " status = excluded.status"
            ),
            {
                "person_id": person.person_id,
                "employee_number": person.employee_number,
                "email": person.email,
                "display_name": person.display_name,
                "status": person.status,
            },
        )

    def list_all(self) -> tuple[Person, ...]:
        """Return every stored person."""
        rows = (
            self._connection.execute(
                text(
                    "select person_id, employee_number, email, display_name, status"
                    " from persons order by person_id"
                )
            )
            .mappings()
            .all()
        )
        return tuple(person_from_row(row) for row in rows)


class SourceIdentityStore:
    """The ``source_identities`` link rows."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def find(self, source: str, source_user_id: str) -> SourceIdentity | None:
        """Return the link for one source object, or ``None``."""
        row = (
            self._connection.execute(
                text(
                    "select source, source_user_id, person_id from source_identities"
                    " where source = :source and source_user_id = :source_user_id"
                ),
                {"source": source, "source_user_id": source_user_id},
            )
            .mappings()
            .first()
        )
        return None if row is None else identity_from_row(row)

    def save(self, identity: SourceIdentity) -> None:
        """Insert or update the link; `` (source, source_user_id)`` is unique."""
        self._connection.execute(
            text(
                "insert into source_identities (source, source_user_id, person_id)"
                " values (:source, :source_user_id, :person_id)"
                " on conflict (source, source_user_id) do update set"
                " person_id = excluded.person_id"
            ),
            {
                "source": identity.source,
                "source_user_id": identity.source_user_id,
                "person_id": identity.person_id,
            },
        )

    def list_for_source(self, source: str) -> tuple[SourceIdentity, ...]:
        """Return every stored identity link for one source."""
        rows = (
            self._connection.execute(
                text(
                    "select source, source_user_id, person_id from source_identities"
                    " where source = :source order by source_user_id"
                ),
                {"source": source},
            )
            .mappings()
            .all()
        )
        return tuple(identity_from_row(row) for row in rows)
