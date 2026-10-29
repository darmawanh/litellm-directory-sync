"""The Phase 2 schema: two revisions, eleven tables, and the constraints they promise.

Each schema test gets its own empty database on the pinned container, so the
up/down/up sequence runs on a clean cluster rather than on state a previous test
left behind. The revision files are the schema authority; nothing here imports
``src``.

The column sets below are literals copied from the design, not from the
migration, so deleting a column from a revision cannot shrink the proof with it
. Where a table carries a column the design does not name, the extra is
listed and the reason is in the same tuple.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy
from sqlalchemy.exc import IntegrityError

from tests.integration.conftest import run_alembic

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = REPO_ROOT / "migrations" / "versions"

#: Design 8's five stored entities, the membership snapshot, idempotency, cursors.
CANONICAL_TABLES = {
    "persons",
    "source_identities",
    "entitlements",
    "litellm_accounts",
    "audit_events",
    "source_group_members",
    "processed_events",
    "source_cursors",
}

#: Design 9.1's queue plus its two satellites.
OUTBOX_TABLES = {
    "identity_event_outbox",
    "reconciliation_misses",
    "budget_policy_overrides",
}

#: The design-named columns of each entity. A subset assertion: the tables also
#: carry the surrogate keys and the columns the three naming-gap rulings added.
DESIGN_COLUMNS: dict[str, set[str]] = {
    "persons": {"person_id", "employee_number", "email", "display_name", "status"},
    "source_identities": {"source", "source_user_id", "person_id"},
    "entitlements": {
        "person_id",
        "role",
        "team",
        "budget_policy",
        "source",
        "effective_from",
        "effective_to",
    },
    "litellm_accounts": {"user_id", "status", "role", "team", "budget", "keys"},
    "audit_events": {
        "event_id",
        "source_event_id",
        # Ruled extra: FR14 names the source in the record, although design 8's
        # AuditEvent has no such field.
        "source",
        "actor",
        "action",
        "target",
        "decision",
        "reason",
    },
    "source_group_members": {"source", "source_group_id", "source_user_id"},
    "processed_events": {"event_id", "processed_at"},
    "source_cursors": {"source", "feed_scope", "cursor", "updated_at"},
    "reconciliation_misses": {"person_id", "source", "miss_count", "last_seen_at"},
    "budget_policy_overrides": {"scope", "key", "policy"},
}

#: Design 9.1's thirteen columns plus ADR-015's ``person_key``, in ordinal order.
OUTBOX_COLUMNS = (
    "id",
    "event_id",
    "source",
    "source_event_id",
    "person_key",
    "event_type",
    "payload",
    "status",
    "attempts",
    "next_attempt_at",
    "locked_until",
    "last_error",
    "created_at",
    "updated_at",
)

#: Every ``timestamptz`` column this schema creates.
TIMESTAMP_COLUMNS = {
    "entitlements": {"effective_from", "effective_to"},
    "litellm_accounts": {"delete_after"},
    "audit_events": {"occurred_at"},
    "processed_events": {"processed_at"},
    "source_cursors": {"updated_at"},
    "reconciliation_misses": {"last_seen_at"},
    "identity_event_outbox": {
        "next_attempt_at",
        "locked_until",
        "created_at",
        "updated_at",
    },
}


@pytest.fixture
def fresh_database(database_url: str) -> Iterator[str]:
    """An empty database on the pinned container, dropped afterwards."""
    url = sqlalchemy.engine.make_url(database_url)
    name = f"schema_{uuid.uuid4().hex[:12]}"
    admin = sqlalchemy.create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(sqlalchemy.text(f'create database "{name}"'))
        yield url.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as connection:
            connection.execute(sqlalchemy.text(f'drop database if exists "{name}" with (force)'))
        admin.dispose()


def _alembic(*args: str, database_url: str) -> str:
    result = run_alembic(*args, database_url=database_url)
    assert (
        result.returncode == 0
    ), f"alembic {' '.join(args)} failed with exit code {result.returncode}:\n{result.stderr}"
    return result.stdout


def _upgrade(database_url: str, revision: str = "head") -> None:
    _alembic("upgrade", revision, database_url=database_url)


def _tables(database_url: str) -> set[str]:
    engine = sqlalchemy.create_engine(database_url)
    try:
        with engine.connect() as connection:
            return set(sqlalchemy.inspect(connection).get_table_names())
    finally:
        engine.dispose()


def _columns(database_url: str, table: str) -> list[sqlalchemy.engine.reflection.ColumnDict]:
    engine = sqlalchemy.create_engine(database_url)
    try:
        with engine.connect() as connection:
            return sqlalchemy.inspect(connection).get_columns(table)
    finally:
        engine.dispose()


def _column_names(database_url: str, table: str) -> set[str]:
    return {column["name"] for column in _columns(database_url, table)}


def _execute(database_url: str, statement: str, **parameters: object) -> None:
    """Run one statement and commit it, so a rejected insert leaves no row."""
    engine = sqlalchemy.create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sqlalchemy.text(statement), parameters)
    finally:
        engine.dispose()


def _insert_person(database_url: str, person_id: str = "p-1") -> None:
    _execute(
        database_url,
        "insert into persons (person_id, email, display_name, status)"
        " values (:person_id, :email, :display_name, 'active')",
        person_id=person_id,
        email="person@example.com",
        display_name="Example Person",
    )


# Revisions apply and reverse


def test_migration_0002_creates_eight_tables(fresh_database: str) -> None:
    _upgrade(fresh_database, "0002")

    assert _tables(fresh_database) == CANONICAL_TABLES | {"alembic_version"}


def test_migration_0003_creates_three_tables(fresh_database: str) -> None:
    _upgrade(fresh_database, "0002")
    _upgrade(fresh_database)

    assert _tables(fresh_database) == CANONICAL_TABLES | OUTBOX_TABLES | {"alembic_version"}


def test_upgrade_downgrade_upgrade_leaves_the_schema_intact(fresh_database: str) -> None:
    _upgrade(fresh_database)
    at_head = _tables(fresh_database)

    _alembic("downgrade", "-1", database_url=fresh_database)
    assert _tables(fresh_database) == CANONICAL_TABLES | {"alembic_version"}
    assert "0002" in _alembic("current", database_url=fresh_database)

    _upgrade(fresh_database)
    assert _tables(fresh_database) == at_head
    assert "0003" in _alembic("current", database_url=fresh_database)


# Columns


@pytest.mark.parametrize(("table", "design_fields"), sorted(DESIGN_COLUMNS.items()))
def test_every_design_column_is_present(
    fresh_database: str, table: str, design_fields: set[str]
) -> None:
    _upgrade(fresh_database)

    assert design_fields <= _column_names(fresh_database, table)


def test_outbox_columns_are_design_9_1_plus_person_key(fresh_database: str) -> None:
    _upgrade(fresh_database)

    columns = _columns(fresh_database, "identity_event_outbox")

    assert tuple(column["name"] for column in columns) == OUTBOX_COLUMNS
    assert "person_key" in _column_names(fresh_database, "identity_event_outbox")


def test_every_timestamp_is_timestamptz(fresh_database: str) -> None:
    _upgrade(fresh_database)

    for table, names in TIMESTAMP_COLUMNS.items():
        by_name = {column["name"]: column for column in _columns(fresh_database, table)}
        for name in names:
            column_type = by_name[name]["type"]
            assert isinstance(column_type, sqlalchemy.DateTime), f"{table}.{name} is not a datetime"
            assert column_type.timezone is True, f"{table}.{name} is not timestamptz"


# Constraints the ticket names


def test_outbox_rejects_unknown_status(fresh_database: str) -> None:
    _upgrade(fresh_database)

    with pytest.raises(IntegrityError, match="ck_identity_event_outbox_status"):
        _execute(
            fresh_database,
            "insert into identity_event_outbox (event_id, source, event_type, payload, status)"
            " values (:event_id, 'corp-ad', 'group.member_added', '{}'::jsonb, 'bogus')",
            event_id=uuid.uuid4(),
        )


def test_outbox_event_id_is_unique(fresh_database: str) -> None:
    _upgrade(fresh_database)
    event_id = uuid.uuid4()
    statement = (
        "insert into identity_event_outbox (event_id, source, event_type, payload)"
        " values (:event_id, 'corp-ad', 'group.member_added', '{}'::jsonb)"
    )
    _execute(fresh_database, statement, event_id=event_id)

    with pytest.raises(IntegrityError, match="uq_identity_event_outbox_event_id"):
        _execute(fresh_database, statement, event_id=event_id)


def test_account_row_without_a_budget_is_rejected(fresh_database: str) -> None:
    """ADR-017 section 2: the budget is required once the account is stored.

    A ``not null`` column on an empty table proves nothing by itself, so the
    test inserts the row a nullable column would have accepted. The domain
    field ``LiteLLMAccount.budget`` is a non-optional ``float``, so a stored
    NULL could not be read back into it.
    """
    _upgrade(fresh_database)
    budget = next(
        column
        for column in _columns(fresh_database, "litellm_accounts")
        if column["name"] == "budget"
    )
    assert budget["nullable"] is False

    with pytest.raises(IntegrityError, match="budget"):
        _execute(
            fresh_database,
            "insert into litellm_accounts (user_id, status, role, team, budget)"
            " values ('user-1', 'active', 'internal_user', 'ai-platform', null)",
        )


def test_two_people_may_share_an_employee_number(fresh_database: str) -> None:
    """ADR-005 section 3: a duplicated employeeID must not block either person.

    Two live objects may carry the same ``employeeID``, are provisioned
    independently, and are never unified through it. A ``UNIQUE`` constraint
    would make the second person's row unstorable, so this test is the inverse
    of ``test_source_identities_unique_pair``: the same link is allowed twice.
    """
    _upgrade(fresh_database)
    statement = (
        "insert into persons (person_id, employee_number, email, display_name, status)"
        " values (:person_id, 'E20002', :email, 'Example Person', 'active')"
    )

    _execute(fresh_database, statement, person_id="p-1", email="one@example.com")
    _execute(fresh_database, statement, person_id="p-2", email="two@example.com")

    engine = sqlalchemy.create_engine(fresh_database)
    try:
        with engine.connect() as connection:
            shared = connection.execute(
                sqlalchemy.text("select count(*) from persons where employee_number = 'E20002'")
            ).scalar_one()
    finally:
        engine.dispose()

    assert shared == 2


def test_source_identities_unique_pair(fresh_database: str) -> None:
    _upgrade(fresh_database)
    _insert_person(fresh_database)
    statement = (
        "insert into source_identities (source, source_user_id, person_id)"
        " values ('corp-ad', 'object-guid', 'p-1')"
    )
    _execute(fresh_database, statement)

    with pytest.raises(IntegrityError, match="pk_source_identities"):
        _execute(fresh_database, statement)


def test_processed_events_event_id_unique(fresh_database: str) -> None:
    _upgrade(fresh_database)
    event_id = uuid.uuid4()
    statement = "insert into processed_events (event_id) values (:event_id)"
    _execute(fresh_database, statement, event_id=event_id)

    with pytest.raises(IntegrityError, match="pk_processed_events"):
        _execute(fresh_database, statement, event_id=event_id)


def test_person_key_is_nullable_and_not_indexed(fresh_database: str) -> None:
    _upgrade(fresh_database)
    engine = sqlalchemy.create_engine(fresh_database)
    try:
        with engine.connect() as connection:
            inspector = sqlalchemy.inspect(connection)
            person_key = next(
                column
                for column in inspector.get_columns("identity_event_outbox")
                if column["name"] == "person_key"
            )
            indexes = inspector.get_indexes("identity_event_outbox")
            unique = inspector.get_unique_constraints("identity_event_outbox")
            checks = connection.execute(
                sqlalchemy.text(
                    "select pg_get_constraintdef(oid) as definition"
                    " from pg_constraint where conrelid = 'identity_event_outbox'::regclass"
                    " and contype = 'c'"
                )
            ).scalars()
            generated = connection.execute(
                sqlalchemy.text(
                    "select generation_expression from information_schema.columns"
                    " where table_name = 'identity_event_outbox' and column_name = 'person_key'"
                )
            ).scalar_one()
    finally:
        engine.dispose()

    assert isinstance(person_key["type"], sqlalchemy.Text)
    assert person_key["nullable"] is True
    # A plain column has no generation expression; information_schema reports NULL.
    assert generated in (None, "")
    assert all("person_key" not in index["column_names"] for index in indexes)
    assert all("person_key" not in constraint["column_names"] for constraint in unique)
    assert all("person_key" not in definition for definition in checks)


def test_outbox_claim_index_exists(fresh_database: str) -> None:
    _upgrade(fresh_database)
    engine = sqlalchemy.create_engine(fresh_database)
    try:
        with engine.connect() as connection:
            indexes = sqlalchemy.inspect(connection).get_indexes("identity_event_outbox")
    finally:
        engine.dispose()

    # The unique constraint's backing index appears here too on PostgreSQL, so
    # the assertion names the claim index and pins the *set* of other indexes:
    # only the event_id unique constraint, nothing else.
    named = {index["name"]: index["column_names"] for index in indexes}

    assert named["ix_identity_event_outbox_claim"] == ["status", "next_attempt_at"]
    assert set(named) == {
        "ix_identity_event_outbox_claim",
        "uq_identity_event_outbox_event_id",
    }


# Classification


def test_the_migrations_mark_their_personal_data() -> None:
    canonical = (MIGRATIONS / "0002_canonical_store.py").read_text(encoding="utf-8")
    outbox = (MIGRATIONS / "0003_outbox_and_overrides.py").read_text(encoding="utf-8")

    assert "Personal data" in canonical
    for name in ("employee_number", "email", "display_name", "audit_events.target"):
        assert name in canonical, f"0002 does not classify {name}"
    assert "Personal data" in outbox
    for name in ("payload", "person_id"):
        assert name in outbox, f"0003 does not classify {name}"
