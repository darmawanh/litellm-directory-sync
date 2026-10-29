"""The integration harness migrates the pinned PostgreSQL container."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import pytest
import sqlalchemy
from testcontainers.postgres import PostgresContainer

from tests.integration.conftest import POSTGRES_IMAGE, run_alembic

pytestmark = pytest.mark.integration

BASELINE_REVISION = "0001"
HEAD_REVISION = "0003"

#: The eleven service tables revisions 0002 and 0003 create.
SERVICE_TABLES = {
    "persons",
    "source_identities",
    "entitlements",
    "litellm_accounts",
    "audit_events",
    "source_group_members",
    "processed_events",
    "source_cursors",
    "identity_event_outbox",
    "reconciliation_misses",
    "budget_policy_overrides",
}

#: The three tables revision 0003 adds, so ``downgrade -1`` can be checked.
OUTBOX_TABLES = {
    "identity_event_outbox",
    "reconciliation_misses",
    "budget_policy_overrides",
}

# Not a database URL at all: SQLAlchemy rejects it before connecting, so a
# command that succeeds with it set proves it was ignored.
INVALID_DATABASE_URL = "not-a-database-url"


def _alembic(*args: str, database_url: str) -> str:
    result = run_alembic(*args, database_url=database_url)
    assert (
        result.returncode == 0
    ), f"alembic {' '.join(args)} failed with exit code {result.returncode}:\n{result.stderr}"
    return result.stdout


def _reset_database(database_url: str) -> None:
    """Return the container database to the state of a fresh cluster.

    Dropping ``alembic_version`` alone was enough while the baseline created no
    table. Revision 0002 and 0003 do, so the schema is dropped and recreated;
    a leftover table would make the "clean database" assertion below false.
    """
    engine = sqlalchemy.create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sqlalchemy.text("drop schema public cascade"))
            connection.execute(sqlalchemy.text("create schema public"))
    finally:
        engine.dispose()


def _tables(database_url: str) -> set[str]:
    engine = sqlalchemy.create_engine(database_url)
    try:
        with engine.connect() as connection:
            return set(sqlalchemy.inspect(connection).get_table_names())
    finally:
        engine.dispose()


def test_container_image_is_postgres_16_alpine() -> None:
    assert POSTGRES_IMAGE == "postgres:16-alpine"


def test_database_url_is_built_from_the_container_mapped_port(
    postgres_container: PostgresContainer, database_url: str
) -> None:
    port = int(postgres_container.get_exposed_port(5432))
    url = urlsplit(database_url)

    assert url.scheme == "postgresql+psycopg"
    assert url.port == port
    assert url.path == "/test"


def test_harness_ignores_database_url_from_the_shell(
    monkeypatch: pytest.MonkeyPatch,
    postgres_container: PostgresContainer,
    database_url: str,
) -> None:
    monkeypatch.setenv("DATABASE_URL", INVALID_DATABASE_URL)

    assert database_url != os.environ["DATABASE_URL"]
    assert database_url == postgres_container.get_connection_url()
    _alembic("current", database_url=database_url)


def test_alembic_uses_database_url_from_the_environment(database_url: str) -> None:
    assert run_alembic("current", database_url=INVALID_DATABASE_URL).returncode != 0

    _alembic("current", database_url=database_url)


def test_alembic_upgrade_head_on_clean_database(database_url: str) -> None:
    _reset_database(database_url)
    assert _tables(database_url) == set()

    _alembic("upgrade", "head", database_url=database_url)

    assert HEAD_REVISION in _alembic("current", database_url=database_url)
    assert _tables(database_url) == SERVICE_TABLES | {"alembic_version"}


def test_alembic_downgrade_one_then_upgrade(migrated_database_url: str) -> None:
    _alembic("downgrade", "-1", database_url=migrated_database_url)

    assert "0002" in _alembic("current", database_url=migrated_database_url)
    assert BASELINE_REVISION not in _alembic("current", database_url=migrated_database_url)
    assert not OUTBOX_TABLES & _tables(migrated_database_url)

    _alembic("upgrade", "head", database_url=migrated_database_url)
    assert HEAD_REVISION in _alembic("current", database_url=migrated_database_url)
    assert _tables(migrated_database_url) >= OUTBOX_TABLES
