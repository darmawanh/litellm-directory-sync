"""Integration test harness: one pinned PostgreSQL container per session.

The container URL is built from the container's own mapped port. The harness
never reads ``DATABASE_URL`` from the developer's shell, so a local stack on a
different port or a different PostgreSQL major version cannot leak in.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy
from testcontainers.postgres import PostgresContainer

POSTGRES_IMAGE = "postgres:16-alpine"

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_alembic(*args: str, database_url: str) -> subprocess.CompletedProcess[str]:
    """Run the Alembic CLI with ``database_url`` as the only ``DATABASE_URL``."""
    environment = {**os.environ, "DATABASE_URL": database_url}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def docker_unavailable_reason() -> str | None:
    """Return why Docker cannot be used, or ``None`` when the daemon answers."""
    try:
        import docker
        from docker.errors import DockerException
    except ImportError as exc:  # pragma: no cover - testcontainers installs docker
        return f"the docker package is not installed ({exc})"

    try:
        client = docker.from_env()
        client.ping()
    except (DockerException, OSError) as exc:
        return f"{type(exc).__name__}: {exc}"
    else:
        client.close()
    return None


@pytest.fixture(scope="session", autouse=True)
def require_docker() -> None:
    """Skip the whole integration suite when no Docker daemon is reachable."""
    reason = docker_unavailable_reason()
    if reason is not None:
        pytest.skip(f"Docker daemon is unreachable, skipping integration tests: {reason}")


@pytest.fixture(scope="session")
def postgres_container() -> Iterator[PostgresContainer]:
    """Start the pinned image once and stop it when the session ends."""
    container = PostgresContainer(POSTGRES_IMAGE, driver="psycopg")
    container.start()
    try:
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="session")
def database_url(postgres_container: PostgresContainer) -> str:
    """The container's connection URL, with the container's mapped port."""
    return postgres_container.get_connection_url()


@pytest.fixture(scope="session")
def migrated_database_url(database_url: str) -> str:
    """Bring the container database to ``head`` once for the session."""
    alembic_upgrade(database_url)
    return database_url


def alembic_upgrade(database_url: str, revision: str = "head") -> None:
    """Migrate one database to ``revision``, failing the test on a non-zero exit."""
    result = run_alembic("upgrade", revision, database_url=database_url)
    assert (
        result.returncode == 0
    ), f"alembic upgrade {revision} failed with exit code {result.returncode}:\n{result.stderr}"


@pytest.fixture
def migrated_database(fresh_database: str) -> str:
    """A fresh database brought to ``head``, for a test that writes rows."""
    alembic_upgrade(fresh_database)
    return fresh_database


@pytest.fixture
def fresh_database(database_url: str) -> Iterator[str]:
    """An empty database on the pinned container, dropped afterwards.

    Each test that needs a schema of its own takes this fixture and calls
    :func:`alembic_upgrade`, so no test inherits rows a previous one left behind.
    """
    url = sqlalchemy.engine.make_url(database_url)
    name = f"test_{uuid.uuid4().hex[:12]}"
    admin = sqlalchemy.create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(sqlalchemy.text(f'create database "{name}"'))
        yield url.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as connection:
            connection.execute(sqlalchemy.text(f'drop database if exists "{name}" with (force)'))
        admin.dispose()
