"""Alembic environment for the identity lifecycle database.

The connection URL always comes from the environment. ``alembic.ini`` leaves
``sqlalchemy.url`` blank so no credential is committed; the test harness and
the service set ``DATABASE_URL`` explicitly.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

database_url = os.environ.get("DATABASE_URL")
if database_url:
    # ConfigParser treats "%" as interpolation syntax, so escape it.
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

# The schema is written as explicit ``op.create_table`` calls in the revision
# files, not as declarative models (explicit SQL),
# so there is no metadata for autogenerate to read.
target_metadata = None


def _database_url() -> str:
    """Return the configured URL, or explain why it is missing."""
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set; alembic.ini stores no credential and "
            "migrations/env.py reads the URL from the environment."
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations without a live database connection."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
