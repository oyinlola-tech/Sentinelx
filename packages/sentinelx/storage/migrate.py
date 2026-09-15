"""Programmatic migrations, used by ``sentinelx db`` and by start-up schema checks."""

from __future__ import annotations

import asyncio
import warnings
from pathlib import Path

from alembic import command
from alembic.config import Config

__all__ = [
    "INITIAL_REVISION",
    "adopt_unversioned",
    "alembic_config",
    "current_revision",
    "downgrade",
    "head_revision",
    "stamp",
    "upgrade",
]

#: The first migration. Databases created before migrations were tracked (by
#: ``create_all``) match this revision and are stamped with it before upgrading.
INITIAL_REVISION = "540eb200aacd"

MIGRATIONS = Path(__file__).parent / "migrations"


def alembic_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    # ConfigParser interpolation treats '%' specially; escape it in passwords.
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


async def upgrade(database_url: str, revision: str = "head") -> None:
    """Migrate to ``revision``, first adopting a database created without Alembic."""
    await adopt_unversioned(database_url)
    # env.py calls asyncio.run(), which cannot nest inside a running loop.
    await asyncio.to_thread(command.upgrade, alembic_config(database_url), revision)


async def adopt_unversioned(database_url: str) -> str | None:
    """Stamp a database whose tables exist but whose revision was never recorded.

    Such databases were created with ``create_all``: by releases that predated
    migrations (their schema is :data:`INITIAL_REVISION`), or from the current models
    (their schema is already the head). Stamping the wrong one would make the upgrade
    fail on objects that already exist, or skip changes that were never applied, so
    the schema is compared with the models to tell which.

    Returns:
        The revision stamped, or None when the database needed no adoption.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect
    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import create_async_engine

    from sentinelx.storage.database import normalise_database_url
    from sentinelx.storage.models import Base

    def detect(connection: Connection) -> str | None:
        tables = set(inspect(connection).get_table_names())
        if "alembic_version" in tables or "detections" not in tables:
            return None
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        with warnings.catch_warnings():
            # SQLite cannot reflect expression indexes; that is not a difference.
            warnings.simplefilter("ignore")
            differences = compare_metadata(context, Base.metadata)
        return head_revision() if not differences else INITIAL_REVISION

    engine = create_async_engine(normalise_database_url(database_url))
    try:
        async with engine.connect() as connection:
            revision = await connection.run_sync(detect)
    finally:
        await engine.dispose()
    if revision is not None:
        await stamp(database_url, revision)
    return revision


async def stamp(database_url: str, revision: str) -> None:
    await asyncio.to_thread(command.stamp, alembic_config(database_url), revision)


async def downgrade(database_url: str, revision: str) -> None:
    await asyncio.to_thread(command.downgrade, alembic_config(database_url), revision)


def head_revision() -> str | None:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(alembic_config("sqlite://")).get_current_head()


async def current_revision(database_url: str) -> str | None:
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy.ext.asyncio import create_async_engine

    from sentinelx.storage.database import normalise_database_url

    engine = create_async_engine(normalise_database_url(database_url))
    try:
        async with engine.connect() as connection:
            return await connection.run_sync(
                lambda sync: MigrationContext.configure(sync).get_current_revision()
            )
    finally:
        await engine.dispose()
