"""Start-up never runs against a schema that does not match the code."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelx.common.errors import StorageError
from sentinelx.config.settings import StorageSettings
from sentinelx.storage import migrate
from sentinelx.storage.database import Database

POSTGRES_URL = os.environ.get("SENTINELX_TEST_POSTGRES_URL")


async def columns(url: str, table: str) -> set[str]:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            return {
                column["name"]
                for column in await connection.run_sync(
                    lambda sync: inspect(sync).get_columns(table)
                )
            }
    finally:
        await engine.dispose()


async def test_existing_sqlite_database_is_upgraded_on_start(tmp_path: Path) -> None:
    # A database made by an earlier release: the initial schema, then stamped nothing.
    url = f"sqlite+aiosqlite:///{tmp_path / 'old.db'}"
    await migrate.upgrade(url, migrate.INITIAL_REVISION)
    assert "replay_id" not in await columns(url, "response_actions")

    database = Database(StorageSettings(database_url=url))
    await database.connect()
    await database.close()
    assert "replay_id" in await columns(url, "response_actions")
    assert await migrate.current_revision(url) == migrate.head_revision()


async def test_pre_migration_sqlite_file_is_stamped_then_upgraded(tmp_path: Path) -> None:
    # Files created with create_all before migrations existed have tables but no
    # alembic_version; upgrading must not try to create those tables again.
    url = f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}"
    await migrate.upgrade(url, migrate.INITIAL_REVISION)
    engine = create_async_engine(url)
    async with engine.begin() as connection:
        await connection.exec_driver_sql("DROP TABLE alembic_version")
    await engine.dispose()

    database = Database(StorageSettings(database_url=url))
    await database.connect()
    await database.close()
    assert await migrate.current_revision(url) == migrate.head_revision()


@pytest.mark.skipif(not POSTGRES_URL, reason="SENTINELX_TEST_POSTGRES_URL not set")
async def test_outdated_postgresql_schema_is_refused() -> None:
    assert POSTGRES_URL
    from sqlalchemy.ext.asyncio import create_async_engine as engine_for

    admin = engine_for(
        POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://"), isolation_level="AUTOCOMMIT"
    )
    async with admin.connect() as connection:
        await connection.exec_driver_sql("DROP DATABASE IF EXISTS sx_schema_test")
        await connection.exec_driver_sql("CREATE DATABASE sx_schema_test")
    url = POSTGRES_URL.rsplit("/", 1)[0] + "/sx_schema_test"
    try:
        await migrate.upgrade(url, migrate.INITIAL_REVISION)
        database = Database(StorageSettings(database_url=url))
        with pytest.raises(StorageError, match="sentinelx db upgrade"):
            await database.connect()
        await migrate.upgrade(url)
        await database.connect()
        await database.close()
    finally:
        async with admin.connect() as connection:
            await connection.exec_driver_sql("DROP DATABASE IF EXISTS sx_schema_test WITH (FORCE)")
        await admin.dispose()
