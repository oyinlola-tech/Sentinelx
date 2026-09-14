"""Database engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinelx.common.errors import StorageError
from sentinelx.config.settings import StorageSettings
from sentinelx.storage.models import Base
from sentinelx.telemetry.logging import get_logger

__all__ = ["Database", "normalise_database_url"]

log = get_logger(__name__)


def normalise_database_url(url: str) -> str:
    """Map convenient URLs onto async drivers.

    ``postgresql://`` and ``postgres://`` (what most hosting providers hand out)
    become ``postgresql+asyncpg://``; ``sqlite://`` becomes ``sqlite+aiosqlite://``.
    """
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url[len("postgresql://") :]
    if url.startswith("sqlite://") and not url.startswith("sqlite+"):
        return "sqlite+aiosqlite://" + url[len("sqlite://") :]
    return url


class Database:
    """Owns the async engine and hands out sessions.

    Example:
        >>> database = Database(settings.storage)
        >>> await database.connect()
        >>> async with database.session() as session:
        ...     ...
    """

    def __init__(self, settings: StorageSettings) -> None:
        self.settings = settings
        self.url = normalise_database_url(settings.database_url)
        self._engine: AsyncEngine | None = None
        self._sessions: async_sessionmaker[AsyncSession] | None = None

    @property
    def dialect(self) -> str:
        return make_url(self.url).get_backend_name()

    @property
    def safe_url(self) -> str:
        """The URL with the password hidden, for logs and status output."""
        return make_url(self.url).render_as_string(hide_password=True)

    async def connect(self, *, create_schema: bool | None = None) -> None:
        """Create the engine and verify connectivity.

        Args:
            create_schema: create missing tables directly from the models. Defaults
                to True for SQLite (zero-setup development) and False for PostgreSQL,
                where schema changes go through Alembic (``sentinelx db upgrade``).

        Raises:
            StorageError: when the database is unreachable, with the host (never the
                password) in the message.
        """
        kwargs: dict[str, Any] = {"echo": self.settings.database_echo, "pool_pre_ping": True}
        if self.dialect == "sqlite":
            kwargs["connect_args"] = {"timeout": 30}
            if ":memory:" in self.url or self.url.endswith("sqlite+aiosqlite://"):
                from sqlalchemy.pool import StaticPool

                kwargs["poolclass"] = StaticPool  # one shared in-memory database
        else:
            kwargs["pool_size"] = self.settings.pool_size
            kwargs["max_overflow"] = self.settings.max_overflow

        engine = create_async_engine(self.url, **kwargs)
        if self.dialect == "sqlite":
            @event.listens_for(engine.sync_engine, "connect")
            def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()

        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except (SQLAlchemyError, OSError) as exc:
            await engine.dispose()
            raise StorageError(f"cannot connect to database {self.safe_url}: {type(exc).__name__}: {exc}") from exc

        self._engine = engine
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)
        should_create = create_schema if create_schema is not None else self.dialect == "sqlite"
        if should_create:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        log.info("database_connected", url=self.safe_url, dialect=self.dialect, schema_created=should_create)

    async def close(self) -> None:
        engine, self._engine = self._engine, None
        if engine is not None:
            await engine.dispose()

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise StorageError("database is not connected")
        return self._engine

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """A session that commits on success and rolls back on any exception."""
        if self._sessions is None:
            raise StorageError("database is not connected")
        async with self._sessions() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    async def health(self) -> dict[str, Any]:
        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return {"ok": True, "dialect": self.dialect, "url": self.safe_url}
        except (SQLAlchemyError, OSError, StorageError) as exc:
            return {"ok": False, "dialect": self.dialect, "url": self.safe_url, "error": type(exc).__name__}
