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

    async def connect(
        self, *, create_schema: bool | None = None, prepare_schema: bool = True
    ) -> None:
        """Create the engine and verify connectivity.

        Args:
            create_schema: bring the schema to the latest revision by running the
                migrations. Defaults to True for SQLite (zero-setup development) and
                False for PostgreSQL, where schema changes go through Alembic
                (``sentinelx db upgrade``).
            prepare_schema: check (and for SQLite, migrate) the schema. Diagnostics
                pass False to inspect a database without changing it.

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
            kwargs["pool_timeout"] = self.settings.pool_timeout_seconds
            # asyncpg: bound connecting and every statement (the pool's pre-ping included),
            # so an unresponsive server surfaces as an error the API maps to 503.
            kwargs["connect_args"] = {
                "timeout": self.settings.connect_timeout_seconds,
                "command_timeout": self.settings.statement_timeout_seconds,
            }

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
            raise StorageError(
                f"cannot connect to database {self.safe_url}: {type(exc).__name__}: {exc}"
            ) from exc

        self._engine = engine
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)
        try:
            if prepare_schema:
                await self._prepare_schema(engine, create_schema)
        except BaseException:
            await engine.dispose()
            self._engine = None
            raise
        log.info("database_connected", url=self.safe_url, dialect=self.dialect)

    async def _prepare_schema(self, engine: AsyncEngine, create_schema: bool | None) -> None:
        """Make sure the schema matches this version of SentinelX before any write.

        * In-memory SQLite (tests): tables are created from the models.
        * SQLite files (``create_schema`` default), or any database when
          ``create_schema`` is True: migrated to the latest revision. A database
          created with ``create_all`` (no recorded revision) is adopted first - see
          :func:`sentinelx.storage.migrate.adopt_unversioned` - so upgrading never
          tries to create tables that exist or leaves a column missing.
        * PostgreSQL: never changed automatically. Start-up refuses a schema that is
          not at the latest revision, instead of running and losing writes.
        """
        from sentinelx.storage import migrate

        in_memory = ":memory:" in self.url or self.url.endswith("sqlite+aiosqlite://")
        if in_memory:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            return
        should_migrate = create_schema if create_schema is not None else self.dialect == "sqlite"
        if should_migrate:
            # Tables created without migrations would otherwise leave the database
            # unversioned, which a later normal start refuses and ``db upgrade`` fails.
            await migrate.upgrade(self.url)
            return
        head = migrate.head_revision()
        applied = await migrate.current_revision(self.url)
        if applied != head:
            raise StorageError(
                f"database schema is at revision {applied or 'none'} but this version of "
                f"SentinelX needs {head}; run: sentinelx db upgrade"
            )

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
            except BaseException as exc:
                try:
                    await session.rollback()
                except Exception:  # a broken connection cannot roll back; keep the cause
                    log.debug("rollback_failed", error=type(exc).__name__)
                if isinstance(exc, OSError | TimeoutError) and _raised_by_database_driver(exc):
                    # The driver's own network errors (refused, unresolvable host, timed
                    # out) reach here unwrapped by SQLAlchemy. Report them as the storage
                    # outage they are, so the API answers 503 rather than a generic 500.
                    raise StorageError(
                        f"database unavailable at {self.safe_url}: {type(exc).__name__}"
                    ) from exc
                raise

    async def health(self) -> dict[str, Any]:
        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return {"ok": True, "dialect": self.dialect, "url": self.safe_url}
        except (SQLAlchemyError, OSError, StorageError) as exc:
            return {
                "ok": False,
                "dialect": self.dialect,
                "url": self.safe_url,
                "error": type(exc).__name__,
            }


_DRIVER_PACKAGES = ("sqlalchemy", "asyncpg", "aiosqlite")


def _raised_by_database_driver(exc: BaseException) -> bool:
    """Whether ``exc`` was raised from inside the database driver stack."""
    traceback = exc.__traceback__
    while traceback is not None:
        module = traceback.tb_frame.f_globals.get("__name__", "")
        if module.split(".", 1)[0] in _DRIVER_PACKAGES:
            return True
        traceback = traceback.tb_next
    return False
