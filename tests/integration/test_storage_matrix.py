"""Storage verified against real databases: schema, constraints, migrations, sessions,
event persistence through outages, query counts, and Redis shared state.

Every test runs on a SQLite file; PostgreSQL and Redis variants run when
SENTINELX_TEST_POSTGRES_URL / SENTINELX_TEST_REDIS_URL are set (``make
test-integration``). PostgreSQL tests each use a database of their own, created and
dropped here, so they never disturb other tests sharing the server.

Outages are simulated with an in-process TCP proxy that can be cut and restored,
which behaves like a database or Redis host becoming unreachable (connections reset,
new connections refused) without touching the containers.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
import uuid
import warnings
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import delete, event, func, inspect, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from structlog.testing import capture_logs

from sentinelx.common.errors import StorageError
from sentinelx.config.settings import Settings, StorageSettings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.services.queries import QueryService
from sentinelx.storage import migrate, redis_state
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database, normalise_database_url
from sentinelx.storage.models import (
    Base,
    DetectionRecord,
    IncidentRecord,
    RefreshToken,
    ReplayRecord,
    ResponseActionRecord,
    User,
)
from sentinelx.storage.persister import EventPersister
from sentinelx.storage.redis_state import SharedState
from sentinelx.storage.repositories import (
    AnalyticsRepository,
    AuditRepository,
    BlockRepository,
    DetectionFilter,
    DetectionRepository,
    IncidentRepository,
    ReplayRepository,
    ResponseActionRepository,
    RuleRepository,
    SettingRepository,
    UserRepository,
)
from sentinelx.telemetry.metrics import metrics

POSTGRES_URL = os.environ.get("SENTINELX_TEST_POSTGRES_URL")
REDIS_URL = os.environ.get("SENTINELX_TEST_REDIS_URL")

BACKENDS = [pytest.param("sqlite", id="sqlite-file")]
if POSTGRES_URL:
    BACKENDS.append(pytest.param("postgresql", id="postgresql", marks=pytest.mark.integration))

requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL, reason="SENTINELX_TEST_POSTGRES_URL not set"
)
requires_redis = pytest.mark.skipif(not REDIS_URL, reason="SENTINELX_TEST_REDIS_URL not set")

NOW = datetime.now(UTC)


# ================================================================== helpers


@contextlib.contextmanager
def captured_logs() -> Any:
    """Capture log events at every level (the shared fixtures silence logging)."""
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG))
    try:
        with capture_logs() as logs:
            yield logs
    finally:
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))


@contextlib.asynccontextmanager
async def empty_database(backend: str, tmp_path: Path) -> AsyncIterator[str]:
    """A URL for a brand-new, empty database of the given kind."""
    if backend == "sqlite":
        yield f"sqlite+aiosqlite:///{tmp_path / f'{uuid.uuid4().hex}.db'}"
        return
    assert POSTGRES_URL
    name = f"sx_matrix_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(normalise_database_url(POSTGRES_URL), isolation_level="AUTOCOMMIT")
    async with admin.connect() as connection:
        await connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    try:
        yield POSTGRES_URL.rsplit("/", 1)[0] + f"/{name}"
    finally:
        async with admin.connect() as connection:
            await connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.dispose()


@contextlib.asynccontextmanager
async def migrated_database(
    backend: str, tmp_path: Path, **storage: Any
) -> AsyncIterator[Database]:
    async with empty_database(backend, tmp_path) as url:
        await migrate.upgrade(url)
        database = Database(StorageSettings(database_url=url, **storage))
        await database.connect()
        try:
            yield database
        finally:
            await database.close()


async def run_sync[T](url: str, fn: Callable[[Connection], T]) -> T:
    engine = create_async_engine(normalise_database_url(url))
    try:
        async with engine.connect() as connection:
            return await connection.run_sync(fn)
    finally:
        await engine.dispose()


def schema_differences(connection: Connection) -> list[Any]:
    context = MigrationContext.configure(connection, opts={"compare_type": True})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # SQLite cannot reflect expression indexes
        return list(compare_metadata(context, Base.metadata))


def detection(detection_id: str, **overrides: Any) -> DetectionRecord:
    values: dict[str, Any] = {
        "detection_id": detection_id,
        "timestamp": NOW,
        "detector": "tcp_port_scan",
        "category": "reconnaissance",
        "severity": "high",
        "confidence": 0.9,
        "title": "Port scan",
        "source_ip": "203.0.113.10",
        "recommended_action": "alert",
        "risk_score": 70.0,
    }
    values.update(overrides)
    return DetectionRecord(**values)


def incident_values(incident_id: str, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "incident_id": incident_id,
        "title": "Incident",
        "severity": "high",
        "risk_score": 80.0,
        "first_seen": NOW,
        "last_seen": NOW,
    }
    values.update(overrides)
    return values


def detection_payload(index: int, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "detection_id": f"det-{index:06d}",
        "timestamp": NOW.isoformat(),
        "detector": "tcp_port_scan",
        "category": "reconnaissance",
        "severity": "high",
        "confidence": 0.9,
        "title": "Port scan",
        "source_ip": f"203.0.113.{index % 250}",
        "recommended_action": "alert",
        "risk": {"score": 70.0, "band": "high"},
    }
    payload.update(overrides)
    return payload


def incident_payload(index: int, detection_ids: list[str]) -> dict[str, Any]:
    return {
        "incident_id": f"inc-{index:05d}",
        "title": "Correlated activity",
        "severity": "high",
        "risk": {"score": 85.0, "band": "high"},
        "first_seen": NOW.isoformat(),
        "last_seen": NOW.isoformat(),
        "detection_count": len(detection_ids),
        "linked_detection_ids": detection_ids,
    }


def decision_payload(index: int, detection_id: str) -> dict[str, Any]:
    return {
        "decision_id": f"dec-{index:06d}",
        "decided_at": NOW.isoformat(),
        "action": "alert",
        "target": "203.0.113.1",
        "reason": "test",
        "outcome": "simulated",
        "dry_run": True,
        "detection_id": detection_id,
    }


async def wait_until(condition: Callable[[], bool | Awaitable[bool]], within: float = 30.0) -> None:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        result = condition()
        if await result if isinstance(result, Awaitable) else result:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("condition not met in time")


class TcpProxy:
    """A cuttable TCP forwarder standing in for a network path to a service."""

    def __init__(self, target_host: str, target_port: int) -> None:
        self.target = (target_host, target_port)
        self.port = 0
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def cut(self) -> None:
        """Refuse new connections and reset existing ones."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
        for writer in list(self._writers):
            writer.transport.abort()
        self._writers.clear()
        if server is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 5)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(*self.target)
        except OSError:
            writer.transport.abort()
            return
        self._writers.update({writer, upstream_writer})

        async def pipe(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
            try:
                while data := await source.read(65536):
                    sink.write(data)
                    await sink.drain()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                sink.transport.abort()

        await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))
        self._writers.difference_update({writer, upstream_writer})


def proxied(url: str, proxy: TcpProxy) -> str:
    """``url`` with its host and port replaced by the proxy's."""
    scheme, rest = url.split("://", 1)
    credentials, _, location = rest.rpartition("@")
    path = location.split("/", 1)[1] if "/" in location else ""
    prefix = f"{credentials}@" if credentials else ""
    return f"{scheme}://{prefix}127.0.0.1:{proxy.port}/{path}"


def host_port(url: str, default: int) -> tuple[str, int]:
    location = url.split("://", 1)[1].rpartition("@")[2].split("/", 1)[0]
    host, _, port = location.partition(":")
    return host, int(port or default)


# ======================================================= 1. schema and migrations


@pytest.mark.parametrize("backend", BACKENDS)
async def test_migrated_schema_matches_models(backend: str, tmp_path: Path) -> None:
    async with empty_database(backend, tmp_path) as url:
        await migrate.upgrade(url)
        assert await migrate.current_revision(url) == migrate.head_revision()

        def reflect(connection: Connection) -> dict[str, Any]:
            inspector = inspect(connection)
            tables = [t for t in inspector.get_table_names() if t != "alembic_version"]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                indexes = {i["name"] for t in tables for i in inspector.get_indexes(t)}
                uniques = {u["name"] for t in tables for u in inspector.get_unique_constraints(t)}
            return {
                "diff": schema_differences(connection),
                "tables": set(tables),
                "indexes": indexes,
                "fks": {
                    (t, fk["referred_table"], (fk.get("options") or {}).get("ondelete"))
                    for t in tables
                    for fk in inspector.get_foreign_keys(t)
                },
                "checks": {c["name"] for t in tables for c in inspector.get_check_constraints(t)},
                "uniques": uniques,
            }

        schema = await run_sync(url, reflect)
        assert schema["diff"] == []
        assert schema["tables"] == set(Base.metadata.tables)
        model_indexes = {i.name for t in Base.metadata.tables.values() for i in t.indexes}
        expression_indexes = {"uq_users_username_lower"}
        if backend == "sqlite":
            # SQLite cannot reflect expression indexes: confirm it from the catalogue.
            rows = await run_sync(
                url,
                lambda c: c.exec_driver_sql(
                    "SELECT sql FROM sqlite_master WHERE name = 'uq_users_username_lower'"
                ).scalar(),
            )
            assert rows is not None and "lower(username)" in rows
            assert schema["indexes"] == model_indexes - expression_indexes
        else:
            # PostgreSQL also lists the index backing the unique constraint.
            assert schema["indexes"] == model_indexes | {"uq_response_actions_decision_id"}
        assert schema["fks"] == {
            ("detections", "incidents", "SET NULL"),
            ("refresh_tokens", "users", "CASCADE"),
        }
        assert schema["checks"] == {
            "ck_detections_confidence_range",
            "ck_detections_status_valid",
            "ck_incidents_risk_range",
            "ck_incidents_status_valid",
            "ck_replays_status_valid",
            "ck_users_role_valid",
        }
        assert schema["uniques"] == {"uq_response_actions_decision_id"}


@pytest.mark.parametrize("backend", BACKENDS)
async def test_constraints_reject_invalid_rows(backend: str, tmp_path: Path) -> None:
    async with migrated_database(backend, tmp_path) as database:

        async def rejected(*records: Any) -> None:
            with pytest.raises(IntegrityError):
                async with database.session() as session:
                    session.add_all(records)

        await rejected(detection("bad-confidence", confidence=1.5))
        await rejected(detection("bad-status", status="closed"))
        await rejected(IncidentRecord(**incident_values("bad-risk", risk_score=101)))
        await rejected(IncidentRecord(**incident_values("bad-status", status="done")))
        await rejected(ReplayRecord(replay_id="r", filename="f.pcap", status="paused"))
        await rejected(User(username="eve", password_hash="x", role="root"))
        await rejected(detection("orphan", incident_id="no-such-incident"))  # FK
        await rejected(RefreshToken(jti="t", user_id=999_999, expires_at=NOW))  # FK

        action = {
            "decision_id": "same",
            "decided_at": NOW,
            "action": "alert",
            "target": "t",
            "reason": "r",
            "outcome": "simulated",
            "executed": False,
            "dry_run": True,
        }
        async with database.session() as session:
            session.add(ResponseActionRecord(**action))
        await rejected(ResponseActionRecord(**action))
        async with database.session() as session:
            session.add(User(username="Mallory", password_hash="x", role="viewer"))
        await rejected(User(username="MALLORY", password_hash="x", role="viewer"))

        # ON DELETE SET NULL (detections) and CASCADE (refresh tokens).
        async with database.session() as session:
            await IncidentRepository(session).upsert(incident_values("inc-1"))
            session.add(detection("linked", incident_id="inc-1"))
            user = await UserRepository(session).add(
                User(username="carol", password_hash="x", role="analyst")
            )
            await UserRepository(session).store_refresh_token("jti-1", user.id, NOW)
        async with database.session() as session:
            await session.execute(
                delete(IncidentRecord).where(IncidentRecord.incident_id == "inc-1")
            )
            await session.execute(delete(User).where(User.username == "carol"))
        async with database.session() as session:
            linked = await DetectionRepository(session).get("linked")
            assert linked is not None and linked.incident_id is None
            assert await UserRepository(session).refresh_token("jti-1") is None


@pytest.mark.parametrize("backend", BACKENDS)
async def test_every_migration_downgrades_and_upgrades_again(backend: str, tmp_path: Path) -> None:
    async with empty_database(backend, tmp_path) as url:
        await migrate.upgrade(url)
        database = Database(StorageSettings(database_url=url))
        await database.connect(prepare_schema=False)
        async with database.session() as session:
            session.add(detection("kept"))
            session.add(
                ResponseActionRecord(
                    decision_id="d",
                    decided_at=NOW,
                    action="alert",
                    target="t",
                    reason="r",
                    outcome="simulated",
                    executed=False,
                    dry_run=True,
                    replay_id="replay-x",
                )
            )
        await database.close()

        def columns(table: str) -> Callable[[Connection], set[str]]:
            return lambda c: {col["name"] for col in inspect(c).get_columns(table)}

        await migrate.downgrade(url, "-1")
        assert await migrate.current_revision(url) == "a8829c9a233e"
        assert "sessions_ended_at" not in await run_sync(url, columns("users"))
        await migrate.downgrade(url, "-1")
        assert await migrate.current_revision(url) == migrate.INITIAL_REVISION
        assert "replay_id" not in await run_sync(url, columns("response_actions"))
        # Data outside the dropped column survives the downgrade.
        assert (
            await run_sync(
                url, lambda c: c.exec_driver_sql("SELECT count(*) FROM detections").scalar()
            )
            == 1
        )
        await migrate.downgrade(url, "-1")
        assert await migrate.current_revision(url) is None
        assert await run_sync(url, lambda c: set(inspect(c).get_table_names())) <= {
            "alembic_version"
        }
        await migrate.upgrade(url)
        assert await migrate.current_revision(url) == migrate.head_revision()
        assert await run_sync(url, schema_differences) == []


async def test_sqlite_file_created_from_current_models_is_adopted_on_start(
    tmp_path: Path,
) -> None:
    # Tables made by create_all from today's models, with no recorded revision.
    # Stamping it at the initial revision would re-add columns and fail start-up.
    url = f"sqlite+aiosqlite:///{tmp_path / 'create_all.db'}"
    engine = create_async_engine(url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    await engine.dispose()

    database = Database(StorageSettings(database_url=url))
    await database.connect()
    await database.close()
    assert await migrate.current_revision(url) == migrate.head_revision()


@requires_postgres
@pytest.mark.integration
async def test_unversioned_postgresql_database_is_adopted_by_db_upgrade(tmp_path: Path) -> None:
    async with empty_database("postgresql", tmp_path) as url:
        engine = create_async_engine(normalise_database_url(url))
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await engine.dispose()

        with pytest.raises(StorageError, match="sentinelx db upgrade"):
            await Database(StorageSettings(database_url=url)).connect()
        await migrate.upgrade(url)  # what `sentinelx db upgrade` runs
        assert await migrate.current_revision(url) == migrate.head_revision()
        database = Database(StorageSettings(database_url=url))
        await database.connect()
        await database.close()


@requires_postgres
@pytest.mark.integration
async def test_postgresql_create_schema_records_the_revision(tmp_path: Path) -> None:
    async with empty_database("postgresql", tmp_path) as url:
        database = Database(StorageSettings(database_url=url))
        await database.connect(create_schema=True)
        await database.close()
        assert await migrate.current_revision(url) == migrate.head_revision()
        await database.connect()  # a normal start afterwards is accepted
        await database.close()


# ============================================================ 2. CRUD and sessions


@pytest.mark.parametrize("backend", BACKENDS)
async def test_repository_crud_round_trip(backend: str, tmp_path: Path) -> None:
    async with migrated_database(backend, tmp_path) as database:
        # users and refresh tokens
        async with database.session() as session:
            users = UserRepository(session)
            user = await users.add(User(username="Dana", password_hash="h", role="analyst"))
            assert await users.record_failed_login(user.id) == 1
            assert await users.record_failed_login(user.id) == 2
            await users.store_refresh_token("r1", user.id, NOW + timedelta(days=1))
            await users.store_refresh_token("r2", user.id, NOW + timedelta(days=1))
            user_id = user.id
        async with database.session() as session:
            users = UserRepository(session)
            assert (await users.by_username("dana")) is not None
            assert await users.claim_refresh_token("r1") is True
            assert await users.claim_refresh_token("r1") is False  # single use
            await users.end_sessions(user_id)
        async with database.session() as session:
            users = UserRepository(session)
            assert await users.refresh_token("r1") is not None  # rotated: kept
            assert await users.refresh_token("r2") is None  # unused: deleted

        # detections and incidents: create, triage, assign, close
        async with database.session() as session:
            incidents = IncidentRepository(session)
            await incidents.upsert(incident_values("inc"))
            session.add_all([detection("d1"), detection("d2")])
            await session.flush()
            await DetectionRepository(session).link_incident(["d1", "d2"], "inc")
        async with database.session() as session:
            record = await IncidentRepository(session).get("inc")
            assert record is not None
            record.status, record.assigned_to, record.notes = "investigating", "dana", "on it"
            await DetectionRepository(session).set_status("d1", "acknowledged", "dana")
        async with database.session() as session:
            # The engine updating the incident must not overwrite analyst fields.
            await IncidentRepository(session).upsert(
                incident_values("inc", risk_score=95.0, status="open", assigned_to=None)
            )
        async with database.session() as session:
            record = await IncidentRepository(session).get("inc")
            assert record is not None
            assert (record.status, record.assigned_to, record.risk_score) == (
                "investigating",
                "dana",
                95.0,
            )
            record.status = "resolved"
            linked = await IncidentRepository(session).detections("inc")
            assert [d.detection_id for d in linked] == ["d1", "d2"]
            d1 = await DetectionRepository(session).get("d1")
            assert d1 is not None and d1.status == "acknowledged" and d1.reviewed_by == "dana"
        async with database.session() as session:
            closed = await IncidentRepository(session).page(statuses=["resolved"])
            assert closed.total == 1

        # response actions and blocks
        async with database.session() as session:
            actions = ResponseActionRepository(session)
            for index, action in enumerate(["alert", "block_ip", "block_ip"]):
                await actions.add(
                    ResponseActionRecord(
                        decision_id=f"a{index}",
                        decided_at=NOW + timedelta(seconds=index),
                        action=action,
                        target="203.0.113.7",
                        reason="r",
                        outcome="executed",
                        executed=True,
                        dry_run=False,
                        incident_id="inc" if index == 2 else None,
                        detection_id="d1" if index == 1 else None,
                    )
                )
            blocks = BlockRepository(session)
            await blocks.record_block(
                "203.0.113.7/32", reason="scan", expires_at=None, rate_limited=False, backend="mem"
            )
            await blocks.record_block(
                "203.0.113.7/32", reason="again", expires_at=None, rate_limited=False, backend="mem"
            )
        async with database.session() as session:
            actions = ResponseActionRepository(session)
            assert (await actions.page()).total == 2  # alerts excluded by default
            assert (await actions.page(include_alerts=True)).total == 3
            assert (await actions.page(incident_id="inc", detection_ids=["d1"])).total == 2
            blocks = BlockRepository(session)
            active = await blocks.active()
            assert [b.reason for b in active] == ["again"]
            assert (await blocks.history()).total == 2
            assert await blocks.deactivate("203.0.113.7/32", removal_reason="manual") == 1
        async with database.session() as session:
            assert await BlockRepository(session).active() == []

        # audit, settings, replays, rules
        await AuditService(database).record(actor="dana", action="close_incident", target="inc")
        async with database.session() as session:
            page = await AuditRepository(session).page(actor="dana")
            assert page.total == 1 and page.items[0].action == "CLOSE_INCIDENT"
            settings = SettingRepository(session)
            await settings.set("response", {"dry_run": True}, "dana")
        async with database.session() as session:
            await SettingRepository(session).set("response", {"dry_run": False}, "admin")
            await ReplayRepository(session).add(ReplayRecord(replay_id="rp", filename="x.pcap"))
            rules = RuleRepository(session)
            await rules.upsert("rule-1", name="R", definition="id: rule-1", origin="api")
            await rules.upsert("rule-1", name="Renamed", definition="id: rule-1")
        async with database.session() as session:
            assert await SettingRepository(session).all() == {"response": {"dry_run": False}}
            replay = await ReplayRepository(session).get("rp")
            assert replay is not None and replay.status == "queued"
            replay.status = "completed"
            assert [r.name for r in await RuleRepository(session).all()] == ["Renamed"]
            assert await RuleRepository(session).delete("rule-1") is True
        async with database.session() as session:
            assert [r.status for r in await ReplayRepository(session).recent()] == ["completed"]
            assert await RuleRepository(session).all() == []


@pytest.mark.parametrize("backend", BACKENDS)
async def test_exception_inside_session_rolls_back(backend: str, tmp_path: Path) -> None:
    async with migrated_database(backend, tmp_path) as database:
        with pytest.raises(RuntimeError):
            async with database.session() as session:
                session.add(detection("rolled-back"))
                await session.flush()  # the row reached the database inside the transaction
                raise RuntimeError("boom")
        async with database.session() as session:
            assert await DetectionRepository(session).get("rolled-back") is None


@pytest.mark.parametrize("backend", BACKENDS)
async def test_concurrent_sessions_do_not_deadlock(backend: str, tmp_path: Path) -> None:
    async with migrated_database(backend, tmp_path) as database:
        async with database.session() as session:
            await IncidentRepository(session).upsert(incident_values("shared"))
            session.add_all([detection(f"c{i}") for i in range(50)])

        async def work(index: int) -> None:
            async with database.session() as session:
                await DetectionRepository(session).set_status(f"c{index}", "acknowledged", "x")
                await DetectionRepository(session).link_incident([f"c{index}"], "shared")
                await IncidentRepository(session).upsert(
                    incident_values("shared", detection_count=index)
                )
                await AuditRepository(session).page(limit=5)

        await asyncio.wait_for(asyncio.gather(*(work(i) for i in range(50))), timeout=60)
        async with database.session() as session:
            assert len(await IncidentRepository(session).detections("shared")) == 50


@requires_postgres
@pytest.mark.integration
async def test_pool_limits_hold_and_connections_return_to_idle(tmp_path: Path) -> None:
    pool_size, max_overflow = 4, 3
    async with migrated_database(
        "postgresql", tmp_path, pool_size=pool_size, max_overflow=max_overflow
    ) as database:
        pool: Any = database.engine.pool
        assert pool.size() == pool_size and pool._max_overflow == max_overflow
        dbname = database.url.rsplit("/", 1)[1]
        assert POSTGRES_URL
        observer = create_async_engine(normalise_database_url(POSTGRES_URL))

        async def connections() -> tuple[int, int]:
            async with observer.connect() as connection:
                row = (
                    await connection.execute(
                        text(
                            "SELECT count(*), count(*) FILTER (WHERE state <> 'idle') "
                            "FROM pg_stat_activity WHERE datname = :name"
                        ),
                        {"name": dbname},
                    )
                ).one()
                return int(row[0]), int(row[1])

        for index in range(500):
            async with database.session() as session:
                await session.execute(text("SELECT 1"))
                if index % 50 == 0:
                    session.add(detection(f"seq-{index}"))
        assert pool.checkedout() == 0
        assert (await connections())[0] <= pool_size

        peak = 0
        stop = asyncio.Event()

        async def sample() -> None:
            nonlocal peak
            while not stop.is_set():
                peak = max(peak, (await connections())[0])
                await asyncio.sleep(0.01)

        async def work(index: int) -> None:
            async with database.session() as session:
                session.add(detection(f"con-{index}"))
                await session.flush()
                await session.execute(text("SELECT pg_sleep(0.05)"))

        sampler = asyncio.create_task(sample())
        await asyncio.gather(*(work(i) for i in range(50)))
        stop.set()
        await sampler
        assert 0 < peak <= pool_size + max_overflow
        assert pool.checkedout() == 0
        total, busy = await connections()
        print(f"\npool: peak={peak} after: total={total} busy={busy}")
        assert total <= pool_size and busy == 0  # overflow closed, the rest idle
        await observer.dispose()


# ==================================================== 3. security event persistence


async def publish_paced(bus: EventBus, events: list[tuple[EventType, dict[str, Any]]]) -> None:
    # The pipeline awaits between publishes; so do we, letting the handler run.
    for event_type, payload in events:
        await bus.publish(event_type, payload)
        await asyncio.sleep(0)


def burst(
    count: int, *, start: int = 0, per_incident: int = 100
) -> list[tuple[EventType, dict[str, Any]]]:
    events: list[tuple[EventType, dict[str, Any]]] = []
    ids: list[str] = []
    for index in range(start, start + count):
        payload = detection_payload(index)
        events.append((EventType.DETECTION_CREATED, payload))
        ids.append(payload["detection_id"])
        if len(ids) == per_incident:
            events.append(
                (EventType.INCIDENT_OPENED, incident_payload(index // per_incident, list(ids)))
            )
            events.append((EventType.RESPONSE_DECIDED, decision_payload(index, ids[-1])))
            ids.clear()
    return events


async def stored_counts(database: Database) -> dict[str, int]:
    async with database.session() as session:
        detections = await session.scalar(select(func.count()).select_from(DetectionRecord))
        distinct = await session.scalar(
            select(func.count(func.distinct(DetectionRecord.detection_id)))
        )
        linked = await session.scalar(
            select(func.count())
            .select_from(DetectionRecord)
            .where(DetectionRecord.incident_id.is_not(None))
        )
        incidents = await session.scalar(select(func.count()).select_from(IncidentRecord))
        actions = await session.scalar(select(func.count()).select_from(ResponseActionRecord))
    return {
        "detections": int(detections or 0),
        "distinct": int(distinct or 0),
        "linked": int(linked or 0),
        "incidents": int(incidents or 0),
        "actions": int(actions or 0),
    }


@pytest.mark.parametrize("backend", BACKENDS)
async def test_burst_of_5000_detections_is_stored_exactly_once(
    backend: str, tmp_path: Path
) -> None:
    async with migrated_database(backend, tmp_path) as database:
        settings = Settings(storage={"batch_size": 200, "flush_interval_seconds": 0.2})
        bus = EventBus()
        await bus.start()
        persister = EventPersister(database, bus, settings)
        await persister.start()
        events = burst(5000)
        await publish_paced(bus, events)
        # Duplicates (a re-published detection) must not create a second row.
        await publish_paced(bus, events[:50])
        await bus.drain(wait_seconds=60)
        assert await persister.flush()
        await persister.stop()
        await bus.stop()

        assert bus.stats()["dropped"] == 0
        assert persister.failed_batches == 0 and persister.dropped == 0 and persister.pending == 0
        counts = await stored_counts(database)
        assert counts == {
            "detections": 5000,
            "distinct": 5000,
            "linked": 5000,
            "incidents": 50,
            "actions": 50,
        }
        async with database.session() as session:
            linked = await IncidentRepository(session).detections("inc-00007")
            assert [d.detection_id for d in linked] == [f"det-{i:06d}" for i in range(700, 800)]


@pytest.mark.parametrize("backend", BACKENDS)
async def test_bad_event_is_rejected_alone(backend: str, tmp_path: Path) -> None:
    async with migrated_database(backend, tmp_path) as database:
        settings = Settings(storage={"batch_size": 64, "flush_interval_seconds": 0.1})
        bus = EventBus()
        await bus.start()
        persister = EventPersister(database, bus, settings)
        await persister.start()
        events = [(EventType.DETECTION_CREATED, detection_payload(i)) for i in range(100)]
        events[37] = (EventType.DETECTION_CREATED, detection_payload(37, confidence=7.0))
        with captured_logs() as logs:
            await publish_paced(bus, events)
            await bus.drain(wait_seconds=30)
            await persister.flush()
        await persister.stop()
        await bus.stop()
        assert persister.rejected == 1 and persister.written == 99
        assert (await stored_counts(database))["detections"] == 99
        rejected = [log for log in logs if log["event"] == "persist_event_rejected"]
        assert (
            rejected and rejected[0]["key"] == "det-000037" and rejected[0]["log_level"] == "error"
        )


@requires_postgres
@pytest.mark.integration
async def test_detections_survive_a_database_outage(tmp_path: Path) -> None:
    async with empty_database("postgresql", tmp_path) as url:
        await migrate.upgrade(url)
        proxy = TcpProxy(*host_port(url, 5432))
        await proxy.start()
        database = Database(StorageSettings(database_url=proxied(url, proxy)))
        await database.connect()
        settings = Settings(storage={"batch_size": 50, "flush_interval_seconds": 0.1})
        bus = EventBus()
        await bus.start()
        persister = EventPersister(database, bus, settings, max_backoff_seconds=0.5)
        await persister.start()
        try:
            await publish_paced(bus, burst(300))
            await bus.drain(wait_seconds=30)
            await wait_until(lambda: persister.pending == 0)
            assert (await stored_counts(database))["detections"] == 300

            await proxy.cut()
            with captured_logs() as logs:
                await publish_paced(bus, burst(700, start=300))
                await bus.drain(wait_seconds=30)
                await wait_until(lambda: persister.failed_batches > 0 and persister.retrying)
                await asyncio.sleep(1.0)  # several retries against a dead database
            assert persister.pending == 714 and persister.dropped == 0
            assert any(log["event"] == "persist_batch_failed_will_retry" for log in logs)
            assert bus.stats()["dropped"] == 0

            await proxy.start()  # the database comes back on the same address
            await wait_until(lambda: persister.pending == 0 and not persister.retrying, within=60)
        finally:
            await persister.stop()
            await bus.stop()
            await database.close()
            await proxy.cut()

        verify = Database(StorageSettings(database_url=url))
        await verify.connect()
        counts = await stored_counts(verify)
        await verify.close()
        assert counts == {
            "detections": 1000,
            "distinct": 1000,
            "linked": 1000,
            "incidents": 10,
            "actions": 10,
        }
        assert persister.rejected == 0 and persister.dropped == 0


async def test_outage_buffer_is_bounded_and_every_drop_is_counted(tmp_path: Path) -> None:
    async with migrated_database("sqlite", tmp_path) as database:
        settings = Settings(storage={"batch_size": 10, "flush_interval_seconds": 0.05})
        bus = EventBus()
        persister = EventPersister(
            database, bus, settings, max_pending=100, max_backoff_seconds=0.1
        )

        async def unavailable(batch: Any) -> None:
            raise ConnectionRefusedError("database down")

        persister._write = unavailable  # type: ignore[method-assign]
        before = metrics.events_dropped.labels(target="persister")._value.get()
        with captured_logs() as logs:
            for index in range(150):
                await persister._enqueue(
                    bus_event(EventType.DETECTION_CREATED, detection_payload(index))
                )
            assert await persister.flush() is False
        assert persister.pending == 100 and persister.dropped == 50
        assert metrics.events_dropped.labels(target="persister")._value.get() - before == 50
        assert any(
            log["event"] == "persist_buffer_full_event_dropped" and log["log_level"] == "error"
            for log in logs
        )
        # The oldest were shed; the newest are still queued, in order.
        assert persister._pending[0].payload["detection_id"] == "det-000050"
        persister.stop_timeout_seconds = 1.0
        started = time.monotonic()
        with captured_logs() as logs:
            await persister.stop()
        assert time.monotonic() - started < 5
        assert any(log["event"] == "persister_stopped_with_unwritten_events" for log in logs)


def bus_event(event_type: EventType, payload: dict[str, Any]) -> Any:
    from sentinelx.events.bus import Event

    return Event(type=event_type, payload=payload)


# ================================================================ 4. query counts


class StatementCounter:
    def __init__(self, database: Database) -> None:
        self.count = 0
        self._engine = database.engine.sync_engine
        event.listen(self._engine, "before_cursor_execute", self._on_execute)

    def _on_execute(self, *_: Any) -> None:
        self.count += 1

    async def measure(self, operation: Callable[[], Awaitable[Any]]) -> int:
        start = self.count
        await operation()
        return self.count - start


@pytest.mark.parametrize("backend", BACKENDS)
async def test_list_queries_do_not_grow_with_row_count(backend: str, tmp_path: Path) -> None:
    async with migrated_database(backend, tmp_path) as database:
        pipeline = SimpleNamespace(
            risk=SimpleNamespace(source_summary=lambda _ip: {}),
            detection=SimpleNamespace(stats=lambda: {"per_detector": {}}),
        )
        queries = QueryService(database, pipeline)  # type: ignore[arg-type]
        counter = StatementCounter(database)
        since = NOW - timedelta(days=1)

        async def seed(start: int, stop: int) -> None:
            async with database.session() as session:
                await IncidentRepository(session).upsert(incident_values("big"))
                for index in range(start, stop):
                    session.add(
                        detection(
                            f"n{index}",
                            source_ip=f"198.51.100.{index % 200}",
                            incident_id="big",
                            timestamp=NOW - timedelta(seconds=index),
                        )
                    )
                    session.add(IncidentRecord(**incident_values(f"i{index}")))
                    session.add(
                        ResponseActionRecord(
                            decision_id=f"q{index}",
                            decided_at=NOW,
                            action="block_ip",
                            target="t",
                            reason="r",
                            outcome="simulated",
                            executed=False,
                            dry_run=True,
                            detection_id=f"n{index}",
                        )
                    )
                    await BlockRepository(session).record_block(
                        f"198.51.100.{index}/32",
                        reason="r",
                        expires_at=None,
                        rate_limited=False,
                        backend="m",
                    )
            audit = AuditService(database)
            for index in range(start, stop):
                await audit.record(actor="a", action="x", target=str(index))

        async def in_session(fn: Callable[[Any], Awaitable[Any]]) -> Any:
            async with database.session() as session:
                return await fn(session)

        operations: dict[str, Callable[[], Awaitable[Any]]] = {
            "detections page": lambda: queries.detections(
                DetectionFilter(), limit=500, offset=0, order="newest"
            ),
            "incidents page": lambda: queries.incidents(limit=500),
            "incident with detections": lambda: queries.incident("big"),
            "threats (top sources)": lambda: queries.threats(since=since),
            "analytics": lambda: queries.analytics(hours=24),
            "audit page": lambda: queries.audit(limit=500),
            "actions page": lambda: queries.actions(limit=500),
            "block history": lambda: in_session(lambda s: BlockRepository(s).history(limit=500)),
            "analytics summary": lambda: in_session(
                lambda s: AnalyticsRepository(s).summary(since)
            ),
        }

        await seed(0, 20)
        small = {name: await counter.measure(op) for name, op in operations.items()}
        await seed(20, 200)
        large = {name: await counter.measure(op) for name, op in operations.items()}
        async with database.session() as session:
            assert len(await IncidentRepository(session).detections("big")) == 200
        print(f"\nstatements per call ({backend}): 20 rows={small} 200 rows={large}")
        assert large == small, {"20 rows": small, "200 rows": large}


# ======================================================================= 5. Redis


@pytest.fixture
async def redis_client() -> AsyncIterator[Any]:
    import redis.asyncio as redis

    assert REDIS_URL
    client = redis.from_url(REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    yield client
    await client.aclose()


@requires_redis
@pytest.mark.integration
async def test_every_redis_key_expires_and_single_use_values_are_single_use(
    redis_client: Any,
) -> None:
    namespace = f"sx-matrix-{uuid.uuid4().hex[:8]}"
    state = SharedState(StorageSettings(redis_url=REDIS_URL or "", redis_namespace=namespace))
    await state.connect()
    assert not state.degraded
    try:
        for _ in range(4):
            await state.hit("login", "192.0.2.1", limit=3, window_seconds=60)
        allowed, remaining, retry = await state.hit(
            "login", "192.0.2.1", limit=3, window_seconds=60
        )
        assert (allowed, remaining) == (False, 0) and 0 < retry <= 60
        assert await state.count("login-fail", "nobody|192.0.2.1", window_seconds=900) == (0, 0.0)
        for _ in range(5):
            await state.hit("login-fail", "eve|192.0.2.1", limit=5, window_seconds=900)
        failures, wait = await state.count("login-fail", "eve|192.0.2.1", window_seconds=900)
        assert failures == 5 and 0 < wait <= 900
        await state.cache_set("sessions-ended:7", 1_700_000_000, 900)
        await state.cache_set("wsticket:abc", {"user_id": 7}, 30)
        assert await state.cache_get("sessions-ended:7") == 1_700_000_000
        # Two redemptions racing: exactly one gets the ticket.
        results = await asyncio.gather(*(state.cache_pop("wsticket:abc") for _ in range(10)))
        assert [r for r in results if r is not None] == [{"user_id": 7}]

        received: list[dict[str, Any]] = []

        async def listen() -> None:
            async for message in state.subscribe("events"):
                received.append(message)
                return

        listener = asyncio.create_task(listen())
        await asyncio.sleep(0.2)
        await state.publish("events", {"n": 1})
        await asyncio.wait_for(listener, 5)
        assert received == [{"n": 1}]

        keys = [key async for key in redis_client.scan_iter(f"{namespace}:*")]
        assert keys, "expected keys to be written"
        ttls = {key: await redis_client.ttl(key) for key in keys}
        assert all(ttl > 0 for ttl in ttls.values()), ttls

        await state.reset("login", "192.0.2.1")
        assert not await redis_client.exists(f"{namespace}:rl:login:192.0.2.1")
    finally:
        async for key in redis_client.scan_iter(f"{namespace}:*"):
            await redis_client.delete(key)
        await state.close()


@requires_redis
@pytest.mark.integration
async def test_redis_outage_degrades_then_reconnects_without_losing_revocations(
    redis_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(redis_state, "_RETRY_SECONDS", 0.5)
    proxy = TcpProxy(*host_port(REDIS_URL or "", 6379))
    await proxy.start()
    namespace = f"sx-outage-{uuid.uuid4().hex[:8]}"
    state = SharedState(
        StorageSettings(redis_url=proxied(REDIS_URL or "", proxy), redis_namespace=namespace)
    )
    try:
        await state.connect()
        assert not degraded(state) and (await state.health())["ok"]

        await proxy.cut()
        with captured_logs() as logs:
            allowed, _, _ = await state.hit("api", "client", limit=10, window_seconds=60)
            assert allowed  # requests keep working
            assert degraded(state)
            assert (await state.health())["degraded"] is True
            # A revocation made during the outage.
            await state.cache_set("revoked-access:tok", True, 900)
            assert await state.cache_get("revoked-access:tok") is True
        assert any(
            log["event"] == "redis_operation_failed_degrading" and log["log_level"] == "warning"
            for log in logs
        )

        await proxy.start()
        started = time.monotonic()
        # Health checks alone reconnect; no request traffic is needed.
        await wait_until(lambda: _healthy(state), within=15)
        assert time.monotonic() - started < 5
        assert not state.degraded
        # The revocation made while degraded is now visible to every worker.
        assert await redis_client.get(f"{namespace}:cache:revoked-access:tok") == "true"
        assert 0 < await redis_client.ttl(f"{namespace}:cache:revoked-access:tok") <= 900
        assert await state.cache_get("revoked-access:tok") is True
    finally:
        async for key in redis_client.scan_iter(f"{namespace}:*"):
            await redis_client.delete(key)
        await state.close()
        await proxy.cut()


def degraded(state: SharedState) -> bool:
    return state.degraded


async def _healthy(state: SharedState) -> bool:
    return bool((await state.health())["ok"])
