"""Storage tests.

Run against SQLite always. Set SENTINELX_TEST_POSTGRES_URL / SENTINELX_TEST_REDIS_URL
(``make test-integration`` does this with docker compose) to run the same tests
against real PostgreSQL and Redis.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from sentinelx.config.settings import Settings, StorageSettings
from sentinelx.events.bus import EventBus
from sentinelx.firewall import MemoryFirewall
from sentinelx.pipeline import Pipeline
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database, normalise_database_url
from sentinelx.storage.models import AuditEvent, DetectionRecord, User
from sentinelx.storage.persister import EventPersister
from sentinelx.storage.redis_state import SharedState
from sentinelx.storage.repositories import (
    AnalyticsRepository,
    AuditRepository,
    DetectionFilter,
    DetectionRepository,
    IncidentRepository,
    RetentionRepository,
    UserRepository,
)
from sentinelx.testing import get_scenario

POSTGRES_URL = os.environ.get("SENTINELX_TEST_POSTGRES_URL")
REDIS_URL = os.environ.get("SENTINELX_TEST_REDIS_URL")

BACKENDS = [pytest.param("sqlite+aiosqlite:///:memory:", id="sqlite")]
if POSTGRES_URL:
    BACKENDS.append(pytest.param(POSTGRES_URL, id="postgresql", marks=pytest.mark.integration))


@pytest.fixture(params=BACKENDS)
async def database(request: pytest.FixtureRequest) -> AsyncIterator[Database]:
    url = request.param
    db = Database(StorageSettings(database_url=url))
    if url.startswith("postgresql"):
        from sentinelx.storage.migrate import upgrade

        await db.connect(create_schema=False)
        async with db.engine.begin() as connection:
            await connection.execute(text("DROP SCHEMA public CASCADE"))
            await connection.execute(text("CREATE SCHEMA public"))
        await upgrade(url)  # the real migration path, not create_all
    else:
        await db.connect()
    yield db
    await db.close()


def test_url_normalisation() -> None:
    assert normalise_database_url("postgres://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"
    assert normalise_database_url("sqlite:///x.db") == "sqlite+aiosqlite:///x.db"
    assert "p@ss" not in Database(StorageSettings(database_url="postgresql://u:p@ss@h/db")).safe_url


async def test_unreachable_database_error_hides_password() -> None:
    from sentinelx.common.errors import StorageError

    db = Database(StorageSettings(database_url="postgresql://user:topsecret@127.0.0.1:1/none"))
    with pytest.raises(StorageError) as excinfo:
        await db.connect()
    assert "topsecret" not in str(excinfo.value)


async def test_usernames_are_unique_case_insensitively(database: Database) -> None:
    async with database.session() as session:
        repo = UserRepository(session)
        await repo.add(User(username="alice", password_hash="x", role="admin"))
        await repo.add(User(username="bob", password_hash="x", role="viewer"))
    with pytest.raises(IntegrityError):
        async with database.session() as session:
            await UserRepository(session).add(User(username="ALICE", password_hash="x", role="viewer"))
    async with database.session() as session:
        assert (await UserRepository(session).by_username("Alice")) is not None
        assert await UserRepository(session).count() == 2


async def run_pipeline_with_persistence(database: Database, scenario: str, replay_id: str | None = None) -> EventPersister:
    settings = Settings()
    bus = EventBus()
    persister = EventPersister(database, bus, settings)
    pipeline = Pipeline(settings, bus=bus, firewall=MemoryFirewall(), audit=AuditService(database, bus).sink)
    pipeline.response.guard._local_addresses = lambda: set()
    pipeline.replay_id = replay_id
    await pipeline.start()
    await persister.start()
    from sentinelx.capture import MockCapture

    await pipeline.run(MockCapture(get_scenario(scenario).frames))
    await asyncio.sleep(0.1)  # let the handler worker drain
    await persister.stop()
    await pipeline.stop()
    return persister


async def test_pipeline_events_are_persisted_and_linked(database: Database) -> None:
    persister = await run_pipeline_with_persistence(database, "mixed_intrusion")
    assert persister.failed_batches == 0
    async with database.session() as session:
        page = await DetectionRepository(session).page(DetectionFilter(), limit=100)
        assert page.total >= 3
        detection = page.items[0]
        assert detection.evidence and detection.risk["rationale"]
        incidents = await IncidentRepository(session).page()
        assert incidents.total == 1
        incident = incidents.items[0]
        assert incident.title == "Potential host compromise attempt"
        linked = await IncidentRepository(session).detections(incident.incident_id)
        assert len(linked) == incident.detection_count


async def test_replay_data_is_isolated_from_live_views(database: Database) -> None:
    await run_pipeline_with_persistence(database, "tcp_port_scan", replay_id="replay-1")
    async with database.session() as session:
        repo = DetectionRepository(session)
        assert (await repo.page(DetectionFilter())).total == 0
        assert (await repo.page(DetectionFilter(replay_id="replay-1"))).total >= 1
        assert (await AnalyticsRepository(session).summary(datetime.now(UTC) - timedelta(days=3650)))["detections"] == 0


async def test_detection_filters_and_like_escaping(database: Database) -> None:
    now = datetime.now(UTC)
    async with database.session() as session:
        for index, (severity, title) in enumerate([("high", "100% match"), ("low", "100 matches"), ("critical", "scan")]):
            session.add(DetectionRecord(
                detection_id=f"d{index}", timestamp=now - timedelta(minutes=index), detector="tcp_port_scan",
                category="reconnaissance", severity=severity, confidence=0.9, title=title, source_ip=f"203.0.113.{index}",
                recommended_action="alert", risk_score=50 + index * 20,
            ))
    async with database.session() as session:
        repo = DetectionRepository(session)
        assert (await repo.page(DetectionFilter(search="100%"))).total == 1  # % is literal, not a wildcard
        assert (await repo.page(DetectionFilter(severities=["high", "critical"]))).total == 2
        assert (await repo.page(DetectionFilter(min_risk=80))).total == 1
        assert (await repo.page(DetectionFilter(source_ip="203.0.113.1"))).items[0].title == "100 matches"
        assert (await repo.page(DetectionFilter(), limit=10_000)).limit == 500
        await repo.set_status("d0", "false_positive", "analyst")
    async with database.session() as session:
        summary = await AnalyticsRepository(session).summary(now - timedelta(days=1))
        assert summary["false_positives"] == 1 and summary["false_positive_rate"] == 1.0
        timeline = await AnalyticsRepository(session).timeline(now - timedelta(days=1), 60, database.dialect)
        assert sum(bucket["total"] for bucket in timeline) == 3


async def test_audit_redacts_secrets_and_orders_newest_first(database: Database) -> None:
    audit = AuditService(database)
    await audit.record(actor="admin", action="change_settings", details={"jwt_secret": "s3cr3t", "field": "dry_run"})
    await audit.record(actor="admin", action="block_ip", target="203.0.113.5", reason="scan", source="dashboard")
    async with database.session() as session:
        page = await AuditRepository(session).page()
        assert [event.action for event in page.items] == ["BLOCK_IP", "CHANGE_SETTINGS"]
        assert page.items[1].details["jwt_secret"] == "[redacted]"
        assert (await AuditRepository(session).page(action="block_ip")).items[0].target == "203.0.113.5"


async def test_retention_purges_old_data_but_keeps_open_incidents_and_recent_audit(database: Database) -> None:
    old = datetime.now(UTC) - timedelta(days=90)
    async with database.session() as session:
        session.add(DetectionRecord(detection_id="old", timestamp=old, detector="d", category="other", severity="low",
                                    confidence=0.5, title="t", source_ip="1.1.1.1", recommended_action="alert"))
        session.add(DetectionRecord(detection_id="new", timestamp=datetime.now(UTC), detector="d", category="other",
                                    severity="low", confidence=0.5, title="t", source_ip="1.1.1.1", recommended_action="alert"))
        session.add(AuditEvent(actor="a", action="X", timestamp=old))
        await IncidentRepository(session).upsert({"incident_id": "open-old", "title": "t", "severity": "high", "risk_score": 90,
                                                  "first_seen": old, "last_seen": old, "status": "open"})
    async with database.session() as session:
        purged = await RetentionRepository(session).purge(retention_days=30, audit_days=365, metrics_days=7)
    assert purged["detections"] == 1 and purged["audit_events"] == 0 and purged["incidents"] == 0
    async with database.session() as session:
        assert (await DetectionRepository(session).get("new")) is not None
        assert (await IncidentRepository(session).get("open-old")) is not None


class TestSharedState:
    async def test_degraded_mode_when_redis_unreachable(self) -> None:
        state = SharedState(StorageSettings(redis_url="redis://127.0.0.1:1/0"))
        await state.connect()
        assert state.degraded
        results = [await state.hit("login", "1.2.3.4", limit=3, window_seconds=60) for _ in range(5)]
        assert [allowed for allowed, _, _ in results] == [True, True, True, False, False]
        assert results[-1][2] > 0
        await state.cache_set("k", {"a": 1}, 60)
        assert await state.cache_get("k") == {"a": 1}
        assert (await state.health())["degraded"] is True

    async def test_required_redis_refuses_to_start(self) -> None:
        from sentinelx.common.errors import StorageError

        with pytest.raises(StorageError):
            await SharedState(StorageSettings(redis_url="redis://127.0.0.1:1/0", redis_required=True)).connect()

    async def test_sliding_window_expires(self) -> None:
        clock = [1000.0]
        state = SharedState(StorageSettings(redis_url="redis://127.0.0.1:1/0"), clock=lambda: clock[0])
        await state.connect()
        for _ in range(3):
            await state.hit("api", "x", limit=3, window_seconds=10)
        assert not (await state.hit("api", "x", limit=3, window_seconds=10))[0]
        clock[0] += 11
        assert (await state.hit("api", "x", limit=3, window_seconds=10))[0]

    @pytest.mark.integration
    @pytest.mark.skipif(not REDIS_URL, reason="SENTINELX_TEST_REDIS_URL not set")
    async def test_real_redis_limits_are_shared_between_instances(self) -> None:
        settings = StorageSettings(redis_url=REDIS_URL or "", redis_namespace="sentinelx-test")
        first, second = SharedState(settings), SharedState(settings)
        await first.connect()
        await second.connect()
        assert not first.degraded and not second.degraded
        await first.reset("login", "shared")
        for _ in range(2):
            await first.hit("login", "shared", limit=3, window_seconds=60)
        await second.hit("login", "shared", limit=3, window_seconds=60)
        allowed, remaining, _ = await second.hit("login", "shared", limit=3, window_seconds=60)
        assert not allowed and remaining == 0  # a limit spanning two "workers"
        await first.cache_set("shared", [1, 2], 30)
        assert await second.cache_get("shared") == [1, 2]
        await first.reset("login", "shared")
        await first.close()
        await second.close()
