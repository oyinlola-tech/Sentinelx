"""Data access.

Every query is built with SQLAlchemy expressions and bound parameters; no SQL text
is ever assembled from input.  Free-text search escapes ``%`` and ``_`` so a search
for ``100%`` means the literal string.

Repositories take a session and never commit - the caller's unit of work does, via
:meth:`sentinelx.storage.database.Database.session`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.storage.models import (
    AuditEvent,
    BlockRecord,
    DetectionRecord,
    IncidentRecord,
    RefreshToken,
    ReplayRecord,
    ResponseActionRecord,
    RuleRecord,
    SettingRecord,
    SystemMetric,
    TrafficSummary,
    User,
)

__all__ = [
    "AnalyticsRepository",
    "AuditRepository",
    "BlockRepository",
    "DetectionFilter",
    "DetectionRepository",
    "IncidentRepository",
    "Page",
    "ReplayRepository",
    "ResponseActionRepository",
    "RetentionRepository",
    "RuleRepository",
    "SettingRepository",
    "TelemetryRepository",
    "UserRepository",
]

MAX_PAGE_SIZE = 500


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _clamp(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, MAX_PAGE_SIZE)), max(0, offset)


@dataclass(slots=True)
class Page[T]:
    items: list[T]
    total: int
    limit: int
    offset: int


# ====================================================================== users


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, user_id: int) -> User | None:
        return await self.session.get(User, user_id)

    async def by_username(self, username: str) -> User | None:
        result = await self.session.execute(select(User).where(func.lower(User.username) == username.lower()))
        return result.scalar_one_or_none()

    async def count(self) -> int:
        return int(await self.session.scalar(select(func.count()).select_from(User)) or 0)

    async def list(self) -> list[User]:
        return list((await self.session.execute(select(User).order_by(User.username))).scalars())

    async def add(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        return user

    async def delete(self, user: User) -> None:
        await self.session.delete(user)

    async def store_refresh_token(self, jti: str, user_id: int, expires_at: datetime) -> None:
        self.session.add(RefreshToken(jti=jti, user_id=user_id, expires_at=expires_at))

    async def refresh_token(self, jti: str) -> RefreshToken | None:
        return await self.session.get(RefreshToken, jti)

    async def revoke_tokens(self, user_id: int) -> None:
        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )


# ================================================================ detections


@dataclass(slots=True)
class DetectionFilter:
    severities: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    incident_id: str | None = None
    replay_id: str | None = None
    include_replays: bool = False
    since: datetime | None = None
    until: datetime | None = None
    min_risk: float | None = None
    search: str | None = None

    def apply(self, query: Select[Any]) -> Select[Any]:
        model = DetectionRecord
        conditions = []
        if self.severities:
            conditions.append(model.severity.in_(self.severities))
        if self.detectors:
            conditions.append(model.detector.in_(self.detectors))
        if self.categories:
            conditions.append(model.category.in_(self.categories))
        if self.statuses:
            conditions.append(model.status.in_(self.statuses))
        if self.source_ip:
            conditions.append(model.source_ip == self.source_ip)
        if self.destination_ip:
            conditions.append(model.destination_ip == self.destination_ip)
        if self.protocol:
            conditions.append(model.protocol == self.protocol.lower())
        if self.incident_id:
            conditions.append(model.incident_id == self.incident_id)
        if self.replay_id:
            conditions.append(model.replay_id == self.replay_id)
        elif not self.include_replays:
            conditions.append(model.replay_id.is_(None))
        if self.since:
            conditions.append(model.timestamp >= self.since)
        if self.until:
            conditions.append(model.timestamp <= self.until)
        if self.min_risk is not None:
            conditions.append(model.risk_score >= self.min_risk)
        if self.search:
            pattern = f"%{_escape_like(self.search.strip()[:200])}%"
            conditions.append(
                or_(
                    model.title.ilike(pattern, escape="\\"),
                    model.description.ilike(pattern, escape="\\"),
                    model.source_ip.ilike(pattern, escape="\\"),
                    model.detector.ilike(pattern, escape="\\"),
                )
            )
        return query.where(and_(*conditions)) if conditions else query


class DetectionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, record: DetectionRecord) -> None:
        self.session.add(record)

    async def get(self, detection_id: str) -> DetectionRecord | None:
        return await self.session.get(DetectionRecord, detection_id)

    async def list(self, filters: DetectionFilter, *, limit: int = 50, offset: int = 0, order: str = "newest") -> Page[DetectionRecord]:
        limit, offset = _clamp(limit, offset)
        base = filters.apply(select(DetectionRecord))
        total = int(await self.session.scalar(filters.apply(select(func.count()).select_from(DetectionRecord))) or 0)
        ordering = {
            "newest": DetectionRecord.timestamp.desc(),
            "oldest": DetectionRecord.timestamp.asc(),
            "risk": DetectionRecord.risk_score.desc(),
        }.get(order, DetectionRecord.timestamp.desc())
        rows = await self.session.execute(base.order_by(ordering).limit(limit).offset(offset))
        return Page(list(rows.scalars()), total, limit, offset)

    async def set_status(self, detection_id: str, status: str, reviewer: str) -> DetectionRecord | None:
        record = await self.get(detection_id)
        if record is None:
            return None
        record.status = status
        record.reviewed_by = reviewer
        record.reviewed_at = datetime.now(UTC)
        return record

    async def link_incident(self, detection_ids: list[str], incident_id: str) -> None:
        if detection_ids:
            await self.session.execute(
                update(DetectionRecord).where(DetectionRecord.detection_id.in_(detection_ids)).values(incident_id=incident_id)
            )


# ================================================================= incidents


class IncidentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, incident_id: str) -> IncidentRecord | None:
        return await self.session.get(IncidentRecord, incident_id)

    async def upsert(self, values: dict[str, Any]) -> IncidentRecord:
        record = await self.get(values["incident_id"])
        if record is None:
            record = IncidentRecord(**values)
            self.session.add(record)
        else:
            # Analyst-owned fields are never overwritten by the engine.
            for key, value in values.items():
                if key not in {"status", "assigned_to", "notes", "created_at"}:
                    setattr(record, key, value)
        await self.session.flush()
        return record

    async def list(
        self,
        *,
        statuses: list[str] | None = None,
        severities: list[str] | None = None,
        min_risk: float | None = None,
        include_replays: bool = False,
        replay_id: str | None = None,
        since: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[IncidentRecord]:
        limit, offset = _clamp(limit, offset)
        conditions = []
        if statuses:
            conditions.append(IncidentRecord.status.in_(statuses))
        if severities:
            conditions.append(IncidentRecord.severity.in_(severities))
        if min_risk is not None:
            conditions.append(IncidentRecord.risk_score >= min_risk)
        if replay_id:
            conditions.append(IncidentRecord.replay_id == replay_id)
        elif not include_replays:
            conditions.append(IncidentRecord.replay_id.is_(None))
        if since:
            conditions.append(IncidentRecord.last_seen >= since)
        where = and_(*conditions) if conditions else None
        count_query = select(func.count()).select_from(IncidentRecord)
        query = select(IncidentRecord)
        if where is not None:
            count_query = count_query.where(where)
            query = query.where(where)
        total = int(await self.session.scalar(count_query) or 0)
        rows = await self.session.execute(query.order_by(IncidentRecord.last_seen.desc()).limit(limit).offset(offset))
        return Page(list(rows.scalars()), total, limit, offset)

    async def detections(self, incident_id: str) -> list[DetectionRecord]:
        rows = await self.session.execute(
            select(DetectionRecord).where(DetectionRecord.incident_id == incident_id).order_by(DetectionRecord.timestamp)
        )
        return list(rows.scalars())


# ================================================================== response


class ResponseActionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, record: ResponseActionRecord) -> None:
        self.session.add(record)

    async def list(
        self, *, target: str | None = None, outcomes: list[str] | None = None, incident_id: str | None = None,
        detection_id: str | None = None, limit: int = 100, offset: int = 0,
    ) -> Page[ResponseActionRecord]:
        limit, offset = _clamp(limit, offset)
        conditions = []
        if target:
            conditions.append(ResponseActionRecord.target == target)
        if outcomes:
            conditions.append(ResponseActionRecord.outcome.in_(outcomes))
        if incident_id:
            conditions.append(ResponseActionRecord.incident_id == incident_id)
        if detection_id:
            conditions.append(ResponseActionRecord.detection_id == detection_id)
        query = select(ResponseActionRecord)
        count_query = select(func.count()).select_from(ResponseActionRecord)
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))
        total = int(await self.session.scalar(count_query) or 0)
        rows = await self.session.execute(query.order_by(ResponseActionRecord.decided_at.desc()).limit(limit).offset(offset))
        return Page(list(rows.scalars()), total, limit, offset)


class BlockRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record_block(self, network: str, *, reason: str, expires_at: datetime | None, rate_limited: bool, backend: str) -> BlockRecord:
        await self.deactivate(network, removal_reason="superseded by new block")
        record = BlockRecord(
            network=network, reason=reason, expires_at=expires_at, rate_limited=rate_limited, backend=backend, active=True
        )
        self.session.add(record)
        return record

    async def deactivate(self, network: str, *, removal_reason: str) -> int:
        result = await self.session.execute(
            update(BlockRecord)
            .where(BlockRecord.network == network, BlockRecord.active.is_(True))
            .values(active=False, removed_at=datetime.now(UTC), removal_reason=removal_reason)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def active(self) -> list[BlockRecord]:
        rows = await self.session.execute(
            select(BlockRecord).where(BlockRecord.active.is_(True)).order_by(BlockRecord.created_at.desc())
        )
        return list(rows.scalars())

    async def history(self, *, limit: int = 100, offset: int = 0) -> Page[BlockRecord]:
        limit, offset = _clamp(limit, offset)
        total = int(await self.session.scalar(select(func.count()).select_from(BlockRecord)) or 0)
        rows = await self.session.execute(select(BlockRecord).order_by(BlockRecord.created_at.desc()).limit(limit).offset(offset))
        return Page(list(rows.scalars()), total, limit, offset)


# ===================================================================== audit


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, record: AuditEvent) -> AuditEvent:
        self.session.add(record)
        await self.session.flush()
        return record

    async def list(
        self, *, actor: str | None = None, action: str | None = None, target: str | None = None,
        since: datetime | None = None, limit: int = 100, offset: int = 0,
    ) -> Page[AuditEvent]:
        limit, offset = _clamp(limit, offset)
        conditions = []
        if actor:
            conditions.append(AuditEvent.actor == actor)
        if action:
            conditions.append(AuditEvent.action == action.upper())
        if target:
            conditions.append(AuditEvent.target == target)
        if since:
            conditions.append(AuditEvent.timestamp >= since)
        query = select(AuditEvent)
        count_query = select(func.count()).select_from(AuditEvent)
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))
        total = int(await self.session.scalar(count_query) or 0)
        rows = await self.session.execute(query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).limit(limit).offset(offset))
        return Page(list(rows.scalars()), total, limit, offset)


# =============================================================== configuration


class RuleRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, rule_id: str) -> RuleRecord | None:
        return await self.session.get(RuleRecord, rule_id)

    async def list(self) -> list[RuleRecord]:
        return list((await self.session.execute(select(RuleRecord).order_by(RuleRecord.name))).scalars())

    async def upsert(self, rule_id: str, **values: Any) -> RuleRecord:
        record = await self.get(rule_id)
        if record is None:
            record = RuleRecord(rule_id=rule_id, **values)
            self.session.add(record)
        else:
            for key, value in values.items():
                setattr(record, key, value)
        await self.session.flush()
        return record

    async def delete(self, rule_id: str) -> bool:
        result = await self.session.execute(delete(RuleRecord).where(RuleRecord.rule_id == rule_id))
        return bool(getattr(result, "rowcount", 0))


class SettingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def all(self) -> dict[str, dict[str, Any]]:
        rows = await self.session.execute(select(SettingRecord))
        return {row.key: row.value for row in rows.scalars()}

    async def set(self, key: str, value: dict[str, Any], actor: str) -> None:
        record = await self.session.get(SettingRecord, key)
        if record is None:
            self.session.add(SettingRecord(key=key, value=value, updated_by=actor))
        else:
            record.value = value
            record.updated_by = actor


class ReplayRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, record: ReplayRecord) -> None:
        self.session.add(record)
        await self.session.flush()

    async def get(self, replay_id: str) -> ReplayRecord | None:
        return await self.session.get(ReplayRecord, replay_id)

    async def list(self, *, limit: int = 50) -> list[ReplayRecord]:
        limit, _ = _clamp(limit, 0)
        rows = await self.session.execute(select(ReplayRecord).order_by(ReplayRecord.created_at.desc()).limit(limit))
        return list(rows.scalars())


# ================================================================= telemetry


class TelemetryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add_summary(self, record: TrafficSummary) -> None:
        self.session.add(record)

    async def add_metric(self, record: SystemMetric) -> None:
        self.session.add(record)

    async def summaries(self, since: datetime, *, sensor: str | None = None) -> list[TrafficSummary]:
        query = select(TrafficSummary).where(TrafficSummary.bucket_start >= since)
        if sensor:
            query = query.where(TrafficSummary.sensor == sensor)
        rows = await self.session.execute(query.order_by(TrafficSummary.bucket_start).limit(20_000))
        return list(rows.scalars())

    async def metrics(self, since: datetime) -> list[SystemMetric]:
        rows = await self.session.execute(
            select(SystemMetric).where(SystemMetric.timestamp >= since).order_by(SystemMetric.timestamp).limit(20_000)
        )
        return list(rows.scalars())


class AnalyticsRepository:
    """Aggregations for the Overview and Analytics pages."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _grouped(self, column: Any, since: datetime, *, limit: int = 20) -> list[dict[str, Any]]:
        rows = await self.session.execute(
            select(column, func.count())
            .where(DetectionRecord.timestamp >= since, DetectionRecord.replay_id.is_(None))
            .group_by(column)
            .order_by(func.count().desc())
            .limit(limit)
        )
        return [{"key": key, "count": int(count)} for key, count in rows.all()]

    async def summary(self, since: datetime) -> dict[str, Any]:
        live = and_(DetectionRecord.timestamp >= since, DetectionRecord.replay_id.is_(None))
        total = int(await self.session.scalar(select(func.count()).select_from(DetectionRecord).where(live)) or 0)
        false_positives = int(
            await self.session.scalar(
                select(func.count()).select_from(DetectionRecord).where(live, DetectionRecord.status == "false_positive")
            )
            or 0
        )
        reviewed = int(
            await self.session.scalar(
                select(func.count()).select_from(DetectionRecord).where(live, DetectionRecord.status != "new")
            )
            or 0
        )
        mean_risk = await self.session.scalar(select(func.avg(DetectionRecord.risk_score)).where(live))
        return {
            "since": since.isoformat(),
            "detections": total,
            "by_severity": await self._grouped(DetectionRecord.severity, since),
            "by_category": await self._grouped(DetectionRecord.category, since),
            "by_detector": await self._grouped(DetectionRecord.detector, since),
            "top_sources": await self._grouped(DetectionRecord.source_ip, since, limit=10),
            "top_destinations": await self._grouped(DetectionRecord.destination_ip, since, limit=10),
            "by_protocol": await self._grouped(DetectionRecord.protocol, since),
            "false_positives": false_positives,
            "reviewed": reviewed,
            # Only reviewed detections have a known verdict; dividing by all of them
            # would report unreviewed alerts as true positives.
            "false_positive_rate": round(false_positives / reviewed, 4) if reviewed else None,
            "mean_risk": round(float(mean_risk), 1) if mean_risk is not None else None,
        }

    async def timeline(self, since: datetime, bucket_minutes: int, dialect: str) -> list[dict[str, Any]]:
        """Detection counts per time bucket, split by severity."""
        bucket_seconds = max(60, bucket_minutes * 60)
        if dialect == "postgresql":
            epoch = func.extract("epoch", DetectionRecord.timestamp)
            bucket = func.floor(epoch / bucket_seconds) * bucket_seconds
            rows = await self.session.execute(
                select(bucket.label("bucket"), DetectionRecord.severity, func.count())
                .where(DetectionRecord.timestamp >= since, DetectionRecord.replay_id.is_(None))
                .group_by("bucket", DetectionRecord.severity)
            )
            raw = [(float(b), sev, int(c)) for b, sev, c in rows.all()]
        else:
            rows = await self.session.execute(
                select(DetectionRecord.timestamp, DetectionRecord.severity)
                .where(DetectionRecord.timestamp >= since, DetectionRecord.replay_id.is_(None))
                .limit(200_000)
            )
            raw = []
            for timestamp, severity in rows.all():
                moment = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)
                raw.append((float(int(moment.timestamp() // bucket_seconds) * bucket_seconds), severity, 1))

        buckets: dict[float, dict[str, Any]] = {}
        for start, severity, count in raw:
            entry = buckets.setdefault(start, {"bucket_start": datetime.fromtimestamp(start, UTC).isoformat(), "total": 0})
            entry[severity] = entry.get(severity, 0) + count
            entry["total"] += count
        return [buckets[key] for key in sorted(buckets)]


class RetentionRepository:
    """Deletes data past its retention period."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def purge(self, *, retention_days: int, audit_days: int, metrics_days: int) -> dict[str, int]:
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=retention_days)
        metric_cutoff = now - timedelta(days=metrics_days)
        audit_cutoff = now - timedelta(days=audit_days)
        results: dict[str, int] = {}

        async def run(name: str, statement: Any) -> None:
            result = await self.session.execute(statement)
            results[name] = int(getattr(result, "rowcount", 0) or 0)

        await run("detections", delete(DetectionRecord).where(DetectionRecord.timestamp < cutoff))
        # Closed incidents only; an open incident is live work regardless of age.
        await run(
            "incidents",
            delete(IncidentRecord).where(
                IncidentRecord.last_seen < cutoff, IncidentRecord.status.in_(["resolved", "false_positive"])
            ),
        )
        await run("response_actions", delete(ResponseActionRecord).where(ResponseActionRecord.decided_at < cutoff))
        await run("blocked_sources", delete(BlockRecord).where(BlockRecord.active.is_(False), BlockRecord.created_at < cutoff))
        await run("traffic_summaries", delete(TrafficSummary).where(TrafficSummary.bucket_start < metric_cutoff))
        await run("system_metrics", delete(SystemMetric).where(SystemMetric.timestamp < metric_cutoff))
        await run("audit_events", delete(AuditEvent).where(AuditEvent.timestamp < audit_cutoff))
        await run("replays", delete(ReplayRecord).where(ReplayRecord.created_at < cutoff))
        await run(
            "refresh_tokens",
            delete(RefreshToken).where(or_(RefreshToken.expires_at < now, RefreshToken.revoked_at.is_not(None))),
        )
        return results
