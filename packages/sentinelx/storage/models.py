"""Database schema.

PostgreSQL is the production target; SQLite is supported so the platform runs with
no infrastructure at all.  Types are chosen to be correct on PostgreSQL and
portable to SQLite: ``JSONB`` and identity columns on PostgreSQL, their SQLite
equivalents elsewhere, ``TIMESTAMPTZ`` everywhere.

What is deliberately *not* stored: raw packets.  Detections carry their evidence;
captures belong in PCAP files under ``PCAP_DIRECTORY``, with retention of their
own.  Putting every packet in PostgreSQL would make the database the bottleneck of
the sensor, and is what a packet store, not a relational database, is for.

Identifiers: detections, incidents and replays use the hex UUID the engine assigns
at creation.  The engine publishes these events *before* they are persisted (so the
dashboard is never waiting on the database), which means the id must exist before
a row does - a database-assigned identity cannot serve.  Tables written only by
storage (audit, actions, metrics) use identity keys.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "AuditEvent",
    "Base",
    "BlockRecord",
    "DetectionRecord",
    "IncidentRecord",
    "RefreshToken",
    "ReplayRecord",
    "ResponseActionRecord",
    "RuleRecord",
    "SettingRecord",
    "SystemMetric",
    "TrafficSummary",
    "User",
]

#: Stable constraint names, so Alembic migrations are deterministic across databases.
NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JsonType = JSON().with_variant(JSONB(), "postgresql")
Identity = BigInteger().with_variant(Integer(), "sqlite")  # SQLite autoincrements INTEGER PRIMARY KEY only
TZ = DateTime(timezone=True)


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    type_annotation_map: ClassVar[dict[Any, Any]] = {dict[str, Any]: JsonType, list[Any]: JsonType, datetime: TZ}


# ======================================================================= auth


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('viewer', 'analyst', 'admin')", name="role_valid"),
        # text(), not a bare string: func.lower("username") would index the *literal*
        # 'username', making every row collide and allowing only one user in total.
        Index("uq_users_username_lower", func.lower(text("username")), unique=True),
    )

    id: Mapped[int] = mapped_column(Identity, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TZ)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, onupdate=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(TZ)


class RefreshToken(Base):
    """Issued refresh tokens, so they can be revoked (logout, password change)."""

    __tablename__ = "refresh_tokens"

    jti: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[int] = mapped_column(Identity, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now)
    expires_at: Mapped[datetime] = mapped_column(TZ, nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TZ)


# ================================================================== detection


class IncidentRecord(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'resolved', 'false_positive')", name="status_valid"
        ),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_range"),
        Index("ix_incidents_status_last_seen", "status", "last_seen"),
    )

    incident_id: Mapped[str] = mapped_column(Text, primary_key=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    risk: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    categories: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    affected_sources: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    affected_destinations: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    affected_services: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    correlation_rule: Mapped[str | None] = mapped_column(Text)
    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timeline: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(TZ, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(TZ, nullable=False, index=True)
    assigned_to: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sensor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    replay_id: Mapped[str | None] = mapped_column(Text, index=True)
    created_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, onupdate=_now)


class DetectionRecord(Base):
    __tablename__ = "detections"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        CheckConstraint(
            "status IN ('new', 'acknowledged', 'false_positive', 'resolved')", name="status_valid"
        ),
        Index("ix_detections_source_ip_timestamp", "source_ip", "timestamp"),
        Index("ix_detections_severity_timestamp", "severity", "timestamp"),
        Index("ix_detections_detector_timestamp", "detector", "timestamp"),
    )

    detection_id: Mapped[str] = mapped_column(Text, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(TZ, nullable=False, index=True)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_ip: Mapped[str] = mapped_column(Text, nullable=False)
    destination_ip: Mapped[str | None] = mapped_column(Text, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    risk_band: Mapped[str] = mapped_column(Text, nullable=False, default="informational")
    risk: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    observation_window_seconds: Mapped[float | None] = mapped_column(Float)
    packet_count: Mapped[int | None] = mapped_column(Integer)
    tags: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    incident_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("incidents.incident_id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default="new")
    reviewed_by: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(TZ)
    sensor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    replay_id: Mapped[str | None] = mapped_column(Text, index=True)
    """Set for detections produced by a PCAP replay, so lab runs never pollute live data."""


# =================================================================== response


class ResponseActionRecord(Base):
    """Every response decision: executed, simulated, refused, or queued."""

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Identity, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    decided_at: Mapped[datetime] = mapped_column(TZ, nullable=False, index=True)
    action: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    executed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    detection_id: Mapped[str | None] = mapped_column(Text, index=True)
    incident_id: Mapped[str | None] = mapped_column(Text, index=True)
    error: Mapped[str | None] = mapped_column(Text)
    sensor: Mapped[str] = mapped_column(Text, nullable=False, default="")


class BlockRecord(Base):
    """Block history. ``active`` rows mirror what the firewall enforces now."""

    __tablename__ = "blocked_sources"
    __table_args__ = (Index("ix_blocked_sources_active_network", "active", "network"),)

    id: Mapped[int] = mapped_column(Identity, primary_key=True, autoincrement=True)
    network: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(TZ)
    removed_at: Mapped[datetime | None] = mapped_column(TZ)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rate_limited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    removal_reason: Mapped[str | None] = mapped_column(Text)
    backend: Mapped[str] = mapped_column(Text, nullable=False, default="")


# ===================================================================== audit


class AuditEvent(Base):
    """Append-only record of administrative and response actions."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_actor_timestamp", "actor", "timestamp"),)

    id: Mapped[int] = mapped_column(Identity, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, index=True)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(Text, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    """Where the action came from: dashboard, api, cli, engine, approval."""
    outcome: Mapped[str] = mapped_column(Text, nullable=False, default="success")
    client_ip: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)


# ============================================================ configuration


class RuleRecord(Base):
    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    definition: Mapped[str] = mapped_column(Text, nullable=False)
    """The rule's YAML, as written. Re-validated on every load."""
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    origin: Mapped[str] = mapped_column(Text, nullable=False, default="api")
    """``file`` rules are synced from RULES_DIRECTORY; ``api`` rules were created in the dashboard."""
    source_path: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, onupdate=_now)
    updated_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")


class SettingRecord(Base):
    """Runtime overrides of settings changed from the dashboard."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, onupdate=_now)
    updated_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")


# ================================================================ telemetry


class TrafficSummary(Base):
    """Per-minute traffic aggregates. Replaces storing packets."""

    __tablename__ = "traffic_summaries"
    __table_args__ = (Index("ix_traffic_summaries_sensor_bucket", "sensor", "bucket_start"),)

    id: Mapped[int] = mapped_column(Identity, primary_key=True, autoincrement=True)
    bucket_start: Mapped[datetime] = mapped_column(TZ, nullable=False, index=True)
    sensor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    packets: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_per_second: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    detections: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_flows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tracked_sources: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    protocols: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    top_sources: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    top_destinations: Mapped[list[Any]] = mapped_column(nullable=False, default=list)


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id: Mapped[int] = mapped_column(Identity, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, index=True)
    sensor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_bytes: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    packets_processed: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_dropped: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    detections: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_bus_dropped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ReplayRecord(Base):
    __tablename__ = "replays"
    __table_args__ = (
        CheckConstraint("status IN ('queued', 'running', 'completed', 'failed', 'cancelled')", name="status_valid"),
    )

    replay_id: Mapped[str] = mapped_column(Text, primary_key=True)
    filename: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(TZ, nullable=False, default=_now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(TZ)
    finished_at: Mapped[datetime | None] = mapped_column(TZ)
    created_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    options: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    progress: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    report: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
