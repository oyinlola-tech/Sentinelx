"""Persists pipeline events.

Subscribes to the event bus and writes detections, incidents, response decisions,
blocks and traffic summaries in batches.  Batching matters: a scan can produce a
burst of events, and one transaction per event would make the database the
pipeline's bottleneck.  A failed batch is logged and counted but does not stop
persistence of later batches.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

from sentinelx.config.settings import Settings
from sentinelx.events.bus import Event, EventBus, EventType
from sentinelx.storage.database import Database
from sentinelx.storage.models import (
    DetectionRecord,
    ResponseActionRecord,
    SystemMetric,
    TrafficSummary,
)
from sentinelx.storage.repositories import (
    BlockRepository,
    DetectionRepository,
    IncidentRepository,
    ResponseActionRepository,
    TelemetryRepository,
)
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["EventPersister"]

log = get_logger(__name__)

_PERSISTED = {
    EventType.DETECTION_CREATED,
    EventType.INCIDENT_OPENED,
    EventType.INCIDENT_UPDATED,
    EventType.RESPONSE_DECIDED,
    EventType.IP_BLOCKED,
    EventType.IP_UNBLOCKED,
    EventType.PACKET_STATS,
}


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class EventPersister:
    def __init__(self, database: Database, bus: EventBus, settings: Settings) -> None:
        self.database = database
        self.bus = bus
        self.settings = settings
        self._buffer: list[Event] = []
        self._lock = asyncio.Lock()
        self._flusher: asyncio.Task[None] | None = None
        self.written = 0
        self.failed_batches = 0
        self._minute: int | None = None
        self._minute_stats: dict[str, Any] | None = None
        self._minute_start_frames: int = 0
        self._minute_detections = 0

    async def start(self) -> None:
        self.bus.add_handler("persister", self._enqueue, _PERSISTED)
        self._flusher = asyncio.create_task(self._flush_loop(), name="persister-flush")

    async def stop(self) -> None:
        self.bus.remove_handler("persister")
        flusher, self._flusher = self._flusher, None
        if flusher is not None:
            flusher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await flusher
        await self.flush()

    async def _enqueue(self, event: Event) -> None:
        self._buffer.append(event)
        if len(self._buffer) >= self.settings.storage.batch_size:
            await self.flush()

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.settings.storage.flush_interval_seconds)
            await self.flush()

    async def flush(self) -> None:
        async with self._lock:
            batch, self._buffer = self._buffer, []
            if not batch:
                return
            try:
                await self._write(batch)
                self.written += len(batch)
            except Exception:
                self.failed_batches += 1
                metrics.storage_errors.labels(operation="persist_batch").inc(len(batch))
                log.exception("persist_batch_failed", events=len(batch))

    async def _write(self, batch: list[Event]) -> None:
        sensor = self.settings.sensor_name
        async with self.database.session() as session:
            detections = DetectionRepository(session)
            incidents = IncidentRepository(session)
            actions = ResponseActionRepository(session)
            blocks = BlockRepository(session)
            telemetry = TelemetryRepository(session)

            seen_detections: set[str] = set()
            for event in batch:
                if event.type is EventType.DETECTION_CREATED:
                    payload = event.payload
                    if payload["detection_id"] in seen_detections or await detections.get(payload["detection_id"]):
                        continue
                    seen_detections.add(payload["detection_id"])
                    await detections.add(self._detection(payload, sensor))
            await session.flush()

            for event in batch:
                payload = event.payload
                if event.type in (EventType.INCIDENT_OPENED, EventType.INCIDENT_UPDATED):
                    await incidents.upsert(self._incident(payload, sensor))
                    await detections.link_incident(list(payload.get("detection_ids", [])), payload["incident_id"])
                elif event.type is EventType.RESPONSE_DECIDED:
                    await actions.add(self._action(payload, sensor))
                elif event.type is EventType.IP_BLOCKED:
                    expires = payload.get("expires_at")
                    await blocks.record_block(
                        payload["network"], reason=str(payload.get("reason", "")),
                        expires_at=_dt(expires) if expires else None,
                        rate_limited=bool(payload.get("rate_limited")),
                        backend=str(payload.get("backend", "")),
                    )
                elif event.type is EventType.IP_UNBLOCKED:
                    await blocks.deactivate(payload["network"], removal_reason=str(payload.get("reason", "unblocked")))
                elif event.type is EventType.PACKET_STATS:
                    summary, metric = self._stats(payload, sensor)
                    if summary is not None:
                        await telemetry.add_summary(summary)
                    if metric is not None:
                        await telemetry.add_metric(metric)
                if event.type is EventType.DETECTION_CREATED and not payload.get("replay_id"):
                    self._minute_detections += 1

    @staticmethod
    def _detection(payload: dict[str, Any], sensor: str) -> DetectionRecord:
        risk = payload.get("risk") or {}
        return DetectionRecord(
            detection_id=payload["detection_id"],
            timestamp=_dt(payload["timestamp"]),
            detector=payload["detector"],
            rule_name=payload.get("rule_name"),
            category=payload["category"],
            severity=payload["severity"],
            confidence=float(payload["confidence"]),
            title=payload["title"],
            description=payload.get("description", ""),
            source_ip=payload["source_ip"],
            destination_ip=payload.get("destination_ip"),
            source_port=payload.get("source_port"),
            destination_port=payload.get("destination_port"),
            protocol=payload.get("protocol"),
            evidence=payload.get("evidence", []),
            recommended_action=payload["recommended_action"],
            risk_score=float(risk.get("score", 0.0)),
            risk_band=str(risk.get("band", "informational")),
            risk=risk,
            observation_window_seconds=payload.get("observation_window_seconds"),
            packet_count=payload.get("packet_count"),
            tags=payload.get("tags", []),
            sensor=sensor,
            replay_id=payload.get("replay_id"),
        )

    @staticmethod
    def _incident(payload: dict[str, Any], sensor: str) -> dict[str, Any]:
        return {
            "incident_id": payload["incident_id"],
            "title": payload["title"],
            "summary": payload.get("summary", ""),
            "severity": payload["severity"],
            "status": payload.get("status", "open"),
            "risk_score": float(payload["risk"]["score"]),
            "risk": payload["risk"],
            "categories": payload.get("categories", []),
            "affected_sources": payload.get("affected_sources", []),
            "affected_destinations": payload.get("affected_destinations", []),
            "affected_services": payload.get("affected_services", []),
            "correlation_rule": payload.get("correlation_rule"),
            "detection_count": int(payload.get("detection_count", 0)),
            "timeline": payload.get("timeline", []),
            "first_seen": _dt(payload["first_seen"]),
            "last_seen": _dt(payload["last_seen"]),
            "sensor": sensor,
            "replay_id": payload.get("replay_id"),
        }

    @staticmethod
    def _action(payload: dict[str, Any], sensor: str) -> ResponseActionRecord:
        return ResponseActionRecord(
            decision_id=payload["decision_id"],
            decided_at=_dt(payload["decided_at"]),
            action=payload["action"],
            target=payload["target"],
            reason=payload.get("reason", ""),
            outcome=payload["outcome"],
            executed=bool(payload.get("executed")),
            dry_run=bool(payload.get("dry_run")),
            requires_approval=bool(payload.get("requires_approval")),
            duration_seconds=payload.get("duration_seconds"),
            detection_id=payload.get("detection_id"),
            incident_id=payload.get("incident_id"),
            error=payload.get("error"),
            sensor=sensor,
        )

    def _stats(self, payload: dict[str, Any], sensor: str) -> tuple[TrafficSummary | None, SystemMetric | None]:
        """Roll per-second stats into one traffic summary per wall-clock minute.

        Only live capture is summarised; replay statistics describe a file, not the
        network, and would distort traffic history.
        """
        if payload.get("kind") != "live":
            return None, None
        now = datetime.now(UTC)
        minute = int(now.timestamp() // 60)
        summary: TrafficSummary | None = None
        metric: SystemMetric | None = None
        if self._minute is None:
            self._minute = minute
            self._minute_start_frames = int(payload.get("frames", 0))
        elif minute != self._minute and self._minute_stats is not None:
            last = self._minute_stats
            packets = max(int(last.get("frames", 0)) - self._minute_start_frames, 0)
            summary = TrafficSummary(
                bucket_start=datetime.fromtimestamp(self._minute * 60, UTC),
                sensor=sensor,
                packets=packets,
                bytes_total=int(last.get("bytes", 0)),
                packets_per_second=round(packets / 60.0, 2),
                detections=self._minute_detections,
                active_flows=int(last.get("active_flows", 0)),
                tracked_sources=int(last.get("tracked_sources", 0)),
                protocols=last.get("protocols", {}),
            )
            metric = SystemMetric(
                sensor=sensor,
                cpu_percent=float(last.get("cpu_percent", 0.0)),
                memory_bytes=float(last.get("memory_bytes", 0.0)),
                packets_processed=int(last.get("frames", 0)),
                packets_dropped=int(last.get("dropped", 0)),
                detections=self._minute_detections,
                event_bus_dropped=self.bus.stats()["dropped"],
            )
            self._minute = minute
            self._minute_start_frames = int(last.get("frames", 0))
            self._minute_detections = 0
        self._minute_stats = payload
        return summary, metric
