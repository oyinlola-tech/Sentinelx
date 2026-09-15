"""Persists pipeline events.

Subscribes to the event bus and writes detections, incidents, response decisions,
blocks and traffic summaries in batches.  Batching matters: a scan can produce a
burst of events, and one transaction per event would make the database the
pipeline's bottleneck.

Security events must survive a database outage, so writes are decoupled from the
bus and failures are retried:

* The bus handler only appends to a bounded in-memory buffer; it never waits on the
  database.  A slow or unreachable database therefore cannot back up the bus's
  handler queue (which drops events when full).
* A batch that fails because the database is unavailable (connection errors,
  timeouts, or any error while a health probe also fails) is put back at the front
  of the buffer, in order, and retried with exponential backoff.
* A batch that fails while the database is healthy contains bad data.  It is split
  until the offending events are isolated; only those are rejected, each logged at
  error level and counted, and the rest of the batch is written.
* The buffer is bounded (``max_pending``).  When it overflows, traffic statistics are
  shed first, then the oldest events; every drop is counted in
  ``sentinelx_events_dropped_total{target="persister"}`` and logged at error level.
  Nothing is discarded silently.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import Counter, deque
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import DataError, DBAPIError, IntegrityError

from sentinelx.common.errors import StorageError
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

#: Errors that say "this data cannot be stored", as opposed to "storage is unavailable".
_DATA_ERRORS: tuple[type[BaseException], ...] = (
    IntegrityError,
    DataError,
    KeyError,
    ValueError,
    TypeError,
)
#: Errors that say "storage is unavailable": retry, never reject.
_OUTAGE_ERRORS: tuple[type[BaseException], ...] = (OSError, TimeoutError, StorageError)


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _event_key(event: Event) -> str | None:
    payload = event.payload
    for key in ("detection_id", "incident_id", "decision_id", "network"):
        if key in payload:
            return str(payload[key])
    return None


class EventPersister:
    def __init__(
        self,
        database: Database,
        bus: EventBus,
        settings: Settings,
        *,
        max_pending: int = 50_000,
        write_timeout_seconds: float = 60.0,
        max_backoff_seconds: float = 30.0,
        stop_timeout_seconds: float = 30.0,
    ) -> None:
        self.database = database
        self.bus = bus
        self.settings = settings
        self.max_pending = max(max_pending, settings.storage.batch_size)
        self.write_timeout_seconds = write_timeout_seconds
        self.max_backoff_seconds = max_backoff_seconds
        self.stop_timeout_seconds = stop_timeout_seconds
        self._pending: deque[Event] = deque()
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()
        self._flusher: asyncio.Task[None] | None = None
        self._backoff = 0.0
        self.written = 0
        #: Write attempts that failed (each is retried or narrowed down; see module docs).
        self.failed_batches = 0
        #: Events refused by the database while it was healthy (bad data).
        self.rejected = 0
        #: Events discarded because the buffer overflowed during a long outage.
        self.dropped = 0
        self._minute: int | None = None
        self._minute_stats: dict[str, Any] | None = None
        self._minute_start_frames: int = 0
        self._minute_detections = 0

    @property
    def pending(self) -> int:
        """Events accepted from the bus and not yet written."""
        return len(self._pending)

    @property
    def retrying(self) -> bool:
        """True while writes are failing and being retried."""
        return self._backoff > 0

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
        final = asyncio.create_task(self.flush(), name="persister-final-flush")
        done, _ = await asyncio.wait({final}, timeout=self.stop_timeout_seconds)
        if final not in done:
            final.cancel()
        if self._pending or final not in done:
            log.error(
                "persister_stopped_with_unwritten_events",
                pending=len(self._pending),
                by_type=dict(Counter(event.type.value for event in self._pending)),
                write_in_progress=final not in done,
            )

    async def _enqueue(self, event: Event) -> None:
        """Accept an event from the bus. Never waits on the database."""
        if event.type is EventType.PACKET_STATS:
            summary, metric = self._stats(event.payload, self.settings.sensor_name)
            if summary is None and metric is None:
                return
            event = Event(
                type=EventType.PACKET_STATS, payload={"summary": summary, "metric": metric}
            )
        elif event.type is EventType.DETECTION_CREATED and not event.payload.get("replay_id"):
            self._minute_detections += 1

        if len(self._pending) >= self.max_pending:
            if event.type is EventType.PACKET_STATS:
                self._drop(event)
                return
            self._drop(self._pending.popleft())
        self._pending.append(event)
        if len(self._pending) >= self.settings.storage.batch_size:
            self._wake.set()

    def _drop(self, event: Event) -> None:
        self.dropped += 1
        metrics.events_dropped.labels(target="persister").inc()
        metrics.storage_errors.labels(operation="persist_dropped").inc()
        if self.dropped == 1 or self.dropped % 1000 == 0:
            log.error(
                "persist_buffer_full_event_dropped",
                dropped_total=self.dropped,
                type=event.type.value,
                key=_event_key(event),
                max_pending=self.max_pending,
            )

    async def _flush_loop(self) -> None:
        interval = self.settings.storage.flush_interval_seconds
        while True:
            if self._backoff:
                await asyncio.sleep(self._backoff)
            else:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=interval)
            self._wake.clear()
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:  # never let the flusher die; flush() handles write errors
                log.exception("persister_flush_loop_error")

    async def flush(self) -> bool:
        """Write everything pending, in batches of ``batch_size``.

        Returns:
            True when nothing is left pending; False when the database is unavailable
            and events remain buffered for retry.
        """
        async with self._lock:
            batch_size = self.settings.storage.batch_size
            while self._pending:
                batch = [self._pending.popleft() for _ in range(min(batch_size, len(self._pending)))]
                unwritten = await self._write_isolating(batch)
                if unwritten:
                    self._pending.extendleft(reversed(unwritten))
                    self._backoff = min(max(self._backoff * 2, 0.5), self.max_backoff_seconds)
                    return False
                if self._backoff:
                    log.warning("persist_recovered", pending=len(self._pending))
                    self._backoff = 0.0
            return True

    async def _write_isolating(self, batch: list[Event]) -> list[Event]:
        """Write ``batch``; return the events left unwritten because storage is down."""
        parts = [batch]
        while parts:
            part = parts.pop()
            try:
                async with asyncio.timeout(self.write_timeout_seconds):
                    await self._write(part)
            except asyncio.CancelledError:
                self._pending.extendleft(reversed(part + [e for p in reversed(parts) for e in p]))
                raise
            except Exception as exc:
                self.failed_batches += 1
                metrics.storage_errors.labels(operation="persist_batch").inc(len(part))
                if not await self._is_data_error(exc):
                    log.error(
                        "persist_batch_failed_will_retry",
                        events=len(part),
                        pending=len(self._pending) + sum(len(p) for p in parts) + len(part),
                        error=type(exc).__name__,
                        detail=str(exc)[:300],
                    )
                    return part + [event for remaining in reversed(parts) for event in remaining]
                if len(part) == 1:
                    event = part[0]
                    self.rejected += 1
                    metrics.storage_errors.labels(operation="persist_rejected").inc()
                    log.error(
                        "persist_event_rejected",
                        type=event.type.value,
                        key=_event_key(event),
                        error=type(exc).__name__,
                        detail=str(exc)[:300],
                    )
                else:
                    middle = len(part) // 2
                    parts.append(part[middle:])
                    parts.append(part[:middle])
            else:
                self.written += len(part)
        return []

    async def _is_data_error(self, exc: BaseException) -> bool:
        """Whether a failed write was caused by the data rather than by an outage."""
        if isinstance(exc, DBAPIError) and exc.connection_invalidated:
            return False
        if isinstance(exc, _DATA_ERRORS):
            return True
        if isinstance(exc, _OUTAGE_ERRORS):
            return False
        # Anything else: if the database answers, the batch itself is the problem.
        try:
            async with asyncio.timeout(5.0):
                return bool((await self.database.health())["ok"])
        except Exception:
            return False

    async def _write(self, batch: list[Event]) -> None:
        sensor = self.settings.sensor_name
        async with self.database.session() as session:
            detections = DetectionRepository(session)
            incidents = IncidentRepository(session)
            actions = ResponseActionRepository(session)
            blocks = BlockRepository(session)
            telemetry = TelemetryRepository(session)

            detection_ids = [
                str(event.payload["detection_id"])
                for event in batch
                if event.type is EventType.DETECTION_CREATED
            ]
            seen_detections = await detections.existing_ids(detection_ids)
            for event in batch:
                if event.type is EventType.DETECTION_CREATED:
                    payload = event.payload
                    if payload["detection_id"] in seen_detections:
                        continue
                    seen_detections.add(payload["detection_id"])
                    await detections.add(self._detection(payload, sensor))
            await session.flush()

            for event in batch:
                payload = event.payload
                if event.type in (EventType.INCIDENT_OPENED, EventType.INCIDENT_UPDATED):
                    await incidents.upsert(self._incident(payload, sensor))
                    await detections.link_incident(
                        list(payload.get("linked_detection_ids", payload.get("detection_ids", []))),
                        payload["incident_id"],
                    )
                elif event.type is EventType.RESPONSE_DECIDED:
                    await actions.add(self._action(payload, sensor))
                elif event.type is EventType.IP_BLOCKED:
                    expires = payload.get("expires_at")
                    await blocks.record_block(
                        payload["network"],
                        reason=str(payload.get("reason", "")),
                        expires_at=_dt(expires) if expires else None,
                        rate_limited=bool(payload.get("rate_limited")),
                        backend=str(payload.get("backend", "")),
                    )
                elif event.type is EventType.IP_UNBLOCKED:
                    await blocks.deactivate(
                        payload["network"], removal_reason=str(payload.get("reason", "unblocked"))
                    )
                elif event.type is EventType.PACKET_STATS:
                    if payload.get("summary") is not None:
                        await telemetry.add_summary(TrafficSummary(**payload["summary"]))
                    if payload.get("metric") is not None:
                        await telemetry.add_metric(SystemMetric(**payload["metric"]))

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
            replay_id=payload.get("replay_id"),
        )

    def _stats(
        self, payload: dict[str, Any], sensor: str
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Roll per-second stats into one traffic summary per wall-clock minute.

        Only live capture is summarised; replay statistics describe a file, not the
        network, and would distort traffic history.
        """
        if payload.get("kind") != "live":
            return None, None
        now = datetime.now(UTC)
        minute = int(now.timestamp() // 60)
        summary: dict[str, Any] | None = None
        metric: dict[str, Any] | None = None
        if self._minute is None:
            self._minute = minute
            self._minute_start_frames = int(payload.get("frames", 0))
        elif minute != self._minute and self._minute_stats is not None:
            last = self._minute_stats
            packets = max(int(last.get("frames", 0)) - self._minute_start_frames, 0)
            summary = {
                "bucket_start": datetime.fromtimestamp(self._minute * 60, UTC),
                "sensor": sensor,
                "packets": packets,
                "bytes_total": int(last.get("bytes", 0)),
                "packets_per_second": round(packets / 60.0, 2),
                "detections": self._minute_detections,
                "active_flows": int(last.get("active_flows", 0)),
                "tracked_sources": int(last.get("tracked_sources", 0)),
                "protocols": last.get("protocols", {}),
            }
            metric = {
                "timestamp": datetime.now(UTC),
                "sensor": sensor,
                "cpu_percent": float(last.get("cpu_percent", 0.0)),
                "memory_bytes": float(last.get("memory_bytes", 0.0)),
                "packets_processed": int(last.get("frames", 0)),
                "packets_dropped": int(last.get("dropped", 0)),
                "detections": self._minute_detections,
                "event_bus_dropped": self.bus.stats()["dropped"],
            }
            self._minute = minute
            self._minute_start_frames = int(last.get("frames", 0))
            self._minute_detections = 0
        self._minute_stats = payload
        return summary, metric
