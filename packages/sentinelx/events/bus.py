"""In-process asynchronous event bus.

The pipeline publishes; storage, the WebSocket hub, the response engine and the
CLI monitor subscribe.  Decoupling them this way is what lets the detection core
run with no API, no database and no dashboard attached - a subscriber that is not
there simply does not receive anything.

Design decisions worth knowing:

* **Subscribers must never block the pipeline.**  Each subscriber owns a bounded
  queue.  When that queue is full the *event is dropped for that subscriber only*
  and counted, rather than applying back-pressure to packet capture.  A slow
  dashboard must not cause packet loss.
* **A subscriber exception must never kill the publisher.**  Handler errors are
  logged and counted; the bus keeps running.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sentinelx.common.models import new_id, utcnow
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = [
    "DURABLE_EVENT_TYPES",
    "Event",
    "EventBus",
    "EventType",
    "get_event_bus",
    "reset_event_bus",
]

log = get_logger(__name__)


class EventType(StrEnum):
    """Every event the platform can emit.

    This enum is the contract with the dashboard: the WebSocket ``type`` field is
    always one of these values, so the frontend can switch on it exhaustively.
    """

    DETECTION_CREATED = "detection.created"
    INCIDENT_OPENED = "incident.opened"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_CLOSED = "incident.closed"
    SEVERITY_CHANGED = "severity.changed"
    IP_BLOCKED = "ip.blocked"
    IP_UNBLOCKED = "ip.unblocked"
    RESPONSE_DECIDED = "response.decided"
    RESPONSE_PENDING_APPROVAL = "response.pending_approval"
    SENSOR_STATUS = "sensor.status"
    PACKET_STATS = "packet.stats"
    SYSTEM_HEALTH = "system.health"
    REPLAY_PROGRESS = "replay.progress"
    REPLAY_COMPLETED = "replay.completed"
    AUDIT_EVENT = "audit.event"
    RULE_CHANGED = "rule.changed"
    CONFIG_CHANGED = "config.changed"


#: Security records that must reach storage. When the handler queue is full, publishing
#: one of these waits for room (bounded by :data:`DURABLE_PUBLISH_WAIT_SECONDS`) instead
#: of dropping it: a burst slows the publisher rather than losing detections. Everything
#: else (statistics, progress, health) is still dropped under pressure.
DURABLE_EVENT_TYPES: frozenset[EventType] = frozenset(
    {
        EventType.DETECTION_CREATED,
        EventType.INCIDENT_OPENED,
        EventType.INCIDENT_UPDATED,
        EventType.INCIDENT_CLOSED,
        EventType.RESPONSE_DECIDED,
        EventType.IP_BLOCKED,
        EventType.IP_UNBLOCKED,
    }
)
DURABLE_PUBLISH_WAIT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class Event:
    """An envelope carrying a JSON-serialisable payload."""

    type: EventType
    payload: dict[str, Any]
    event_id: str = field(default_factory=new_id)
    timestamp: str = field(default_factory=lambda: utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


Handler = Callable[[Event], Awaitable[None]]

#: Put on subscriber queues when the bus stops, to end their iterators.
_CLOSED = Event(type=EventType.SYSTEM_HEALTH, payload={"closed": True})


@dataclass
class _Subscription:
    """One subscriber's bounded mailbox."""

    name: str
    types: frozenset[EventType] | None
    queue: asyncio.Queue[Event]
    dropped: int = 0

    def accepts(self, event_type: EventType) -> bool:
        return self.types is None or event_type in self.types


class EventBus:
    """Fan-out bus with bounded per-subscriber queues.

    Use :meth:`subscribe` for a pull-based async iterator (the WebSocket hub and
    the CLI monitor use this), or :meth:`add_handler` for push-based callbacks
    driven by a background worker task (storage uses this).
    """

    def __init__(self, queue_size: int = 1000) -> None:
        self._queue_size = queue_size
        self._subscriptions: dict[str, _Subscription] = {}
        self._handlers: list[tuple[str, frozenset[EventType] | None, Handler]] = []
        self._handler_queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._worker: asyncio.Task[None] | None = None
        self._published = 0
        self._dropped = 0
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        """Start the handler worker. Idempotent."""
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run_handlers(), name="eventbus-handlers")
            log.debug("event_bus_started", queue_size=self._queue_size)

    async def stop(self) -> None:
        """Stop the worker and release subscribers.

        Subscribers are woken so their ``async for`` loops exit rather than
        hanging on a queue that will never be fed again.
        """
        worker = self._worker
        self._worker = None
        if worker is not None and not worker.done():
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker
        async with self._lock:
            subscriptions = list(self._subscriptions.values())
            self._subscriptions.clear()
        for subscription in subscriptions:
            # Wake each subscriber so its iterator ends instead of waiting forever.
            with contextlib.suppress(asyncio.QueueFull):
                subscription.queue.put_nowait(_CLOSED)
        log.debug("event_bus_stopped", published=self._published, dropped=self._dropped)

    # ------------------------------------------------------------- publishing

    async def publish(self, event_type: EventType, payload: dict[str, Any]) -> Event:
        """Publish an event. Never raises, never blocks on a slow subscriber.

        Storage handlers are different: a security record (:data:`DURABLE_EVENT_TYPES`)
        waits for room in a full handler queue for up to ten seconds before it is
        dropped, counted and logged as an error.
        """
        event = Event(type=event_type, payload=payload)
        self._published += 1
        metrics.events_published.labels(event_type=event_type.value).inc()

        for subscription in list(self._subscriptions.values()):
            if not subscription.accepts(event_type):
                continue
            try:
                subscription.queue.put_nowait(event)
            except asyncio.QueueFull:
                subscription.dropped += 1
                self._dropped += 1
                metrics.events_dropped.labels(target="subscriber").inc()
                # Logged at debug: a busy dashboard dropping stats frames is
                # expected and must not itself become a log flood.
                log.debug("event_dropped", subscriber=subscription.name, type=event_type.value)

        if self._handlers:
            try:
                self._handler_queue.put_nowait(event)
            except asyncio.QueueFull:
                worker_running = self._worker is not None and not self._worker.done()
                if event_type in DURABLE_EVENT_TYPES and worker_running:
                    try:
                        await asyncio.wait_for(
                            self._handler_queue.put(event), timeout=DURABLE_PUBLISH_WAIT_SECONDS
                        )
                        return event
                    except TimeoutError:
                        pass
                self._dropped += 1
                metrics.events_dropped.labels(target="handlers").inc()
                if event_type in DURABLE_EVENT_TYPES:
                    log.error(
                        "security_event_dropped", type=event_type.value, reason="handler queue full"
                    )
                else:
                    log.warning("event_handler_queue_full", type=event_type.value)
        return event

    def publish_nowait(self, event_type: EventType, payload: dict[str, Any]) -> None:
        """Publish from synchronous code running inside a loop's thread.

        Used by the pipeline, which is synchronous on the hot path.  When no loop
        is running the event is discarded - that happens only in unit tests that
        exercise detectors directly, where no subscriber exists anyway.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.publish(event_type, payload))  # noqa: RUF006

    # ------------------------------------------------------------ subscribing

    @contextlib.asynccontextmanager
    async def subscribe(
        self,
        name: str,
        types: set[EventType] | None = None,
        queue_size: int | None = None,
    ) -> AsyncIterator[AsyncIterator[Event]]:
        """Subscribe for the duration of the context.

        Yields an async iterator of events.  The subscription is always removed on
        exit, including when the consumer is cancelled, so a disconnecting
        WebSocket client cannot leak a queue.

        Example:
            >>> async with bus.subscribe("ws-1", {EventType.DETECTION_CREATED}) as stream:
            ...     async for event in stream:
            ...         await websocket.send_json(event.to_dict())
        """
        key = f"{name}-{new_id()[:8]}"
        subscription = _Subscription(
            name=name,
            types=frozenset(types) if types else None,
            queue=asyncio.Queue(maxsize=queue_size or self._queue_size),
        )
        async with self._lock:
            self._subscriptions[key] = subscription
        log.debug("subscriber_added", subscriber=name, filtered=bool(types))
        try:
            yield self._iterate(subscription)
        finally:
            async with self._lock:
                self._subscriptions.pop(key, None)
            log.debug("subscriber_removed", subscriber=name, dropped=subscription.dropped)

    @staticmethod
    async def _iterate(subscription: _Subscription) -> AsyncIterator[Event]:
        while True:
            event = await subscription.queue.get()
            if event is _CLOSED:
                return
            yield event

    def add_handler(
        self,
        name: str,
        handler: Handler,
        types: set[EventType] | None = None,
    ) -> None:
        """Register a push-based coroutine handler.

        Handlers run sequentially in one worker task, which gives them ordering
        guarantees.  A handler that needs concurrency should dispatch internally.
        """
        self._handlers.append((name, frozenset(types) if types else None, handler))
        log.debug("handler_registered", handler=name)

    def remove_handler(self, name: str) -> None:
        self._handlers = [entry for entry in self._handlers if entry[0] != name]

    async def _run_handlers(self) -> None:
        while True:
            event = await self._handler_queue.get()
            try:
                for name, types, handler in list(self._handlers):
                    if types is not None and event.type not in types:
                        continue
                    try:
                        await handler(event)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        # A broken subscriber must not stop the others or the bus.
                        metrics.event_handler_failures.labels(handler=name).inc()
                        log.exception("event_handler_failed", handler=name, type=event.type.value)
            finally:
                self._handler_queue.task_done()

    async def drain(self, wait_seconds: float = 5.0) -> bool:
        """Wait until every queued event has been handled. False if the wait ran out.

        Called on shutdown before storage stops, so detections still queued for the
        persister are written rather than lost.
        """
        if self._worker is None or self._worker.done():
            return self._handler_queue.empty()
        try:
            await asyncio.wait_for(self._handler_queue.join(), timeout=wait_seconds)
        except TimeoutError:
            log.warning("event_bus_drain_timeout", backlog=self._handler_queue.qsize())
            return False
        return True

    # ----------------------------------------------------------------- status

    def stats(self) -> dict[str, int]:
        return {
            "published": self._published,
            "dropped": self._dropped,
            "subscribers": len(self._subscriptions),
            "handlers": len(self._handlers),
            "handler_backlog": self._handler_queue.qsize(),
        }


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """The process-wide bus.

    A module-level singleton rather than dependency injection because the
    synchronous pipeline needs to publish from deep inside the hot path without
    threading a reference through every detector.
    """
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Drop the singleton. For tests, so bus state never leaks between cases."""
    global _bus
    _bus = None
