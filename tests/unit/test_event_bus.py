"""Event bus delivery guarantees under pressure."""

from __future__ import annotations

import asyncio

from sentinelx.events.bus import EventBus, EventType


async def test_security_events_wait_for_room_instead_of_being_dropped() -> None:
    # A burst larger than the handler queue, published without yielding, used to lose
    # everything past the first queue-full of detections before storage saw them.
    bus = EventBus(queue_size=10)
    handled: list[str] = []

    async def slow_storage(event) -> None:  # type: ignore[no-untyped-def]
        await asyncio.sleep(0.001)
        handled.append(event.type.value)

    bus.add_handler("storage", slow_storage, {EventType.DETECTION_CREATED, EventType.PACKET_STATS})
    await bus.start()
    for number in range(300):
        await bus.publish(EventType.DETECTION_CREATED, {"n": number})
    assert await bus.drain(wait_seconds=10)
    assert handled.count("detection.created") == 300
    assert bus.stats()["dropped"] == 0

    # Statistics are still shed under pressure rather than slowing the pipeline.
    for number in range(300):
        await bus.publish(EventType.PACKET_STATS, {"n": number})
    await bus.drain(wait_seconds=10)
    assert bus.stats()["dropped"] > 0
    await bus.stop()


async def test_without_a_running_worker_publishing_never_blocks() -> None:
    bus = EventBus(queue_size=2)

    async def handler(event) -> None:  # type: ignore[no-untyped-def]
        return None

    bus.add_handler("storage", handler, None)
    for number in range(10):
        await asyncio.wait_for(bus.publish(EventType.DETECTION_CREATED, {"n": number}), 1)
    assert bus.stats()["dropped"] == 8
