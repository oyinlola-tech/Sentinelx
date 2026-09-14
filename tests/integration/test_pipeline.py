"""End-to-end: frames in, detections, incidents, decisions and events out."""

from __future__ import annotations

import asyncio
from pathlib import Path

from sentinelx.capture import MockCapture, PcapFileCapture
from sentinelx.common.enums import ResponseMode
from sentinelx.config.settings import Settings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.firewall import MemoryFirewall
from sentinelx.pipeline import Pipeline
from sentinelx.testing import get_scenario, write_pcap


def make_pipeline(
    settings: Settings, bus: EventBus | None = None
) -> tuple[Pipeline, MemoryFirewall, list[dict[str, object]]]:
    firewall = MemoryFirewall()
    audit: list[dict[str, object]] = []

    async def sink(record: dict[str, object]) -> None:
        audit.append(record)

    pipeline = Pipeline(settings, bus=bus, firewall=firewall, audit=sink)
    pipeline.response.guard._local_addresses = lambda: set()
    return pipeline, firewall, audit


async def test_mixed_intrusion_produces_one_incident_and_publishes_events(
    settings: Settings,
) -> None:
    bus = EventBus()
    pipeline, firewall, _ = make_pipeline(settings, bus)
    await pipeline.start()
    received: list[str] = []

    async def consume() -> None:
        async with bus.subscribe("test") as stream:
            async for event in stream:
                received.append(event.type.value)

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0)
    report = await pipeline.run(MockCapture(get_scenario("mixed_intrusion").frames))
    await asyncio.sleep(0.05)
    consumer.cancel()
    await pipeline.stop()

    assert {r.detection.detector for r in report.detections} >= {
        "tcp_port_scan",
        "ssh_brute_force",
        "icmp_flood",
    }
    assert len(report.incidents) == 1
    incident = next(iter(report.incidents.values()))
    assert incident.title == "Potential host compromise attempt" and incident.risk.score >= 90
    assert (
        EventType.DETECTION_CREATED.value in received
        and EventType.INCIDENT_OPENED.value in received
    )
    assert EventType.PACKET_STATS.value in received
    assert firewall.operations == []  # default posture never blocks


async def test_prevention_blocks_attacker_once(settings: Settings) -> None:
    settings.response.mode = ResponseMode.AUTOMATIC
    settings.response.dry_run = False
    pipeline, firewall, audit = make_pipeline(settings)
    await pipeline.start()
    await pipeline.run(MockCapture(get_scenario("mixed_intrusion").frames))
    await pipeline.stop()
    assert firewall.operations == [("block", "203.0.113.200/32")]
    assert [a["outcome"] for a in audit] == ["executed"]


async def test_replay_matches_in_memory_run(settings: Settings, tmp_path: Path) -> None:
    """PCAP replay must produce exactly what feeding the same frames directly produces."""
    scenario = get_scenario("mixed_intrusion")
    path = tmp_path / "mixed.pcap"
    write_pcap(path, scenario.frames)

    direct, _, _ = make_pipeline(settings)
    await direct.start()
    direct_report = await direct.run(MockCapture(scenario.frames))
    await direct.stop()

    replayed, _, _ = make_pipeline(
        Settings(storage={"database_url": "sqlite+aiosqlite:///:memory:"})
    )
    await replayed.start()
    replay_report = await replayed.run(PcapFileCapture(path))
    await replayed.stop()

    def signature(report) -> list[tuple[str, str, str]]:  # type: ignore[no-untyped-def]
        return [
            (r.detection.detector, r.detection.source_ip, r.detection.severity.value)
            for r in report.detections
        ]

    assert signature(direct_report) == signature(replay_report)
    assert replay_report.frames == len(scenario.frames)


async def test_benign_traffic_report_is_clean_and_measured(settings: Settings) -> None:
    pipeline, _, _ = make_pipeline(settings)
    await pipeline.start()
    report = await pipeline.run(
        MockCapture(get_scenario("normal_traffic", packet_count=2000).frames)
    )
    await pipeline.stop()
    data = report.as_dict()
    assert data["detection_count"] == 0 and data["incident_count"] == 0
    assert data["frames"] == 2000 and data["packets_per_second"] > 0
    assert data["latency"]["per_packet_p99_ms"] > 0
