from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx.capture import (
    MockCapture,
    PcapFileCapture,
    RawFrame,
    create_capture,
    list_interfaces,
    pcap_metadata,
)
from sentinelx.capture.live import LiveCapture
from sentinelx.common.errors import InterfaceNotFoundError, PcapError
from sentinelx.config.settings import CaptureSettings
from sentinelx.testing import get_scenario, write_pcap


async def collect(capture) -> list[RawFrame]:  # type: ignore[no-untyped-def]
    async with capture:
        return [frame async for frame in capture.frames()]


async def test_pcap_round_trip_preserves_bytes_and_timestamps(tmp_path: Path) -> None:
    scenario = get_scenario("tcp_port_scan", ports=30)
    path = tmp_path / "scan.pcap"
    assert write_pcap(path, scenario.frames) == len(scenario.frames)

    frames = await collect(PcapFileCapture(path))
    assert len(frames) == len(scenario.frames)
    for original, replayed in zip(scenario.frames, frames, strict=True):
        assert replayed.data == original.data
        assert replayed.timestamp == pytest.approx(original.timestamp, abs=1e-6)


async def test_pcap_limit_and_stats(tmp_path: Path) -> None:
    path = tmp_path / "n.pcap"
    write_pcap(path, get_scenario("normal_traffic", packet_count=100).frames)
    capture = PcapFileCapture(path, limit=25)
    frames = await collect(capture)
    assert len(frames) == 25
    assert capture.stats.received == 25 and capture.stats.bytes_received > 0


def test_pcap_metadata(tmp_path: Path) -> None:
    path = tmp_path / "m.pcap"
    scenario = get_scenario("icmp_flood", count=50)
    write_pcap(path, scenario.frames)
    meta = pcap_metadata(path)
    assert meta["packet_count"] == 50
    assert meta["duration_seconds"] == pytest.approx(scenario.duration_seconds, abs=1e-3)


@pytest.mark.parametrize("content", [None, b"", b"definitely not a pcap file at all"])
async def test_invalid_pcap_raises_pcap_error(tmp_path: Path, content: bytes | None) -> None:
    path = tmp_path / "bad.pcap"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(PcapError):
        await collect(PcapFileCapture(path))


async def test_paced_replay_respects_speed(tmp_path: Path) -> None:
    frames = [RawFrame(data=get_scenario("icmp_flood", count=1).frames[0].data, timestamp=100.0 + i * 0.05) for i in range(5)]
    path = tmp_path / "paced.pcap"
    write_pcap(path, frames)
    import time

    start = time.perf_counter()
    await collect(PcapFileCapture(path, speed=1.0))
    assert time.perf_counter() - start >= 0.15  # 4 gaps of 50ms at real time


async def test_mock_capture_repeat_and_stop() -> None:
    frames = get_scenario("icmp_flood", count=10).frames
    assert len(await collect(MockCapture(frames, repeat=3))) == 30

    capture = MockCapture(frames)
    seen = 0
    async with capture:
        async for _ in capture.frames():
            seen += 1
            if seen == 4:
                capture.stop()
    assert seen == 4


def test_mock_capture_rejects_invalid_repeat() -> None:
    with pytest.raises(ValueError):
        MockCapture([], repeat=0)


def test_factory_selects_pcap_or_live(tmp_path: Path) -> None:
    assert isinstance(create_capture(CaptureSettings(), pcap_path=tmp_path / "x.pcap"), PcapFileCapture)
    assert isinstance(create_capture(CaptureSettings(interface="lo")), LiveCapture)


def test_list_interfaces_includes_loopback() -> None:
    names = {entry["name"] for entry in list_interfaces()}
    if names:  # Linux with /sys mounted
        assert "lo" in names


async def test_live_capture_unknown_interface_names_alternatives() -> None:
    if not list_interfaces():
        pytest.skip("interface enumeration unavailable")
    with pytest.raises(InterfaceNotFoundError) as excinfo:
        await LiveCapture("definitely-not-an-iface0").open()
    assert "lo" in excinfo.value.available
