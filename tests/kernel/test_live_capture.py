"""Live capture against a real kernel, for every backend."""

from __future__ import annotations

import asyncio
import socket

import pytest

from sentinelx.capture.afpacket import AfPacketCapture
from sentinelx.capture.base import PacketCapture, RawFrame
from sentinelx.capture.libpcap import PcapLiveCapture
from sentinelx.capture.live import LiveCapture
from sentinelx.common.errors import CaptureError
from sentinelx.parser.decoder import PacketDecoder


async def capture_udp(capture: PacketCapture, wanted: int = 10) -> list[RawFrame]:
    frames: list[RawFrame] = []

    async def send() -> None:
        await asyncio.sleep(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for index in range(3 * wanted):
                sender.sendto(b"sentinelx-%d" % index, ("127.0.0.1", 9999))
                await asyncio.sleep(0.01)

    async def read() -> None:
        async for frame in capture.frames():
            frames.append(frame)
            if len(frames) >= wanted:
                return

    async with capture:
        sender = asyncio.create_task(send())
        await asyncio.wait_for(read(), timeout=10)
        await sender
    return frames


def assert_decodes(frames: list[RawFrame]) -> None:
    decoder = PacketDecoder()
    packets = [decoder.decode(f.data, f.timestamp, f.link_type) for f in frames]
    assert frames and all(packet is not None for packet in packets)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: AfPacketCapture("lo"),
        # Regression: 'any' (the default interface) once decoded nothing.
        lambda: AfPacketCapture("any"),
        lambda: AfPacketCapture("lo", bpf_filter="udp and port 9999"),
        lambda: PcapLiveCapture("lo"),
        lambda: PcapLiveCapture("any"),
        lambda: LiveCapture("any"),
    ],
    ids=["af_packet-lo", "af_packet-any", "af_packet-bpf", "libpcap-lo", "libpcap-any", "auto-any"],
)
async def test_backend_captures_decodable_frames(factory) -> None:  # type: ignore[no-untyped-def]
    assert_decodes(await capture_udp(factory()))


async def test_bpf_filter_is_applied_in_the_kernel() -> None:
    frames = await capture_udp(AfPacketCapture("lo", bpf_filter="udp and port 9999"))
    decoder = PacketDecoder()
    assert {str(decoder.decode(f.data, f.timestamp, f.link_type).protocol) for f in frames} == {
        "udp"
    }  # type: ignore[union-attr]


@pytest.mark.parametrize("factory", [AfPacketCapture, PcapLiveCapture])
async def test_invalid_bpf_filter_is_refused_not_ignored(factory) -> None:  # type: ignore[no-untyped-def]
    # Regression: an invalid filter used to fall back silently to an unfiltered or
    # dead capture that reported itself as running.
    with pytest.raises(CaptureError, match="invalid BPF filter"):
        await factory("lo", bpf_filter="this is not bpf").open()
