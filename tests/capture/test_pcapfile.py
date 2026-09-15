"""The capture-file reader: formats, resolutions, link types and hostile input."""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from sentinelx.capture import PcapFileCapture
from sentinelx.capture.pcapfile import read_capture
from sentinelx.common.errors import PcapError
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.parser.layers import LinkType
from sentinelx.testing import get_scenario, write_pcap

FRAME = get_scenario("tcp_port_scan", ports=3).frames[0].data


def pcap(magic: int, order: str, records: list[tuple[int, int, bytes]], link: int = 1) -> bytes:
    body = struct.pack(f"{order}IHHiIII", magic, 2, 4, 0, 0, 65535, link)
    for seconds, fraction, data in records:
        body += struct.pack(f"{order}IIII", seconds, fraction, len(data), len(data)) + data
    return body


def block(kind: int, body: bytes) -> bytes:
    padded = body + b"\0" * (-len(body) % 4)
    length = 12 + len(padded)
    return struct.pack("<II", kind, length) + padded + struct.pack("<I", length)


def pcapng(
    interfaces: list[tuple[int, int | None]], packets: list[tuple[int, int, bytes]]
) -> bytes:
    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    for link, tsresol in interfaces:
        options = b""
        if tsresol is not None:
            options = (
                struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\0\0\0" + struct.pack("<HH", 0, 0)
            )
        data += block(1, struct.pack("<HHI", link, 0, 65535) + options)
    for interface, ticks, frame in packets:
        data += block(
            6,
            struct.pack(
                "<IIIII", interface, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)
            )
            + frame,
        )
    return data


def test_nanosecond_pcap_timestamps_are_not_read_as_microseconds(tmp_path: Path) -> None:
    path = tmp_path / "ns.pcap"
    path.write_bytes(pcap(0xA1B23C4D, "<", [(100, 500_000_000, FRAME), (100, 750_000_000, FRAME)]))
    stamps = [r.timestamp for r in read_capture(path)]
    assert stamps == pytest.approx([100.5, 100.75])


def test_big_endian_microsecond_pcap(tmp_path: Path) -> None:
    path = tmp_path / "be.pcap"
    path.write_bytes(pcap(0xA1B2C3D4, ">", [(7, 250_000, FRAME)]))
    (record,) = list(read_capture(path))
    assert record.timestamp == pytest.approx(7.25) and record.data == FRAME


def test_pcapng_link_type_and_resolution_are_per_interface(tmp_path: Path) -> None:
    cooked = b"\x00\x00\x00\x01\x00\x06" + FRAME[6:12] + b"\x00\x00" + FRAME[12:]
    path = tmp_path / "mixed.pcapng"
    path.write_bytes(
        pcapng(
            [(LinkType.ETHERNET, None), (LinkType.LINUX_SLL, 9)],
            [(0, 2_000_000, FRAME), (1, 3_500_000_000, cooked)],
        )
    )
    records = list(read_capture(path))
    assert [r.link_type for r in records] == [LinkType.ETHERNET, LinkType.LINUX_SLL]
    assert [r.timestamp for r in records] == pytest.approx([2.0, 3.5])
    decoder = PacketDecoder()
    assert all(decoder.decode(r.data, r.timestamp, r.link_type) is not None for r in records)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "empty"),
        (b"GIF89a", "not a pcap"),
        (pcap(0xA1B2C3D4, "<", [])[:10], "truncated"),
        (pcap(0xA1B2C3D4, "<", [(1, 0, FRAME)])[:-5], "truncated"),
        (
            pcap(0xA1B2C3D4, "<", []) + struct.pack("<IIII", 0, 0, 2**31, 2**31),
            "corrupt",
        ),
        (
            block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            + struct.pack("<II", 6, 0x7FFFFFF0),
            "invalid block length",
        ),
        (pcapng([], [(3, 0, FRAME)]), "undeclared interface"),
    ],
    ids=[
        "empty",
        "not-capture",
        "short-header",
        "short-record",
        "huge-record",
        "huge-block",
        "no-interface",
    ],
)
def test_hostile_or_broken_files_raise_pcap_error(
    tmp_path: Path, content: bytes, message: str
) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(PcapError, match=message):
        list(read_capture(path))


@pytest.mark.skipif(shutil.which("editcap") is None, reason="Wireshark editcap not installed")
@pytest.mark.parametrize("fmt", ["pcapng", "nsecpcap"])
def test_files_written_by_wireshark_tools_replay_identically(tmp_path: Path, fmt: str) -> None:
    frames = get_scenario("mixed_intrusion").frames[:500]
    source = tmp_path / "source.pcap"
    write_pcap(source, frames)
    converted = tmp_path / f"converted.{fmt}"
    subprocess.run(["editcap", "-F", fmt, str(source), str(converted)], check=True)  # noqa: S603, S607
    records = list(read_capture(converted))
    assert [r.data for r in records] == [f.data for f in frames]
    assert [r.timestamp for r in records] == pytest.approx([f.timestamp for f in frames], abs=1e-6)


async def test_replay_uses_per_record_link_type(tmp_path: Path) -> None:
    cooked = b"\x00\x00\x00\x01\x00\x06" + FRAME[6:12] + b"\x00\x00" + FRAME[12:]
    path = tmp_path / "cooked.pcapng"
    path.write_bytes(pcapng([(LinkType.LINUX_SLL, None)], [(0, 1_000_000, cooked)]))
    async with PcapFileCapture(path) as capture:
        frames = [frame async for frame in capture.frames()]
    assert frames[0].link_type == LinkType.LINUX_SLL
    assert (
        PacketDecoder().decode(frames[0].data, frames[0].timestamp, frames[0].link_type) is not None
    )


def test_generated_fixtures_are_byte_identical_across_runs(tmp_path: Path) -> None:
    # Header fields (IP id, TCP sequence, DNS id) used to come from the global random
    # module, so every "sentinelx fixtures generate" wrote different files.
    first, second = tmp_path / "a.pcap", tmp_path / "b.pcap"
    write_pcap(first, get_scenario("mixed_intrusion").frames)
    write_pcap(second, get_scenario("mixed_intrusion").frames)
    assert first.read_bytes() == second.read_bytes()
    reseeded = get_scenario("normal_traffic", seed=8).frames
    assert [f.data for f in reseeded] != [f.data for f in get_scenario("normal_traffic").frames]
