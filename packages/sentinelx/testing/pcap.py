"""Minimal libpcap file writer.

Writes the classic pcap format (not pcapng) with microsecond timestamps.  Kept
dependency-free so fixture generation works anywhere Python does, and so the
replay tests exercise a file written by something other than the reader under test.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

from sentinelx.capture.base import RawFrame
from sentinelx.parser.layers import LinkType

__all__ = ["write_pcap"]

_MAGIC = 0xA1B2C3D4
_VERSION = (2, 4)


def write_pcap(
    path: Path | str,
    frames: Iterable[RawFrame],
    *,
    link_type: int = LinkType.ETHERNET,
    snaplen: int = 65535,
) -> int:
    """Write frames to ``path``. Returns the number of records written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", _MAGIC, *_VERSION, 0, 0, snaplen, link_type))
        for frame in frames:
            seconds = int(frame.timestamp)
            micros = round((frame.timestamp - seconds) * 1_000_000)
            if micros >= 1_000_000:
                seconds, micros = seconds + 1, micros - 1_000_000
            data = frame.data[:snaplen]
            handle.write(
                struct.pack("<IIII", seconds, micros, len(data), frame.wire_length or len(data))
            )
            handle.write(data)
            count += 1
    return count
