"""PCAP file replay.

Replay feeds frames through the identical code path as live capture, so a
detection that fires on a capture file would have fired on the wire.  That
property is what makes the PCAP Lab a real test harness rather than a demo.

Files are read by :mod:`sentinelx.capture.pcapfile`, a streaming reader for pcap
and pcapng that honours nanosecond timestamps and per-interface link types and
validates every length field. It needs no privileges and no capture library, so
replay works on every platform.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

from sentinelx.capture.base import PacketCapture, RawFrame
from sentinelx.capture.pcapfile import CaptureRecord, read_capture
from sentinelx.common.errors import PcapError
from sentinelx.telemetry.logging import get_logger

__all__ = ["PcapFileCapture", "pcap_metadata"]

log = get_logger(__name__)

#: Longest the replay may run the event loop without yielding. Replay is CPU-bound
#: (decode, detection, scoring) and shares the loop with the API, WebSocket and
#: database tasks; yielding on a time budget keeps them responsive.
_YIELD_AFTER_SECONDS = 0.005


def _check_file(path: Path) -> None:
    if not path.exists():
        raise PcapError(f"capture file not found: {path.name}")
    if not path.is_file():
        raise PcapError(f"not a regular file: {path.name}")
    if path.stat().st_size == 0:
        raise PcapError(f"capture file is empty: {path.name}")


def pcap_metadata(path: Path | str) -> dict[str, Any]:
    """Summarise a capture file without running a full replay.

    Reads every record header to count packets and measure the timespan, which is
    what the PCAP Lab shows before you commit to a replay.

    Raises:
        PcapError: if the file cannot be read as a capture.
    """
    path = Path(path)
    _check_file(path)
    count = 0
    total_bytes = 0
    first: float | None = None
    last: float | None = None
    link_types: set[int] = set()
    for record in read_capture(path):
        count += 1
        total_bytes += len(record.data)
        link_types.add(record.link_type)
        if first is None:
            first = record.timestamp
        last = record.timestamp
    span = (last - first) if (first is not None and last is not None) else 0.0
    return {
        "path": str(path),
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "packet_count": count,
        "total_bytes": total_bytes,
        "link_type": min(link_types) if link_types else None,
        "link_types": sorted(link_types),
        "first_timestamp": first,
        "last_timestamp": last,
        "duration_seconds": round(span, 6),
        "average_packet_size": round(total_bytes / count, 1) if count else 0.0,
    }


class PcapFileCapture(PacketCapture):
    """Replays a capture file through the standard capture interface.

    Args:
        path: pcap or pcapng file to read.
        speed: replay pacing. ``0`` (default) is as fast as possible, which is
            what tests and benchmarks want. ``1.0`` reproduces the original
            inter-packet timing; ``2.0`` is twice real time. Pacing sleeps are
            capped so a capture with a one-hour gap does not stall a replay.
        rewrite_timestamps: when True, present the packets as if captured now.
            Off by default - detectors window on packet time, and preserving the
            original timing is what makes replay faithful.
        limit: stop after this many packets. Useful for sampling a large file.

    Example:
        >>> async with PcapFileCapture("scan.pcap", speed=0) as capture:
        ...     async for frame in capture.frames():
        ...         ...
    """

    source_kind = "pcap"

    def __init__(
        self,
        path: Path | str,
        *,
        speed: float = 0.0,
        rewrite_timestamps: bool = False,
        limit: int | None = None,
        max_sleep_seconds: float = 1.0,
    ) -> None:
        super().__init__(interface=f"pcap:{Path(path).name}")
        self.path = Path(path)
        if speed < 0:
            raise ValueError(f"speed must be >= 0, got {speed}")
        self.speed = speed
        self.rewrite_timestamps = rewrite_timestamps
        self.limit = limit
        self.max_sleep_seconds = max_sleep_seconds
        self._records: Iterator[CaptureRecord] | None = None

    async def _open(self) -> None:
        # Validates the file header now, so a bad file fails at open, not mid-replay.
        # Done in a thread so a slow or networked filesystem cannot block the loop.
        await asyncio.to_thread(_check_file, self.path)
        records = read_capture(self.path)
        first = await asyncio.to_thread(next, records, None)
        self._records = _prepend(first, records)
        log.info("pcap_opened", path=self.path.name, speed=self.speed or "max")

    async def _frames(self) -> AsyncIterator[RawFrame]:
        records = self._records
        if records is None:
            raise PcapError("capture file is not open")

        base_capture_time: float | None = None
        loop = asyncio.get_running_loop()
        replay_start = loop.time()
        time_offset = 0.0
        last_yield = time.perf_counter()

        for index, record in enumerate(records):
            if not self.running:
                break
            if self.limit is not None and index >= self.limit:
                break

            timestamp = record.timestamp
            if base_capture_time is None:
                base_capture_time = timestamp
                if self.rewrite_timestamps:
                    time_offset = time.time() - timestamp

            if self.speed > 0:
                await self._pace(timestamp - base_capture_time, replay_start)

            yield RawFrame(
                data=record.data,
                timestamp=timestamp + time_offset,
                link_type=record.link_type,
                interface=self.interface,
                wire_length=record.wire_length,
            )
            now = time.perf_counter()
            if now - last_yield > _YIELD_AFTER_SECONDS:
                await asyncio.sleep(0)
                last_yield = time.perf_counter()

    async def _pace(self, capture_elapsed: float, replay_start: float) -> None:
        """Sleep so replay tracks the original timing at ``self.speed``."""
        target = capture_elapsed / self.speed
        actual = asyncio.get_running_loop().time() - replay_start
        delay = target - actual
        if delay > 0:
            await asyncio.sleep(min(delay, self.max_sleep_seconds))

    async def _close(self) -> None:
        records, self._records = self._records, None
        if records is not None and hasattr(records, "close"):
            records.close()  # closes the file handle held by the generator


def _prepend(first: CaptureRecord | None, rest: Iterator[CaptureRecord]) -> Iterator[CaptureRecord]:
    if first is not None:
        yield first
        yield from rest
