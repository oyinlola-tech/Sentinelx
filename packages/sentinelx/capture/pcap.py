"""PCAP file replay.

Replay feeds frames through the identical code path as live capture, so a
detection that fires on a capture file would have fired on the wire.  That
property is what makes the PCAP Lab a real test harness rather than a demo.

The reader uses Scapy's ``RawPcapReader``/``RawPcapNgReader``, which hand back raw
bytes and the file's link type without constructing a packet object per record.
That is the one place Scapy is genuinely the right tool: file-format handling
(pcap, pcapng, both endiannesses, nanosecond timestamps) is fiddly and it is
already correct, while the per-packet decode - the part that has to be fast - is
ours.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from sentinelx.capture.base import PacketCapture, RawFrame
from sentinelx.common.errors import PcapError
from sentinelx.parser.layers import LinkType
from sentinelx.telemetry.logging import get_logger

__all__ = ["PcapFileCapture", "pcap_metadata"]

log = get_logger(__name__)

#: Frames read between event-loop yields. Replay is CPU-bound and synchronous;
#: without periodic yields it would starve the API and WebSocket tasks sharing
#: the loop. 256 keeps the loop responsive at a negligible throughput cost.
_YIELD_EVERY = 256


def _open_reader(path: Path) -> tuple[Any, int]:
    """Open a capture file, returning ``(reader, link_type)``.

    Raises:
        PcapError: if the file is missing, unreadable, or not a capture file.
    """
    try:
        from scapy.utils import RawPcapNgReader, RawPcapReader
    except ImportError as exc:  # pragma: no cover - scapy is a hard dependency
        raise PcapError("scapy is required to read capture files") from exc

    if not path.exists():
        raise PcapError(f"capture file not found: {path}")
    if not path.is_file():
        raise PcapError(f"not a regular file: {path}")
    if path.stat().st_size == 0:
        raise PcapError(f"capture file is empty: {path}")

    try:
        reader: Any = RawPcapReader(str(path))
        return reader, int(getattr(reader, "linktype", LinkType.ETHERNET))
    except Exception as pcap_exc:
        # pcapng has a different magic; try it before giving up.
        try:
            reader = RawPcapNgReader(str(path))
        except Exception as png_exc:
            raise PcapError(
                f"{path} is not a readable pcap or pcapng file ({pcap_exc}; {png_exc})"
            ) from png_exc
        return reader, int(getattr(reader, "linktype", LinkType.ETHERNET) or LinkType.ETHERNET)


def _frame_timestamp(metadata: Any, index: int) -> float:
    """Extract a UNIX timestamp from a reader's per-packet metadata.

    pcap and pcapng expose this differently (``sec``/``usec`` vs ``tshigh``/
    ``tslow``/``tsresol``), and older Scapy versions differ again.  Falling back to
    the record index keeps replay ordered even for a file with unusable
    timestamps, rather than collapsing every packet onto time zero and destroying
    the sliding windows every detector depends on.
    """
    sec = getattr(metadata, "sec", None)
    if sec is not None:
        usec = getattr(metadata, "usec", 0) or 0
        return float(sec) + float(usec) / 1_000_000.0

    tshigh = getattr(metadata, "tshigh", None)
    tslow = getattr(metadata, "tslow", None)
    if tshigh is not None and tslow is not None:
        resolution = getattr(metadata, "tsresol", 1_000_000) or 1_000_000
        return ((tshigh << 32) | tslow) / float(resolution)

    return float(index) * 0.001


def pcap_metadata(path: Path | str) -> dict[str, Any]:
    """Summarise a capture file without running a full replay.

    Reads every record header to count packets and measure the timespan, which is
    what the PCAP Lab shows before you commit to a replay.

    Raises:
        PcapError: if the file cannot be read as a capture.
    """
    path = Path(path)
    reader, link_type = _open_reader(path)
    count = 0
    total_bytes = 0
    first: float | None = None
    last: float | None = None
    try:
        for index, (data, metadata) in enumerate(reader):
            count += 1
            total_bytes += len(data)
            timestamp = _frame_timestamp(metadata, index)
            if first is None:
                first = timestamp
            last = timestamp
    finally:
        reader.close()

    span = (last - first) if (first is not None and last is not None) else 0.0
    return {
        "path": str(path),
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "packet_count": count,
        "total_bytes": total_bytes,
        "link_type": link_type,
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
        self._reader: Any | None = None
        self._link_type: int = LinkType.ETHERNET

    async def _open(self) -> None:
        # Opening reads the file header; doing it in a thread keeps a slow or
        # networked filesystem from blocking the event loop.
        self._reader, self._link_type = await asyncio.to_thread(_open_reader, self.path)
        log.info(
            "pcap_opened",
            path=str(self.path),
            link_type=self._link_type,
            speed=self.speed or "max",
        )

    async def _frames(self) -> AsyncIterator[RawFrame]:
        reader = self._reader
        if reader is None:
            raise PcapError("capture file is not open")

        base_capture_time: float | None = None
        replay_start = asyncio.get_running_loop().time()
        time_offset = 0.0
        index = -1

        for index, (data, metadata) in enumerate(reader):
            if not self.running:
                break
            if self.limit is not None and index >= self.limit:
                break

            timestamp = _frame_timestamp(metadata, index)
            if base_capture_time is None:
                base_capture_time = timestamp
                if self.rewrite_timestamps:
                    time_offset = asyncio.get_running_loop().time() - timestamp

            if self.speed > 0 and base_capture_time is not None:
                await self._pace(timestamp - base_capture_time, replay_start)

            # pcapng records carry the wire length; pcap ones may not.
            wire_length = int(getattr(metadata, "wirelen", 0) or len(data))

            yield RawFrame(
                data=bytes(data),
                timestamp=timestamp + time_offset,
                link_type=self._link_type,
                interface=self.interface,
                wire_length=wire_length,
            )
            if (index + 1) % _YIELD_EVERY == 0:
                await asyncio.sleep(0)

    async def _pace(self, capture_elapsed: float, replay_start: float) -> None:
        """Sleep so replay tracks the original timing at ``self.speed``."""
        target = capture_elapsed / self.speed
        actual = asyncio.get_running_loop().time() - replay_start
        delay = target - actual
        if delay > 0:
            await asyncio.sleep(min(delay, self.max_sleep_seconds))

    async def _close(self) -> None:
        reader = self._reader
        self._reader = None
        if reader is not None:
            await asyncio.to_thread(reader.close)
