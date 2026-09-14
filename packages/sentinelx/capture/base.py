"""The packet-source abstraction.

Everything that can produce packets implements :class:`PacketCapture`.  The
pipeline consumes that interface and nothing else, which is what makes the three
concrete sources - a live interface, a PCAP file, and a synthetic generator -
interchangeable, and what makes "replay a PCAP through the *same* engine that
handles live traffic" true rather than aspirational.

Capture yields :class:`RawFrame` (bytes plus capture metadata), not decoded
packets.  Decoding belongs to :mod:`sentinelx.parser`, so a future capture
implementation in another language only has to produce frames.
"""

from __future__ import annotations

import abc
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Self

from sentinelx.parser.layers import LinkType
from sentinelx.telemetry.logging import get_logger

__all__ = ["CaptureCapabilities", "CaptureStats", "PacketCapture", "RawFrame"]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RawFrame:
    """One captured frame, before decoding.

    ``wire_length`` may exceed ``len(data)`` when the snapshot length truncated
    the capture.  Keeping both is what lets throughput accounting stay honest on a
    sensor configured with a small snaplen.
    """

    data: bytes
    timestamp: float
    link_type: int = LinkType.ETHERNET
    interface: str = "unknown"
    wire_length: int = 0

    def __post_init__(self) -> None:
        if self.wire_length == 0:
            object.__setattr__(self, "wire_length", len(self.data))

    @property
    def truncated(self) -> bool:
        return self.wire_length > len(self.data)


@dataclass
class CaptureStats:
    """Counters reported by a capture source.

    ``dropped_kernel`` is what libpcap/the kernel reports as lost before userspace
    saw it; ``dropped_queue`` is what *we* lost because the pipeline could not keep
    up.  They have different remedies (bigger ring buffer vs. faster processing),
    so they are never merged into one number.
    """

    received: int = 0
    bytes_received: int = 0
    dropped_kernel: int = 0
    dropped_queue: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.monotonic)
    first_packet_time: float | None = None
    last_packet_time: float | None = None

    @property
    def elapsed_seconds(self) -> float:
        return max(time.monotonic() - self.started_at, 1e-9)

    @property
    def packets_per_second(self) -> float:
        """Measured rate. Wall-clock based, so it is meaningful for live capture
        and for replay speed alike."""
        return self.received / self.elapsed_seconds

    @property
    def megabits_per_second(self) -> float:
        return (self.bytes_received * 8) / self.elapsed_seconds / 1_000_000

    @property
    def capture_span_seconds(self) -> float:
        """Timespan covered by the packets themselves, not by the run."""
        if self.first_packet_time is None or self.last_packet_time is None:
            return 0.0
        return self.last_packet_time - self.first_packet_time

    @property
    def total_dropped(self) -> int:
        return self.dropped_kernel + self.dropped_queue

    @property
    def drop_rate(self) -> float:
        """Fraction of offered packets lost, 0.0-1.0."""
        offered = self.received + self.total_dropped
        return self.total_dropped / offered if offered else 0.0

    def record(self, frame: RawFrame) -> None:
        self.received += 1
        self.bytes_received += frame.wire_length
        if self.first_packet_time is None:
            self.first_packet_time = frame.timestamp
        self.last_packet_time = frame.timestamp

    def as_dict(self) -> dict[str, float | int]:
        return {
            "received": self.received,
            "bytes_received": self.bytes_received,
            "dropped_kernel": self.dropped_kernel,
            "dropped_queue": self.dropped_queue,
            "errors": self.errors,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "packets_per_second": round(self.packets_per_second, 2),
            "megabits_per_second": round(self.megabits_per_second, 3),
            "capture_span_seconds": round(self.capture_span_seconds, 3),
            "drop_rate": round(self.drop_rate, 6),
        }


@dataclass(frozen=True, slots=True)
class CaptureCapabilities:
    """What a capture backend can do on *this* host, determined at runtime."""

    backend: str
    available: bool
    """The backend can be opened here (library present and privileges granted)."""
    live: bool
    """Captures traffic from a network interface, as opposed to a file or generator."""
    reason: str = ""
    """Why it is unavailable, or what it relies on when available."""
    remedy: str = ""
    """How to make it available."""
    bpf_filter: bool = False
    any_interface: bool = False
    """Supports capturing from every interface at once."""
    promiscuous: bool = False
    kernel_drop_counters: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "available": self.available,
            "live": self.live,
            "reason": self.reason,
            "remedy": self.remedy,
            "bpf_filter": self.bpf_filter,
            "any_interface": self.any_interface,
            "promiscuous": self.promiscuous,
            "kernel_drop_counters": self.kernel_drop_counters,
        }


class PacketCapture(abc.ABC):
    """Base class for packet sources.

    Subclasses implement :meth:`_open`, :meth:`_frames` and :meth:`_close`.  The
    base class owns lifecycle, statistics and the async-context-manager protocol so
    every source behaves identically to the pipeline.

    Example:
        >>> async with PcapFileCapture("suspicious.pcap") as capture:
        ...     async for frame in capture.frames():
        ...         handle(frame)
    """

    #: Human-readable source kind, used as a metric label and in status output.
    source_kind: str = "unknown"

    def __init__(self, *, interface: str = "unknown") -> None:
        self.interface = interface
        self.stats = CaptureStats()
        self._running = False
        self._opened = False

    # ------------------------------------------------------------- lifecycle

    async def open(self) -> None:
        """Acquire the underlying source.

        Raises:
            CaptureError: or a subclass, when the source cannot be opened. The
                message names the concrete problem (missing interface, missing
                privilege, unreadable file) so the CLI can print something useful.
        """
        if self._opened:
            return
        await self._open()
        self._opened = True
        self._running = True
        self.stats = CaptureStats()
        log.info("capture_opened", source=self.source_kind, interface=self.interface)

    async def close(self) -> None:
        """Release the source. Safe to call repeatedly and after a failed open."""
        if not self._opened:
            self._running = False
            return
        self._running = False
        self._opened = False
        try:
            await self._close()
        finally:
            log.info("capture_closed", source=self.source_kind, **self.stats.as_dict())

    def stop(self) -> None:
        """Ask the frame iterator to finish at the next opportunity.

        Cooperative rather than forceful: the iterator checks :attr:`running` so a
        frame already in flight is delivered instead of being lost mid-stream.
        """
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    async def __aenter__(self) -> Self:
        await self.open()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # -------------------------------------------------------------- iteration

    async def frames(self) -> AsyncIterator[RawFrame]:
        """Yield frames until the source is exhausted or :meth:`stop` is called.

        Statistics are recorded here, once, so every source reports them the same
        way whatever its internals look like.
        """
        if not self._opened:
            await self.open()
        async for frame in self._frames():
            self.stats.record(frame)
            yield frame
            if not self._running:
                break

    # ----------------------------------------------------- subclass interface

    @abc.abstractmethod
    async def _open(self) -> None:
        """Acquire the source. Raise a CaptureError subclass on failure."""

    @abc.abstractmethod
    def _frames(self) -> AsyncIterator[RawFrame]:
        """Produce frames. Must be an async generator."""

    @abc.abstractmethod
    async def _close(self) -> None:
        """Release the source. Must tolerate being called after a failed open."""

    # ------------------------------------------------------------ discovery

    @classmethod
    def capabilities(cls) -> CaptureCapabilities:
        """What this kind of source can do on this host. Live backends override it."""
        return CaptureCapabilities(backend=cls.source_kind, available=True, live=False)

    @staticmethod
    def list_interfaces() -> list[dict[str, Any]]:
        """Interfaces this source can capture from. Empty for non-live sources."""
        return []

    # ----------------------------------------------------------------- status

    def describe(self) -> dict[str, object]:
        """Source description for ``sentinelx status`` and the API."""
        return {
            "kind": self.source_kind,
            "interface": self.interface,
            "running": self._running,
            "stats": self.stats.as_dict(),
        }
