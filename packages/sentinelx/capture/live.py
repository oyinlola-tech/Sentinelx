"""Live interface capture, with the backend chosen for the host it runs on.

``af_packet`` (Linux)
    Raw ``AF_PACKET`` sockets: fastest, kernel BPF, kernel drop counters.
    See :mod:`sentinelx.capture.afpacket`.

``libpcap`` (Linux, macOS, Windows)
    libpcap through Scapy: ``/dev/bpf*`` on macOS, the Npcap driver on Windows.
    See :mod:`sentinelx.capture.libpcap`.

``auto`` tries them in that order and falls back *only* when a backend cannot run on
this host at all. Permission problems, unknown interfaces and invalid BPF filters are
reported as they are, because falling back would hide them.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from sentinelx.capture.afpacket import AfPacketCapture
from sentinelx.capture.base import CaptureCapabilities, PacketCapture, RawFrame
from sentinelx.capture.libpcap import PcapLiveCapture
from sentinelx.common.errors import BackendUnavailableError, CaptureError
from sentinelx.system.interfaces import list_interfaces as _list_interfaces
from sentinelx.telemetry.logging import get_logger

__all__ = ["LIVE_BACKENDS", "LiveCapture"]

log = get_logger(__name__)

PLATFORM: str = sys.platform

LIVE_BACKENDS: dict[str, type[PacketCapture]] = {
    "af_packet": AfPacketCapture,
    "libpcap": PcapLiveCapture,
}


def _auto_order() -> list[str]:
    return ["af_packet", "libpcap"] if PLATFORM.startswith("linux") else ["libpcap"]


class LiveCapture(PacketCapture):
    """Captures from a live interface using the best backend available here.

    Args:
        interface: interface name, or ``"any"`` for every interface.
        backend: ``"auto"``, ``"af_packet"`` or ``"libpcap"``.
        bpf_filter: kernel BPF expression, e.g. ``"tcp or udp"``.
        snapshot_length: bytes captured per frame.
        promiscuous: put a named interface into promiscuous mode.
        buffer_size_mb: kernel receive buffer.

    Raises:
        PermissionDeniedError: the process lacks the privilege capture needs here.
        InterfaceNotFoundError: the interface does not exist.
        BackendUnavailableError: no backend can run on this host.
        CaptureError: any other failure, including an invalid BPF filter.
    """

    source_kind = "live"
    backend_names: ClassVar[tuple[str, ...]] = ("auto", *LIVE_BACKENDS)

    def __init__(
        self,
        interface: str = "any",
        *,
        backend: str = "auto",
        bpf_filter: str = "",
        snapshot_length: int = 2048,
        promiscuous: bool = True,
        buffer_size_mb: int = 16,
        queue_size: int = 20_000,
    ) -> None:
        if backend not in self.backend_names:
            raise CaptureError(
                f"unknown capture backend {backend!r}; choose one of {', '.join(self.backend_names)}"
            )
        super().__init__(interface=interface)
        self.requested_backend = backend
        self.backend = "none"
        self.bpf_filter = bpf_filter
        self._options: dict[str, Any] = {
            "bpf_filter": bpf_filter,
            "snapshot_length": snapshot_length,
            "promiscuous": promiscuous,
            "buffer_size_mb": buffer_size_mb,
        }
        self._queue_size = queue_size
        self._inner: PacketCapture | None = None

    # ------------------------------------------------------------ discovery

    @classmethod
    def capabilities(cls, backend: str = "auto") -> CaptureCapabilities:
        """The backend ``auto`` would use, or why none is usable."""
        order = _auto_order() if backend == "auto" else [backend]
        reports = [LIVE_BACKENDS[name].capabilities() for name in order if name in LIVE_BACKENDS]
        for report in reports:
            if report.available:
                return report
        if not reports:
            return CaptureCapabilities(
                backend=backend, available=False, live=True, reason="unknown backend"
            )
        # Prefer the explanation of the backend that exists on this OS but lacks
        # privileges over one that cannot exist here at all.
        first = reports[0]
        for report in reports:
            if report.remedy:
                return report
        return first

    @staticmethod
    def list_interfaces() -> list[dict[str, Any]]:
        return _list_interfaces()

    # ------------------------------------------------------------- lifecycle

    async def _open(self) -> None:
        order = _auto_order() if self.requested_backend == "auto" else [self.requested_backend]
        unavailable: list[str] = []
        for name in order:
            options = dict(self._options)
            if name == "libpcap":
                options["queue_size"] = self._queue_size
            inner = LIVE_BACKENDS[name](self.interface, **options)  # type: ignore[call-arg]
            try:
                await inner.open()
            except BackendUnavailableError as exc:
                unavailable.append(f"{name}: {exc}")
                log.info("capture_backend_unavailable", backend=name, reason=str(exc))
                continue
            self._inner, self.backend = inner, name
            return
        raise BackendUnavailableError(
            "no live capture backend can run on this host (" + "; ".join(unavailable) + "). "
            "PCAP replay does not need live capture."
        )

    async def _frames(self) -> AsyncIterator[RawFrame]:
        inner = self._inner
        if inner is None:
            raise CaptureError("live capture is not open")
        # One statistics object: the backend records drops, the base class records
        # received frames.
        inner.stats = self.stats
        async for frame in inner._frames():
            yield frame
            if not self.running:
                break

    def stop(self) -> None:
        super().stop()
        if self._inner is not None:
            self._inner.stop()

    async def _close(self) -> None:
        inner, self._inner = self._inner, None
        if inner is not None:
            await inner.close()

    def describe(self) -> dict[str, object]:
        info = self._inner.describe() if self._inner is not None else super().describe()
        info.update(
            kind=self.source_kind,
            interface=self.interface,
            running=self.running,
            backend=self.backend,
            requested_backend=self.requested_backend,
            stats=self.stats.as_dict(),
        )
        return info
