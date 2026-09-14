"""Portable live capture through libpcap (macOS BPF devices, Windows Npcap).

Uses Scapy's sniffer, which reads from ``/dev/bpf*`` on macOS, from the Npcap
driver on Windows, and from libpcap or a packet socket elsewhere. It is slower than
:mod:`sentinelx.capture.afpacket` because Scapy builds an object per packet, and the
sensor reports which backend is running so a throughput figure is explainable.

Scapy runs its sniffer on a thread and keeps any error to itself. This module waits
for the sniffer to start and watches it while running, so a permission or driver
failure surfaces as an error instead of a capture that silently receives nothing.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

from sentinelx.capture.base import CaptureCapabilities, PacketCapture, RawFrame
from sentinelx.common.errors import (
    BackendUnavailableError,
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
)
from sentinelx.parser.layers import LinkType
from sentinelx.system.interfaces import list_interfaces as _list_interfaces
from sentinelx.system.privileges import capture_privilege, libpcap_library
from sentinelx.telemetry.logging import get_logger

__all__ = ["PcapLiveCapture"]

log = get_logger(__name__)

PLATFORM: str = sys.platform

_DECODABLE_LINK_TYPES = frozenset(
    {
        LinkType.NULL,
        LinkType.ETHERNET,
        LinkType.RAW,
        LinkType.LINUX_SLL,
        LinkType.IPV4,
        LinkType.IPV6,
        LinkType.LINUX_SLL2,
    }
)
_START_TIMEOUT = 5.0
_PERMISSION_MARKERS = ("permission", "not permitted", "access is denied", "administrator")


def _is_permission_error(exc: BaseException) -> bool:
    return isinstance(exc, PermissionError) or any(
        marker in str(exc).lower() for marker in _PERMISSION_MARKERS
    )


class PcapLiveCapture(PacketCapture):
    """Captures from one interface, or from every interface with ``"any"``."""

    source_kind = "live"
    backend = "libpcap"

    def __init__(
        self,
        interface: str = "any",
        *,
        bpf_filter: str = "",
        snapshot_length: int = 2048,
        promiscuous: bool = True,
        buffer_size_mb: int = 16,
        read_timeout: float = 0.5,
        queue_size: int = 20_000,
    ) -> None:
        super().__init__(interface=interface)
        self.bpf_filter = bpf_filter
        self.snapshot_length = snapshot_length
        self.promiscuous = promiscuous
        self.buffer_size_mb = buffer_size_mb
        self.read_timeout = read_timeout
        self.queue_size = queue_size
        self.unsupported_frames = 0
        self._sniffer: Any | None = None
        self._queue: asyncio.Queue[RawFrame] | None = None

    # ------------------------------------------------------------ discovery

    @classmethod
    def capabilities(cls) -> CaptureCapabilities:
        try:
            import scapy.sendrecv  # noqa: F401
        except ImportError:
            return CaptureCapabilities(
                backend=cls.backend,
                available=False,
                live=True,
                reason="scapy is not installed",
                remedy="pip install scapy",
            )
        library = libpcap_library()
        privilege = capture_privilege()
        if PLATFORM == "win32" and library is None:
            return CaptureCapabilities(
                backend=cls.backend,
                available=False,
                live=True,
                reason=privilege.detail,
                remedy=privilege.remedy,
            )
        return CaptureCapabilities(
            backend=cls.backend,
            available=privilege.granted,
            live=True,
            reason=privilege.detail,
            remedy=privilege.remedy,
            bpf_filter=library is not None or PLATFORM == "darwin",
            any_interface=True,
            promiscuous=True,
            kernel_drop_counters=False,
        )

    @staticmethod
    def list_interfaces() -> list[dict[str, Any]]:
        return _list_interfaces()

    # ------------------------------------------------------------- lifecycle

    async def _open(self) -> None:
        try:
            from scapy.config import conf
            from scapy.sendrecv import AsyncSniffer
        except ImportError as exc:
            raise BackendUnavailableError("scapy is not installed") from exc

        interfaces = self._capture_interfaces(conf)
        queue: asyncio.Queue[RawFrame] = asyncio.Queue(maxsize=self.queue_size)
        loop = asyncio.get_running_loop()
        layer_to_link = conf.l2types.layer2num
        started = threading.Event()

        def enqueue(frame: RawFrame) -> None:
            # Runs on the event loop, where a full queue can be counted.
            try:
                queue.put_nowait(frame)
            except asyncio.QueueFull:
                self.stats.dropped_queue += 1

        def on_packet(packet: Any) -> None:
            # Runs on Scapy's sniffer thread: never block it.
            link_type = layer_to_link.get(type(packet))
            if link_type not in _DECODABLE_LINK_TYPES:
                self.unsupported_frames += 1
                return
            try:
                data = bytes(packet)
            except Exception:
                self.stats.errors += 1
                return
            frame = RawFrame(
                data=data[: self.snapshot_length],
                timestamp=float(getattr(packet, "time", 0.0)) or time.time(),
                link_type=link_type,
                interface=getattr(packet, "sniffed_on", None) or self.interface,
                wire_length=int(getattr(packet, "wirelen", None) or len(data)),
            )
            try:
                loop.call_soon_threadsafe(enqueue, frame)
            except RuntimeError:  # loop closed during shutdown
                pass

        sniffer = AsyncSniffer(
            iface=interfaces,
            filter=self.bpf_filter or None,
            prn=on_packet,
            store=False,
            promisc=self.promiscuous,
            started_callback=started.set,
        )
        try:
            sniffer.start()
        except Exception as exc:
            raise self._translate(exc) from exc
        self._sniffer, self._queue = sniffer, queue
        try:
            await asyncio.to_thread(self._await_started, sniffer, started)
        except CaptureError:
            self._sniffer = None
            raise
        log.info(
            "live_capture_ready",
            backend=self.backend,
            interface=self.interface,
            bpf=self.bpf_filter or None,
        )

    def _capture_interfaces(self, conf: Any) -> Any:
        if self.interface == "any":
            try:
                from scapy.interfaces import get_if_list

                names = list(get_if_list())
            except Exception as exc:
                raise CaptureError(
                    f"could not list interfaces for 'any' capture ({exc}); name one interface"
                ) from exc
            if not names:
                raise CaptureError("no capturable interfaces found; name one interface")
            return names
        known = [entry["name"] for entry in _list_interfaces()]
        try:
            known.extend(str(name) for name in conf.ifaces)
        except Exception:  # pragma: no cover - scapy internals vary by platform
            pass
        if known and self.interface not in known:
            raise InterfaceNotFoundError(self.interface, sorted(set(known)))
        return self.interface

    def _await_started(self, sniffer: Any, started: threading.Event) -> None:
        """Wait until the sniffer is capturing, or report why it died. Worker thread."""
        deadline = time.monotonic() + _START_TIMEOUT
        while time.monotonic() < deadline:
            if started.wait(0.05):
                return
            thread = getattr(sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                exception = getattr(sniffer, "exception", None)
                if exception is not None:
                    raise self._translate(exception)
                raise CaptureError("the capture thread exited before capturing started")
        raise CaptureError(f"capture did not start within {_START_TIMEOUT:.0f} seconds")

    def _translate(self, exc: BaseException) -> CaptureError:
        if isinstance(exc, CaptureError):
            return exc
        if _is_permission_error(exc):
            remedy = capture_privilege().remedy
            return PermissionDeniedError(
                f"live capture was refused ({exc})" + (f": {remedy}" if remedy else "")
            )
        text = str(exc)
        if self.bpf_filter and ("filter" in text.lower() or "syntax" in text.lower()):
            return CaptureError(f"invalid BPF filter {self.bpf_filter!r}: {text}")
        return CaptureError(f"live capture failed: {type(exc).__name__}: {text}")

    async def _close(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is None or not getattr(sniffer, "running", False):
            return
        try:
            await asyncio.to_thread(sniffer.stop)
        except Exception as exc:
            log.warning("sniffer_stop_failed", error=str(exc))

    # -------------------------------------------------------------- iteration

    async def _frames(self) -> AsyncIterator[RawFrame]:
        queue = self._queue
        if queue is None:
            raise CaptureError("the sniffer is not running")
        delivered = 0
        while self.running:
            try:
                frame = await asyncio.wait_for(queue.get(), timeout=self.read_timeout)
            except TimeoutError:
                self._raise_if_sniffer_failed()
                continue
            yield frame
            delivered += 1
            if delivered % 256 == 0:
                self._raise_if_sniffer_failed()
                await asyncio.sleep(0)  # let other tasks run during a burst

    def _raise_if_sniffer_failed(self) -> None:
        sniffer = self._sniffer
        thread = getattr(sniffer, "thread", None)
        if sniffer is None or thread is None or thread.is_alive():
            return
        exception = getattr(sniffer, "exception", None)
        if exception is not None:
            raise self._translate(exception)
        if self.running:
            raise CaptureError("the capture thread stopped unexpectedly")

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info.update(
            backend=self.backend,
            bpf_filter=self.bpf_filter or None,
            snapshot_length=self.snapshot_length,
            unsupported_frames=self.unsupported_frames,
        )
        return info
