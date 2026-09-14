"""Linux live capture through ``AF_PACKET`` raw sockets.

Reading returns bytes straight from the kernel with no per-packet Python object, and
``PACKET_STATISTICS`` gives real kernel drop counts. Packets are read in batches on a
worker thread, so the event loop is not woken once per packet.

Requires ``CAP_NET_RAW`` (or root). BPF filters are compiled by libpcap and run in
the kernel.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import struct
import sys
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

__all__ = ["AfPacketCapture"]

log = get_logger(__name__)

PLATFORM: str = sys.platform

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4

#: Linux ARPHRD_* hardware type -> the link-layer framing AF_PACKET delivers for it.
_ARPHRD_LINK_TYPES: dict[int, int] = {
    1: LinkType.ETHERNET,  # ARPHRD_ETHER
    772: LinkType.ETHERNET,  # ARPHRD_LOOPBACK: a zeroed Ethernet header
    65534: LinkType.RAW,  # ARPHRD_NONE: tun devices, WireGuard
    512: LinkType.RAW,  # ARPHRD_PPP
    776: LinkType.RAW,  # ARPHRD_SIT
    778: LinkType.RAW,  # ARPHRD_IPGRE
    769: LinkType.RAW,  # ARPHRD_TUNNEL6
}
_ARPHRD_LOOPBACK = 772
_BATCH_PACKETS = 512


class AfPacketCapture(PacketCapture):
    """Captures from a Linux interface, or from every interface with ``"any"``.

    With ``"any"`` the socket is unbound and each frame carries its own interface's
    framing, which is honoured per frame. A BPF filter is compiled for Ethernet
    framing in that case, so it does not apply correctly to tunnel interfaces; name
    the interface when filtering matters.
    """

    source_kind = "live"
    backend = "af_packet"

    def __init__(
        self,
        interface: str = "any",
        *,
        bpf_filter: str = "",
        snapshot_length: int = 2048,
        promiscuous: bool = True,
        buffer_size_mb: int = 16,
        read_timeout: float = 0.5,
    ) -> None:
        super().__init__(interface=interface)
        self.bpf_filter = bpf_filter
        self.snapshot_length = snapshot_length
        self.promiscuous = promiscuous
        self.buffer_size_mb = buffer_size_mb
        self.read_timeout = read_timeout
        self._socket: socket.socket | None = None
        self.unsupported_frames = 0

    # ------------------------------------------------------------ discovery

    @classmethod
    def capabilities(cls) -> CaptureCapabilities:
        if not PLATFORM.startswith("linux") or not hasattr(socket, "AF_PACKET"):
            return CaptureCapabilities(
                backend=cls.backend,
                available=False,
                live=True,
                reason="AF_PACKET sockets exist only on Linux",
            )
        privilege = capture_privilege()
        return CaptureCapabilities(
            backend=cls.backend,
            available=privilege.granted,
            live=True,
            reason=privilege.detail,
            remedy=privilege.remedy,
            bpf_filter=libpcap_library() is not None,
            any_interface=True,
            promiscuous=True,
            kernel_drop_counters=True,
        )

    @staticmethod
    def list_interfaces() -> list[dict[str, Any]]:
        return _list_interfaces()

    # ------------------------------------------------------------- lifecycle

    async def _open(self) -> None:
        if self.interface != "any":
            available = [entry["name"] for entry in _list_interfaces()]
            if self.interface not in available:
                raise InterfaceNotFoundError(self.interface, available)
        await asyncio.to_thread(self._open_socket)
        log.info(
            "live_capture_ready",
            backend=self.backend,
            interface=self.interface,
            bpf=self.bpf_filter or None,
        )

    def _open_socket(self) -> None:
        af_packet = getattr(socket, "AF_PACKET", None)
        if af_packet is None:
            raise BackendUnavailableError("AF_PACKET is not available on this platform")
        try:
            sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise PermissionDeniedError(
                "live capture requires CAP_NET_RAW or root: " + capture_privilege().remedy
            ) from exc
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.ENOSYS):
                raise BackendUnavailableError(f"AF_PACKET sockets are unavailable: {exc}") from exc
            raise CaptureError(f"could not open raw socket: {exc}") from exc

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size_mb * 1024 * 1024)
            if self.interface != "any":
                sock.bind((self.interface, ETH_P_ALL))
                if self.promiscuous:
                    index = socket.if_nametoindex(self.interface)
                    membership = struct.pack("IHH8s", index, PACKET_MR_PROMISC, 0, b"")
                    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership)
            if self.bpf_filter:
                self._attach_filter(sock)
            sock.settimeout(self.read_timeout)
        except CaptureError:
            sock.close()
            raise
        except OSError as exc:
            sock.close()
            raise CaptureError(f"could not configure capture socket: {exc}") from exc
        self._socket = sock

    def _attach_filter(self, sock: socket.socket) -> None:
        """Compile the BPF expression with libpcap and attach it in the kernel.

        Any failure is a configuration error reported to the operator. It is never a
        reason to fall back to another backend: silently capturing unfiltered, or not
        at all, is worse than refusing to start.
        """
        if libpcap_library() is None:
            raise CaptureError(
                "BPF filters are compiled with libpcap, which is not installed "
                "(install libpcap, e.g. 'apt install libpcap0.8', or remove BPF_FILTER)"
            )
        try:
            from scapy.arch.common import compile_filter
        except ImportError as exc:
            raise CaptureError("BPF filters need scapy's libpcap bindings") from exc
        try:
            program = compile_filter(self.bpf_filter, linktype=LinkType.ETHERNET)
        except Exception as exc:
            raise CaptureError(f"invalid BPF filter {self.bpf_filter!r}: {exc}") from exc
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, program)
        except OSError as exc:
            raise CaptureError(f"the kernel rejected the BPF program: {exc}") from exc
        log.info("bpf_attached", filter=self.bpf_filter)

    async def _close(self) -> None:
        sock, self._socket = self._socket, None
        if sock is not None:
            self._update_kernel_drops(sock)
            sock.close()

    # -------------------------------------------------------------- iteration

    async def _frames(self) -> AsyncIterator[RawFrame]:
        sock = self._socket
        if sock is None:
            raise CaptureError("capture socket is not open")
        batches = 0
        while self.running:
            try:
                batch = await asyncio.to_thread(self._read_batch, sock)
            except OSError as exc:
                if self._stop_requested():  # close() may have raced the read
                    break
                self.stats.errors += 1
                log.warning("capture_read_error", error=str(exc))
                await asyncio.sleep(0.05)
                continue
            for frame in batch:
                yield frame
            batches += 1
            if batches % 64 == 0:
                self._update_kernel_drops(sock)

    def _read_batch(self, sock: socket.socket) -> list[RawFrame]:
        """Block for the first packet (up to the read timeout), then drain what is queued.

        Runs on a worker thread. Timestamps are taken here, at receipt, not after the
        hand-off back to the event loop.
        """
        frames: list[RawFrame] = []
        try:
            data, address = sock.recvfrom(self.snapshot_length)
        except TimeoutError:
            return frames
        self._append(frames, data, address, time.time())
        sock.setblocking(False)
        try:
            while len(frames) < _BATCH_PACKETS:
                try:
                    data, address = sock.recvfrom(self.snapshot_length)
                except (BlockingIOError, InterruptedError):
                    break
                self._append(frames, data, address, time.time())
        finally:
            sock.settimeout(self.read_timeout)
        return frames

    def _append(self, frames: list[RawFrame], data: bytes, address: Any, timestamp: float) -> None:
        interface, _protocol, packet_type, hardware_type = (
            address[0],
            address[1],
            address[2],
            address[3],
        )
        # The loopback device delivers every packet twice to an unbound socket (once
        # outgoing, once incoming); keep one, as libpcap does.
        if hardware_type == _ARPHRD_LOOPBACK and packet_type == PACKET_OUTGOING:
            return
        link_type = _ARPHRD_LINK_TYPES.get(hardware_type)
        if link_type is None:
            self.unsupported_frames += 1
            return
        frames.append(
            RawFrame(
                data=data,
                timestamp=timestamp,
                link_type=link_type,
                interface=interface or self.interface,
                wire_length=len(data),
            )
        )

    def _stop_requested(self) -> bool:
        # A method, not an inline check, so type checkers do not narrow the flag from
        # the enclosing loop: stop() runs in another task while this one awaits.
        return not self._running

    def _update_kernel_drops(self, sock: socket.socket) -> None:
        """Accumulate ``PACKET_STATISTICS`` (the kernel resets them on each read)."""
        try:
            raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        except OSError:
            return
        _received, dropped = struct.unpack("II", raw)
        self.stats.dropped_kernel += dropped

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info.update(
            backend=self.backend,
            bpf_filter=self.bpf_filter or None,
            snapshot_length=self.snapshot_length,
            unsupported_frames=self.unsupported_frames,
        )
        return info
