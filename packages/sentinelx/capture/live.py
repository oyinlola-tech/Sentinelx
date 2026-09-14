"""Live interface capture on Linux.

Two backends, chosen automatically:

``AF_PACKET`` (preferred)
    A raw ``socket.AF_PACKET`` with an attached BPF program.  Reading returns
    bytes straight from the kernel ring buffer with no per-packet Python object,
    which is why it is the default: on the hot path, object allocation, not
    syscalls, is what costs.  Kernel drop counters are read via ``PACKET_STATISTICS``
    so we report real loss instead of guessing.

``scapy``
    Used when AF_PACKET is unavailable (non-Linux, or a restricted sandbox).
    Correct and portable, but slower; the sensor logs which backend it chose so a
    surprising throughput number is always explainable.

Capturing packets requires ``CAP_NET_RAW``.  Granting the capability to the
binary is preferable to running the whole platform as root:

    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from sentinelx.capture.base import PacketCapture, RawFrame
from sentinelx.common.errors import (
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
)
from sentinelx.parser.layers import LinkType
from sentinelx.telemetry.logging import get_logger

__all__ = ["LiveCapture", "has_capture_privileges", "list_interfaces"]

log = get_logger(__name__)

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_STATISTICS = 6
SO_ATTACH_FILTER = 26
_SIOCGIFADDR = 0x8915  # ioctl: read an interface's IPv4 address
_SYS_NET = Path("/sys/class/net")


def _sysfs_reader(directory: Path) -> Callable[..., str]:
    """Return a reader for files under one ``/sys/class/net`` entry.

    Missing attributes are normal (a loopback device has no MAC), so absence
    yields the default rather than an error.
    """

    def read(name: str, default: str = "") -> str:
        try:
            return (directory / name).read_text(encoding="ascii").strip()
        except OSError:
            return default

    return read


def list_interfaces() -> list[dict[str, Any]]:
    """Enumerate network interfaces with their state.

    Reads ``/sys/class/net`` directly rather than shelling out to ``ip``: no
    subprocess, no parsing of human-oriented output, and it works in a container
    where ``iproute2`` may not be installed.
    """
    interfaces: list[dict[str, Any]] = []
    if not _SYS_NET.is_dir():  # pragma: no cover - non-Linux
        return interfaces

    for entry in sorted(_SYS_NET.iterdir()):
        if not entry.is_dir():
            continue
        read = _sysfs_reader(entry)
        flags_raw = read("flags", "0x0")
        try:
            flags = int(flags_raw, 16)
        except ValueError:
            flags = 0

        interfaces.append(
            {
                "name": entry.name,
                "state": read("operstate", "unknown"),
                "mac": read("address") or None,
                "mtu": int(read("mtu", "0") or 0),
                "is_up": bool(flags & 0x1),  # IFF_UP
                "is_loopback": bool(flags & 0x8),  # IFF_LOOPBACK
                "addresses": _interface_addresses(entry.name),
                "statistics": {
                    "rx_packets": int(read("statistics/rx_packets", "0") or 0),
                    "tx_packets": int(read("statistics/tx_packets", "0") or 0),
                    "rx_bytes": int(read("statistics/rx_bytes", "0") or 0),
                    "tx_bytes": int(read("statistics/tx_bytes", "0") or 0),
                    "rx_dropped": int(read("statistics/rx_dropped", "0") or 0),
                },
            }
        )
    return interfaces


def _interface_addresses(name: str) -> list[str]:
    """IP addresses assigned to an interface.

    Uses ``socket.if_nameindex`` plus ``/proc`` rather than a subprocess.  Best
    effort: an interface with no address simply reports none.
    """
    addresses: list[str] = []
    try:
        import fcntl

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = struct.pack("256s", name.encode()[:15])
            result = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)
            addresses.append(socket.inet_ntoa(result[20:24]))
    except (OSError, ImportError, ValueError):
        pass

    # IPv6 addresses live in /proc/net/if_inet6 as hex, one per line.
    try:
        for line in Path("/proc/net/if_inet6").read_text(encoding="ascii").splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[5] == name:
                raw = bytes.fromhex(parts[0])
                addresses.append(socket.inet_ntop(socket.AF_INET6, raw))
    except (OSError, ValueError):
        pass

    return addresses


def local_addresses() -> set[str]:
    """Every IP address assigned to this host.

    Used by the firewall safety layer to refuse blocking our own management
    addresses, so a misfiring detector cannot cut off the operator.
    """
    result: set[str] = set()
    for interface in list_interfaces():
        result.update(interface["addresses"])
    return result


def has_capture_privileges() -> bool:
    """True when this process can open a raw socket.

    Tested by actually opening one; capability bits are easy to misread and a
    genuine attempt gives the real answer.
    """
    if sys.platform != "linux":
        return False
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except (PermissionError, OSError):
        return False
    sock.close()
    return True


class LiveCapture(PacketCapture):
    """Captures from a live network interface.

    Args:
        interface: interface name, or ``"any"`` to capture on all of them.
        bpf_filter: kernel-level BPF expression, e.g. ``"tcp or udp"``. Applied
            before userspace sees a packet, so it reduces load rather than just
            hiding packets.
        snapshot_length: bytes to capture per frame.
        promiscuous: put the interface into promiscuous mode.
        buffer_size_mb: socket receive buffer. A larger buffer absorbs bursts that
            would otherwise show up as kernel drops.

    Raises:
        PermissionDeniedError: when the process lacks CAP_NET_RAW.
        InterfaceNotFoundError: when the named interface does not exist.
    """

    source_kind = "live"

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
        self.backend = "none"
        self._socket: socket.socket | None = None
        self._scapy_sniffer: Any | None = None
        self._scapy_queue: asyncio.Queue[RawFrame] | None = None
        self._link_type = LinkType.ETHERNET

    # ------------------------------------------------------------- lifecycle

    async def _open(self) -> None:
        self._validate_interface()
        if sys.platform == "linux":
            try:
                await asyncio.to_thread(self._open_af_packet)
                self.backend = "af_packet"
                log.info(
                    "live_capture_ready",
                    backend=self.backend,
                    interface=self.interface,
                    bpf=self.bpf_filter or None,
                )
                return
            except PermissionDeniedError:
                raise
            except Exception as exc:
                log.warning("af_packet_unavailable", error=str(exc), falling_back_to="scapy")
        await self._open_scapy()
        self.backend = "scapy"
        log.info("live_capture_ready", backend=self.backend, interface=self.interface)

    def _validate_interface(self) -> None:
        if self.interface == "any":
            return
        available = [entry["name"] for entry in list_interfaces()]
        if available and self.interface not in available:
            raise InterfaceNotFoundError(self.interface, available)

    def _open_af_packet(self) -> None:
        """Open and configure the raw socket. Runs in a worker thread."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise PermissionDeniedError(
                "live capture needs CAP_NET_RAW. Either run as root, or grant the "
                "capability once with:\n"
                "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
            ) from exc
        except OSError as exc:
            raise CaptureError(f"could not open raw socket: {exc}") from exc

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size_mb * 1024 * 1024)
            if self.interface != "any":
                sock.bind((self.interface, ETH_P_ALL))
                self._link_type = LinkType.ETHERNET
            else:
                # Capturing on every interface yields Linux cooked-capture frames.
                self._link_type = LinkType.LINUX_SLL
            if self.bpf_filter:
                self._attach_filter(sock)
            sock.settimeout(self.read_timeout)
        except OSError as exc:
            sock.close()
            raise CaptureError(f"could not configure capture socket: {exc}") from exc

        self._socket = sock

    def _attach_filter(self, sock: socket.socket) -> None:
        """Attach a compiled BPF program to the socket.

        Filtering in the kernel is strictly better than filtering in Python: a
        dropped packet costs nothing instead of a decode.
        """
        try:
            from scapy.arch.common import compile_filter
        except ImportError:
            log.warning("bpf_unavailable", reason="scapy not installed; filtering in userspace")
            return
        try:
            program = compile_filter(self.bpf_filter, linktype=self._link_type)
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, program)
            log.info("bpf_attached", filter=self.bpf_filter)
        except Exception as exc:
            raise CaptureError(f"invalid BPF filter {self.bpf_filter!r}: {exc}") from exc

    async def _open_scapy(self) -> None:
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError as exc:
            raise CaptureError(
                "no capture backend available: AF_PACKET failed and scapy is not installed"
            ) from exc

        queue: asyncio.Queue[RawFrame] = asyncio.Queue(maxsize=20_000)
        loop = asyncio.get_running_loop()
        self._scapy_queue = queue
        interface = None if self.interface == "any" else self.interface

        def on_packet(packet: Any) -> None:
            # Runs on Scapy's sniffer thread: hand off to the loop, never block.
            try:
                raw_bytes = bytes(packet)
            except Exception:
                return
            frame = RawFrame(
                data=raw_bytes,
                timestamp=float(getattr(packet, "time", 0.0)),
                link_type=LinkType.ETHERNET,
                interface=self.interface,
                wire_length=len(raw_bytes),
            )
            try:
                loop.call_soon_threadsafe(queue.put_nowait, frame)
            except (RuntimeError, asyncio.QueueFull):
                self.stats.dropped_queue += 1

        try:
            sniffer = AsyncSniffer(
                iface=interface,
                filter=self.bpf_filter or None,
                prn=on_packet,
                store=False,
            )
            sniffer.start()
        except PermissionError as exc:
            raise PermissionDeniedError("live capture needs CAP_NET_RAW or root") from exc
        except Exception as exc:
            raise CaptureError(f"scapy sniffer failed to start: {exc}") from exc
        self._scapy_sniffer = sniffer

    # -------------------------------------------------------------- iteration

    async def _frames(self) -> AsyncIterator[RawFrame]:
        if self.backend == "af_packet":
            async for frame in self._af_packet_frames():
                yield frame
        else:
            async for frame in self._scapy_frames():
                yield frame

    async def _af_packet_frames(self) -> AsyncIterator[RawFrame]:
        sock = self._socket
        if sock is None:
            raise CaptureError("capture socket is not open")

        read_size = self.snapshot_length
        poll_counter = 0

        while self.running:
            try:
                # recvfrom in a thread keeps the loop free during the timeout.
                result = await asyncio.to_thread(self._recv, sock, read_size)
            except TimeoutError:
                continue
            except OSError as exc:
                if self._stop_requested():  # stop() may have closed the socket mid-read
                    break
                self.stats.errors += 1
                log.warning("capture_read_error", error=str(exc))
                continue

            if result is None:
                continue
            data, address = result
            yield RawFrame(
                data=data,
                timestamp=time.time(),
                link_type=self._link_type,
                interface=address[0] if address else self.interface,
                wire_length=len(data),
            )

            poll_counter += 1
            if poll_counter % 512 == 0:
                self._update_kernel_drops(sock)

    def _stop_requested(self) -> bool:
        """Re-read the running flag after an await.

        A method rather than an inline ``not self.running`` so the type checker does
        not narrow the flag from the enclosing ``while`` - another task can call
        :meth:`stop` while this one is suspended.
        """
        return not self._running

    @staticmethod
    def _recv(sock: socket.socket, size: int) -> tuple[bytes, Any] | None:
        try:
            return sock.recvfrom(size)
        except TimeoutError:
            raise
        except BlockingIOError:
            return None

    def _update_kernel_drops(self, sock: socket.socket) -> None:
        """Read and accumulate ``PACKET_STATISTICS``.

        The counters reset on each read, so they are added rather than assigned.
        """
        try:
            raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            _received, dropped = struct.unpack("II", raw)
            if dropped:
                self.stats.dropped_kernel += dropped
        except OSError:
            pass

    async def _scapy_frames(self) -> AsyncIterator[RawFrame]:
        queue = self._scapy_queue
        if queue is None:
            raise CaptureError("scapy sniffer is not running")
        while self.running:
            try:
                yield await asyncio.wait_for(queue.get(), timeout=self.read_timeout)
            except TimeoutError:
                continue

    async def _close(self) -> None:
        sock = self._socket
        self._socket = None
        if sock is not None:
            self._update_kernel_drops(sock)
            sock.close()

        sniffer = self._scapy_sniffer
        self._scapy_sniffer = None
        if sniffer is not None:
            try:
                await asyncio.to_thread(sniffer.stop)
            except Exception as exc:  # pragma: no cover
                log.warning("sniffer_stop_failed", error=str(exc))

    def describe(self) -> dict[str, object]:
        info = super().describe()
        info["backend"] = self.backend
        info["bpf_filter"] = self.bpf_filter or None
        info["snapshot_length"] = self.snapshot_length
        return info
