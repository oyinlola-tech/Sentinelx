"""What SentinelX can do on this host, determined at runtime.

Nothing here is assumed from the operating system's name. Each capability is probed
(a raw socket is opened, a capture file is parsed, firewall tooling and privileges
are checked), and each carries the reason it is available or not, and what would
make it available. The CLI (``sentinelx capabilities``, ``sentinelx doctor``), the API
(``GET /api/v1/system/capabilities``) and the dashboard all show this same report.
"""

from __future__ import annotations

import io
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from sentinelx.config.settings import Settings
from sentinelx.system.environment import HostEnvironment, detect_environment
from sentinelx.system.privileges import is_elevated, linux_capabilities

__all__ = ["Capability", "PlatformCapabilities", "detect_capabilities"]


@dataclass(frozen=True, slots=True)
class Capability:
    available: bool
    detail: str
    remedy: str = ""
    backend: str | None = None

    @property
    def label(self) -> str:
        return "AVAILABLE" if self.available else "UNAVAILABLE"

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "status": self.label,
            "detail": self.detail,
            "remedy": self.remedy,
            "backend": self.backend,
        }


@dataclass(frozen=True, slots=True)
class PlatformCapabilities:
    environment: HostEnvironment
    privileged_access: Capability
    interface_enumeration: Capability
    packet_capture: Capability
    """A capture library/kernel interface exists (independent of privileges)."""
    live_capture: Capability
    """This process can capture from an interface right now."""
    pcap_replay: Capability
    detection_engine: Capability
    firewall: Capability
    """The configured firewall backend can enforce changes here."""
    automatic_blocking: Capability
    firewall_backends: list[dict[str, Any]] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)

    def items(self) -> list[tuple[str, Capability]]:
        return [
            ("Detection engine", self.detection_engine),
            ("PCAP replay", self.pcap_replay),
            ("Interface enumeration", self.interface_enumeration),
            ("Packet capture", self.packet_capture),
            ("Live capture", self.live_capture),
            ("Firewall control", self.firewall),
            ("Automatic blocking", self.automatic_blocking),
            ("Privileged access", self.privileged_access),
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "operating_system": self.environment.operating_system,
            "architecture": self.environment.architecture,
            "environment": self.environment.as_dict(),
            "privileged_access": self.privileged_access.as_dict(),
            "interface_enumeration_available": self.interface_enumeration.available,
            "packet_capture_available": self.packet_capture.available,
            "live_capture_available": self.live_capture.available,
            "pcap_replay_available": self.pcap_replay.available,
            "firewall_available": self.firewall.available,
            "automatic_blocking_available": self.automatic_blocking.available,
            "capabilities": {
                key: capability.as_dict()
                for key, capability in (
                    ("detection_engine", self.detection_engine),
                    ("pcap_replay", self.pcap_replay),
                    ("interface_enumeration", self.interface_enumeration),
                    ("packet_capture", self.packet_capture),
                    ("live_capture", self.live_capture),
                    ("firewall", self.firewall),
                    ("automatic_blocking", self.automatic_blocking),
                    ("privileged_access", self.privileged_access),
                )
            },
            "firewall_backends": self.firewall_backends,
            "detected_at": self.detected_at,
        }


def _pcap_replay() -> Capability:
    """Parse a one-packet capture from memory with the reader replays use."""
    from sentinelx.capture.pcapfile import read_capture_stream
    from sentinelx.common.errors import PcapError

    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = bytes(12) + b"\x08\x00" + bytes(20)
    record = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    try:
        records = list(read_capture_stream(io.BytesIO(header + record)))
    except PcapError as exc:
        return Capability(False, f"the capture reader failed: {exc}")
    if len(records) != 1 or records[0].data != frame:
        return Capability(False, "the capture reader returned unexpected results")
    return Capability(True, "pcap and pcapng files can be read; no privileges needed")


def _privileges() -> Capability:
    elevated = is_elevated()
    caps = linux_capabilities()
    if caps is not None:
        names = [name for bit, name in ((13, "CAP_NET_RAW"), (12, "CAP_NET_ADMIN")) if bit in caps]
        detail = "root" if elevated else (", ".join(names) or "no network capabilities")
        return Capability(
            elevated or bool(names),
            detail,
            "" if elevated or names else "only needed for live capture and firewall control",
        )
    return Capability(
        elevated,
        "elevated" if elevated else "not elevated",
        "" if elevated else "only needed for live capture and firewall control",
    )


def detect_capabilities(settings: Settings) -> PlatformCapabilities:
    """Probe this host.

    The first call in a process imports the capture libraries (about a second); later
    calls take milliseconds. Callers that poll should still cache the result.
    """
    from sentinelx.capture.live import LiveCapture
    from sentinelx.firewall import (
        BACKENDS_BY_PLATFORM,
        firewall_capabilities,
        platform_family,
        resolve_backend,
    )
    from sentinelx.system.interfaces import list_interfaces
    from sentinelx.system.privileges import libpcap_library

    environment = detect_environment()

    try:
        interfaces = list_interfaces()
        enumeration = Capability(True, f"{len(interfaces)} interfaces found")
    except OSError as exc:
        enumeration = Capability(False, f"interface enumeration failed: {exc}")

    library = libpcap_library()
    if environment.is_linux:
        present = True
        capture_detail = "AF_PACKET sockets" + (" and libpcap" if library else "")
    elif environment.is_macos:
        present = True
        capture_detail = "BPF devices via libpcap"
    elif environment.is_windows:
        present = library is not None
        capture_detail = "Npcap" if present else "Npcap is not installed"
    else:
        present = False
        capture_detail = f"no capture backend for {environment.operating_system}"
    packet_capture = Capability(
        present,
        capture_detail,
        "" if present else "install Npcap from https://npcap.com",
    )

    live = LiveCapture.capabilities(settings.capture.backend)
    live_detail = live.reason
    if environment.wsl:
        live_detail += (
            f"; under WSL{environment.wsl} this sees the WSL virtual machine's traffic, "
            "not the Windows host's"
        )
    if environment.container:
        live_detail += (
            f"; inside {environment.container} this sees the container's own network "
            "namespace unless it uses host networking"
        )
    live_capture = Capability(live.available, live_detail, live.remedy, live.backend)

    backend, why = resolve_backend(settings.response.firewall_backend)
    candidates = BACKENDS_BY_PLATFORM.get(platform_family(), ())
    backend_reports = [firewall_capabilities(name).as_dict() for name in candidates]

    if backend == "null":
        firewall = Capability(
            False,
            "no firewall backend is configured (FIREWALL_BACKEND=null)"
            if settings.response.firewall_backend == "null"
            else why,
            "set FIREWALL_BACKEND to 'auto' or to a backend listed as available"
            if settings.response.firewall_backend == "null"
            else "install a supported firewall (see the backend list) and run with the "
            "privileges it needs, or set FIREWALL_BACKEND to a specific backend",
            "null",
        )
    else:
        report = firewall_capabilities(backend)
        firewall = Capability(report.available, report.reason, report.remedy, backend)

    if not firewall.available:
        automatic = Capability(False, "no usable firewall: " + firewall.detail, firewall.remedy)
    elif settings.response.prevention_active:
        automatic = Capability(True, f"enabled: {settings.safety_banner()}", backend=backend)
    else:
        automatic = Capability(
            True,
            f"possible with {backend}; currently off ({settings.safety_banner()})",
            "enable prevention in Settings, or RESPONSE_MODE=automatic with DRY_RUN=false",
            backend,
        )

    return PlatformCapabilities(
        environment=environment,
        privileged_access=_privileges(),
        interface_enumeration=enumeration,
        packet_capture=packet_capture,
        live_capture=live_capture,
        pcap_replay=_pcap_replay(),
        detection_engine=Capability(True, "pure Python; runs on every supported platform"),
        firewall=firewall,
        automatic_blocking=automatic,
        firewall_backends=backend_reports,
    )
