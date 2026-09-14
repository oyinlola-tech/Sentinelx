"""Which privileged operations this process may perform, and what to do if it may not.

Each probe answers from the operating system's own mechanism - Linux capability
bits and a real raw socket, macOS BPF device permissions, Windows elevation and the
Npcap driver's settings - rather than from ``euid == 0``, which is wrong inside
containers, user namespaces and on Windows.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

#: ``sys.platform`` as a plain string, so type checkers analyse every branch rather
#: than only the one for the platform the check happens to run on.
PLATFORM: str = sys.platform

__all__ = [
    "PrivilegeCheck",
    "capture_privilege",
    "firewall_privilege",
    "is_elevated",
    "libpcap_library",
    "linux_capabilities",
]

CAP_NET_ADMIN = 12
CAP_NET_RAW = 13
_ETH_P_ALL = 0x0003


@dataclass(frozen=True, slots=True)
class PrivilegeCheck:
    granted: bool
    detail: str
    """What was found, e.g. "CAP_NET_RAW is in the effective set"."""
    remedy: str = ""
    """How to obtain the privilege when it is missing."""


def is_elevated() -> bool:
    """Root on POSIX, an elevated (administrator) token on Windows."""
    if PLATFORM == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def linux_capabilities() -> set[int] | None:
    """Effective capability numbers of this process, or ``None`` off Linux."""
    if not PLATFORM.startswith("linux"):
        return None
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        return None
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            mask = int(line.split()[1], 16)
            return {bit for bit in range(64) if mask >> bit & 1}
    return None


def libpcap_library() -> str | None:
    """The libpcap (or Npcap ``wpcap``) shared library, if one is installed."""
    if PLATFORM == "win32":
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")  # case-insensitive on Windows
        npcap = Path(system_root) / "System32" / "Npcap" / "wpcap.dll"
        if npcap.is_file():
            return str(npcap)
        return ctypes.util.find_library("wpcap")
    return ctypes.util.find_library("pcap")


def _npcap_admin_only() -> bool:
    """Npcap's "restrict driver access to Administrators" install option."""
    try:
        import winreg  # type: ignore[import-not-found, unused-ignore]

        with winreg.OpenKey(  # type: ignore[attr-defined, unused-ignore]
            winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined, unused-ignore]
            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AdminOnly")  # type: ignore[attr-defined, unused-ignore]
            return bool(value)
    except (ImportError, OSError):
        return False


def capture_privilege() -> PrivilegeCheck:
    """Can this process open a live capture device?"""
    if PLATFORM.startswith("linux"):
        return _linux_capture()
    if PLATFORM == "darwin":
        return _macos_capture()
    if PLATFORM == "win32":
        return _windows_capture()
    return PrivilegeCheck(False, f"live capture is not supported on {PLATFORM}")


def _linux_capture() -> PrivilegeCheck:
    remedy = (
        "run as root, or grant the interpreter the capability once: "
        "sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)"
    )
    af_packet = getattr(socket, "AF_PACKET", None)
    if af_packet is None:
        return PrivilegeCheck(False, "this Linux Python build has no AF_PACKET support", remedy)
    try:
        # A genuine attempt: capability bits are easy to misread (ambient sets, user
        # namespaces, seccomp), the kernel's answer is not.
        probe = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    except PermissionError:
        return PrivilegeCheck(False, "opening a raw AF_PACKET socket was refused", remedy)
    except OSError as exc:
        return PrivilegeCheck(False, f"raw sockets are unavailable here: {exc}", remedy)
    probe.close()
    if is_elevated():
        return PrivilegeCheck(True, "running as root")
    if CAP_NET_RAW in (linux_capabilities() or set()):
        return PrivilegeCheck(True, "CAP_NET_RAW is in the effective set")
    return PrivilegeCheck(True, "the kernel permits raw sockets for this process")


def _macos_capture() -> PrivilegeCheck:
    remedy = (
        "run as root, or give your user read access to /dev/bpf* (Wireshark's "
        "'ChmodBPF' launch daemon does this)"
    )
    devices = sorted(Path("/dev").glob("bpf*"))
    if not devices:
        return PrivilegeCheck(False, "no /dev/bpf* devices found", remedy)
    if any(os.access(device, os.R_OK | os.W_OK) for device in devices):
        return PrivilegeCheck(True, "a /dev/bpf device is readable by this user")
    return PrivilegeCheck(False, "no /dev/bpf device is readable by this user", remedy)


def _windows_capture() -> PrivilegeCheck:
    install = "install Npcap from https://npcap.com (WinPcap API-compatible mode)"
    if libpcap_library() is None:
        return PrivilegeCheck(False, "Npcap is not installed", install)
    if _npcap_admin_only() and not is_elevated():
        return PrivilegeCheck(
            False,
            "Npcap is restricted to Administrators and this process is not elevated",
            "run SentinelX from an elevated (Administrator) terminal",
        )
    return PrivilegeCheck(True, "Npcap is installed and accessible")


def firewall_privilege() -> PrivilegeCheck:
    """Can this process change the host firewall?"""
    if PLATFORM.startswith("linux"):
        caps = linux_capabilities()
        if caps is not None and CAP_NET_ADMIN in caps:
            return PrivilegeCheck(True, "CAP_NET_ADMIN is in the effective set")
        return PrivilegeCheck(
            False,
            "CAP_NET_ADMIN is not in the effective set",
            "run the sensor as root, grant CAP_NET_ADMIN, or use the docker compose "
            "'capture' profile",
        )
    if PLATFORM == "win32":
        if is_elevated():
            return PrivilegeCheck(True, "running with an elevated administrator token")
        return PrivilegeCheck(
            False,
            "Windows Firewall changes require Administrator privileges",
            "run SentinelX from an elevated (Administrator) terminal",
        )
    if PLATFORM == "darwin":
        if is_elevated():
            return PrivilegeCheck(True, "running as root")
        return PrivilegeCheck(
            False, "pf changes require root", "run the sensor as root (for example with sudo)"
        )
    return PrivilegeCheck(False, f"firewall control is not supported on {PLATFORM}")
