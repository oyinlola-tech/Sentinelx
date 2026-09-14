"""What kind of machine SentinelX is running on.

Detection is by observation (files, environment variables, kernel release strings),
never by assumption, because the same Linux binary behaves very differently on bare
metal, inside a container, under WSL2 or inside Docker Desktop's virtual machine.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

#: ``sys.platform`` as a plain string, so type checkers analyse every branch rather
#: than only the one for the platform the check happens to run on.
PLATFORM: str = sys.platform

__all__ = ["HostEnvironment", "detect_environment"]


@dataclass(frozen=True, slots=True)
class HostEnvironment:
    operating_system: str
    """``linux``, ``windows``, ``macos`` or the raw ``PLATFORM`` value."""
    os_release: str
    architecture: str
    """Normalised machine type: ``x86_64``, ``arm64``, ..."""
    python_version: str
    python_implementation: str
    wsl: int | None
    """1 or 2 under Windows Subsystem for Linux, otherwise ``None``."""
    container: str | None
    """``docker``, ``podman``, ``kubernetes`` or ``container`` when detected."""

    @property
    def is_linux(self) -> bool:
        return self.operating_system == "linux"

    @property
    def is_windows(self) -> bool:
        return self.operating_system == "windows"

    @property
    def is_macos(self) -> bool:
        return self.operating_system == "macos"

    def label(self) -> str:
        parts = [f"{self.operating_system} {self.architecture}"]
        if self.wsl:
            parts.append(f"WSL{self.wsl}")
        if self.container:
            parts.append(f"in {self.container}")
        return ", ".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "label": self.label()}


_ARCH_ALIASES = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64", "armv8": "arm64"}


def _operating_system() -> str:
    if PLATFORM.startswith("linux"):
        return "linux"
    if PLATFORM == "win32":
        return "windows"
    if PLATFORM == "darwin":
        return "macos"
    return PLATFORM


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _wsl_version() -> int | None:
    if not PLATFORM.startswith("linux"):
        return None
    release = _read("/proc/sys/kernel/osrelease").lower()
    marked = bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"))
    if "microsoft" not in release and "wsl" not in release and not marked:
        return None
    # WSL2 kernels are real Linux kernels named "...-microsoft-standard-WSL2";
    # WSL1 reports a "Microsoft" suffix on a translated 4.4 kernel.
    return 2 if "wsl2" in release or "standard" in release else 1


def _container() -> str | None:
    if not PLATFORM.startswith("linux"):
        return None
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "kubernetes"
    if Path("/run/.containerenv").exists():
        return "podman"
    if Path("/.dockerenv").exists():
        return "docker"
    # systemd-nspawn, podman and LXC export a lower-case "container" variable.
    marker = os.environ.get("container")  # noqa: SIM112
    if marker:
        return marker
    cgroup = _read("/proc/1/cgroup")
    for name in ("docker", "kubepods", "containerd", "libpod"):
        if name in cgroup:
            return "kubernetes" if name == "kubepods" else name
    return None


@lru_cache(maxsize=1)
def detect_environment() -> HostEnvironment:
    machine = platform.machine().lower() or "unknown"
    return HostEnvironment(
        operating_system=_operating_system(),
        os_release=platform.release(),
        architecture=_ARCH_ALIASES.get(machine, machine),
        python_version=platform.python_version(),
        python_implementation=platform.python_implementation(),
        wsl=_wsl_version(),
        container=_container(),
    )
