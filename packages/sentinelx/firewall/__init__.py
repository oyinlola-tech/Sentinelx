"""Firewall adapters and the choice between them.

=====================  ==========  =============================================
Backend                Platforms   Mechanism
=====================  ==========  =============================================
``nftables``           Linux       ``nft`` sets with kernel-side timeouts
``iptables``           Linux       ``iptables``/``ip6tables`` chain + hashlimit
``pf``                 macOS, BSD  ``pfctl`` anchor and table
``windows_firewall``   Windows     NetSecurity PowerShell cmdlets
``null``               any         no firewall: enforcement is refused, loudly
``auto``               any         the first backend usable on this host
=====================  ==========  =============================================

A configured backend that cannot run here (binary missing, wrong operating system)
does not stop SentinelX from starting: detection keeps working, the backend reports
itself unavailable in health checks, and every attempted action fails with the
reason. Nothing is ever reported as enforced when it was not.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import asdict, dataclass
from typing import Any

from sentinelx.common.errors import FirewallError
from sentinelx.config.settings import ResponseSettings
from sentinelx.firewall.base import BlockEntry, CommandResult, CommandRunner, FirewallAdapter
from sentinelx.firewall.memory import MemoryFirewall, NullFirewall, UnavailableFirewall
from sentinelx.system.privileges import firewall_privilege

__all__ = [
    "BACKENDS_BY_PLATFORM",
    "BlockEntry",
    "CommandResult",
    "CommandRunner",
    "FirewallAdapter",
    "FirewallCapabilities",
    "MemoryFirewall",
    "NullFirewall",
    "UnavailableFirewall",
    "create_firewall",
    "firewall_capabilities",
]

PLATFORM: str = sys.platform

#: Enforcing backends in order of preference, per platform family.
BACKENDS_BY_PLATFORM: dict[str, tuple[str, ...]] = {
    "linux": ("nftables", "iptables"),
    "darwin": ("pf",),
    "freebsd": ("pf",),
    "openbsd": ("pf",),
    "win32": ("windows_firewall",),
}


@dataclass(frozen=True, slots=True)
class FirewallCapabilities:
    backend: str
    available: bool
    """The backend's tooling exists on this host and this process may use it."""
    reason: str
    remedy: str = ""
    native_expiry: bool = False
    """Temporary blocks expire in the firewall itself, even if SentinelX is stopped."""
    rate_limit: bool = False
    ipv6: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _platform_family() -> str:
    for family in BACKENDS_BY_PLATFORM:
        if PLATFORM.startswith(family):
            return family
    return PLATFORM


def firewall_capabilities(backend: str) -> FirewallCapabilities:
    """Whether ``backend`` can enforce blocks on this host, and why not if it cannot."""
    family = _platform_family()
    if backend == "null":
        return FirewallCapabilities("null", True, "no firewall configured; nothing is enforced")
    supported = BACKENDS_BY_PLATFORM.get(family, ())
    if backend not in supported:
        where = ", ".join(
            sorted(f for f, names in BACKENDS_BY_PLATFORM.items() if backend in names)
        )
        return FirewallCapabilities(
            backend,
            False,
            f"{backend} is not available on {family} (supported on: {where or 'none'})",
        )
    if backend == "windows_firewall":
        from sentinelx.firewall.windows import powershell_path

        tool: str | None = powershell_path()
        tool_name = "Windows PowerShell"
    else:
        tool_name = {"nftables": "nft", "iptables": "iptables", "pf": "pfctl"}[backend]
        tool = shutil.which(tool_name) or (
            "/sbin/pfctl" if backend == "pf" and shutil.which("/sbin/pfctl") else None
        )
    traits = {
        "native_expiry": backend == "nftables",
        "rate_limit": backend in ("nftables", "iptables"),
        "ipv6": backend != "iptables" or shutil.which("ip6tables") is not None,
    }
    if tool is None:
        return FirewallCapabilities(
            backend, False, f"{tool_name} is not installed", f"install {tool_name}", **traits
        )
    privilege = firewall_privilege()
    return FirewallCapabilities(
        backend, privilege.granted, privilege.detail, privilege.remedy, **traits
    )


def resolve_backend(requested: str) -> tuple[str, str]:
    """Pick the concrete backend for ``requested`` (resolving ``auto``) and explain why."""
    if requested != "auto":
        return requested, "configured"
    candidates = BACKENDS_BY_PLATFORM.get(_platform_family(), ())
    reports = [firewall_capabilities(name) for name in candidates]
    for report in reports:
        if report.available:
            return report.backend, f"auto: {report.reason}"
    if reports:
        return "null", "auto: no usable firewall (" + "; ".join(
            f"{r.backend}: {r.reason}" for r in reports
        ) + ")"
    return "null", f"auto: no firewall backend exists for {PLATFORM}"


def create_firewall(settings: ResponseSettings) -> FirewallAdapter:
    """Build the configured adapter, never failing start-up.

    Returns:
        The adapter, a :class:`NullFirewall` for ``null`` (or ``auto`` with nothing
        usable), or an :class:`UnavailableFirewall` describing why the configured
        backend cannot run here.
    """
    backend, why = resolve_backend(settings.firewall_backend)
    try:
        if backend == "nftables":
            from sentinelx.firewall.nftables import NftablesAdapter

            return NftablesAdapter(
                table=settings.nft_table,
                set_prefix=settings.nft_set,
                family=settings.nft_family,
                rate_limit_pps=settings.rate_limit_packets_per_second,
            )
        if backend == "iptables":
            from sentinelx.firewall.iptables import IptablesAdapter

            return IptablesAdapter(rate_limit_pps=settings.rate_limit_packets_per_second)
        if backend == "pf":
            from sentinelx.firewall.pf import PfAdapter

            return PfAdapter(anchor=settings.pf_anchor)
        if backend == "windows_firewall":
            from sentinelx.firewall.windows import WindowsFirewallAdapter

            return WindowsFirewallAdapter()
    except FirewallError as exc:
        return UnavailableFirewall(backend, str(exc))
    if backend == "null":
        return NullFirewall(reason=why if settings.firewall_backend == "auto" else "")
    return UnavailableFirewall(backend, f"unknown firewall backend {backend!r}")
