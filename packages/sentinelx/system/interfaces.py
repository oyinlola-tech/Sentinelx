"""Network interface enumeration on Linux, macOS and Windows.

Built on :mod:`psutil`, which asks each operating system directly (netlink/sysfs,
``getifaddrs``, ``GetAdaptersAddresses``) and returns every address, not only the
primary IPv4 one. No subprocesses, no parsing of localised command output.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path
from typing import Any

import psutil

__all__ = ["cached_local_addresses", "list_interfaces", "local_addresses"]


def _strip_scope(address: str) -> str:
    # IPv6 link-local addresses carry a zone ("fe80::1%eth0"); the zone is not part
    # of the address for comparison purposes.
    return address.split("%", 1)[0]


def _linux_operstate(name: str) -> str | None:
    try:
        return (Path("/sys/class/net") / name / "operstate").read_text(encoding="ascii").strip()
    except OSError:
        return None


def list_interfaces() -> list[dict[str, Any]]:
    """Interfaces with their addresses, state and counters.

    Raises:
        OSError: when the operating system refuses enumeration. Callers that make
            safety decisions from the result must treat that as "unknown", never as
            "no addresses".
    """
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    link_family = getattr(psutil, "AF_LINK", None)

    interfaces: list[dict[str, Any]] = []
    for name in sorted(set(addresses) | set(stats)):
        ips: list[str] = []
        mac: str | None = None
        for entry in addresses.get(name, []):
            if entry.family in (socket.AF_INET, socket.AF_INET6):
                ips.append(_strip_scope(entry.address))
            elif link_family is not None and entry.family == link_family and entry.address:
                mac = entry.address.replace("-", ":").lower()
        stat = stats.get(name)
        io = counters.get(name)
        is_loopback = name in {"lo", "lo0"} or any(ip in {"127.0.0.1", "::1"} for ip in ips)
        state = _linux_operstate(name) if sys.platform.startswith("linux") else None
        interfaces.append(
            {
                "name": name,
                "state": state or ("up" if stat and stat.isup else "down"),
                "mac": mac if mac and mac != "00:00:00:00:00:00" else None,
                "mtu": stat.mtu if stat else 0,
                "is_up": bool(stat and stat.isup),
                "is_loopback": is_loopback,
                "speed_mbps": stat.speed if stat and stat.speed else None,
                "addresses": ips,
                "statistics": {
                    "rx_packets": io.packets_recv if io else 0,
                    "tx_packets": io.packets_sent if io else 0,
                    "rx_bytes": io.bytes_recv if io else 0,
                    "tx_bytes": io.bytes_sent if io else 0,
                    "rx_dropped": io.dropin if io else 0,
                },
            }
        )
    return interfaces


def local_addresses() -> set[str]:
    """Every IP address assigned to this host.

    Raises:
        OSError: when enumeration fails, so the firewall safety guard can refuse to
            act rather than assume the host has no addresses to protect.
    """
    return {ip for interface in list_interfaces() for ip in interface["addresses"]}


_cache: tuple[float, frozenset[str]] | None = None
_CACHE_SECONDS = 10.0


def cached_local_addresses() -> frozenset[str]:
    """:func:`local_addresses`, re-read at most every 10 seconds.

    The safety guard consults this on every block; enumerating interfaces each time
    would put a system call storm on the response path during an attack. Addresses
    change rarely, and a failed enumeration is never cached.
    """
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < _CACHE_SECONDS:
        return _cache[1]
    addresses = frozenset(local_addresses())
    _cache = (now, addresses)
    return addresses
