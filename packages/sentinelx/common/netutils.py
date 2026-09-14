"""IP address handling.

Every address that reaches the firewall passes through this module first.  All
parsing goes through the standard library's :mod:`ipaddress`; strings are never
interpolated into commands and never trusted as-is.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import lru_cache

__all__ = [
    "SENSITIVE_PORTS",
    "WELL_KNOWN_SERVICES",
    "IPAddressT",
    "IPNetworkT",
    "describe_network",
    "in_any_network",
    "is_private",
    "is_special",
    "is_valid_ip",
    "parse_ip",
    "parse_network",
    "parse_networks",
    "prefix_host_count",
    "service_name",
    "to_network",
]

IPAddressT = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetworkT = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip(value: str) -> IPAddressT:
    """Parse a single IP address.

    Raises:
        ValueError: if ``value`` is not a valid IPv4 or IPv6 address. The message
            includes the offending input so callers can surface it directly.
    """
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid IP address") from exc


def parse_network(value: str, *, strict: bool = False) -> IPNetworkT:
    """Parse a CIDR network. A bare address is treated as a /32 or /128.

    Args:
        value: e.g. ``10.0.0.0/8``, ``192.168.1.5``, ``2001:db8::/32``.
        strict: when True, reject networks with host bits set.

    Raises:
        ValueError: if the value is not a valid network.
    """
    try:
        return ipaddress.ip_network(value.strip(), strict=strict)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid IP network") from exc


def is_valid_ip(value: str) -> bool:
    """True when ``value`` parses as an IP address. Never raises."""
    try:
        parse_ip(value)
    except ValueError:
        return False
    return True


def to_network(address: IPAddressT) -> IPNetworkT:
    """Wrap a single address as its host network (/32 or /128)."""
    return ipaddress.ip_network(address)


def in_any_network(address: IPAddressT, networks: Iterable[IPNetworkT]) -> bool:
    """True when ``address`` falls inside any of ``networks``.

    Address families are compared safely: an IPv4 address is never reported as
    being inside an IPv6 network.
    """
    return any(address.version == net.version and address in net for net in networks)


def parse_networks(values: Iterable[str]) -> list[IPNetworkT]:
    """Parse a collection of CIDR strings, reporting *all* failures at once.

    Raises:
        ValueError: listing every entry that failed, rather than only the first.
            Configuration mistakes usually come in batches.
    """
    parsed: list[IPNetworkT] = []
    problems: list[str] = []
    for raw in values:
        text = raw.strip()
        if not text:
            continue
        try:
            parsed.append(parse_network(text))
        except ValueError as exc:
            problems.append(str(exc))
    if problems:
        raise ValueError("invalid network list: " + "; ".join(problems))
    return parsed


def is_private(address: IPAddressT) -> bool:
    return address.is_private


def is_special(address: IPAddressT) -> bool:
    """True for addresses that must never be blocked automatically.

    Covers loopback, link-local, multicast, unspecified (0.0.0.0/::), and
    reserved ranges.  These either identify the sensor itself or are not
    meaningful unicast sources, so a block would be either self-harm or a no-op
    that hides a detection bug.
    """
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def prefix_host_count(network: IPNetworkT) -> int:
    """Number of addresses a prefix covers. Used to cap blast radius."""
    return network.num_addresses


def describe_network(network: IPNetworkT) -> str:
    """Human description such as ``192.168.1.0/24 (256 addresses)``."""
    count = network.num_addresses
    if count == 1:
        return f"{network.network_address} (single host)"
    return f"{network} ({count} addresses)"


@lru_cache(maxsize=1024)
def service_name(port: int, protocol: str = "tcp") -> str | None:
    """Well-known service name for a port, or None.

    Backed by a small built-in table rather than ``socket.getservbyport`` so the
    result is identical on every host and needs no ``/etc/services``.
    """
    return WELL_KNOWN_SERVICES.get((port, protocol.lower()))


WELL_KNOWN_SERVICES: dict[tuple[int, str], str] = {
    (20, "tcp"): "ftp-data",
    (21, "tcp"): "ftp",
    (22, "tcp"): "ssh",
    (23, "tcp"): "telnet",
    (25, "tcp"): "smtp",
    (53, "tcp"): "dns",
    (53, "udp"): "dns",
    (67, "udp"): "dhcp-server",
    (68, "udp"): "dhcp-client",
    (69, "udp"): "tftp",
    (80, "tcp"): "http",
    (110, "tcp"): "pop3",
    (111, "tcp"): "rpcbind",
    (123, "udp"): "ntp",
    (135, "tcp"): "msrpc",
    (137, "udp"): "netbios-ns",
    (139, "tcp"): "netbios-ssn",
    (143, "tcp"): "imap",
    (161, "udp"): "snmp",
    (389, "tcp"): "ldap",
    (443, "tcp"): "https",
    (445, "tcp"): "smb",
    (465, "tcp"): "smtps",
    (500, "udp"): "isakmp",
    (514, "udp"): "syslog",
    (587, "tcp"): "submission",
    (636, "tcp"): "ldaps",
    (993, "tcp"): "imaps",
    (995, "tcp"): "pop3s",
    (1080, "tcp"): "socks",
    (1433, "tcp"): "mssql",
    (1521, "tcp"): "oracle",
    (1723, "tcp"): "pptp",
    (1900, "udp"): "ssdp",
    (2049, "tcp"): "nfs",
    (3306, "tcp"): "mysql",
    (3389, "tcp"): "rdp",
    (5060, "udp"): "sip",
    (5432, "tcp"): "postgresql",
    (5900, "tcp"): "vnc",
    (6379, "tcp"): "redis",
    (8080, "tcp"): "http-alt",
    (8443, "tcp"): "https-alt",
    (9200, "tcp"): "elasticsearch",
    (11211, "tcp"): "memcached",
    (27017, "tcp"): "mongodb",
}

#: Ports whose compromise is high-impact. The risk engine adds weight when one of
#: these is the destination of a detection.
SENSITIVE_PORTS: frozenset[int] = frozenset(
    {22, 23, 445, 3389, 3306, 5432, 6379, 27017, 9200, 11211, 1433, 1521, 2049}
)
