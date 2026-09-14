"""Link, network and transport decoding.

Implemented with :mod:`struct` against raw bytes rather than by building Scapy
objects.  Scapy is excellent for crafting and for interactive analysis, but it
allocates a Python object per layer per packet, which dominates cost on a capture
hot path.  ``scripts/benchmark.py`` measures both on the same frames; on the
reference machine recorded in docs/benchmarking.md this decoder was about 2.1-2.5x
faster than ``Ether(raw_bytes)``. Measure on your own hardware before relying on
that figure.

Every decoder is total: malformed input yields ``None`` or a partial result and is
counted, never an exception.  Malformed packets are normal on a real network, and
an intrusion detection system that crashes on one is trivially defeated.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Final

from sentinelx.common.enums import Protocol
from sentinelx.common.models import TcpFlags

__all__ = [
    "ArpInfo",
    "IcmpInfo",
    "IpInfo",
    "LinkInfo",
    "LinkType",
    "TcpInfo",
    "TransportInfo",
    "UdpInfo",
    "decode_arp",
    "decode_icmp",
    "decode_icmpv6",
    "decode_ipv4",
    "decode_ipv6",
    "decode_link",
    "decode_tcp",
    "decode_udp",
]

# --------------------------------------------------------------- link types
# libpcap DLT_* values. See https://www.tcpdump.org/linktypes.html


class LinkType:
    """libpcap link-layer type numbers we can decode."""

    NULL: Final = 0
    ETHERNET: Final = 1
    RAW: Final = 101
    LINUX_SLL: Final = 113
    IPV4: Final = 228
    IPV6: Final = 229
    LINUX_SLL2: Final = 276


ETHERTYPE_IPV4: Final = 0x0800
ETHERTYPE_ARP: Final = 0x0806
ETHERTYPE_IPV6: Final = 0x86DD
ETHERTYPE_VLAN: Final = 0x8100
ETHERTYPE_QINQ: Final = 0x88A8

IPPROTO_HOPOPTS: Final = 0
IPPROTO_ICMP: Final = 1
IPPROTO_TCP: Final = 6
IPPROTO_UDP: Final = 17
IPPROTO_ROUTING: Final = 43
IPPROTO_FRAGMENT: Final = 44
IPPROTO_ICMPV6: Final = 58
IPPROTO_NONE: Final = 59
IPPROTO_DSTOPTS: Final = 60

#: IPv6 extension headers that share the ``next header`` / ``length`` shape and can
#: therefore be skipped generically to reach the transport header.
_IPV6_EXT_HEADERS: Final = frozenset({IPPROTO_HOPOPTS, IPPROTO_ROUTING, IPPROTO_DSTOPTS, 51, 135})

_ETH_HEADER = struct.Struct("!6s6sH")
_IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")
_IPV6_HEADER = struct.Struct("!IHBB16s16s")
_TCP_HEADER = struct.Struct("!HHIIBBHHH")
_UDP_HEADER = struct.Struct("!HHHH")
_ICMP_HEADER = struct.Struct("!BBH")
_ARP_HEADER = struct.Struct("!HHBBH6s4s6s4s")
_SLL_HEADER = struct.Struct("!HHH8sH")
_SLL2_HEADER = struct.Struct("!HHIHBB8s")


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


@dataclass(frozen=True, slots=True)
class LinkInfo:
    """Result of link-layer decoding."""

    payload: bytes
    ethertype: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    vlan_id: int | None = None


@dataclass(frozen=True, slots=True)
class IpInfo:
    """Result of IPv4/IPv6 decoding."""

    src_ip: str
    dst_ip: str
    protocol_number: int
    payload: bytes
    ttl: int
    version: int
    total_length: int
    identification: int | None = None
    fragment_offset: int = 0
    more_fragments: bool = False
    dscp: int = 0

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.fragment_offset > 0


@dataclass(frozen=True, slots=True)
class TcpInfo:
    src_port: int
    dst_port: int
    flags: TcpFlags
    seq: int
    ack: int
    window: int
    payload: bytes
    header_length: int
    urgent_pointer: int = 0
    options_raw: bytes = b""


@dataclass(frozen=True, slots=True)
class UdpInfo:
    src_port: int
    dst_port: int
    length: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class IcmpInfo:
    icmp_type: int
    code: int
    payload: bytes
    identifier: int | None = None
    sequence: int | None = None

    @property
    def is_echo_request(self) -> bool:
        return self.icmp_type == 8

    @property
    def is_echo_reply(self) -> bool:
        return self.icmp_type == 0

    @property
    def is_unreachable(self) -> bool:
        return self.icmp_type == 3


@dataclass(frozen=True, slots=True)
class ArpInfo:
    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def is_request(self) -> bool:
        return self.operation == 1

    @property
    def is_reply(self) -> bool:
        return self.operation == 2


TransportInfo = TcpInfo | UdpInfo | IcmpInfo


# ================================================================ link layer


def decode_link(data: bytes, link_type: int) -> LinkInfo | None:
    """Strip the link header and report the enclosed ethertype.

    Handles Ethernet (including stacked VLAN tags), Linux cooked capture v1/v2
    (what ``-i any`` produces), raw IP and BSD loopback.  Returns ``None`` for
    link types we do not decode, which the caller counts as a parse error.
    """
    if link_type == LinkType.ETHERNET:
        return _decode_ethernet(data)
    if link_type == LinkType.LINUX_SLL:
        return _decode_sll(data)
    if link_type == LinkType.LINUX_SLL2:
        return _decode_sll2(data)
    if link_type in (LinkType.RAW, LinkType.IPV4, LinkType.IPV6):
        return _decode_raw_ip(data)
    if link_type == LinkType.NULL:
        return _decode_null(data)
    return None


def _decode_ethernet(data: bytes) -> LinkInfo | None:
    if len(data) < _ETH_HEADER.size:
        return None
    dst_raw, src_raw, ethertype = _ETH_HEADER.unpack_from(data)
    offset = _ETH_HEADER.size
    vlan_id: int | None = None

    # Walk stacked VLAN tags (802.1Q / 802.1ad). Bounded to avoid a crafted
    # packet of nothing but tags spinning here.
    for _ in range(4):
        if ethertype not in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
            break
        if len(data) < offset + 4:
            return None
        tci, ethertype = struct.unpack_from("!HH", data, offset)
        if vlan_id is None:
            vlan_id = tci & 0x0FFF
        offset += 4

    return LinkInfo(
        payload=data[offset:],
        ethertype=ethertype,
        src_mac=_mac(src_raw),
        dst_mac=_mac(dst_raw),
        vlan_id=vlan_id,
    )


def _decode_sll(data: bytes) -> LinkInfo | None:
    """Linux cooked capture v1 (DLT 113), produced by capturing on 'any'."""
    if len(data) < _SLL_HEADER.size:
        return None
    _pkt_type, _ha_type, ha_len, address, protocol = _SLL_HEADER.unpack_from(data)
    src = _mac(address[:6]) if ha_len >= 6 else None
    return LinkInfo(payload=data[_SLL_HEADER.size :], ethertype=protocol, src_mac=src)


def _decode_sll2(data: bytes) -> LinkInfo | None:
    """Linux cooked capture v2 (DLT 276), used by newer libpcap on 'any'."""
    if len(data) < _SLL2_HEADER.size:
        return None
    protocol, _reserved, _ifindex, _ha_type, _pkt_type, ha_len, address = _SLL2_HEADER.unpack_from(
        data
    )
    src = _mac(address[:6]) if ha_len >= 6 else None
    return LinkInfo(payload=data[_SLL2_HEADER.size :], ethertype=protocol, src_mac=src)


def _decode_raw_ip(data: bytes) -> LinkInfo | None:
    """No link header at all - infer the family from the IP version nibble."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        return LinkInfo(payload=data, ethertype=ETHERTYPE_IPV4)
    if version == 6:
        return LinkInfo(payload=data, ethertype=ETHERTYPE_IPV6)
    return None


def _decode_null(data: bytes) -> LinkInfo | None:
    """BSD loopback: a 4-byte host-order address family."""
    if len(data) < 4:
        return None
    family = struct.unpack_from("=I", data)[0]
    ethertype = {2: ETHERTYPE_IPV4, 24: ETHERTYPE_IPV6, 28: ETHERTYPE_IPV6, 30: ETHERTYPE_IPV6}.get(
        family
    )
    return LinkInfo(payload=data[4:], ethertype=ethertype)


# ============================================================= network layer


def decode_ipv4(data: bytes) -> IpInfo | None:
    """Decode an IPv4 header, honouring IHL and trimming to the stated length."""
    if len(data) < 20:
        return None
    (
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol_number,
        _checksum,
        src_raw,
        dst_raw,
    ) = _IPV4_HEADER.unpack_from(data)

    if version_ihl >> 4 != 4:
        return None
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20 or len(data) < header_length:
        return None

    # Trust the wire length only as far as the bytes we actually captured; a
    # truncated snaplen or a lying header must not produce a negative slice.
    end = min(total_length, len(data)) if total_length >= header_length else len(data)
    payload = data[header_length:end]

    return IpInfo(
        src_ip=socket.inet_ntop(socket.AF_INET, src_raw),
        dst_ip=socket.inet_ntop(socket.AF_INET, dst_raw),
        protocol_number=protocol_number,
        payload=payload,
        ttl=ttl,
        version=4,
        total_length=total_length,
        identification=identification,
        fragment_offset=(flags_fragment & 0x1FFF) * 8,
        more_fragments=bool(flags_fragment & 0x2000),
        dscp=dscp_ecn >> 2,
    )


def decode_ipv6(data: bytes) -> IpInfo | None:
    """Decode an IPv6 header and walk extension headers to the transport header."""
    if len(data) < 40:
        return None
    flow_label, payload_length, next_header, hop_limit, src_raw, dst_raw = _IPV6_HEADER.unpack_from(
        data
    )
    if flow_label >> 28 != 6:
        return None

    offset = 40
    # Bounded walk: a crafted chain of extension headers must not loop forever.
    for _ in range(8):
        if next_header not in _IPV6_EXT_HEADERS:
            break
        if len(data) < offset + 2:
            return None
        next_header, ext_len = data[offset], data[offset + 1]
        offset += (ext_len + 1) * 8
        if offset > len(data):
            return None

    if next_header == IPPROTO_FRAGMENT:
        if len(data) < offset + 8:
            return None
        next_header = data[offset]
        offset += 8

    return IpInfo(
        src_ip=socket.inet_ntop(socket.AF_INET6, src_raw),
        dst_ip=socket.inet_ntop(socket.AF_INET6, dst_raw),
        protocol_number=next_header,
        payload=data[offset:],
        ttl=hop_limit,
        version=6,
        total_length=payload_length + 40,
        dscp=(flow_label >> 20) & 0xFF,
    )


def decode_arp(data: bytes) -> ArpInfo | None:
    """Decode ARP. Only Ethernet/IPv4 hardware and protocol types are meaningful."""
    if len(data) < _ARP_HEADER.size:
        return None
    (
        hw_type,
        proto_type,
        hw_len,
        proto_len,
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    ) = _ARP_HEADER.unpack_from(data)
    if hw_type != 1 or proto_type != ETHERTYPE_IPV4 or hw_len != 6 or proto_len != 4:
        return None
    return ArpInfo(
        operation=operation,
        sender_mac=_mac(sender_mac),
        sender_ip=socket.inet_ntop(socket.AF_INET, sender_ip),
        target_mac=_mac(target_mac),
        target_ip=socket.inet_ntop(socket.AF_INET, target_ip),
    )


# =========================================================== transport layer


def decode_tcp(data: bytes) -> TcpInfo | None:
    """Decode a TCP header, including the data offset and options."""
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved, flags, window, _checksum, urgent = (
        _TCP_HEADER.unpack_from(data)
    )
    header_length = (offset_reserved >> 4) * 4
    if header_length < 20:
        return None
    header_length = min(header_length, len(data))
    return TcpInfo(
        src_port=src_port,
        dst_port=dst_port,
        flags=TcpFlags.from_int(flags),
        seq=seq,
        ack=ack,
        window=window,
        payload=data[header_length:],
        header_length=header_length,
        urgent_pointer=urgent,
        options_raw=data[20:header_length],
    )


def decode_udp(data: bytes) -> UdpInfo | None:
    if len(data) < 8:
        return None
    src_port, dst_port, length, _checksum = _UDP_HEADER.unpack_from(data)
    return UdpInfo(src_port=src_port, dst_port=dst_port, length=length, payload=data[8:])


def decode_icmp(data: bytes) -> IcmpInfo | None:
    if len(data) < 4:
        return None
    icmp_type, code, _checksum = _ICMP_HEADER.unpack_from(data)
    identifier = sequence = None
    # Echo request/reply and timestamp carry an id/seq pair in the next 4 bytes.
    if icmp_type in (0, 8, 13, 14) and len(data) >= 8:
        identifier, sequence = struct.unpack_from("!HH", data, 4)
    return IcmpInfo(
        icmp_type=icmp_type,
        code=code,
        payload=data[8:] if len(data) > 8 else b"",
        identifier=identifier,
        sequence=sequence,
    )


def decode_icmpv6(data: bytes) -> IcmpInfo | None:
    if len(data) < 4:
        return None
    icmp_type, code, _checksum = _ICMP_HEADER.unpack_from(data)
    identifier = sequence = None
    if icmp_type in (128, 129) and len(data) >= 8:  # echo request/reply
        identifier, sequence = struct.unpack_from("!HH", data, 4)
    return IcmpInfo(
        icmp_type=icmp_type,
        code=code,
        payload=data[8:] if len(data) > 8 else b"",
        identifier=identifier,
        sequence=sequence,
    )


def protocol_from_number(number: int, version: int) -> Protocol:
    """Map an IP protocol number onto the platform's :class:`Protocol` enum."""
    if number == IPPROTO_TCP:
        return Protocol.TCP
    if number == IPPROTO_UDP:
        return Protocol.UDP
    if number == IPPROTO_ICMP:
        return Protocol.ICMP
    if number == IPPROTO_ICMPV6:
        return Protocol.ICMPV6
    return Protocol.IPV6 if version == 6 else Protocol.IPV4
