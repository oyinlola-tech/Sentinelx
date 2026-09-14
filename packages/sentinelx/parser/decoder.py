"""Turns raw frames into :class:`PacketEvent`.

This is the boundary of the capture layer.  Everything upstream deals in bytes;
everything downstream deals in normalised events.  Swapping libpcap for AF_XDP, or
Python for a Rust capture process, means reimplementing only what feeds this
module - the detection engine is unaffected.

Application-protocol parsing is registered rather than hard-coded, so adding a new
protocol is a matter of writing a function and registering it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sentinelx.common.enums import Direction, Protocol
from sentinelx.common.models import PacketEvent
from sentinelx.common.netutils import IPNetworkT, parse_ip
from sentinelx.parser import layers
from sentinelx.parser.application import parse_dns, parse_http, parse_tls
from sentinelx.telemetry.metrics import metrics

__all__ = ["AppParser", "PacketDecoder", "register_app_parser"]

#: An application parser receives the transport payload plus the ports involved
#: and returns metadata to merge into ``PacketEvent.metadata``, or ``None``.
AppParser = Callable[[bytes, int, int], dict[str, Any] | None]

_DNS_PORTS = frozenset({53, 5353, 5355})
_HTTP_PORTS = frozenset({80, 8080, 8000, 8008, 8888, 3000})
_TLS_PORTS = frozenset({443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061})


def _dns_parser(payload: bytes, src_port: int, dst_port: int) -> dict[str, Any] | None:
    if not (_DNS_PORTS & {src_port, dst_port}):
        return None
    info = parse_dns(payload)
    if info is None:
        return None
    return {
        "dns": {
            "transaction_id": info.transaction_id,
            "is_response": info.is_response,
            "rcode": info.rcode,
            "query_name": info.query_name,
            "query_type": info.query_type,
            "answer_count": info.answer_count,
            "is_nxdomain": info.is_nxdomain,
            "max_label_length": info.max_label_length,
            "name_entropy": round(info.name_entropy, 3),
        }
    }


def _http_parser(payload: bytes, src_port: int, dst_port: int) -> dict[str, Any] | None:
    if not (_HTTP_PORTS & {src_port, dst_port}) or not payload:
        return None
    info = parse_http(payload)
    if info is None:
        return None
    return {
        "http": {
            "is_request": info.is_request,
            "method": info.method,
            "path": info.path,
            "status_code": info.status_code,
            "host": info.host,
            "user_agent": info.user_agent,
            "has_authorization": info.has_authorization,
        }
    }


def _tls_parser(payload: bytes, src_port: int, dst_port: int) -> dict[str, Any] | None:
    if not (_TLS_PORTS & {src_port, dst_port}) or not payload:
        return None
    info = parse_tls(payload)
    if info is None:
        return None
    return {
        "tls": {
            "handshake_type": info.handshake_type,
            "version": info.negotiated_version,
            "sni": info.sni,
            "alpn": info.alpn,
            "cipher_count": len(info.cipher_suites),
            "is_legacy_version": info.is_legacy_version,
        }
    }


_APP_PARSERS: dict[str, tuple[AppParser, frozenset[Protocol]]] = {
    "dns": (_dns_parser, frozenset({Protocol.UDP, Protocol.TCP})),
    "http": (_http_parser, frozenset({Protocol.TCP})),
    "tls": (_tls_parser, frozenset({Protocol.TCP})),
}


def register_app_parser(
    name: str,
    parser: AppParser,
    protocols: set[Protocol] | None = None,
) -> None:
    """Register an application-protocol parser.

    Args:
        name: unique key; re-registering the same name replaces the parser.
        parser: called with ``(payload, src_port, dst_port)``.
        protocols: transport protocols to run it for. Defaults to TCP and UDP.

    Example:
        >>> def ntp(payload, src, dst):
        ...     if 123 not in (src, dst) or len(payload) < 4:
        ...         return None
        ...     return {"ntp": {"mode": payload[0] & 0x07}}
        >>> register_app_parser("ntp", ntp, {Protocol.UDP})
    """
    _APP_PARSERS[name] = (
        parser,
        frozenset(protocols) if protocols else frozenset({Protocol.TCP, Protocol.UDP}),
    )


class PacketDecoder:
    """Decodes raw frames into :class:`PacketEvent`.

    Stateless apart from the home-network list used to label direction, so a
    decoder may be shared freely or created per worker.
    """

    __slots__ = ("_home_networks", "_parse_application", "decoded", "failed")

    def __init__(
        self,
        home_networks: list[IPNetworkT] | None = None,
        *,
        parse_application: bool = True,
    ) -> None:
        self._home_networks = home_networks or []
        self._parse_application = parse_application
        self.decoded = 0
        self.failed = 0

    def decode(
        self,
        data: bytes,
        timestamp: float,
        link_type: int = layers.LinkType.ETHERNET,
        interface: str = "unknown",
        wire_length: int | None = None,
    ) -> PacketEvent | None:
        """Decode one frame.

        Args:
            data: captured bytes, possibly truncated by the snaplen.
            timestamp: capture time, UNIX epoch seconds.
            link_type: libpcap DLT value describing ``data``.
            interface: name recorded on the event.
            wire_length: original on-wire length when the capture was truncated.
                Falls back to ``len(data)``.

        Returns:
            A normalised event, or ``None`` when the frame could not be decoded
            far enough to be useful. Failures are counted, never raised: malformed
            frames are an expected condition on a real network.
        """
        total_length = wire_length if wire_length is not None else len(data)

        link = layers.decode_link(data, link_type)
        if link is None:
            self.failed += 1
            metrics.parse_errors.labels(layer="link").inc()
            return None

        event = self._decode_network(link, timestamp, total_length, interface)
        if event is None:
            self.failed += 1
            return None
        self.decoded += 1
        return event

    # ------------------------------------------------------------- internals

    def _decode_network(
        self,
        link: layers.LinkInfo,
        timestamp: float,
        total_length: int,
        interface: str,
    ) -> PacketEvent | None:
        ethertype = link.ethertype
        base_metadata: dict[str, Any] = {}
        if link.vlan_id is not None:
            base_metadata["vlan_id"] = link.vlan_id

        if ethertype == layers.ETHERTYPE_ARP:
            return self._build_arp(link, timestamp, total_length, interface, base_metadata)

        if ethertype == layers.ETHERTYPE_IPV4:
            ip = layers.decode_ipv4(link.payload)
        elif ethertype == layers.ETHERTYPE_IPV6:
            ip = layers.decode_ipv6(link.payload)
        else:
            metrics.parse_errors.labels(layer="network").inc()
            return None

        if ip is None:
            metrics.parse_errors.labels(layer="network").inc()
            return None

        return self._build_ip(ip, link, timestamp, total_length, interface, base_metadata)

    def _build_arp(
        self,
        link: layers.LinkInfo,
        timestamp: float,
        total_length: int,
        interface: str,
        metadata: dict[str, Any],
    ) -> PacketEvent | None:
        arp = layers.decode_arp(link.payload)
        if arp is None:
            metrics.parse_errors.labels(layer="arp").inc()
            return None
        metadata["arp"] = {
            "operation": "request" if arp.is_request else "reply" if arp.is_reply else "other",
            "sender_mac": arp.sender_mac,
            "target_ip": arp.target_ip,
        }
        return PacketEvent(
            timestamp=timestamp,
            src_ip=arp.sender_ip,
            dst_ip=arp.target_ip,
            protocol=Protocol.ARP,
            length=total_length,
            interface=interface,
            direction=self._direction(arp.sender_ip, arp.target_ip),
            src_mac=link.src_mac or arp.sender_mac,
            dst_mac=link.dst_mac,
            metadata=metadata,
        )

    def _build_ip(
        self,
        ip: layers.IpInfo,
        link: layers.LinkInfo,
        timestamp: float,
        total_length: int,
        interface: str,
        metadata: dict[str, Any],
    ) -> PacketEvent | None:
        protocol = layers.protocol_from_number(ip.protocol_number, ip.version)
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags = None
        payload = b""

        if ip.is_fragment and ip.fragment_offset > 0:
            # A non-first fragment has no transport header. Record it as such
            # rather than misreading payload bytes as ports.
            metadata["fragment"] = {"offset": ip.fragment_offset, "more": ip.more_fragments}
        elif protocol is Protocol.TCP:
            tcp = layers.decode_tcp(ip.payload)
            if tcp is None:
                metrics.parse_errors.labels(layer="tcp").inc()
                return None
            src_port, dst_port = tcp.src_port, tcp.dst_port
            tcp_flags = tcp.flags
            payload = tcp.payload
        elif protocol is Protocol.UDP:
            udp = layers.decode_udp(ip.payload)
            if udp is None:
                metrics.parse_errors.labels(layer="udp").inc()
                return None
            src_port, dst_port = udp.src_port, udp.dst_port
            payload = udp.payload
        elif protocol in (Protocol.ICMP, Protocol.ICMPV6):
            decode = layers.decode_icmp if protocol is Protocol.ICMP else layers.decode_icmpv6
            icmp = decode(ip.payload)
            if icmp is None:
                metrics.parse_errors.labels(layer="icmp").inc()
                return None
            metadata["icmp"] = {
                "type": icmp.icmp_type,
                "code": icmp.code,
                "identifier": icmp.identifier,
                "sequence": icmp.sequence,
                "is_echo_request": icmp.is_echo_request,
                "is_unreachable": icmp.is_unreachable,
            }
            payload = icmp.payload

        if self._parse_application and payload and src_port is not None and dst_port is not None:
            self._apply_app_parsers(protocol, payload, src_port, dst_port, metadata)

        return PacketEvent(
            timestamp=timestamp,
            src_ip=ip.src_ip,
            dst_ip=ip.dst_ip,
            protocol=protocol,
            length=total_length,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            ttl=ip.ttl,
            interface=interface,
            direction=self._direction(ip.src_ip, ip.dst_ip),
            src_mac=link.src_mac,
            dst_mac=link.dst_mac,
            payload_length=len(payload),
            metadata=metadata,
        )

    @staticmethod
    def _apply_app_parsers(
        protocol: Protocol,
        payload: bytes,
        src_port: int,
        dst_port: int,
        metadata: dict[str, Any],
    ) -> None:
        """Run every registered parser that applies, tolerating failures.

        A parser raising must not drop the packet: the L3/L4 fields are still
        valuable to detectors even if an application decode went wrong.
        """
        for name, (parser, protocols) in _APP_PARSERS.items():
            if protocol not in protocols:
                continue
            try:
                result = parser(payload, src_port, dst_port)
            except Exception:
                metrics.parse_errors.labels(layer=name).inc()
                continue
            if result:
                metadata.update(result)

    def _direction(self, src_ip: str, dst_ip: str) -> Direction:
        """Label direction relative to the configured home networks.

        Returns ``UNKNOWN`` when no home networks are configured - guessing would
        put a wrong label on every packet, which is worse than admitting we do
        not know.
        """
        if not self._home_networks:
            return Direction.UNKNOWN
        try:
            source = parse_ip(src_ip)
            destination = parse_ip(dst_ip)
        except ValueError:
            return Direction.UNKNOWN

        src_home = any(source.version == net.version and source in net for net in self._home_networks)
        dst_home = any(
            destination.version == net.version and destination in net for net in self._home_networks
        )
        if src_home and dst_home:
            return Direction.INTERNAL
        if dst_home:
            return Direction.INBOUND
        if src_home:
            return Direction.OUTBOUND
        return Direction.EXTERNAL

    def stats(self) -> dict[str, int]:
        return {"decoded": self.decoded, "failed": self.failed}
