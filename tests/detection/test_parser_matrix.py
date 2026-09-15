"""Parser matrix: every supported layer, built byte-by-byte with :mod:`struct`.

``tests/capture/test_parser.py`` checks the decoder against Scapy. This file covers
what that one does not: every link type, IPv4 options and fragments, IPv6
extension headers, all 256 TCP flag values, DNS compression edge cases, TLS
ClientHello metadata, and a truncation/fuzz sweep proving ``decode`` never raises
and never hangs.
"""

from __future__ import annotations

import random
import socket
import struct
import sys
import time

import pytest

from sentinelx.common.enums import Protocol
from sentinelx.parser import layers
from sentinelx.parser.application import parse_dns, parse_http, parse_tls
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.parser.layers import LinkType

TS = 1_700_000_000.25
SRC_MAC = bytes.fromhex("0a0b0c0d0e0f")
DST_MAC = bytes.fromhex("020304050607")

# ================================================================ builders


def eth(payload: bytes, ethertype: int = 0x0800, *, vlans: tuple[int, ...] = ()) -> bytes:
    header = struct.pack("!6s6s", DST_MAC, SRC_MAC)
    for index, vid in enumerate(vlans):
        tpid = 0x88A8 if index == 0 and len(vlans) > 1 else 0x8100
        header += struct.pack("!HH", tpid, vid)
    return header + struct.pack("!H", ethertype) + payload


def ipv4(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    *,
    options: bytes = b"",
    ihl: int | None = None,
    total_length: int | None = None,
    frag: int = 0,
    more_fragments: bool = False,
    ttl: int = 64,
    version: int = 4,
) -> bytes:
    assert len(options) % 4 == 0
    header_words = ihl if ihl is not None else 5 + len(options) // 4
    length = total_length if total_length is not None else 20 + len(options) + len(payload)
    flags_frag = (0x2000 if more_fragments else 0) | (frag & 0x1FFF)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | header_words,
        0x28,  # DSCP 10
        length,
        0x1234,
        flags_frag,
        ttl,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + options + payload


def ipv6(
    src: str,
    dst: str,
    next_header: int,
    payload: bytes,
    *,
    hlim: int = 64,
    payload_length: int | None = None,
    version: int = 6,
    traffic_class: int = 0,
) -> bytes:
    length = len(payload) if payload_length is None else payload_length
    first = (version << 28) | (traffic_class << 20) | 0x12345
    return (
        struct.pack(
            "!IHBB16s16s",
            first,
            length,
            next_header,
            hlim,
            socket.inet_pton(socket.AF_INET6, src),
            socket.inet_pton(socket.AF_INET6, dst),
        )
        + payload
    )


def ext_header(next_header: int, body_len_units: int = 0) -> bytes:
    """Generic IPv6 extension header ((len+1)*8 bytes)."""
    total = (body_len_units + 1) * 8
    return struct.pack("!BB", next_header, body_len_units) + b"\x01\x00" * ((total - 2) // 2)


def tcp(
    sport: int,
    dport: int,
    flags: int = 0x02,
    *,
    payload: bytes = b"",
    options: bytes = b"",
    data_offset: int | None = None,
    seq: int = 1000,
    ack: int = 0,
    window: int = 65535,
    urgent: int = 0,
) -> bytes:
    offset = data_offset if data_offset is not None else 5 + len(options) // 4
    return (
        struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, window, 0, urgent)
        + options
        + payload
    )


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(icmp_type: int, code: int = 0, rest: bytes = b"\x00\x07\x00\x09") -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + rest


def arp(op: int, spa: str, tpa: str, *, hw_type: int = 1) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s",
        hw_type,
        0x0800,
        6,
        4,
        op,
        SRC_MAC,
        socket.inet_aton(spa),
        b"\x00" * 6,
        socket.inet_aton(tpa),
    )


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"


def dns_header(*, txid: int = 0xBEEF, flags: int = 0x0100, qd: int = 1, an: int = 0) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qd, an, 0, 0)


def client_hello(
    sni: str | None = "Login.Example.COM",
    *,
    alpn: tuple[str, ...] = ("h2", "http/1.1"),
    versions: tuple[int, ...] = (0x0304, 0x0303),
    record_version: int = 0x0301,
    ciphers: tuple[int, ...] = (0x1301, 0x1302, 0xC02F),
) -> bytes:
    extensions = b""
    if sni is not None:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        body = struct.pack("!H", len(entry)) + entry
        extensions += struct.pack("!HH", 0x0000, len(body)) + body
    if alpn:
        protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        body = struct.pack("!H", len(protos)) + protos
        extensions += struct.pack("!HH", 0x0010, len(body)) + body
    if versions:
        body = bytes([2 * len(versions)]) + b"".join(struct.pack("!H", v) for v in versions)
        extensions += struct.pack("!HH", 0x002B, len(body)) + body
    suites = b"".join(struct.pack("!H", c) for c in ciphers)
    hello = (
        b"\x03\x03"
        + b"\x42" * 32
        + b"\x20"
        + b"\x07" * 32  # 32-byte session id
        + struct.pack("!H", len(suites))
        + suites
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    return struct.pack("!BHH", 0x16, record_version, len(handshake)) + handshake


def server_hello(cipher: int = 0xC02F, record_version: int = 0x0303) -> bytes:
    hello = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", cipher) + b"\x00"
    handshake = b"\x02" + struct.pack("!I", len(hello))[1:] + hello
    return struct.pack("!BHH", 0x16, record_version, len(handshake)) + handshake


@pytest.fixture
def dec() -> PacketDecoder:
    return PacketDecoder()


def one(dec: PacketDecoder, frame: bytes, link: int = LinkType.ETHERNET):  # type: ignore[no-untyped-def]
    return dec.decode(frame, TS, link, "test0")


# ================================================================ link layer


class TestLinkLayer:
    def test_ethernet_ipv4_tcp_every_field(self, dec: PacketDecoder) -> None:
        frame = eth(ipv4("10.1.2.3", "10.9.8.7", 6, tcp(40000, 443, 0x12, payload=b"abc"), ttl=33))
        event = one(dec, frame)
        assert event is not None
        assert (event.src_ip, event.dst_ip, event.src_port, event.dst_port) == (
            "10.1.2.3",
            "10.9.8.7",
            40000,
            443,
        )
        assert event.protocol is Protocol.TCP and event.ttl == 33
        assert event.length == len(frame) and event.payload_length == 3
        assert event.src_mac == "0a:0b:0c:0d:0e:0f" and event.dst_mac == "02:03:04:05:06:07"
        assert event.interface == "test0" and event.timestamp == TS
        assert event.tcp_flags is not None and event.tcp_flags.is_syn_ack
        assert dec.stats() == {"decoded": 1, "failed": 0}

    def test_wire_length_overrides_captured_length(self, dec: PacketDecoder) -> None:
        frame = eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2, b"x" * 10)))
        event = dec.decode(frame, TS, LinkType.ETHERNET, "eth0", wire_length=1514)
        assert event is not None and event.length == 1514

    def test_single_vlan_tag(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(5, 6)), vlans=(0x2064,)))
        # PCP bits (0x2000) must be masked off: VLAN id is the low 12 bits.
        assert event is not None and event.metadata["vlan_id"] == 0x064 and event.dst_port == 6

    def test_qinq_reports_outer_vlan_and_decodes_inner(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(5, 7)), vlans=(100, 200)))
        assert event is not None and event.metadata["vlan_id"] == 100 and event.dst_port == 7

    def test_vlan_over_arp(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(arp(1, "10.0.0.1", "10.0.0.2"), 0x0806, vlans=(5,)))
        assert event is not None and event.protocol is Protocol.ARP
        assert event.metadata["vlan_id"] == 5

    def test_excessive_vlan_stack_is_rejected_not_looped(self, dec: PacketDecoder) -> None:
        inner = ipv4("10.0.0.1", "10.0.0.2", 17, udp(5, 7))
        frame = struct.pack("!6s6s", DST_MAC, SRC_MAC)
        frame += b"".join(struct.pack("!HH", 0x8100, n) for n in range(6))
        frame += struct.pack("!H", 0x0800) + inner
        assert one(dec, frame) is None and dec.failed == 1

    def test_vlan_tag_truncated(self, dec: PacketDecoder) -> None:
        frame = struct.pack("!6s6sH", DST_MAC, SRC_MAC, 0x8100) + b"\x00"
        assert one(dec, frame) is None

    @pytest.mark.parametrize("ha_len", [6, 0])
    def test_linux_cooked_v1(self, dec: PacketDecoder, ha_len: int) -> None:
        header = struct.pack("!HHH8sH", 0, 1, ha_len, SRC_MAC + b"\x00\x00", 0x0800)
        event = one(
            dec, header + ipv4("192.0.2.1", "192.0.2.2", 17, udp(53, 5353)), LinkType.LINUX_SLL
        )
        assert event is not None and event.dst_port == 5353 and event.dst_mac is None
        assert event.src_mac == ("0a:0b:0c:0d:0e:0f" if ha_len == 6 else None)

    def test_linux_cooked_v2_ipv6(self, dec: PacketDecoder) -> None:
        header = struct.pack("!HHIHBB8s", 0x86DD, 0, 3, 1, 0, 6, SRC_MAC + b"\x00\x00")
        packet = ipv6("2001:db8::1", "2001:db8::2", 6, tcp(1, 22))
        event = one(dec, header + packet, LinkType.LINUX_SLL2)
        assert event is not None and event.protocol is Protocol.TCP and event.dst_port == 22
        assert event.src_mac == "0a:0b:0c:0d:0e:0f"

    @pytest.mark.parametrize("link", [LinkType.RAW, LinkType.IPV4, LinkType.IPV6])
    def test_raw_ip_infers_family_from_version_nibble(self, dec: PacketDecoder, link: int) -> None:
        v4 = one(dec, ipv4("198.51.100.1", "198.51.100.2", 17, udp(1, 2)), link)
        v6 = one(dec, ipv6("2001:db8::a", "2001:db8::b", 17, udp(3, 4)), link)
        assert v4 is not None and v4.src_ip == "198.51.100.1" and v4.src_mac is None
        assert v6 is not None and v6.src_ip == "2001:db8::a" and v6.dst_port == 4
        assert one(dec, b"\x50" + b"\x00" * 40, link) is None  # version 5

    @pytest.mark.parametrize(
        ("family", "expected"), [(2, "10.0.0.1"), (24, "::1"), (28, "::1"), (30, "::1")]
    )
    @pytest.mark.parametrize("order", ["native", "swapped"])
    def test_bsd_loopback_both_byte_orders(
        self, dec: PacketDecoder, family: int, expected: str, order: str
    ) -> None:
        """DLT_NULL stores the family in the *capturing* host's byte order, so a
        capture made on a machine of the other endianness must still decode."""
        native = "<" if sys.byteorder == "little" else ">"
        swapped = ">" if native == "<" else "<"
        prefix = struct.pack(f"{native if order == 'native' else swapped}I", family)
        if family == 2:
            body = ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2))
        else:
            body = ipv6("::1", "::1", 17, udp(1, 2))
        event = one(dec, prefix + body, LinkType.NULL)
        assert event is not None and event.src_ip == expected and event.dst_port == 2

    def test_unknown_link_type_counts_failure(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2))), 105) is None
        assert dec.stats() == {"decoded": 0, "failed": 1}

    @pytest.mark.parametrize("ethertype", [0x88CC, 0x0842, 0x05DC, 0x0000, 0xFFFF])
    def test_unknown_ethertype_is_a_counted_failure(
        self, dec: PacketDecoder, ethertype: int
    ) -> None:
        assert one(dec, eth(b"\x45" + b"\x00" * 40, ethertype)) is None
        assert dec.failed == 1


# ============================================================== IPv4 / IPv6


class TestIpv4:
    @pytest.mark.parametrize("option_words", range(0, 11))
    def test_options_shift_transport_header(self, dec: PacketDecoder, option_words: int) -> None:
        options = b"\x01" * (4 * option_words)  # NOPs
        event = one(
            dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 80 + option_words), options=options))
        )
        assert event is not None and event.src_port == 1234 and event.dst_port == 80 + option_words

    @pytest.mark.parametrize("ihl", [0, 1, 4])
    def test_ihl_below_minimum_rejected(self, dec: PacketDecoder, ihl: int) -> None:
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2), ihl=ihl))) is None
        assert dec.failed == 1

    def test_ihl_beyond_captured_bytes_rejected(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, b"", ihl=15))) is None

    def test_total_length_larger_than_capture_uses_captured_bytes(self, dec: PacketDecoder) -> None:
        packet = ipv4("10.0.0.1", "10.0.0.2", 17, udp(7, 8, b"q" * 12), total_length=1500)
        event = one(dec, eth(packet))
        assert event is not None and event.dst_port == 8 and event.payload_length == 12

    def test_total_length_smaller_than_capture_strips_ethernet_padding(
        self, dec: PacketDecoder
    ) -> None:
        packet = ipv4("10.0.0.1", "10.0.0.2", 17, udp(7, 8, b"ab"))
        event = one(dec, eth(packet + b"\x00" * 18))  # padded to the 60-byte minimum
        assert event is not None and event.payload_length == 2

    @pytest.mark.parametrize("total_length", [0, 10])
    def test_total_length_below_header_falls_back_to_capture(
        self, dec: PacketDecoder, total_length: int
    ) -> None:
        """TSO/GRO captures report total length 0; the packet must still decode."""
        packet = ipv4(
            "10.0.0.1", "10.0.0.2", 6, tcp(1, 2, payload=b"hi"), total_length=total_length
        )
        event = one(dec, eth(packet))
        assert event is not None and event.dst_port == 2 and event.payload_length == 2

    def test_first_fragment_keeps_ports(self, dec: PacketDecoder) -> None:
        event = one(
            dec,
            eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(1000, 53, b"x" * 30), more_fragments=True)),
        )
        assert event is not None and event.src_port == 1000 and "fragment" not in event.metadata
        info = layers.decode_ipv4(ipv4("10.0.0.1", "10.0.0.2", 17, b"x" * 8, more_fragments=True))
        assert (
            info is not None
            and info.is_fragment
            and info.more_fragments
            and info.fragment_offset == 0
        )

    @pytest.mark.parametrize("more", [True, False])
    def test_non_first_fragment_has_no_transport_fields(
        self, dec: PacketDecoder, more: bool
    ) -> None:
        body = tcp(1111, 2222)  # would be misread as ports if the offset were ignored
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, body, frag=185, more_fragments=more)))
        assert event is not None and event.protocol is Protocol.TCP
        assert event.src_port is None and event.dst_port is None and event.tcp_flags is None
        assert event.metadata["fragment"] == {"offset": 185 * 8, "more": more}

    def test_header_fields(self) -> None:
        info = layers.decode_ipv4(ipv4("1.2.3.4", "5.6.7.8", 99, b"zz", ttl=7))
        assert info is not None
        assert (info.version, info.ttl, info.protocol_number, info.identification) == (
            4,
            7,
            99,
            0x1234,
        )
        assert info.dscp == 10 and info.payload == b"zz" and info.total_length == 22
        # Traffic class 0x29 = DSCP 10 with an ECN bit set; DSCP must match IPv4's.
        v6 = layers.decode_ipv6(ipv6("::1", "::2", 17, udp(1, 2), traffic_class=0x29))
        assert v6 is not None and v6.dscp == 10

    def test_wrong_version_nibble_inside_ipv4_ethertype(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2), version=6))) is None

    @pytest.mark.parametrize("proto", [0, 2, 47, 50, 89, 255])
    def test_unknown_ip_protocol_is_kept_as_generic_ip(
        self, dec: PacketDecoder, proto: int
    ) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", proto, b"\xde\xad\xbe\xef" * 5)))
        assert event is not None and event.protocol is Protocol.IPV4
        assert event.src_port is None and event.payload_length == 0 and event.tcp_flags is None


class TestIpv6:
    def test_udp_and_hop_limit(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv6("2001:db8::1", "2001:db8::2", 17, udp(5000, 53), hlim=3), 0x86DD))
        assert event is not None and event.protocol is Protocol.UDP and event.ttl == 3
        assert (event.src_ip, event.dst_port) == ("2001:db8::1", 53)

    def test_extension_header_chain_is_walked(self, dec: PacketDecoder) -> None:
        # hop-by-hop(0) -> routing(43) -> destination options(60) -> TCP(6)
        packet = ipv6(
            "2001:db8::1",
            "2001:db8::2",
            0,
            ext_header(43, 0) + ext_header(60, 1) + ext_header(6, 0) + tcp(4321, 8443),
        )
        event = one(dec, eth(packet, 0x86DD))
        assert event is not None and event.protocol is Protocol.TCP
        assert (event.src_port, event.dst_port) == (4321, 8443)

    def test_fragment_header_first_fragment_keeps_ports(self, dec: PacketDecoder) -> None:
        frag = struct.pack("!BBHI", 17, 0, (0 << 3) | 1, 0xABCD)  # offset 0, more fragments
        event = one(dec, eth(ipv6("2001:db8::1", "2001:db8::2", 44, frag + udp(1234, 53)), 0x86DD))
        assert event is not None and event.protocol is Protocol.UDP and event.dst_port == 53

    def test_non_first_fragment_has_no_transport_fields(self, dec: PacketDecoder) -> None:
        """Mirror of the IPv4 rule: data in a non-first fragment is not a header."""
        frag = struct.pack("!BBHI", 6, 0, (100 << 3) | 0, 0xABCD)
        event = one(
            dec, eth(ipv6("2001:db8::1", "2001:db8::2", 44, frag + tcp(1111, 2222)), 0x86DD)
        )
        assert event is not None
        assert event.src_port is None and event.dst_port is None and event.tcp_flags is None
        assert event.metadata["fragment"] == {"offset": 800, "more": False}

    def test_fragment_followed_by_destination_options(self, dec: PacketDecoder) -> None:
        frag = struct.pack("!BBHI", 60, 0, 1, 7)
        packet = ipv6("2001:db8::1", "2001:db8::2", 44, frag + ext_header(17, 0) + udp(9, 10))
        event = one(dec, eth(packet, 0x86DD))
        assert event is not None and event.protocol is Protocol.UDP and event.dst_port == 10

    def test_authentication_header_uses_its_own_length_unit(self, dec: PacketDecoder) -> None:
        """AH (RFC 4302) measures length in 4-octet units minus 2, unlike other
        extension headers (8-octet units minus 1)."""
        icv = b"\xaa" * 12
        ah = struct.pack("!BBHII", 6, (12 + len(icv)) // 4 - 2, 0, 0x100, 1) + icv
        event = one(dec, eth(ipv6("2001:db8::1", "2001:db8::2", 51, ah + tcp(5555, 22)), 0x86DD))
        assert event is not None and event.protocol is Protocol.TCP
        assert (event.src_port, event.dst_port) == (5555, 22)

    def test_no_next_header(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv6("2001:db8::1", "2001:db8::2", 59, b""), 0x86DD))
        assert event is not None and event.protocol is Protocol.IPV6 and event.src_port is None

    def test_truncated_extension_chain_rejected(self, dec: PacketDecoder) -> None:
        packet = ipv6("2001:db8::1", "2001:db8::2", 0, struct.pack("!BB", 6, 10) + b"\x00" * 6)
        assert one(dec, eth(packet, 0x86DD)) is None

    def test_extension_header_loop_is_bounded(self, dec: PacketDecoder) -> None:
        chain = b"".join(ext_header(0, 0) for _ in range(64)) + udp(1, 2)
        started = time.perf_counter()
        one(dec, eth(ipv6("2001:db8::1", "2001:db8::2", 0, chain), 0x86DD))
        assert time.perf_counter() - started < 0.1

    def test_wrong_version_rejected(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(ipv6("::1", "::2", 17, udp(1, 2), version=4), 0x86DD)) is None

    def test_payload_trimmed_to_payload_length(self, dec: PacketDecoder) -> None:
        """Bytes after the IPv6 payload (trailer/FCS) are not transport payload."""
        packet = ipv6("2001:db8::1", "2001:db8::2", 17, udp(1, 2, b"data")) + b"\xff" * 4
        event = one(dec, eth(packet, 0x86DD))
        assert event is not None and event.payload_length == 4

    def test_jumbo_payload_length_zero_uses_capture(self, dec: PacketDecoder) -> None:
        packet = ipv6("2001:db8::1", "2001:db8::2", 17, udp(1, 2, b"data"), payload_length=0)
        event = one(dec, eth(packet, 0x86DD))
        assert event is not None and event.payload_length == 4

    def test_icmpv6_echo(self, dec: PacketDecoder) -> None:
        event = one(
            dec, eth(ipv6("fe80::1", "fe80::2", 58, icmp(128, 0, b"\x12\x34\x00\x05")), 0x86DD)
        )
        assert event is not None and event.protocol is Protocol.ICMPV6
        assert event.metadata["icmp"]["identifier"] == 0x1234
        assert event.metadata["icmp"]["sequence"] == 5
        neighbour = one(
            dec, eth(ipv6("fe80::1", "ff02::1", 58, icmp(135, 0, b"\x00" * 20)), 0x86DD)
        )
        assert neighbour is not None and neighbour.metadata["icmp"]["type"] == 135
        assert neighbour.metadata["icmp"]["identifier"] is None


# ================================================================ transport


class TestTcp:
    @pytest.mark.parametrize("value", range(256))
    def test_every_flag_combination_round_trips(self, dec: PacketDecoder, value: int) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, value))))
        assert event is not None and event.tcp_flags is not None
        assert event.tcp_flags.to_int() == value

    def test_options_and_payload(self, dec: PacketDecoder) -> None:
        options = b"\x02\x04\x05\xb4" + b"\x04\x02" + b"\x01" + b"\x03\x03\x07" + b"\x01\x01"
        segment = tcp(
            1, 2, 0x18, options=options, payload=b"hello", seq=7, ack=9, window=512, urgent=3
        )
        info = layers.decode_tcp(segment)
        assert info is not None
        assert info.header_length == 20 + len(options) and info.options_raw == options
        assert (info.seq, info.ack, info.window, info.urgent_pointer, info.payload) == (
            7,
            9,
            512,
            3,
            b"hello",
        )
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, segment)))
        assert event is not None and event.payload_length == 5

    @pytest.mark.parametrize("data_offset", [0, 1, 4])
    def test_data_offset_below_minimum_is_a_counted_failure(
        self, dec: PacketDecoder, data_offset: int
    ) -> None:
        assert (
            one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, data_offset=data_offset))))
            is None
        )
        assert dec.stats() == {"decoded": 0, "failed": 1}

    def test_data_offset_beyond_capture_is_clamped(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, data_offset=15))))
        assert event is not None and event.dst_port == 2 and event.payload_length == 0

    def test_short_tcp_header_rejected(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2)[:19]))) is None


class TestUdpIcmpArp:
    def test_udp_fields(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(123, 40000, b"\x00" * 48))))
        assert event is not None and event.protocol is Protocol.UDP
        assert (event.src_port, event.dst_port, event.payload_length) == (123, 40000, 48)

    def test_short_udp_rejected(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, b"\x00" * 7))) is None

    @pytest.mark.parametrize(
        ("icmp_type", "code", "echo_request", "unreachable", "has_id"),
        [
            (8, 0, True, False, True),
            (0, 0, False, False, True),
            (3, 3, False, True, False),
            (11, 0, False, False, False),
            (13, 0, False, False, True),
        ],
    )
    def test_icmp_types(
        self,
        dec: PacketDecoder,
        icmp_type: int,
        code: int,
        echo_request: bool,
        unreachable: bool,
        has_id: bool,
    ) -> None:
        event = one(
            dec,
            eth(
                ipv4(
                    "10.0.0.1",
                    "10.0.0.2",
                    1,
                    icmp(icmp_type, code, b"\x00\x07\x00\x09" + b"p" * 16),
                )
            ),
        )
        assert event is not None and event.protocol is Protocol.ICMP
        meta = event.metadata["icmp"]
        assert (meta["type"], meta["code"]) == (icmp_type, code)
        assert meta["is_echo_request"] is echo_request and meta["is_unreachable"] is unreachable
        assert (meta["identifier"], meta["sequence"]) == ((7, 9) if has_id else (None, None))
        assert event.payload_length == 16
        assert event.src_port is None

    def test_icmp_echo_too_short_for_id(self, dec: PacketDecoder) -> None:
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 1, icmp(8, 0, b"\x00"))))
        assert event is not None and event.metadata["icmp"]["identifier"] is None
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\x00"))) is None

    @pytest.mark.parametrize(("op", "label"), [(1, "request"), (2, "reply"), (3, "other")])
    def test_arp(self, dec: PacketDecoder, op: int, label: str) -> None:
        event = one(dec, eth(arp(op, "192.168.1.1", "192.168.1.77"), 0x0806))
        assert event is not None and event.protocol is Protocol.ARP
        assert (event.src_ip, event.dst_ip) == ("192.168.1.1", "192.168.1.77")
        assert event.metadata["arp"] == {
            "operation": label,
            "sender_mac": "0a:0b:0c:0d:0e:0f",
            "target_ip": "192.168.1.77",
        }

    def test_non_ethernet_arp_rejected(self, dec: PacketDecoder) -> None:
        assert one(dec, eth(arp(1, "192.168.1.1", "192.168.1.2", hw_type=6), 0x0806)) is None
        assert one(dec, eth(arp(1, "192.168.1.1", "192.168.1.2")[:27], 0x0806)) is None


# ====================================================================== DNS


class TestDns:
    def test_query_via_decoder(self, dec: PacketDecoder) -> None:
        message = (
            dns_header() + dns_name("x7f2k9qp3mzr8v1bq4w6.Example.com") + struct.pack("!HH", 16, 1)
        )
        event = one(dec, eth(ipv4("10.0.0.5", "10.0.0.1", 17, udp(40000, 53, message))))
        assert event is not None
        dns = event.metadata["dns"]
        assert dns["transaction_id"] == 0xBEEF and dns["is_response"] is False
        assert dns["query_name"] == "x7f2k9qp3mzr8v1bq4w6.Example.com"
        assert dns["query_type"] == "TXT" and dns["max_label_length"] == 20
        assert dns["name_entropy"] > 3.8 and dns["is_nxdomain"] is False

    @pytest.mark.parametrize("port", [53, 5353, 5355])
    def test_dns_ports(self, dec: PacketDecoder, port: int) -> None:
        message = dns_header() + dns_name("a.local") + struct.pack("!HH", 1, 1)
        event = one(dec, eth(ipv4("10.0.0.5", "224.0.0.251", 17, udp(port, port, message))))
        assert event is not None and event.metadata["dns"]["query_name"] == "a.local"

    def test_not_parsed_on_other_ports(self, dec: PacketDecoder) -> None:
        message = dns_header() + dns_name("a.example") + struct.pack("!HH", 1, 1)
        event = one(dec, eth(ipv4("10.0.0.5", "10.0.0.1", 17, udp(40000, 9999, message))))
        assert event is not None and "dns" not in event.metadata

    def test_nxdomain_response_with_compressed_answer(self, dec: PacketDecoder) -> None:
        question = dns_name("gone.example.com") + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        message = dns_header(flags=0x8183, an=1) + question + answer
        event = one(dec, eth(ipv4("10.0.0.1", "10.0.0.5", 17, udp(53, 40000, message))))
        assert event is not None
        dns = event.metadata["dns"]
        assert dns["is_response"] and dns["rcode"] == 3 and dns["is_nxdomain"]
        assert dns["answer_count"] == 1 and dns["query_name"] == "gone.example.com"

    def test_compression_pointer_in_second_question(self) -> None:
        first = dns_name("www.example.com") + struct.pack("!HH", 1, 1)
        # "mail" + pointer to offset 16, where "example.com" starts in the first name.
        second = b"\x04mail\xc0\x10" + struct.pack("!HH", 28, 1)
        info = parse_dns(dns_header(qd=2) + first + second)
        assert info is not None
        assert [q.name for q in info.questions] == ["www.example.com", "mail.example.com"]
        assert [q.type_name for q in info.questions] == ["A", "AAAA"]

    @pytest.mark.parametrize(
        "name_bytes",
        [
            b"\xc0\x0c",  # points at itself
            b"\xc0\x0e\xc0\x0c",  # A -> B -> A
            b"\x03abc\xc0\x0c",  # label then back to its own start
            b"\xc3\xff",  # points past the end
            b"\xc0",  # pointer cut in half
        ],
    )
    def test_pointer_loops_and_bad_pointers_terminate(self, name_bytes: bytes) -> None:
        payload = dns_header() + name_bytes + struct.pack("!HH", 1, 1)
        started = time.perf_counter()
        info = parse_dns(payload)
        assert time.perf_counter() - started < 0.05
        assert info is not None and info.transaction_id == 0xBEEF

    def test_many_chained_pointers_terminate(self) -> None:
        # 400 pointers, each jumping to the next: bounded by the label cap, not by
        # the loop-detection set (no offset repeats).
        chain = b"".join(struct.pack("!H", 0xC000 | (12 + 2 * (i + 1))) for i in range(400))
        payload = dns_header() + chain + b"\x01a\x00" + struct.pack("!HH", 1, 1)
        started = time.perf_counter()
        info = parse_dns(payload)
        assert time.perf_counter() - started < 0.05
        assert info is not None

    def test_truncated_name_and_missing_qtype(self) -> None:
        info = parse_dns(dns_header() + b"\x3fabc")  # label claims 63 bytes, has 3
        assert info is not None and info.questions == [] and info.query_name is None
        info = parse_dns(dns_header() + dns_name("ok.example") + b"\x00")
        assert info is not None and info.questions == []

    def test_label_cap_bounds_huge_names(self) -> None:
        name = b"\x01a" * 300 + b"\x00"
        info = parse_dns(dns_header() + name + struct.pack("!HH", 1, 1))
        assert info is not None
        for question in info.questions:
            assert question.name.count(".") < 64

    @pytest.mark.parametrize("label_type", [0x40, 0x80])
    def test_reserved_label_types_do_not_produce_oversized_labels(self, label_type: int) -> None:
        payload = (
            dns_header()
            + bytes([label_type | 0x05])
            + b"z" * 200
            + b"\x00"
            + struct.pack("!HH", 1, 1)
        )
        info = parse_dns(payload)
        assert info is not None and info.max_label_length <= 63

    def test_qdcount_zero_and_short_header(self) -> None:
        info = parse_dns(dns_header(qd=0))
        assert info is not None and info.questions == [] and info.max_label_length == 0
        assert info.name_entropy == 0.0
        assert parse_dns(b"\x00" * 11) is None

    def test_qdcount_capped(self) -> None:
        question = dns_name("a.b") + struct.pack("!HH", 1, 1)
        info = parse_dns(dns_header(qd=65535) + question * 40)
        assert info is not None and len(info.questions) == 16

    def test_dns_over_tcp_skips_length_prefix(self, dec: PacketDecoder) -> None:
        """DNS over TCP (RFC 1035 4.2.2) prefixes each message with a 2-byte length.
        Without skipping it the transaction id and flags are misread."""
        message = dns_header(txid=0x1111) + dns_name("big.example.org") + struct.pack("!HH", 252, 1)
        segment = tcp(40000, 53, 0x18, payload=struct.pack("!H", len(message)) + message)
        event = one(dec, eth(ipv4("10.0.0.5", "10.0.0.1", 6, segment)))
        assert event is not None
        dns = event.metadata["dns"]
        assert dns["transaction_id"] == 0x1111 and dns["query_name"] == "big.example.org"
        assert dns["query_type"] == "AXFR" and dns["is_response"] is False


# =============================================================== HTTP / TLS


class TestHttp:
    def test_request_metadata_via_decoder(self, dec: PacketDecoder) -> None:
        request = (
            b"POST /api/login?next=/ HTTP/1.1\r\nHost: portal.example\r\n"
            b"User-Agent: curl/8.0\r\nAuthorization: Bearer s3cr3t\r\n\r\n{}"
        )
        event = one(
            dec, eth(ipv4("10.0.0.5", "10.0.0.80", 6, tcp(50000, 8080, 0x18, payload=request)))
        )
        assert event is not None
        assert event.metadata["http"] == {
            "is_request": True,
            "method": "POST",
            "path": "/api/login?next=/",
            "status_code": None,
            "host": "portal.example",
            "user_agent": "curl/8.0",
            "has_authorization": True,
        }
        assert "s3cr3t" not in repr(event)

    def test_response_metadata(self, dec: PacketDecoder) -> None:
        response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
        event = one(
            dec, eth(ipv4("10.0.0.80", "10.0.0.5", 6, tcp(80, 50000, 0x18, payload=response)))
        )
        assert event is not None
        assert (
            event.metadata["http"]["status_code"] == 503
            and not event.metadata["http"]["is_request"]
        )

    def test_http_on_unregistered_port_is_not_parsed(self, dec: PacketDecoder) -> None:
        request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        event = one(
            dec, eth(ipv4("10.0.0.5", "10.0.0.80", 6, tcp(50000, 9999, 0x18, payload=request)))
        )
        assert event is not None and "http" not in event.metadata

    @pytest.mark.parametrize(
        "payload",
        [
            b"GET / HTTP/1.1",  # no CRLF, and shorter than the minimum
            b"GET /index.html HTTP/1.1 without line ending",
            b"FOO /x HTTP/1.1\r\nHost: a\r\n\r\n",
            b"HTTP/1.1 abc Weird\r\n\r\n\r\n\r\n",
            b"GET\r\nHost: example\r\n\r\n",
        ],
    )
    def test_non_http_payloads(self, payload: bytes) -> None:
        assert parse_http(payload) is None

    def test_header_and_path_caps(self) -> None:
        headers = b"".join(b"X-Filler-%d: v\r\n" % i for i in range(100))
        request = (
            b"GET /" + b"a" * 2000 + b" HTTP/1.1\r\n" + headers + b"Host: late.example\r\n\r\n"
        )
        info = parse_http(request)
        assert info is not None and info.path is not None and len(info.path) == 512
        assert info.host is None  # beyond the 40-header scan cap


class TestTls:
    def test_client_hello_metadata(self) -> None:
        info = parse_tls(client_hello())
        assert info is not None and info.is_client_hello
        assert info.sni == "login.example.com"
        assert info.alpn == ["h2", "http/1.1"]
        assert info.supported_versions == ["TLS1.3", "TLS1.2"]
        assert info.negotiated_version == "TLS1.3" and not info.is_legacy_version
        assert info.cipher_suites == [0x1301, 0x1302, 0xC02F]

    def test_legacy_client_without_extensions(self) -> None:
        info = parse_tls(client_hello(None, alpn=(), versions=(), ciphers=(0x002F,)))
        assert info is not None and info.sni is None and info.alpn == []
        assert info.negotiated_version == "TLS1.0" and info.is_legacy_version

    def test_server_hello(self) -> None:
        info = parse_tls(server_hello(cipher=0x1303))
        assert info is not None and not info.is_client_hello and info.selected_cipher == 0x1303

    def test_via_decoder_on_tls_port(self, dec: PacketDecoder) -> None:
        segment = tcp(51000, 443, 0x18, payload=client_hello("api.example.net"))
        event = one(dec, eth(ipv4("10.0.0.5", "203.0.113.10", 6, segment)))
        assert event is not None
        assert event.metadata["tls"] == {
            "handshake_type": "client_hello",
            "version": "TLS1.3",
            "sni": "api.example.net",
            "alpn": ["h2", "http/1.1"],
            "cipher_count": 3,
            "is_legacy_version": False,
        }

    def test_application_data_and_non_tls(self) -> None:
        assert parse_tls(b"\x17\x03\x03\x00\x20" + b"\x00" * 32) is None
        assert parse_tls(b"\x16\x03\x01\x00\x10\x0b" + b"\x00" * 40) is None  # certificate msg

    def test_truncated_client_hello_at_every_length(self) -> None:
        hello = client_hello()
        for cut in range(len(hello) + 1):
            info = parse_tls(hello[:cut])
            if info is not None:
                assert info.sni in (None, "login.example.com")

    def test_lying_extension_lengths(self) -> None:
        hello = bytearray(client_hello())
        # Corrupt the SNI name length to claim far more than is present.
        index = hello.find(b"Login")
        hello[index - 2 : index] = b"\xff\xff"
        info = parse_tls(bytes(hello))
        assert info is None or info.sni is None


# ============================================================ robustness


def _valid_frames() -> list[tuple[bytes, int]]:
    dns = dns_header() + dns_name("www.example.com") + struct.pack("!HH", 1, 1)
    return [
        (
            eth(
                ipv4(
                    "10.0.0.1",
                    "10.0.0.2",
                    6,
                    tcp(
                        1,
                        80,
                        0x18,
                        options=b"\x01" * 4,
                        payload=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                    ),
                    options=b"\x01" * 8,
                )
            ),
            LinkType.ETHERNET,
        ),
        (
            eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(4000, 53, dns)), vlans=(10, 20)),
            LinkType.ETHERNET,
        ),
        (eth(ipv4("10.0.0.1", "10.0.0.2", 1, icmp(8))), LinkType.ETHERNET),
        (eth(arp(1, "10.0.0.1", "10.0.0.2"), 0x0806), LinkType.ETHERNET),
        (
            eth(
                ipv6(
                    "2001:db8::1",
                    "2001:db8::2",
                    0,
                    ext_header(44, 0)
                    + struct.pack("!BBHI", 6, 0, 1, 9)
                    + tcp(5, 443, 0x18, payload=client_hello()),
                ),
                0x86DD,
            ),
            LinkType.ETHERNET,
        ),
        (
            struct.pack("!HHH8sH", 0, 1, 6, SRC_MAC + b"\x00\x00", 0x0800)
            + ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2)),
            LinkType.LINUX_SLL,
        ),
        (
            struct.pack("!HHIHBB8s", 0x86DD, 0, 1, 1, 0, 6, SRC_MAC + b"\x00\x00")
            + ipv6("::1", "::2", 58, icmp(128)),
            LinkType.LINUX_SLL2,
        ),
        (struct.pack("=I", 2) + ipv4("127.0.0.1", "127.0.0.1", 6, tcp(1, 2)), LinkType.NULL),
        (ipv4("10.0.0.1", "10.0.0.2", 17, udp(53, 53, dns)), LinkType.RAW),
    ]


#: Header boundaries (in bytes from the start of the frame) below which each of the
#: frames above cannot yield an event: link + network + transport minimums.
_MIN_DECODABLE = [
    14 + 28 + 20,
    22 + 20 + 8,
    14 + 20 + 4,
    14 + 28,
    14 + 40 + 8 + 8 + 20,
    16 + 20 + 8,
    20 + 40 + 4,
    4 + 20 + 20,
    20 + 8,
]


class TestRobustness:
    def test_minimum_table_matches_frames(self) -> None:
        assert len(_MIN_DECODABLE) == len(_valid_frames())

    @pytest.mark.parametrize("index", range(9))
    def test_truncated_at_every_length_never_raises(self, index: int) -> None:
        frame, link = _valid_frames()[index]
        decoder = PacketDecoder()
        assert decoder.decode(frame, TS, link) is not None, "untruncated frame must decode"
        decoder = PacketDecoder()
        results = [decoder.decode(frame[:cut], TS, link) for cut in range(len(frame) + 1)]
        assert decoder.decoded + decoder.failed == len(frame) + 1
        assert all(event is None for event in results[: _MIN_DECODABLE[index]])
        assert results[-1] is not None
        for event in results:
            if event is not None:
                assert event.src_ip and event.dst_ip
                assert event.payload_length >= 0

    def test_seeded_random_bytes_never_raise(self) -> None:
        rng = random.Random(0x5E)
        decoder = PacketDecoder()
        links = [
            LinkType.ETHERNET,
            LinkType.RAW,
            LinkType.LINUX_SLL,
            LinkType.LINUX_SLL2,
            LinkType.NULL,
            LinkType.IPV6,
            999,
        ]
        started = time.perf_counter()
        count = 4000
        for _ in range(count):
            size = rng.choice([0, 1, 13, 14, 20, 34, 54, 64, 128, 512, 1514])
            data = rng.randbytes(size)
            if size >= 14 and rng.random() < 0.5:
                # Steer half the frames past the link layer into IPv4/IPv6 decoding.
                data = (
                    data[:12]
                    + rng.choice([b"\x08\x00", b"\x86\xdd", b"\x08\x06", b"\x81\x00"])
                    + bytes([rng.choice([0x45, 0x4F, 0x60])])
                    + data[15:]
                )
            decoder.decode(data, TS, rng.choice(links))
        assert decoder.decoded + decoder.failed == count
        assert time.perf_counter() - started < 10

    def test_seeded_mutations_of_valid_frames_never_raise(self) -> None:
        rng = random.Random(2024)
        frames = _valid_frames()
        decoder = PacketDecoder()
        count = 4000
        for _ in range(count):
            frame, link = rng.choice(frames)
            mutable = bytearray(frame)
            for _ in range(rng.randint(1, 8)):
                mutable[rng.randrange(len(mutable))] = rng.randrange(256)
            if rng.random() < 0.3:
                del mutable[rng.randrange(len(mutable)) :]
            decoder.decode(bytes(mutable), TS, link)
        assert decoder.decoded + decoder.failed == count
        assert decoder.decoded > 0

    def test_application_parsers_fuzz(self) -> None:
        rng = random.Random(77)
        seeds = [
            client_hello(),
            server_hello(),
            dns_header() + dns_name("a.b.c") + b"\x00\x01\x00\x01",
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        ]
        for _ in range(3000):
            base = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 6)):
                base[rng.randrange(len(base))] = rng.randrange(256)
            payload = bytes(base) if rng.random() < 0.7 else rng.randbytes(rng.randint(0, 300))
            parse_dns(payload)
            parse_http(payload)
            parse_tls(payload)

    def test_unexpected_internal_error_is_counted_not_raised(
        self, dec: PacketDecoder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defence in depth: even a bug in a layer decoder must not escape decode()."""

        def broken(data: bytes) -> None:
            raise IndexError("decoder bug")

        monkeypatch.setattr(layers, "decode_udp", broken)
        assert one(dec, eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(1, 2)))) is None
        assert dec.stats() == {"decoded": 0, "failed": 1}
