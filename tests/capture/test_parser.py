"""Decoder tests.

Frames are built with Scapy, an independent implementation, so these tests check
our decoder against a known-good encoder rather than against itself.
"""

from __future__ import annotations

import struct

import pytest

scapy_all = pytest.importorskip("scapy.all")
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Dot1Q, Ether, IPv6, raw  # noqa: E402

from sentinelx.common.enums import Direction, Protocol  # noqa: E402
from sentinelx.common.netutils import parse_networks  # noqa: E402
from sentinelx.parser.application import (  # noqa: E402
    parse_dns,
    parse_http,
    parse_tls,
    shannon_entropy,
)
from sentinelx.parser.decoder import PacketDecoder, register_app_parser  # noqa: E402
from sentinelx.parser.layers import LinkType  # noqa: E402

#: Every frame names its addresses. A field left empty makes Scapy look up this host's
#: routes, interfaces and neighbours while building the frame, which fails without a
#: usable interface (Windows runners) or without root access to /dev/bpf (macOS).
SRC_MAC, DST_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"


def eth(**fields: object) -> Ether:
    return Ether(src=SRC_MAC, dst=DST_MAC, **fields)


def ip(**fields: object) -> IP:
    return IP(**{"src": "10.9.0.1", "dst": "10.9.0.2", **fields})


@pytest.fixture
def home_decoder() -> PacketDecoder:
    return PacketDecoder(parse_networks(["192.168.0.0/16"]))


def decode(decoder: PacketDecoder, packet: object, link_type: int = LinkType.ETHERNET):  # type: ignore[no-untyped-def]
    return decoder.decode(raw(packet), 1_700_000_000.5, link_type, "eth0")


def test_tcp_syn_fields(home_decoder: PacketDecoder) -> None:
    event = decode(
        home_decoder,
        eth()
        / IP(src="192.168.1.10", dst="10.0.0.5", ttl=61)
        / TCP(sport=44321, dport=22, flags="S"),
    )
    assert event is not None
    assert (event.src_ip, event.dst_ip, event.src_port, event.dst_port) == (
        "192.168.1.10",
        "10.0.0.5",
        44321,
        22,
    )
    assert event.protocol is Protocol.TCP and event.ttl == 61
    assert event.tcp_flags is not None and event.tcp_flags.is_syn_only
    assert event.direction is Direction.OUTBOUND
    assert event.payload_length == 0


@pytest.mark.parametrize(
    ("src", "dst", "direction"),
    [
        ("192.168.1.1", "192.168.1.2", Direction.INTERNAL),
        ("8.8.8.8", "192.168.1.2", Direction.INBOUND),
        ("192.168.1.2", "8.8.8.8", Direction.OUTBOUND),
        ("8.8.8.8", "1.1.1.1", Direction.EXTERNAL),
    ],
)
def test_direction_labelling(
    home_decoder: PacketDecoder, src: str, dst: str, direction: Direction
) -> None:
    event = decode(home_decoder, eth() / IP(src=src, dst=dst) / UDP(sport=1, dport=2))
    assert event is not None and event.direction is direction


def test_direction_unknown_without_home_networks(decoder: PacketDecoder) -> None:
    event = decode(decoder, eth() / IP(src="8.8.8.8", dst="1.1.1.1") / UDP())
    assert event is not None and event.direction is Direction.UNKNOWN


def test_ipv6_tcp(decoder: PacketDecoder) -> None:
    event = decode(
        decoder,
        eth()
        / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=58)
        / TCP(sport=1000, dport=443, flags="S"),
    )
    assert (
        event is not None
        and event.src_ip == "2001:db8::1"
        and event.dst_port == 443
        and event.ttl == 58
    )


def test_vlan_tag_is_skipped_and_recorded(decoder: PacketDecoder) -> None:
    event = decode(
        decoder,
        eth() / Dot1Q(vlan=42) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2),
    )
    assert event is not None and event.metadata["vlan_id"] == 42 and event.dst_port == 2


def test_icmp_echo(decoder: PacketDecoder) -> None:
    event = decode(decoder, eth() / IP(src="10.1.1.1", dst="10.1.1.2") / ICMP(type=8, id=99, seq=7))
    assert event is not None and event.protocol is Protocol.ICMP
    assert event.metadata["icmp"]["is_echo_request"] and event.metadata["icmp"]["sequence"] == 7


def test_arp_request(decoder: PacketDecoder) -> None:
    event = decode(
        decoder,
        eth() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.99", hwsrc="aa:bb:cc:dd:ee:ff"),
    )
    assert event is not None and event.protocol is Protocol.ARP
    assert event.metadata["arp"]["operation"] == "request"


def test_raw_ip_link_type(decoder: PacketDecoder) -> None:
    event = decode(decoder, IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5, dport=6), LinkType.RAW)
    assert event is not None and event.dst_port == 6


def test_non_first_fragment_has_no_ports(decoder: PacketDecoder) -> None:
    event = decode(
        decoder, eth() / IP(src="1.1.1.1", dst="2.2.2.2", frag=100, proto=6) / (b"\x00" * 40)
    )
    assert event is not None and event.src_port is None and "fragment" in event.metadata


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\x00",
        b"\xff" * 14,
        b"\x45" * 60,
        bytes(eth() / IP(src="1.1.1.1", dst="2.2.2.2"))[:20],
        bytes(eth() / IP(src="1.1.1.1", dst="2.2.2.2", ihl=15) / TCP()),
        bytes(eth(type=0x86DD) / (b"\x60" + b"\x00" * 10)),
    ],
)
def test_malformed_frames_never_raise(decoder: PacketDecoder, frame: bytes) -> None:
    decoder.decode(frame, 1.0)  # must not raise; returning None is fine


def test_decoder_counts_failures(decoder: PacketDecoder) -> None:
    decoder.decode(b"\x00", 1.0)
    decoder.decode(raw(eth() / ip() / UDP()), 1.0)
    assert decoder.stats() == {"decoded": 1, "failed": 1}


def test_dns_query_metadata(decoder: PacketDecoder) -> None:
    event = decode(
        decoder,
        eth()
        / ip()
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="c2.example.com", qtype="TXT")),
    )
    assert event is not None
    dns = event.metadata["dns"]
    assert (
        dns["query_name"] == "c2.example.com"
        and dns["query_type"] == "TXT"
        and not dns["is_response"]
    )


def test_dns_compression_pointer_loop_terminates() -> None:
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    looping_name = b"\xc0\x0c"  # pointer to itself
    info = parse_dns(header + looping_name + b"\x00\x01\x00\x01")
    assert info is not None  # terminated, did not hang


def test_http_request_keeps_only_allowlisted_headers_and_hides_credentials() -> None:
    payload = b"POST /login HTTP/1.1\r\nHost: app.test\r\nAuthorization: Basic c2VjcmV0\r\nX-Secret: nope\r\nCookie: sid=abc\r\n\r\nbody"
    info = parse_http(payload)
    assert info is not None and info.method == "POST" and info.host == "app.test"
    assert info.headers["authorization"] == "present" and info.headers["cookie"] == "present"
    assert "x-secret" not in info.headers
    assert "c2VjcmV0" not in str(info)


def test_http_response_and_non_http() -> None:
    response = parse_http(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    assert response is not None and response.status_code == 404 and not response.is_request
    assert parse_http(b"\x16\x03\x01garbage-not-http-at-all") is None


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(name)) + name
    body = struct.pack("!H", len(server_name)) + server_name
    ext = struct.pack("!HH", 0x0000, len(body)) + body
    hello = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(ext))
        + ext
    )
    handshake = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_tls_client_hello_sni_lowercased_wire_form() -> None:
    info = parse_tls(_client_hello("Login.Example.COM"))
    assert info is not None and info.is_client_hello and info.sni == "login.example.com"


@pytest.mark.parametrize("cut", [1, 6, 20, 44, 50])
def test_truncated_tls_never_raises(cut: int) -> None:
    parse_tls(_client_hello("a.example")[:cut])


def test_custom_app_parser_registration(decoder: PacketDecoder) -> None:
    from sentinelx.parser import decoder as decoder_module

    register_app_parser(
        "ntp",
        lambda payload, s, d: {"ntp": {"mode": payload[0] & 7}} if 123 in (s, d) else None,
        {Protocol.UDP},
    )
    try:
        event = decode(
            decoder, eth() / ip() / UDP(sport=40000, dport=123) / (b"\xe3" + b"\x00" * 47)
        )
        assert event is not None and event.metadata["ntp"] == {"mode": 3}
    finally:
        decoder_module._APP_PARSERS.pop("ntp", None)


def test_failing_app_parser_does_not_drop_packet(decoder: PacketDecoder) -> None:
    from sentinelx.parser import decoder as decoder_module

    def broken(payload: bytes, src: int, dst: int) -> dict[str, object]:
        raise RuntimeError("parser bug")

    register_app_parser("broken", broken, {Protocol.UDP})
    try:
        event = decode(
            decoder, eth() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=2) / b"payload"
        )
        assert event is not None and event.dst_port == 2
    finally:
        decoder_module._APP_PARSERS.pop("broken", None)


def test_shannon_entropy_separates_words_from_encoded_data() -> None:
    assert shannon_entropy("mail") < 2.5
    assert shannon_entropy("x7f2k9qp3mzr8v1bq4w6") > 3.8
    assert shannon_entropy("") == 0.0
