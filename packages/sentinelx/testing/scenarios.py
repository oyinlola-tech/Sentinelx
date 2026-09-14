"""Synthetic traffic scenarios for testing the detection engine.

Every function here **builds packet bytes in memory**.  Nothing in this module
opens a socket or transmits anything: these are fixtures, the network-security
equivalent of a unit-test factory.  They exist so the detection engine can be
measured against traffic with a known ground truth, which is the only honest way
to report a detection rate or a false-positive rate.

Each scenario returns ``(frames, expectation)``: the packets, and a description of
what a correct detector should conclude.  ``scripts/benchmark.py`` compares the
engine's actual output against that expectation - see ``docs/benchmarking.md``.
"""

from __future__ import annotations

import random
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sentinelx.capture.base import RawFrame
from sentinelx.common.models import TcpFlags
from sentinelx.parser.layers import LinkType

__all__ = [
    "BASE_TIME",
    "SCENARIOS",
    "Scenario",
    "build_dns_query",
    "build_dns_response",
    "build_http_request",
    "build_icmp",
    "build_tcp",
    "build_udp",
    "get_scenario",
]

_DEFAULT_SRC_MAC = bytes.fromhex("020000000001")
_DEFAULT_DST_MAC = bytes.fromhex("020000000002")


@dataclass(slots=True)
class Scenario:
    """A named traffic pattern with its expected detection outcome."""

    name: str
    description: str
    frames: list[RawFrame]
    #: Detector names that *should* fire. Empty means the traffic is benign and
    #: any detection is a false positive.
    expected_detectors: set[str] = field(default_factory=set)
    expected_source: str | None = None
    benign: bool = False
    duration_seconds: float = 0.0

    @property
    def packet_count(self) -> int:
        return len(self.frames)


# ====================================================== low-level frame builders


def _checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack("!6s6sH", _DEFAULT_DST_MAC, _DEFAULT_SRC_MAC, ethertype) + payload


def _ipv4(src: str, dst: str, protocol: int, payload: bytes, ttl: int = 64) -> bytes:
    import socket

    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, random.randint(0, 0xFFFF), 0x4000,
        ttl, protocol, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def build_tcp(
    src: str,
    dst: str,
    src_port: int,
    dst_port: int,
    *,
    flags: str = "S",
    payload: bytes = b"",
    seq: int = 0,
    ack: int = 0,
    ttl: int = 64,
) -> bytes:
    """Build an Ethernet/IPv4/TCP frame.

    Args:
        flags: any combination of ``FSRPAUEC`` (fin, syn, rst, psh, ack, urg, ece, cwr).
    """
    flag_bits = TcpFlags(
        fin="F" in flags, syn="S" in flags, rst="R" in flags, psh="P" in flags,
        ack="A" in flags, urg="U" in flags, ece="E" in flags, cwr="C" in flags,
    ).to_int()
    header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq or random.randint(0, 2**32 - 1), ack,
        5 << 4, flag_bits, 64240, 0, 0,
    )
    return _ethernet(_ipv4(src, dst, 6, header + payload, ttl))


def build_udp(src: str, dst: str, src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    """Build an Ethernet/IPv4/UDP frame."""
    header = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return _ethernet(_ipv4(src, dst, 17, header + payload))


def build_icmp(
    src: str, dst: str, *, icmp_type: int = 8, code: int = 0,
    identifier: int = 1, sequence: int = 1, payload: bytes = b"",
) -> bytes:
    """Build an Ethernet/IPv4/ICMP frame. Type 8 is an echo request."""
    body = struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence) + payload
    checksum = _checksum(body)
    body = body[:2] + struct.pack("!H", checksum) + body[4:]
    return _ethernet(_ipv4(src, dst, 1, body))


def _encode_dns_name(name: str) -> bytes:
    parts = [label.encode("ascii", "replace")[:63] for label in name.split(".") if label]
    return b"".join(bytes([len(part)]) + part for part in parts) + b"\x00"


def build_dns_query(
    src: str, dst: str, query_name: str, *, src_port: int = 40000, qtype: int = 1,
) -> bytes:
    """Build a DNS query frame."""
    header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(query_name) + struct.pack("!HH", qtype, 1)
    return build_udp(src, dst, src_port, 53, header + question)


def build_dns_response(
    src: str, dst: str, query_name: str, *, dst_port: int = 40000, rcode: int = 0,
) -> bytes:
    """Build a DNS response frame. ``rcode=3`` is NXDOMAIN."""
    flags = 0x8180 | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), flags, 1, 0, 0, 0)
    question = _encode_dns_name(query_name) + struct.pack("!HH", 1, 1)
    return build_udp(src, dst, 53, dst_port, header + question)


def build_http_request(
    src: str, dst: str, src_port: int, *, method: str = "GET", path: str = "/", host: str = "example.test",
) -> bytes:
    """Build an HTTP request frame carried over TCP."""
    body = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: sentinelx-fixture/1.0\r\nAccept: */*\r\n\r\n"
    ).encode()
    return build_tcp(src, dst, src_port, 80, flags="PA", payload=body)


def _frames(packets: Iterator[tuple[bytes, float]]) -> list[RawFrame]:
    return [
        RawFrame(data=data, timestamp=timestamp, link_type=LinkType.ETHERNET, interface="synthetic")
        for data, timestamp in packets
    ]


# ============================================================ traffic scenarios

BASE_TIME = 1_700_000_000.0


def normal_traffic(seed: int = 7, packet_count: int = 600) -> Scenario:
    """Ordinary mixed traffic: completed handshakes, web, DNS, occasional pings.

    This is the false-positive control. Every detection produced here is, by
    construction, a false positive.
    """
    rng = random.Random(seed)
    clients = [f"192.168.10.{n}" for n in range(20, 40)]
    servers = ["93.184.216.34", "151.101.1.140", "142.250.200.14"]
    resolver = "192.168.10.1"
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME

    while len(packets) < packet_count:
        client = rng.choice(clients)
        port = rng.randint(32768, 60999)
        now += rng.uniform(0.02, 0.4)

        choice = rng.random()
        if choice < 0.25:
            name = rng.choice(["www.example.com", "cdn.example.net", "api.service.test", "mail.corp.test"])
            packets.append((build_dns_query(client, resolver, name, src_port=port), now))
            packets.append((build_dns_response(resolver, client, name, dst_port=port), now + 0.01))
        elif choice < 0.9:
            server = rng.choice(servers)
            dst_port = rng.choice([80, 443, 443, 443])
            # A complete three-way handshake, data, then an orderly close. This
            # is exactly what a scan does not do.
            packets.append((build_tcp(client, server, port, dst_port, flags="S"), now))
            packets.append((build_tcp(server, client, dst_port, port, flags="SA"), now + 0.012))
            packets.append((build_tcp(client, server, port, dst_port, flags="A"), now + 0.013))
            if dst_port == 80:
                packets.append((build_http_request(client, server, port, path=rng.choice(["/", "/about", "/api/v1/items"])), now + 0.02))
            else:
                packets.append((build_tcp(client, server, port, dst_port, flags="PA", payload=b"\x16\x03\x01" + bytes(48)), now + 0.02))
            packets.append((build_tcp(server, client, dst_port, port, flags="PA", payload=bytes(rng.randint(200, 1400))), now + 0.05))
            packets.append((build_tcp(client, server, port, dst_port, flags="FA"), now + 0.3))
            packets.append((build_tcp(server, client, dst_port, port, flags="FA"), now + 0.31))
        else:
            target = rng.choice(servers)
            packets.append((build_icmp(client, target, sequence=rng.randint(1, 100)), now))
            packets.append((build_icmp(target, client, icmp_type=0, sequence=1), now + 0.02))

    packets = packets[:packet_count]
    return Scenario(
        name="normal_traffic",
        description="Mixed benign web, DNS and ICMP traffic with completed TCP handshakes.",
        frames=_frames(iter(packets)),
        expected_detectors=set(),
        benign=True,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def tcp_port_scan(
    attacker: str = "203.0.113.45",
    target: str = "192.168.10.50",
    ports: int = 220,
    seed: int = 11,
) -> Scenario:
    """A vertical SYN scan: many ports on one host, no handshakes completed.

    The defining features are a high distinct-port count from one source and an
    overwhelming ratio of bare SYNs, with RST replies from closed ports.
    """
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    chosen = rng.sample(range(1, 10000), ports)

    for index, port in enumerate(chosen):
        now += rng.uniform(0.002, 0.02)
        packets.append((build_tcp(attacker, target, 44000 + (index % 2000), port, flags="S"), now))
        # Most ports are closed and answer with RST; a couple are open.
        if index % 80 == 0:
            packets.append((build_tcp(target, attacker, port, 44000 + (index % 2000), flags="SA"), now + 0.004))
        else:
            packets.append((build_tcp(target, attacker, port, 44000 + (index % 2000), flags="RA"), now + 0.003))

    return Scenario(
        name="tcp_port_scan",
        description=f"Vertical SYN scan of {ports} ports on a single host.",
        frames=_frames(iter(packets)),
        expected_detectors={"tcp_port_scan"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def horizontal_scan(
    attacker: str = "203.0.113.77", port: int = 445, hosts: int = 120, seed: int = 13
) -> Scenario:
    """A horizontal sweep: one port across many hosts, characteristic of worm scanning."""
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index in range(hosts):
        now += rng.uniform(0.005, 0.03)
        target = f"192.168.{20 + index // 254}.{1 + index % 254}"
        packets.append((build_tcp(attacker, target, 50000 + index, port, flags="S"), now))
    return Scenario(
        name="horizontal_scan",
        description=f"Horizontal sweep of port {port} across {hosts} hosts.",
        frames=_frames(iter(packets)),
        expected_detectors={"horizontal_scan"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def udp_scan(
    attacker: str = "203.0.113.90", target: str = "192.168.10.60", ports: int = 150, seed: int = 17
) -> Scenario:
    """A UDP port sweep, answered mostly by ICMP port-unreachable."""
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index, port in enumerate(rng.sample(range(1, 20000), ports)):
        now += rng.uniform(0.003, 0.02)
        packets.append((build_udp(attacker, target, 40000 + index, port, b"\x00" * 8), now))
        if index % 3 == 0:
            packets.append((build_icmp(target, attacker, icmp_type=3, code=3), now + 0.004))
    return Scenario(
        name="udp_scan",
        description=f"UDP sweep of {ports} ports with ICMP port-unreachable replies.",
        frames=_frames(iter(packets)),
        expected_detectors={"udp_scan"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def ssh_brute_force(
    attacker: str = "198.51.100.23",
    target: str = "192.168.10.10",
    attempts: int = 60,
    seed: int = 19,
    port: int = 22,
) -> Scenario:
    """Repeated short-lived SSH sessions: connect, exchange a little, get reset.

    The signature is many *complete but short* connections to one auth service
    from one source - distinct from a scan, which never completes a handshake.
    """
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index in range(attempts):
        src = 45000 + index
        now += rng.uniform(0.25, 0.8)
        packets.append((build_tcp(attacker, target, src, port, flags="S"), now))
        packets.append((build_tcp(target, attacker, port, src, flags="SA"), now + 0.01))
        packets.append((build_tcp(attacker, target, src, port, flags="A"), now + 0.011))
        packets.append((build_tcp(target, attacker, port, src, flags="PA", payload=b"SSH-2.0-OpenSSH_9.6\r\n"), now + 0.02))
        packets.append((build_tcp(attacker, target, src, port, flags="PA", payload=b"SSH-2.0-libssh_0.10\r\n"), now + 0.03))
        # Server tears the session down: a failed authentication.
        packets.append((build_tcp(target, attacker, port, src, flags="R"), now + 0.15))
    return Scenario(
        name="ssh_brute_force",
        description=f"{attempts} short-lived sessions to port {port} reset by the server.",
        frames=_frames(iter(packets)),
        expected_detectors={"ssh_brute_force" if port == 22 else "auth_brute_force"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def syn_flood(
    target: str = "192.168.10.80", count: int = 3000, sources: int = 1, seed: int = 23
) -> Scenario:
    """A SYN flood: half-open connections at high rate, no ACKs."""
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    attacker = "198.51.100.200"
    for index in range(count):
        now += rng.uniform(0.0005, 0.002)
        source = attacker if sources == 1 else f"198.51.100.{1 + index % sources}"
        packets.append((build_tcp(source, target, 1024 + (index % 64000), 80, flags="S"), now))
    return Scenario(
        name="syn_flood",
        description=f"{count} SYN packets to one service with no completed handshakes.",
        frames=_frames(iter(packets)),
        expected_detectors={"syn_flood", "connection_rate"},
        expected_source=attacker if sources == 1 else None,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def icmp_flood(
    attacker: str = "198.51.100.66", target: str = "192.168.10.90", count: int = 1200, seed: int = 29
) -> Scenario:
    """A high-rate ICMP echo flood."""
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index in range(count):
        now += rng.uniform(0.001, 0.004)
        packets.append((build_icmp(attacker, target, sequence=index % 65535, payload=b"\x00" * 56), now))
    return Scenario(
        name="icmp_flood",
        description=f"{count} ICMP echo requests at high rate.",
        frames=_frames(iter(packets)),
        expected_detectors={"icmp_flood"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def http_flood(
    attacker: str = "198.51.100.77", target: str = "192.168.10.100", count: int = 900, seed: int = 31
) -> Scenario:
    """A layer-7 request flood against one web server."""
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index in range(count):
        now += rng.uniform(0.001, 0.008)
        packets.append(
            (build_http_request(attacker, target, 40000 + (index % 20000), path=f"/search?q={index}"), now)
        )
    return Scenario(
        name="http_flood",
        description=f"{count} HTTP requests per source against one server.",
        frames=_frames(iter(packets)),
        expected_detectors={"http_flood"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def dns_tunneling(
    client: str = "192.168.10.66", resolver: str = "192.168.10.1", count: int = 400, seed: int = 37
) -> Scenario:
    """DNS used as a data channel: long, high-entropy labels under one domain."""
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index in range(count):
        now += rng.uniform(0.01, 0.05)
        label = "".join(rng.choice(alphabet) for _ in range(rng.randint(48, 60)))
        name = f"{label}.tunnel.example.test"
        packets.append((build_dns_query(client, resolver, name, src_port=40000 + (index % 2000), qtype=16), now))
    return Scenario(
        name="dns_tunneling",
        description=f"{count} DNS TXT queries with long, high-entropy labels.",
        frames=_frames(iter(packets)),
        expected_detectors={"dns_anomaly"},
        expected_source=client,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def dns_flood(
    client: str = "192.168.10.67", resolver: str = "192.168.10.1", count: int = 900, seed: int = 41
) -> Scenario:
    """A DNS query flood with many NXDOMAIN responses, as produced by DGA malware."""
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index in range(count):
        now += rng.uniform(0.002, 0.01)
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(10, 16))) + ".test"
        port = 40000 + (index % 2000)
        packets.append((build_dns_query(client, resolver, name, src_port=port), now))
        packets.append((build_dns_response(resolver, client, name, dst_port=port, rcode=3), now + 0.005))
    return Scenario(
        name="dns_flood",
        description=f"{count} DNS queries for algorithmically generated names, mostly NXDOMAIN.",
        frames=_frames(iter(packets)),
        expected_detectors={"dns_anomaly"},
        expected_source=client,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def mixed_intrusion(seed: int = 43) -> Scenario:
    """A multi-stage sequence from one source: scan, then brute force, then flood.

    Exercises the correlation engine: three detectors should fire for one source
    and be folded into a single incident rather than reported as three unrelated
    events.
    """
    attacker = "203.0.113.200"
    target = "192.168.10.10"
    frames: list[RawFrame] = []

    scan = tcp_port_scan(attacker=attacker, target=target, ports=120, seed=seed)
    frames.extend(scan.frames)

    offset = scan.frames[-1].timestamp + 2.0
    brute = ssh_brute_force(attacker=attacker, target=target, attempts=40, seed=seed + 1)
    shift = offset - brute.frames[0].timestamp
    frames.extend(
        RawFrame(data=f.data, timestamp=f.timestamp + shift, link_type=f.link_type, interface=f.interface)
        for f in brute.frames
    )

    offset = frames[-1].timestamp + 2.0
    flood = icmp_flood(attacker=attacker, target=target, count=600, seed=seed + 2)
    shift = offset - flood.frames[0].timestamp
    frames.extend(
        RawFrame(data=f.data, timestamp=f.timestamp + shift, link_type=f.link_type, interface=f.interface)
        for f in flood.frames
    )

    return Scenario(
        name="mixed_intrusion",
        description="One source performing a port scan, then SSH brute force, then an ICMP flood.",
        frames=frames,
        expected_detectors={"tcp_port_scan", "ssh_brute_force", "icmp_flood"},
        expected_source=attacker,
        duration_seconds=frames[-1].timestamp - frames[0].timestamp,
    )


def dns_rate_spike(
    baseline_seconds: int = 180,
    spike_seconds: int = 20,
    normal_qps: int = 20,
    spike_qps: int = 300,
    seed: int = 47,
) -> Scenario:
    """Steady DNS traffic, then one client's query rate jumps an order of magnitude.

    Tests the statistical detector: the spike rate is unremarkable in absolute
    terms for a large resolver, so only a learned baseline can call it unusual.
    The spike deliberately uses ordinary, low-entropy names so the DNS rule-based
    detector's tunnelling path does not fire on it.
    """
    rng = random.Random(seed)
    clients = [f"192.168.30.{n}" for n in range(10, 30)]
    resolver = "192.168.30.1"
    names = ["www.example.com", "api.example.com", "cdn.example.net", "mail.example.org", "time.example.com"]
    noisy = "192.168.30.99"
    packets: list[tuple[bytes, float]] = []
    for second in range(baseline_seconds + spike_seconds):
        spiking = second >= baseline_seconds
        rate = rng.randint(int(normal_qps * 0.8), int(normal_qps * 1.2))
        for _ in range(rate):
            packets.append((build_dns_query(rng.choice(clients), resolver, rng.choice(names)), BASE_TIME + second + rng.random()))
        if spiking:
            for index in range(spike_qps):
                packets.append((build_dns_query(noisy, resolver, names[index % len(names)]), BASE_TIME + second + rng.random()))
    packets.sort(key=lambda pair: pair[1])
    return Scenario(
        name="dns_rate_spike",
        description=f"{baseline_seconds}s of ~{normal_qps} DNS queries/s, then {spike_seconds}s with one client adding {spike_qps}/s.",
        frames=_frames(iter(packets)),
        expected_detectors={"statistical_anomaly"},
        expected_source=noisy,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def slow_port_scan(
    attacker: str = "203.0.113.61", target: str = "192.168.10.51", ports: int = 60, interval: float = 1.2, seed: int = 53
) -> Scenario:
    """A deliberately slow vertical scan: one probe every ``interval`` seconds.

    An EVASION case. With default settings no more than about a dozen probes fall
    inside the 15 second scan window, below the 20-port threshold, so the scan
    detector is expected to MISS it. Included so benchmarks measure a known
    limitation instead of only reporting successes.
    """
    rng = random.Random(seed)
    packets: list[tuple[bytes, float]] = []
    now = BASE_TIME
    for index, port in enumerate(rng.sample(range(1, 10000), ports)):
        now += interval
        packets.append((build_tcp(attacker, target, 44000 + index, port, flags="S"), now))
        packets.append((build_tcp(target, attacker, port, 44000 + index, flags="RA"), now + 0.003))
    return Scenario(
        name="slow_port_scan",
        description=f"{ports}-port SYN scan spread over {ports * interval:.0f}s (evasion case, expected to be missed).",
        frames=_frames(iter(packets)),
        expected_detectors={"tcp_port_scan"},
        expected_source=attacker,
        duration_seconds=packets[-1][1] - packets[0][1],
    )


def low_rate_brute_force(
    attacker: str = "198.51.100.44", target: str = "192.168.10.10", attempts: int = 30, interval: float = 8.0, seed: int = 59
) -> Scenario:
    """Credential guessing throttled to one attempt every ``interval`` seconds.

    An EVASION case: at most about seven attempts fall in the 60 second window,
    below the threshold of 15, so brute-force detection is expected to MISS it.
    """
    base = ssh_brute_force(attacker=attacker, target=target, attempts=attempts, seed=seed)
    frames: list[RawFrame] = []
    per_attempt = 6  # frames per session in ssh_brute_force
    for index, frame in enumerate(base.frames):
        attempt = index // per_attempt
        session_start = base.frames[attempt * per_attempt].timestamp
        offset = frame.timestamp - session_start
        frames.append(RawFrame(frame.data, BASE_TIME + attempt * interval + offset, frame.link_type, frame.interface, frame.wire_length))
    return Scenario(
        name="low_rate_brute_force",
        description=f"{attempts} SSH attempts, one every {interval:g}s (evasion case, expected to be missed).",
        frames=frames,
        expected_detectors={"ssh_brute_force"},
        expected_source=attacker,
        duration_seconds=frames[-1].timestamp - frames[0].timestamp,
    )


#: Every scenario, by name. Used by the CLI, the benchmark harness and the tests.
SCENARIOS: dict[str, Any] = {
    "normal_traffic": normal_traffic,
    "tcp_port_scan": tcp_port_scan,
    "horizontal_scan": horizontal_scan,
    "udp_scan": udp_scan,
    "ssh_brute_force": ssh_brute_force,
    "syn_flood": syn_flood,
    "icmp_flood": icmp_flood,
    "http_flood": http_flood,
    "dns_tunneling": dns_tunneling,
    "dns_flood": dns_flood,
    "mixed_intrusion": mixed_intrusion,
    "dns_rate_spike": dns_rate_spike,
    "slow_port_scan": slow_port_scan,
    "low_rate_brute_force": low_rate_brute_force,
}


def get_scenario(name: str, **kwargs: Any) -> Scenario:
    """Build a scenario by name.

    Raises:
        ValueError: naming every available scenario, so a typo is self-correcting.
    """
    builder = SCENARIOS.get(name)
    if builder is None:
        raise ValueError(f"unknown scenario {name!r}; available: {', '.join(sorted(SCENARIOS))}")
    return builder(**kwargs)  # type: ignore[no-any-return]
