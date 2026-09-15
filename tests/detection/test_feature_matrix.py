"""Feature extraction with exact expected values.

Traffic is constructed packet by packet, so every count below is known in advance
rather than asserted as "greater than zero".
"""

from __future__ import annotations

import math
import time
import tracemalloc
from typing import Any

import pytest

from sentinelx.anomaly.statistical import IntervalSample
from sentinelx.common.enums import Direction, Protocol
from sentinelx.common.models import PacketEvent, TcpFlags
from sentinelx.config.settings import DetectionSettings
from sentinelx.features.extractor import FeatureExtractor, GlobalStats
from sentinelx.features.profiles import SourceProfile, parent_domain
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.testing.scenarios import (
    BASE_TIME,
    build_dns_query,
    build_http_request,
    build_icmp,
    build_tcp,
    build_udp,
)

T0 = BASE_TIME


def flags(spec: str) -> TcpFlags:
    return TcpFlags(
        fin="F" in spec,
        syn="S" in spec,
        rst="R" in spec,
        psh="P" in spec,
        ack="A" in spec,
        urg="U" in spec,
    )


def tcp(
    src: str, dst: str, sport: int, dport: int, spec: str, ts: float, length: int = 60
) -> PacketEvent:
    return PacketEvent(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        protocol=Protocol.TCP,
        length=length,
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags(spec),
    )


def udp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    ts: float,
    *,
    length: int = 80,
    metadata: dict[str, Any] | None = None,
) -> PacketEvent:
    return PacketEvent(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        protocol=Protocol.UDP,
        length=length,
        src_port=sport,
        dst_port=dport,
        metadata=metadata or {},
    )


def dns_query(
    src: str, name: str, ts: float, *, label: int | None = None, entropy: float = 2.0
) -> PacketEvent:
    leftmost = len(name.split(".")[0])
    return udp(
        src,
        "10.0.0.1",
        40000,
        53,
        ts,
        metadata={
            "dns": {
                "is_response": False,
                "query_name": name,
                "max_label_length": label if label is not None else leftmost,
                "name_entropy": entropy,
            }
        },
    )


def icmp(src: str, dst: str, ts: float, length: int = 98) -> PacketEvent:
    return PacketEvent(timestamp=ts, src_ip=src, dst_ip=dst, protocol=Protocol.ICMP, length=length)


def http(src: str, path: str, ts: float) -> PacketEvent:
    return PacketEvent(
        timestamp=ts,
        src_ip=src,
        dst_ip="10.0.0.80",
        protocol=Protocol.TCP,
        length=300,
        src_port=50000,
        dst_port=80,
        tcp_flags=flags("PA"),
        payload_length=240,
        metadata={"http": {"is_request": True, "path": path, "host": "x"}},
    )


# ============================================================ per-packet view


class TestPacketFeatures:
    def test_packet_fields_are_exposed_verbatim(self) -> None:
        extractor = FeatureExtractor()
        packet = PacketEvent(
            timestamp=T0,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            protocol=Protocol.TCP,
            length=74,
            src_port=44321,
            dst_port=22,
            tcp_flags=flags("S"),
            direction=Direction.OUTBOUND,
        )
        features = extractor.process(packet).features()
        assert features["source_ip"] == "192.168.1.10"
        assert features["destination_ip"] == "10.0.0.5"
        assert features["source_port"] == 44321 and features["destination_port"] == 22
        assert features["protocol"] == "tcp" and features["packet_length"] == 74
        assert features["tcp_flags"] == "S" and features["direction"] == "outbound"
        assert features["flow_packets"] == 1 and features["handshake_complete"] is False

    def test_portless_packet_has_no_port_or_flags(self) -> None:
        features = FeatureExtractor().process(icmp("10.0.0.1", "10.0.0.2", T0)).features()
        assert features["destination_port"] is None and features["source_port"] is None
        assert "tcp_flags" not in features and features["protocol"] == "icmp"

    def test_features_are_cached_per_context(self) -> None:
        context = FeatureExtractor().process(icmp("10.0.0.1", "10.0.0.2", T0))
        assert context.features() is context.features()

    def test_end_to_end_from_real_frames(self) -> None:
        decoder, extractor = PacketDecoder(), FeatureExtractor()
        frames = [
            (build_tcp("10.1.1.1", "10.2.2.2", 40000, 443, flags="S"), T0),
            (build_tcp("10.1.1.1", "10.2.2.3", 40001, 8443, flags="S"), T0 + 1),
            (build_udp("10.1.1.1", "10.2.2.4", 40002, 161, b"\x30" * 20), T0 + 2),
            (build_icmp("10.1.1.1", "10.2.2.5"), T0 + 3),
            (build_dns_query("10.1.1.1", "10.0.0.53", "www.example.com"), T0 + 4),
            (build_http_request("10.1.1.1", "10.2.2.2", 40003, path="/a"), T0 + 5),
        ]
        context = None
        for data, ts in frames:
            packet = decoder.decode(data, ts)
            assert packet is not None
            context = extractor.process(packet)
        assert context is not None
        f = context.features()
        assert f["packet_count"] == 6 and f["total_packets"] == 6
        assert f["unique_dst_ports"] == 3  # 443, 8443, 80 - TCP only
        assert f["unique_dst_ips"] == 5  # 10.2.2.2-5 and the resolver
        assert f["unique_udp_ports"] == 2  # 161 and 53
        assert f["syn_count"] == 2 and f["connection_attempts"] == 2
        assert f["icmp_count"] == 1 and f["dns_query_count"] == 1 and f["http_request_count"] == 1
        assert f["protocol_distribution"] == {"tcp": 0.5, "udp": 0.3333, "icmp": 0.1667}
        assert f["first_seen"] == T0 and f["last_seen"] == T0 + 5
        assert f["observed_span"] == 5.0
        assert f["total_bytes"] == sum(len(data) for data, _ in frames)


# ============================================================== source profile


class TestSourceProfile:
    def test_unique_ports_and_destinations(self) -> None:
        extractor = FeatureExtractor()
        src = "203.0.113.5"
        for i in range(30):
            # 10 hosts x 3 ports, each combination once.
            extractor.process(
                tcp(src, f"10.0.0.{i % 10}", 50000 + i, 1000 + i % 3, "S", T0 + i * 0.1)
            )
        context = extractor.process(tcp(src, "10.0.0.0", 50999, 1000, "S", T0 + 3.0))
        f = context.features()
        assert f["unique_dst_ports"] == 3 and f["unique_dst_ips"] == 10
        assert f["syn_count"] == 31 and f["connection_attempts"] == 31 and f["syn_ratio"] == 1.0
        assert context.profile.scan_ports.unique_count(src, T0 + 3.0) == 3
        assert context.profile.scan_hosts.unique_count(src, T0 + 3.0) == 10

    def test_packet_rate_and_size_statistics_are_exact(self) -> None:
        extractor = FeatureExtractor()
        sizes = [60, 100, 140, 180, 220]
        for i, size in enumerate(sizes):
            context = extractor.process(icmp("10.0.0.1", "10.0.0.2", T0 + i * 0.5, size))
        f = context.features()
        mean = sum(sizes) / len(sizes)
        stddev = math.sqrt(sum((s - mean) ** 2 for s in sizes) / len(sizes))
        assert f["packet_size_mean"] == round(mean, 2) and f["packet_size_stddev"] == round(
            stddev, 2
        )
        assert f["packet_rate"] == round(5 / 2.0, 3)  # 5 packets over a 2 s span
        assert f["icmp_count"] == 5 and f["total_bytes"] == sum(sizes)

    def test_syn_ratio_counts_only_bare_syns(self) -> None:
        extractor = FeatureExtractor()
        src, dst = "10.0.0.7", "10.0.0.8"
        specs = ["S", "A", "PA", "S", "SA", "R"]
        for i, spec in enumerate(specs):
            context = extractor.process(tcp(src, dst, 40000, 80, spec, T0 + i))
        f = context.features()
        assert f["syn_count"] == 2 and f["syn_ratio"] == round(2 / 6, 4)

    def test_replies_drive_syn_ack_and_refusal_ratios(self) -> None:
        extractor = FeatureExtractor()
        scanner, target = "198.51.100.1", "10.0.0.9"
        for port in range(1, 11):
            extractor.process(tcp(scanner, target, 40000 + port, port, "S", T0 + port * 0.01))
            reply = "SA" if port <= 2 else "RA"
            extractor.process(
                tcp(target, scanner, port, 40000 + port, reply, T0 + port * 0.01 + 0.001)
            )
        profile = extractor.profiles[scanner]
        f = profile.snapshot(T0 + 1)
        assert f["syn_ack_ratio"] == 0.2 and f["rst_count"] == 8
        assert f["refusal_ratio"] == 0.8 and f["failed_attempts"] == 8
        # The target's own profile records its replies as packets, not as connections.
        assert extractor.profiles[target].snapshot(T0 + 1)["connection_attempts"] == 0

    def test_udp_service_replies_are_not_counted_as_probed_ports(self) -> None:
        extractor = FeatureExtractor()
        for i in range(40):
            extractor.process(udp("10.0.0.53", f"10.0.1.{i}", 53, 30000 + i, T0 + i * 0.01))
        extractor.process(udp("10.0.0.53", "10.0.1.1", 5353, 5353, T0 + 1))
        f = extractor.profiles["10.0.0.53"].snapshot(T0 + 1)
        assert f["unique_udp_ports"] == 1 and f["unique_dst_ips"] == 40

    def test_dns_request_frequency_and_classification(self) -> None:
        settings = DetectionSettings()
        extractor = FeatureExtractor(settings)
        src = "10.0.0.66"
        names = ["www.example.com", "api.example.com", "www.example.com"]
        for i, name in enumerate(names):
            extractor.process(dns_query(src, name, T0 + i))
        long_label = "a" * settings.dns_long_label_length + ".tunnel.example.org"
        extractor.process(dns_query(src, long_label, T0 + 3, entropy=1.0))
        random_label = "x7f2k9qp3mzr8v1bq4w6.c2.example.net"  # 20 chars, high entropy
        extractor.process(dns_query(src, random_label, T0 + 4, entropy=4.1))
        short_random = "x7f2k9qp3m.cdn.example.net"  # high entropy but only 10 chars
        context = extractor.process(dns_query(src, short_random, T0 + 5, entropy=4.1))
        profile = context.profile
        f = context.features()
        assert f["dns_query_count"] == 6 and f["dns_unique_domains"] == 5
        assert f["dns_suspicious_queries"] == 2
        assert profile.dns_suspicious.distinct_values() == {"example.org", "example.net"}
        assert profile.dns_times.count(settings.dns_window_seconds, T0 + 5) == 6
        assert profile.dns_times.count(2.0, T0 + 5) == 3  # T0+3, T0+4, T0+5

    def test_dns_responses_and_malformed_dns_metadata_are_ignored(self) -> None:
        extractor = FeatureExtractor()
        src = "10.0.0.67"
        extractor.process(
            udp(
                src,
                "10.0.0.1",
                40000,
                53,
                T0,
                metadata={"dns": {"is_response": True, "query_name": "a.b"}},
            )
        )
        extractor.process(udp(src, "10.0.0.1", 40000, 53, T0 + 1, metadata={"dns": "not-a-dict"}))
        extractor.process(
            udp(src, "10.0.0.1", 40000, 53, T0 + 2, metadata={"dns": {"query_name": None}})
        )
        extractor.process(
            udp(
                src,
                "10.0.0.1",
                40000,
                53,
                T0 + 3,
                metadata={
                    "dns": {"query_name": "ok.test", "max_label_length": None, "name_entropy": None}
                },
            )
        )
        f = extractor.profiles[src].snapshot(T0 + 3)
        assert f["dns_query_count"] == 1 and f["dns_suspicious_queries"] == 0

    def test_http_request_frequency_and_paths(self) -> None:
        extractor = FeatureExtractor()
        src = "10.0.0.3"
        for i, path in enumerate(["/", "/a", "/a", "/b", ""]):
            context = extractor.process(http(src, path, T0 + i))
        response = PacketEvent(
            timestamp=T0 + 5,
            src_ip=src,
            dst_ip="10.0.0.80",
            protocol=Protocol.TCP,
            length=60,
            src_port=50000,
            dst_port=80,
            tcp_flags=flags("PA"),
            metadata={"http": {"is_request": False, "status_code": 200}},
        )
        context = extractor.process(response)
        f = context.features()
        assert f["http_request_count"] == 5 and f["http_unique_paths"] == 3  # "" counts as "/"
        assert context.profile.http_times.count(10.0, T0 + 5) == 5

    def test_short_sessions_counted_once_per_flow(self) -> None:
        extractor = FeatureExtractor()
        client, server = "198.51.100.5", "10.0.0.20"
        for i in range(4):
            base = T0 + i * 10
            port = 43000 + i
            extractor.process(tcp(client, server, port, 22, "S", base))
            extractor.process(tcp(server, client, 22, port, "SA", base + 0.01))
            extractor.process(tcp(client, server, port, 22, "A", base + 0.02))
            end = base + (1.0 if i < 3 else 6.0)  # the last session lasts 6 s: not short
            extractor.process(tcp(server, client, 22, port, "FA", end))
            extractor.process(tcp(client, server, port, 22, "R", end + 0.01))
        profile = extractor.profiles[client]
        assert profile.short_sessions.count_of(22) == 3
        assert profile.snapshot(T0 + 40)["short_sessions"] == 3
        # The server never initiated anything.
        assert len(extractor.profiles[server].short_sessions) == 0

    def test_windows_expire_old_events(self) -> None:
        settings = DetectionSettings()
        extractor = FeatureExtractor(settings)
        src = "10.0.0.9"
        for port in range(1, 6):
            extractor.process(tcp(src, "10.0.0.1", 40000, port, "S", T0))
        later = T0 + extractor.window_seconds + 1
        context = extractor.process(tcp(src, "10.0.0.1", 40000, 99, "S", later))
        f = context.features()
        assert f["packet_count"] == 1 and f["unique_dst_ports"] == 1 and f["syn_count"] == 1
        assert f["total_packets"] == 6  # lifetime totals do not expire

    def test_scan_window_is_narrower_than_profile_window(self) -> None:
        settings = DetectionSettings(port_scan_window_seconds=5, brute_force_window_seconds=60)
        extractor = FeatureExtractor(settings)
        src = "10.0.0.10"
        for port in range(1, 11):
            extractor.process(tcp(src, "10.0.0.1", 40000, port, "S", T0))
        context = extractor.process(tcp(src, "10.0.0.1", 40000, 11, "S", T0 + 6))
        assert context.profile.scan_ports.unique_count(src, T0 + 6) == 1
        assert context.features()["unique_dst_ports"] == 11

    def test_profile_of_other_source_is_expired_to_now(self) -> None:
        extractor = FeatureExtractor()
        extractor.process(icmp("10.0.0.1", "10.0.0.2", T0))
        context = extractor.process(icmp("10.0.0.3", "10.0.0.2", T0 + 500))
        other = context.profile_of("10.0.0.1")
        assert other is not None and len(other.packets) == 0 and len(other.icmp_packets) == 0
        assert context.profile_of("192.0.2.250") is None
        assert context.profile_of("10.0.0.3") is context.profile

    def test_parent_domain(self) -> None:
        assert parent_domain("a.b.example.com") == "example.com"
        assert parent_domain("x.example.co.uk") == "example.co.uk"
        assert parent_domain("localhost") == "localhost"
        assert parent_domain("") == ""
        assert parent_domain("..a..b..") == "a.b"

    def test_fresh_profile_snapshot_is_all_zero(self) -> None:
        profile = SourceProfile("10.0.0.1", 60.0, T0, T0, durations=(10.0, 15.0))
        snapshot = profile.snapshot(T0)
        for key in (
            "packet_count",
            "unique_dst_ports",
            "syn_count",
            "dns_query_count",
            "short_sessions",
        ):
            assert snapshot[key] == 0
        assert snapshot["syn_ratio"] == 0.0 and snapshot["protocol_distribution"] == {}
        assert profile.is_idle


# ================================================================= flows


class TestFlows:
    def test_both_directions_share_one_flow_and_handshake_completes(self) -> None:
        extractor = FeatureExtractor()
        a, b = "10.0.0.2", "10.0.0.1"
        extractor.process(tcp(a, b, 40000, 443, "S", T0))
        extractor.process(tcp(b, a, 443, 40000, "SA", T0 + 0.01))
        context = extractor.process(tcp(a, b, 40000, 443, "A", T0 + 0.02, length=66))
        flow = context.flow
        assert len(extractor.flows) == 1
        assert flow.handshake_complete and flow.packets == 3 and flow.bytes_total == 186
        assert (flow.initiator_ip, flow.initiator_port, flow.responder_ip, flow.responder_port) == (
            a,
            40000,
            b,
            443,
        )
        assert context.features()["flow_duration"] == 0.02
        assert not flow.half_open and not flow.refused

    def test_joining_mid_handshake_infers_direction_from_syn_ack(self) -> None:
        extractor = FeatureExtractor()
        context = extractor.process(tcp("10.0.0.1", "10.0.0.2", 22, 50000, "SA", T0))
        flow = context.flow
        assert (flow.initiator_ip, flow.responder_port) == ("10.0.0.2", 22)

    def test_syn_ack_stamped_before_syn_still_completes_handshake(self) -> None:
        """Regression: with captures merged from two taps the SYN-ACK can carry an
        earlier timestamp than its SYN; the handshake was then never complete, so
        short sessions (brute force) and completed-handshake checks missed it."""
        extractor = FeatureExtractor()
        client, server = "10.0.0.1", "10.0.0.2"
        extractor.process(tcp(server, client, 22, 5000, "SA", T0))
        extractor.process(tcp(client, server, 5000, 22, "S", T0 + 0.0001))
        flow = extractor.process(tcp(client, server, 5000, 22, "A", T0 + 0.001)).flow
        assert flow.handshake_complete
        assert (flow.initiator_ip, flow.responder_port) == (client, 22)
        extractor.process(tcp(server, client, 22, 5000, "R", T0 + 0.2))
        assert extractor.profiles[client].short_sessions.count_of(22) == 1

    def test_refused_and_half_open(self) -> None:
        extractor = FeatureExtractor()
        refused = extractor.process(tcp("10.0.0.5", "10.0.0.6", 40000, 81, "S", T0)).flow
        extractor.process(tcp("10.0.0.6", "10.0.0.5", 81, 40000, "RA", T0 + 0.001))
        half_open = extractor.process(tcp("10.0.0.5", "10.0.0.6", 40001, 82, "S", T0 + 0.01)).flow
        assert refused.refused and not refused.half_open
        assert half_open.half_open and not half_open.refused


# ========================================================== global statistics


class TestGlobalStats:
    def test_protocol_distribution_is_exact(self) -> None:
        extractor = FeatureExtractor()
        packets = [
            tcp("10.0.0.1", "10.0.0.2", 1, 2, "S", T0),
            tcp("10.0.0.1", "10.0.0.2", 1, 2, "A", T0 + 1),
            udp("10.0.0.1", "10.0.0.2", 1, 2, T0 + 2),
            icmp("10.0.0.1", "10.0.0.2", T0 + 3),
            PacketEvent(
                timestamp=T0 + 4,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol=Protocol.ICMPV6,
                length=70,
            ),
            PacketEvent(
                timestamp=T0 + 5,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.9",
                protocol=Protocol.ARP,
                length=42,
            ),
            PacketEvent(
                timestamp=T0 + 6,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol=Protocol.IPV4,
                length=50,
            ),
            PacketEvent(
                timestamp=T0 + 7,
                src_ip="fe80::1",
                dst_ip="fe80::2",
                protocol=Protocol.IPV6,
                length=50,
            ),
        ]
        for packet in packets:
            extractor.process(packet)
        stats = extractor.stats
        assert (stats.packets, stats.tcp, stats.udp, stats.icmp, stats.arp, stats.other) == (
            8,
            2,
            1,
            2,
            1,
            2,
        )
        assert stats.bytes_total == sum(p.length for p in packets)
        assert stats.protocol_distribution() == {
            "tcp": 0.25,
            "udp": 0.125,
            "icmp": 0.25,
            "arp": 0.125,
            "other": 0.25,
        }
        state = extractor.state()
        assert state["packets"] == 8 and state["span_seconds"] == 7.0
        assert state["tracked_sources"] == 2 and state["evicted_sources"] == 0

    def test_empty_extractor(self) -> None:
        extractor = FeatureExtractor()
        assert extractor.state()["packets"] == 0 and extractor.state()["span_seconds"] == 0.0
        assert extractor.top_sources() == [] and extractor.top_destinations() == []
        assert GlobalStats().protocol_distribution() == dict.fromkeys(
            ("tcp", "udp", "icmp", "arp", "other"), 0.0
        )

    def test_top_sources_and_destinations(self) -> None:
        extractor = FeatureExtractor()
        for i in range(5):
            extractor.process(icmp("10.0.0.1", "10.0.0.100", T0 + i))
        for i in range(2):
            extractor.process(icmp("10.0.0.2", "10.0.0.200", T0 + i))
        extractor.process(icmp("10.0.0.3", "10.0.0.100", T0 + 3))
        top = extractor.top_sources(limit=2)
        assert [(e["source_ip"], e["packets"]) for e in top] == [("10.0.0.1", 5), ("10.0.0.2", 2)]
        destinations = {e["destination_ip"]: e["packets"] for e in extractor.top_destinations()}
        # Flow keys are canonical, so the aggregation key is the lexicographically larger endpoint.
        assert sum(destinations.values()) == 8

    def test_clock_step_back_beyond_window_restarts_windows(self) -> None:
        """Regression: after packet time jumped backwards, windows stopped expiring
        (late timestamps are clamped to the newest seen), so counts grew without end."""
        extractor = FeatureExtractor()
        src = "10.0.0.5"
        extractor.process(tcp(src, "10.0.0.1", 1, 80, "S", T0 + 5000))
        for i in range(50):
            context = extractor.process(tcp(src, "10.0.0.1", 2000 + i, 443, "S", T0 + i * 10.0))
        profile = context.profile
        assert (
            profile.connections_started.count(10.0, context.now) == 2
        )  # T0+480 and T0+490 (inclusive)
        assert len(profile.packets) == 7  # packets in the last 60 s: T0+430 .. T0+490
        assert extractor.state()["clock_resets"] == 1

    def test_small_reordering_does_not_reset(self) -> None:
        extractor = FeatureExtractor()
        extractor.process(icmp("10.0.0.1", "10.0.0.2", T0 + 30))
        context = extractor.process(
            icmp("10.0.0.1", "10.0.0.2", T0 + 30 - extractor.window_seconds + 1)
        )
        assert extractor.clock_resets == 0 and context.profile.total_packets == 2

    def test_named_baselines_are_shared(self) -> None:
        extractor = FeatureExtractor()
        baseline = extractor.baseline("pps", alpha=0.5, min_samples=5)
        assert extractor.baseline("pps") is baseline and baseline.alpha == 0.5

    def test_reset_drops_everything(self) -> None:
        extractor = FeatureExtractor()
        extractor.process(icmp("10.0.0.1", "10.0.0.2", T0))
        extractor.baseline("x")
        extractor.reset()
        assert extractor.profiles == {} and extractor.flows == {} and extractor.baselines == {}
        assert extractor.stats.packets == 0


class TestTrafficSpikeInputs:
    """The per-interval counters the statistical detector turns into rates."""

    def test_interval_sample_values_are_exact(self) -> None:
        sample = IntervalSample(start=T0)
        for i in range(10):
            sample.observe(tcp(f"10.0.0.{i % 2}", "10.0.1.1", 40000, 80, "S", T0 + 0.1))
        for _ in range(4):
            sample.observe(dns_query("10.0.0.9", "a.example", T0 + 0.2))
        for _ in range(6):
            sample.observe(icmp("10.0.0.8", "10.0.1.1", T0 + 0.3, length=100))
        sample.observe(tcp("10.0.0.1", "10.0.1.1", 40000, 80, "A", T0 + 0.4))
        values = sample.values(2.0)
        assert values == {
            "packets_per_second": 21 / 2,
            "bytes_per_second": (10 * 60 + 4 * 80 + 6 * 100 + 60) / 2,
            "syn_per_second": 5.0,
            "dns_per_second": 2.0,
            "icmp_per_second": 3.0,
            "unique_sources": 4.0,
        }
        assert sample.top_contributor("icmp_per_second") == ("10.0.0.8", 6, 6)
        assert sample.top_contributor("syn_per_second")[1:] == (5, 10)  # type: ignore[index]
        assert IntervalSample(start=T0).top_contributor("dns_per_second") is None


# ===================================================== bounded state under load


class TestBoundedState:
    def test_200k_packets_from_50k_sources_stays_within_caps(self) -> None:
        cap = 1_000
        extractor = FeatureExtractor(DetectionSettings(max_tracked_sources=cap))
        syn = flags("S")
        sources = 50_000
        started = time.perf_counter()
        ts = T0
        for s in range(sources):
            ip = f"10.{s >> 16 & 255}.{s >> 8 & 255}.{s & 255}"
            for p in range(4):  # 200k packets in total
                ts += 0.0002
                extractor.process(
                    PacketEvent(
                        timestamp=ts,
                        src_ip=ip,
                        dst_ip="192.168.0.1",
                        protocol=Protocol.TCP,
                        length=60,
                        src_port=1024 + p,
                        dst_port=80,
                        tcp_flags=syn,
                    )
                )
            assert len(extractor.profiles) <= cap
            assert len(extractor.flows) <= cap * 4
        elapsed = time.perf_counter() - started
        assert extractor.stats.packets == 200_000
        assert extractor.evicted_sources + len(extractor.profiles) == sources
        assert extractor.evicted_flows + len(extractor.flows) == sources * 4
        # Linear, not quadratic: about 10 s would already mean something is wrong.
        assert elapsed < 60, f"200k packets took {elapsed:.1f}s"

    def test_memory_does_not_grow_with_distinct_source_count(self) -> None:
        def footprint(sources: int) -> int:
            extractor = FeatureExtractor(DetectionSettings(max_tracked_sources=500))
            tracemalloc.start()
            for s in range(sources):
                extractor.process(
                    icmp(f"172.16.{s >> 8 & 255}.{s & 255}", "10.0.0.1", T0 + s * 0.001)
                )
            current, _ = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert len(extractor.profiles) <= 500
            return current

        small, large = footprint(1_000), footprint(10_000)
        assert large < small * 1.5, (small, large)

    def test_single_source_flood_is_capped_per_structure(self) -> None:
        extractor = FeatureExtractor()
        count = 120_000
        for i in range(count):  # 120k packets in 1.2 s, all inside every window
            extractor.process(icmp("198.51.100.66", "10.0.0.1", T0 + i * 0.00001))
        profile = extractor.profiles["198.51.100.66"]
        assert len(profile.packets) == 100_000  # SizeWindow hard cap
        assert profile.total_packets == count

    def test_idle_sources_are_swept(self) -> None:
        extractor = FeatureExtractor()
        for s in range(100):
            extractor.process(icmp(f"10.9.0.{s}", "10.0.0.1", T0))
        later = T0 + extractor.window_seconds * 2 + 10
        for i in range(2048):  # the sweep runs every 2048 packets
            extractor.process(icmp("10.8.0.1", "10.0.0.1", later + i * 0.001))
        assert set(extractor.profiles) == {"10.8.0.1"}
        assert len(extractor.flows) == 1

    @pytest.mark.parametrize("cap", [100, 250])
    def test_eviction_keeps_most_recent_sources(self, cap: int) -> None:
        extractor = FeatureExtractor(DetectionSettings(max_tracked_sources=cap))
        for s in range(cap * 3):
            extractor.process(icmp(f"10.7.{s >> 8}.{s & 255}", "10.0.0.1", T0 + s * 0.01))
        newest = f"10.7.{(cap * 3 - 1) >> 8}.{(cap * 3 - 1) & 255}"
        assert newest in extractor.profiles and "10.7.0.0" not in extractor.profiles
        assert len(extractor.profiles) <= cap
