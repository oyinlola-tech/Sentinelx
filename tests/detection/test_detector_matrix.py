"""Detector matrix: every built-in and anomaly detector, one class each.

For each detector: benign traffic is silent; attack traffic produces a detection
with the right name, source, severity, a confidence inside (0, 1) and explained
evidence; malformed input is harmless; and the threshold boundary is exact -
``threshold - 1`` is silent and ``threshold`` fires, with thresholds read from
:class:`DetectionSettings` rather than hard-coded. Evidence is checked against the
traffic actually sent, with more than one input size, so a detector returning a
canned answer would fail.

Detectors are run in isolation (an engine holding only the detector under test)
so that one detector's cooldown or deferral cannot mask another's behaviour.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from itertools import pairwise

import pytest

from sentinelx.anomaly.statistical import StatisticalAnomalyDetector
from sentinelx.common.enums import ActionType, Protocol, Severity, ThreatCategory
from sentinelx.common.models import Detection, PacketEvent, TcpFlags
from sentinelx.config.settings import AnomalySettings, DetectionSettings
from sentinelx.detection.base import Detector
from sentinelx.detection.behavioral import (
    BruteForceDetector,
    ConnectionRateDetector,
    HttpFloodDetector,
    IcmpFloodDetector,
    SynFloodDetector,
)
from sentinelx.detection.dns import DnsAnomalyDetector
from sentinelx.detection.engine import BUILTIN_DETECTORS, DetectionEngine
from sentinelx.detection.policy import DenylistDetector, TcpFlagAnomalyDetector
from sentinelx.detection.scanning import (
    HorizontalScanDetector,
    TcpPortScanDetector,
    UdpScanDetector,
)
from sentinelx.features.extractor import FeatureExtractor
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.testing.scenarios import (
    BASE_TIME,
    build_dns_query,
    build_dns_response,
    build_http_request,
    build_icmp,
    build_tcp,
    build_udp,
    get_scenario,
)

T0 = BASE_TIME
ATTACKER = "203.0.113.66"
TARGET = "192.168.50.10"

Frame = tuple[bytes, float]
Item = Frame | PacketEvent


class Result:
    def __init__(self, detections: list[Detection], engine: DetectionEngine) -> None:
        self.detections = detections
        self.engine = engine

    def named(self, name: str) -> list[Detection]:
        return [d for d in self.detections if d.detector == name]


def run(
    items: Iterable[Item],
    detector: Detector | Sequence[Detector] | None = None,
    settings: DetectionSettings | None = None,
) -> Result:
    """Decode (when given bytes), extract features and evaluate."""
    settings = settings or DetectionSettings()
    if detector is None:
        engine = DetectionEngine(settings)
    else:
        detectors = [detector] if isinstance(detector, Detector) else list(detector)
        engine = DetectionEngine(settings, detectors=detectors)
    decoder, extractor = PacketDecoder(), FeatureExtractor(settings)
    found: list[Detection] = []
    for item in items:
        packet = decoder.decode(item[0], item[1]) if isinstance(item, tuple) else item
        if packet is not None:
            found.extend(engine.evaluate(extractor.process(packet)))
    assert engine.detector_errors == 0
    return Result(found, engine)


def assert_valid(
    detection: Detection,
    name: str,
    source: str,
    severities: set[Severity],
    category: ThreatCategory | None = None,
) -> None:
    assert detection.detector == name
    assert detection.source_ip == source
    assert detection.severity in severities, detection.severity
    assert 0.0 < detection.confidence < 1.0
    assert detection.evidence and all(item.description for item in detection.evidence)
    assert detection.title and detection.description
    if category is not None:
        assert detection.category is category
    # Stamped with capture time, not wall clock.
    assert detection.timestamp < datetime(2024, 1, 1, tzinfo=UTC)


def no_cooldown(**overrides: object) -> DetectionSettings:
    return DetectionSettings(detection_cooldown_seconds=0, **overrides)


def syn(src: str, dst: str, port: int, ts: float, sport: int = 40000) -> Frame:
    return build_tcp(src, dst, sport, port, flags="S"), ts


def short_session(attacker: str, target: str, port: int, start: float, sport: int) -> list[Frame]:
    """Connect, exchange a banner, get reset by the server within 150 ms."""
    return [
        (build_tcp(attacker, target, sport, port, flags="S"), start),
        (build_tcp(target, attacker, port, sport, flags="SA"), start + 0.01),
        (build_tcp(attacker, target, sport, port, flags="A"), start + 0.02),
        (build_tcp(target, attacker, port, sport, flags="PA", payload=b"banner\r\n"), start + 0.03),
        (build_tcp(target, attacker, port, sport, flags="R"), start + 0.15),
    ]


def benign_traffic(seed: int = 5) -> list[Item]:
    frames = get_scenario("normal_traffic", seed=seed, packet_count=2000).frames
    return [(frame.data, frame.timestamp) for frame in frames]


#: Packets that are unusual but legal to construct: missing fields, odd metadata
#: types, non-IP addresses. No detector may raise on them or report them.
MALFORMED: list[PacketEvent] = [
    PacketEvent(
        timestamp=T0, src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol=Protocol.TCP, length=40
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.TCP,
        length=40,
        tcp_flags=TcpFlags(syn=True),
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.UDP,
        length=40,
        dst_port=None,
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="not-an-ip",
        dst_ip="also-not",
        protocol=Protocol.TCP,
        length=40,
        src_port=1,
        dst_port=2,
        tcp_flags=TcpFlags(syn=True),
    ),
    PacketEvent(timestamp=T0, src_ip="10.0.0.1", dst_ip="", protocol=Protocol.IPV4, length=0),
    PacketEvent(
        timestamp=T0, src_ip="fe80::1", dst_ip="ff02::1", protocol=Protocol.ICMPV6, length=86
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.255",
        protocol=Protocol.ARP,
        length=42,
        metadata={"arp": None},
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.UDP,
        length=60,
        src_port=4000,
        dst_port=53,
        metadata={"dns": "garbage"},
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.UDP,
        length=60,
        src_port=4000,
        dst_port=53,
        metadata={
            "dns": {
                "is_response": False,
                "query_name": 5,
                "max_label_length": "63",
                "name_entropy": "high",
                "query_type": None,
            }
        },
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.UDP,
        length=60,
        src_port=4000,
        dst_port=53,
        metadata={"dns": {"is_response": False, "max_label_length": 63, "name_entropy": 5.0}},
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.TCP,
        length=60,
        src_port=4000,
        dst_port=80,
        tcp_flags=TcpFlags(psh=True, ack=True),
        metadata={"http": {"is_request": True, "path": None, "host": None}},
    ),
    PacketEvent(
        timestamp=T0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.TCP,
        length=60,
        src_port=4000,
        dst_port=80,
        tcp_flags=TcpFlags(psh=True, ack=True),
        metadata={"http": ["not", "a", "dict"]},
    ),
    PacketEvent(
        timestamp=-1.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=Protocol.TCP,
        length=60,
        src_port=0,
        dst_port=0,
        tcp_flags=TcpFlags(rst=True),
    ),
]


def all_detectors(settings: DetectionSettings) -> list[Detector]:
    detectors: list[Detector] = [cls(settings) for cls in BUILTIN_DETECTORS]
    detectors.append(StatisticalAnomalyDetector(AnomalySettings(min_samples=5), settings))
    return detectors


# ============================================================ cross-cutting


def test_every_builtin_detector_is_covered_here() -> None:
    covered = {
        DenylistDetector,
        TcpFlagAnomalyDetector,
        TcpPortScanDetector,
        HorizontalScanDetector,
        UdpScanDetector,
        BruteForceDetector,
        SynFloodDetector,
        ConnectionRateDetector,
        IcmpFloodDetector,
        HttpFloodDetector,
        DnsAnomalyDetector,
    }
    assert set(BUILTIN_DETECTORS) == covered


@pytest.mark.parametrize("seed", [2, 13])
def test_benign_traffic_is_silent_for_every_detector(seed: int) -> None:
    settings = no_cooldown(denylist_networks=["198.18.0.0/15"])
    result = run(benign_traffic(seed), all_detectors(settings), settings)
    assert result.detections == []


def test_malformed_input_is_harmless_for_every_detector() -> None:
    settings = no_cooldown(denylist_networks=["198.18.0.0/15"])
    # Repeat so windowed detectors see many of them, not one.
    items = [replace(p, timestamp=T0 + i * 0.001) for i in range(40) for p in MALFORMED]
    result = run(items, all_detectors(settings), settings)
    assert result.detections == []
    assert result.engine.detector_errors == 0


@pytest.mark.parametrize(
    ("scenario", "detector_name", "source"),
    [
        ("tcp_port_scan", "tcp_port_scan", "203.0.113.45"),
        ("horizontal_scan", "horizontal_scan", "203.0.113.77"),
        ("udp_scan", "udp_scan", "203.0.113.90"),
        ("ssh_brute_force", "ssh_brute_force", "198.51.100.23"),
        ("syn_flood", "syn_flood", "198.51.100.200"),
        ("syn_flood", "connection_rate", "198.51.100.200"),
        ("icmp_flood", "icmp_flood", "198.51.100.66"),
        ("http_flood", "http_flood", "198.51.100.77"),
        ("dns_tunneling", "dns_anomaly", "192.168.10.66"),
        ("dns_flood", "dns_anomaly", "192.168.10.67"),
    ],
)
class TestEnginePolicyPerDetector:
    def test_allowlisted_source_is_suppressed(
        self, scenario: str, detector_name: str, source: str
    ) -> None:
        frames = [(f.data, f.timestamp) for f in get_scenario(scenario).frames]
        baseline = run(frames)
        assert baseline.named(detector_name)
        allowed = run(frames, settings=DetectionSettings(allowlist_networks=[f"{source}/32"]))
        assert [d for d in allowed.detections if d.source_ip == source] == []
        assert allowed.engine.suppressed_allowlist > 0
        # A different allowlist entry does not hide it.
        other = run(frames, settings=DetectionSettings(allowlist_networks=["100.64.0.0/10"]))
        assert other.named(detector_name)

    def test_cooldown_deduplicates_unless_escalating(
        self, scenario: str, detector_name: str, source: str
    ) -> None:
        frames = [(f.data, f.timestamp) for f in get_scenario(scenario).frames]
        unlimited = run(frames, settings=no_cooldown()).named(detector_name)
        result = run(frames)
        deduplicated = result.named(detector_name)
        assert 1 <= len(deduplicated) < len(unlimited) or len(unlimited) == 1
        assert result.engine.suppressed_cooldown > 0 or len(unlimited) == 1
        cooldown = DetectionSettings().detection_cooldown_seconds
        for previous, current in pairwise(deduplicated):
            elapsed = (current.timestamp - previous.timestamp).total_seconds()
            if elapsed < cooldown:
                assert (
                    current.severity.rank > previous.severity.rank
                    or current.confidence >= previous.confidence + 0.2
                ), "re-reported inside the cooldown without escalating"
        for detection in deduplicated:
            assert_valid(detection, detection.detector, source, set(Severity))


def test_cooldown_expires_and_sources_are_independent() -> None:
    settings = DetectionSettings()
    threshold = settings.icmp_flood_threshold
    cooldown = settings.detection_cooldown_seconds
    items: list[Item] = []
    for burst_start in (T0, T0 + cooldown + 5):
        for i in range(threshold):
            items.append((build_icmp("198.51.100.1", TARGET, sequence=i), burst_start + i * 0.001))
            items.append(
                (build_icmp("198.51.100.2", TARGET, sequence=i), burst_start + i * 0.001 + 0.0001)
            )
    result = run(items, IcmpFloodDetector(settings), settings)
    per_source = {
        src: [d for d in result.detections if d.source_ip == src]
        for src in ("198.51.100.1", "198.51.100.2")
    }
    assert all(len(found) == 2 for found in per_source.values()), per_source


# ================================================================ port scans


class TestTcpPortScanMatrix:
    NAME = "tcp_port_scan"

    def scan(
        self, ports: Iterable[int], start: float = T0, step: float = 0.01, src: str = ATTACKER
    ) -> list[Item]:
        return [syn(src, TARGET, port, start + i * step, 40000 + i) for i, port in enumerate(ports)]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.port_scan_unique_ports
        below = run(self.scan(range(30000, 30000 + n - 1)), TcpPortScanDetector(settings), settings)
        assert below.detections == []
        at = run(self.scan(range(30000, 30000 + n)), TcpPortScanDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0], self.NAME, ATTACKER, {Severity.HIGH}, ThreatCategory.RECONNAISSANCE
        )
        evidence = at.detections[0].evidence_dict()
        assert evidence["unique_destination_ports"] == n and evidence["syn_ratio"] == 1.0
        assert at.detections[0].recommended_action is ActionType.TEMPORARY_BLOCK

    @pytest.mark.parametrize("threshold", [5, 40])
    def test_threshold_read_from_settings(self, threshold: int) -> None:
        settings = no_cooldown(port_scan_unique_ports=threshold)
        total = threshold + 7
        result = run(
            self.scan(range(30000, 30000 + total)), TcpPortScanDetector(settings), settings
        )
        counts = [d.evidence_dict()["unique_destination_ports"] for d in result.detections]
        assert counts == list(range(threshold, total + 1))
        confidences = [d.confidence for d in result.detections]
        assert confidences == sorted(confidences) and confidences[0] < confidences[-1]

    def test_window_edge(self) -> None:
        settings = DetectionSettings()
        n, window = settings.port_scan_unique_ports, settings.port_scan_window_seconds
        last = T0 + window
        inside = [syn(ATTACKER, TARGET, 30000, T0)] + [
            syn(ATTACKER, TARGET, 30000 + i, last - (n - 1 - i) * 0.01, 40000 + i)
            for i in range(1, n)
        ]
        assert len(run(inside, TcpPortScanDetector(settings), settings).detections) == 1
        outside = [syn(ATTACKER, TARGET, 30000, T0 - 0.05), *inside[1:]]
        assert run(outside, TcpPortScanDetector(settings), settings).detections == []

    def test_syn_ratio_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.port_scan_unique_ports
        ratio = settings.port_scan_min_syn_ratio
        max_other = int(n / ratio) - n  # most non-SYN packets that keep the ratio >= minimum

        def with_acks(k: int) -> list[Item]:
            acks: list[Item] = [
                (build_tcp(ATTACKER, TARGET, 39999, 30000, flags="A"), T0 + i * 0.001)
                for i in range(k)
            ]
            return acks + self.scan(range(30000, 30000 + n), start=T0 + 0.1)

        assert n / (n + max_other) >= ratio > n / (n + max_other + 1)
        assert (
            len(run(with_acks(max_other), TcpPortScanDetector(settings), settings).detections) == 1
        )
        assert (
            run(with_acks(max_other + 1), TcpPortScanDetector(settings), settings).detections == []
        )

    def test_sensitive_port_or_large_scan_is_critical(self) -> None:
        settings = no_cooldown()
        n = settings.port_scan_unique_ports
        sensitive = run(
            self.scan([22, *range(30000, 30000 + n - 1)]), TcpPortScanDetector(settings), settings
        )
        assert sensitive.detections[0].severity is Severity.CRITICAL
        assert sensitive.detections[0].evidence_dict()["sensitive_ports_probed"] == [22]
        large = run(self.scan(range(30000, 30000 + n * 5)), TcpPortScanDetector(settings), settings)
        assert large.detections[0].severity is Severity.HIGH
        assert large.detections[-1].severity is Severity.CRITICAL

    def test_spread_over_many_hosts_is_deferred_to_sweep_detector(self) -> None:
        settings = DetectionSettings()
        n = settings.port_scan_unique_ports
        items = [syn(ATTACKER, f"192.168.50.{i % 6}", 30000 + i, T0 + i * 0.01) for i in range(n)]
        assert run(items, TcpPortScanDetector(settings), settings).detections == []

    def test_completed_handshakes_are_not_a_scan(self) -> None:
        settings = DetectionSettings()
        items: list[Item] = []
        for i in range(settings.port_scan_unique_ports * 2):
            ts = T0 + i * 0.05
            items += [
                syn("10.0.0.5", TARGET, 30000 + i, ts, 40000 + i),
                (build_tcp(TARGET, "10.0.0.5", 30000 + i, 40000 + i, flags="SA"), ts + 0.001),
                (build_tcp("10.0.0.5", TARGET, 40000 + i, 30000 + i, flags="A"), ts + 0.002),
                (
                    build_tcp("10.0.0.5", TARGET, 40000 + i, 30000 + i, flags="PA", payload=b"x"),
                    ts + 0.003,
                ),
            ]
        assert run(items, TcpPortScanDetector(settings), settings).detections == []


class TestHorizontalScanMatrix:
    NAME = "horizontal_scan"

    def sweep(self, hosts: int, port: int | Sequence[int] = 8080) -> list[Item]:
        ports = [port] if isinstance(port, int) else list(port)
        return [
            syn(
                ATTACKER,
                f"192.168.{60 + i // 250}.{1 + i % 250}",
                ports[i % len(ports)],
                T0 + i * 0.01,
                50000 + i,
            )
            for i in range(hosts)
        ]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.horizontal_scan_unique_hosts
        assert run(self.sweep(n - 1), HorizontalScanDetector(settings), settings).detections == []
        at = run(self.sweep(n), HorizontalScanDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0], self.NAME, ATTACKER, {Severity.HIGH}, ThreatCategory.RECONNAISSANCE
        )
        evidence = at.detections[0].evidence_dict()
        assert (
            evidence["unique_destination_hosts"] == n and evidence["unique_destination_ports"] == 1
        )

    @pytest.mark.parametrize("hosts", [30, 70])
    def test_evidence_tracks_input(self, hosts: int) -> None:
        settings = no_cooldown()
        found = run(self.sweep(hosts), HorizontalScanDetector(settings), settings).detections
        assert found[-1].evidence_dict()["unique_destination_hosts"] == hosts
        assert len(found) == hosts - settings.horizontal_scan_unique_hosts + 1

    def test_sensitive_service_is_critical(self) -> None:
        settings = DetectionSettings()
        found = run(
            self.sweep(settings.horizontal_scan_unique_hosts, 3389),
            HorizontalScanDetector(settings),
            settings,
        ).detections
        assert found[0].severity is Severity.CRITICAL and found[0].destination_port == 3389

    def test_too_many_ports_is_not_a_sweep(self) -> None:
        settings = DetectionSettings()
        n = settings.horizontal_scan_unique_hosts
        limit = max(4, n // 8)
        assert (
            len(
                run(
                    self.sweep(n, list(range(9000, 9000 + limit))),
                    HorizontalScanDetector(settings),
                    settings,
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.sweep(n, list(range(9000, 9000 + limit + 1))),
                HorizontalScanDetector(settings),
                settings,
            ).detections
            == []
        )


class TestUdpScanMatrix:
    NAME = "udp_scan"

    def probes(self, ports: Iterable[int], start: float = T0) -> list[Item]:
        return [
            (build_udp(ATTACKER, TARGET, 40000 + i, port, b"\x00" * 8), start + i * 0.01)
            for i, port in enumerate(ports)
        ]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.udp_scan_unique_ports
        assert (
            run(
                self.probes(range(1000, 1000 + n - 1)), UdpScanDetector(settings), settings
            ).detections
            == []
        )
        at = run(self.probes(range(1000, 1000 + n)), UdpScanDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0], self.NAME, ATTACKER, {Severity.MEDIUM}, ThreatCategory.RECONNAISSANCE
        )
        assert at.detections[0].evidence_dict()["unique_udp_ports"] == n
        assert at.detections[0].evidence_dict()["udp_packets"] == n

    @pytest.mark.parametrize("extra", [3, 30])
    def test_evidence_tracks_input(self, extra: int) -> None:
        settings = no_cooldown()
        n = settings.udp_scan_unique_ports
        found = run(
            self.probes(range(1000, 1000 + n + extra)), UdpScanDetector(settings), settings
        ).detections
        assert found[-1].evidence_dict()["unique_udp_ports"] == n + extra

    def test_server_replies_from_service_port_are_not_probes(self) -> None:
        settings = DetectionSettings()
        replies = [
            (
                build_udp(TARGET, f"10.0.{i // 250}.{i % 250 + 1}", 123, 30000 + i, b"\x00" * 48),
                T0 + i * 0.01,
            )
            for i in range(200)
        ]
        assert run(replies, UdpScanDetector(settings), settings).detections == []

    def test_dns_dominated_source_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.udp_scan_unique_ports
        probe_ports = n - 1  # port 53 from the queries makes the n-th distinct port

        def traffic(queries: int) -> list[Item]:
            dns: list[Item] = [
                (
                    build_dns_query(ATTACKER, TARGET, f"h{i % 3}.example.com", src_port=41000 + i),
                    T0 + i * 0.001,
                )
                for i in range(queries)
            ]
            return dns + self.probes(range(2000, 2000 + probe_ports), start=T0 + 0.5)

        at_limit = 4 * probe_ports  # queries / (queries + probes) == 0.8 exactly
        assert len(run(traffic(at_limit), UdpScanDetector(settings), settings).detections) == 1
        assert run(traffic(at_limit + 1), UdpScanDetector(settings), settings).detections == []


# ============================================================== brute force


class TestBruteForceMatrix:
    def sessions(
        self, count: int, port: int = 22, spacing: float = 0.5, attacker: str = ATTACKER
    ) -> list[Item]:
        items: list[Item] = []
        for i in range(count):
            items += short_session(attacker, TARGET, port, T0 + i * spacing, 45000 + i)
        return items

    def test_ssh_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.brute_force_attempts
        assert run(self.sessions(n - 1), BruteForceDetector(settings), settings).detections == []
        at = run(self.sessions(n), BruteForceDetector(settings), settings)
        assert len(at.detections) == 1
        detection = at.detections[0]
        # Fired on the server's RST, yet attributed to the client that opened the sessions.
        assert_valid(
            detection, "ssh_brute_force", ATTACKER, {Severity.HIGH}, ThreatCategory.BRUTE_FORCE
        )
        assert detection.destination_ip == TARGET and detection.destination_port == 22
        assert detection.evidence_dict()["failed_attempts"] == n

    @pytest.mark.parametrize(("count", "severity"), [(20, Severity.HIGH), (60, Severity.CRITICAL)])
    def test_evidence_and_severity_track_input(self, count: int, severity: Severity) -> None:
        settings = no_cooldown()
        found = run(
            self.sessions(count, spacing=0.2), BruteForceDetector(settings), settings
        ).detections
        assert found[-1].evidence_dict()["failed_attempts"] == count
        assert found[-1].severity is severity
        assert len(found) == count - settings.brute_force_attempts + 1

    def test_rdp_is_auth_brute_force(self) -> None:
        settings = DetectionSettings()
        found = run(
            self.sessions(settings.brute_force_attempts, port=3389),
            BruteForceDetector(settings),
            settings,
        ).detections
        assert len(found) == 1
        assert_valid(found[0], "auth_brute_force", ATTACKER, {Severity.HIGH})
        assert found[0].destination_port == 3389 and found[0].destination_ip == TARGET

    def test_only_configured_ports(self) -> None:
        n = DetectionSettings().brute_force_attempts
        assert (
            run(
                self.sessions(n * 2, port=443), BruteForceDetector(), DetectionSettings()
            ).detections
            == []
        )
        custom = DetectionSettings(brute_force_ports=[2222])
        assert (
            len(run(self.sessions(n, port=2222), BruteForceDetector(custom), custom).detections)
            == 1
        )
        assert run(self.sessions(n, port=22), BruteForceDetector(custom), custom).detections == []

    def test_window_edge(self) -> None:
        settings = DetectionSettings()
        n = settings.brute_force_attempts
        extractor_window = FeatureExtractor(settings).window_seconds
        # Session teardown times span just inside / just outside the window.
        inside = extractor_window / (n - 1) - 0.02
        outside = extractor_window / (n - 1) + 0.05
        assert (
            len(
                run(
                    self.sessions(n, spacing=inside), BruteForceDetector(settings), settings
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.sessions(n, spacing=outside), BruteForceDetector(settings), settings
            ).detections
            == []
        )


# =================================================================== floods


class TestSynFloodMatrix:
    NAME = "syn_flood"

    def flood(
        self, count: int, ports: int = 1, step: float = 0.001, src: str = ATTACKER
    ) -> list[Item]:
        return [syn(src, TARGET, 80 + i % ports, T0 + i * step, 1024 + i) for i in range(count)]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.syn_flood_threshold
        assert run(self.flood(n - 1), SynFloodDetector(settings), settings).detections == []
        at = run(self.flood(n), SynFloodDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0], self.NAME, ATTACKER, {Severity.HIGH}, ThreatCategory.DENIAL_OF_SERVICE
        )
        assert at.detections[0].evidence_dict()["syn_count"] == n
        assert at.detections[0].recommended_action is ActionType.RATE_LIMIT

    @pytest.mark.parametrize(("multiple", "severity"), [(2, Severity.HIGH), (4, Severity.CRITICAL)])
    def test_evidence_and_severity_track_input(self, multiple: int, severity: Severity) -> None:
        settings = no_cooldown(syn_flood_threshold=100)
        count = 100 * multiple
        found = run(self.flood(count), SynFloodDetector(settings), settings).detections
        assert found[-1].evidence_dict()["syn_count"] == count and found[-1].severity is severity

    def test_port_spread_limit(self) -> None:
        settings = DetectionSettings()
        n = settings.syn_flood_threshold
        assert (
            len(run(self.flood(n, ports=5), SynFloodDetector(settings), settings).detections) == 1
        )
        assert run(self.flood(n, ports=6), SynFloodDetector(settings), settings).detections == []

    def test_window_edge(self) -> None:
        settings = DetectionSettings()
        n = settings.syn_flood_threshold
        window = FeatureExtractor(settings).window_seconds
        assert (
            len(
                run(
                    self.flood(n, step=(window - 0.5) / (n - 1)),
                    SynFloodDetector(settings),
                    settings,
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.flood(n, step=(window + 0.5) / (n - 1)), SynFloodDetector(settings), settings
            ).detections
            == []
        )


class TestConnectionRateMatrix:
    NAME = "connection_rate"

    def attempts(self, count: int, step: float = 0.001, src: str = ATTACKER) -> list[Item]:
        return [
            syn(src, f"192.168.51.{i % 200}", 443, T0 + i * step, 1024 + i) for i in range(count)
        ]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.connection_rate_threshold
        assert (
            run(self.attempts(n - 1), ConnectionRateDetector(settings), settings).detections == []
        )
        at = run(self.attempts(n), ConnectionRateDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0],
            self.NAME,
            ATTACKER,
            {Severity.MEDIUM},
            ThreatCategory.DENIAL_OF_SERVICE,
        )
        evidence = at.detections[0].evidence_dict()
        assert evidence["connection_attempts"] == n and evidence["unique_destinations"] == min(
            n, 200
        )

    def test_window_edge(self) -> None:
        settings = DetectionSettings()
        n, window = settings.connection_rate_threshold, settings.connection_rate_window_seconds
        assert (
            len(
                run(
                    self.attempts(n, step=(window - 0.01) / (n - 1)),
                    ConnectionRateDetector(settings),
                    settings,
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.attempts(n, step=(window + 0.01) / (n - 1)),
                ConnectionRateDetector(settings),
                settings,
            ).detections
            == []
        )

    @pytest.mark.parametrize(("multiple", "severity"), [(1, Severity.MEDIUM), (3, Severity.HIGH)])
    def test_severity_tracks_volume(self, multiple: int, severity: Severity) -> None:
        settings = no_cooldown()
        count = settings.connection_rate_threshold * multiple
        found = run(self.attempts(count), ConnectionRateDetector(settings), settings).detections
        assert (
            found[-1].severity is severity
            and found[-1].evidence_dict()["connection_attempts"] == count
        )

    def test_slow_client_after_clock_step_back_is_not_a_flood(self) -> None:
        """Regression: after packet time jumped backwards, windows stopped expiring
        and an ordinary client (one connection every 10 s) was reported."""
        settings = DetectionSettings()
        items: list[Item] = [syn("10.0.0.5", TARGET, 443, T0 + 5000)]
        items += [
            syn("10.0.0.5", TARGET, 443, T0 + i * 10.0, 2000 + i)
            for i in range(settings.connection_rate_threshold + 50)
        ]
        assert run(items, ConnectionRateDetector(settings), settings).detections == []


class TestIcmpFloodMatrix:
    NAME = "icmp_flood"

    def pings(
        self, count: int, step: float = 0.001, src: str = ATTACKER, size: int = 56
    ) -> list[Item]:
        return [
            (build_icmp(src, TARGET, sequence=i % 65535, payload=b"\x00" * size), T0 + i * step)
            for i in range(count)
        ]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.icmp_flood_threshold
        assert run(self.pings(n - 1), IcmpFloodDetector(settings), settings).detections == []
        at = run(self.pings(n), IcmpFloodDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0],
            self.NAME,
            ATTACKER,
            {Severity.MEDIUM},
            ThreatCategory.DENIAL_OF_SERVICE,
        )
        evidence = at.detections[0].evidence_dict()
        assert evidence["icmp_packets"] == n
        assert evidence["uniform_packet_size"] == 14 + 20 + 8 + 56

    def test_window_edge(self) -> None:
        settings = DetectionSettings()
        n, window = settings.icmp_flood_threshold, settings.icmp_flood_window_seconds
        assert (
            len(
                run(
                    self.pings(n, step=(window - 0.01) / (n - 1)),
                    IcmpFloodDetector(settings),
                    settings,
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.pings(n, step=(window + 0.01) / (n - 1)), IcmpFloodDetector(settings), settings
            ).detections
            == []
        )

    @pytest.mark.parametrize(("count", "severity"), [(300, Severity.MEDIUM), (600, Severity.HIGH)])
    def test_evidence_tracks_input(self, count: int, severity: Severity) -> None:
        settings = no_cooldown()
        found = run(self.pings(count), IcmpFloodDetector(settings), settings).detections
        assert found[-1].evidence_dict()["icmp_packets"] == count and found[-1].severity is severity

    def test_varied_sizes_have_no_uniformity_evidence(self) -> None:
        settings = DetectionSettings()
        rng = random.Random(3)
        items: list[Item] = [
            (
                build_icmp(ATTACKER, TARGET, sequence=i, payload=b"\x00" * rng.randint(0, 1000)),
                T0 + i * 0.001,
            )
            for i in range(settings.icmp_flood_threshold)
        ]
        found = run(items, IcmpFloodDetector(settings), settings).detections
        assert len(found) == 1 and "uniform_packet_size" not in found[0].evidence_dict()


class TestHttpFloodMatrix:
    NAME = "http_flood"

    def requests(self, count: int, step: float = 0.001, src: str = ATTACKER) -> list[Item]:
        return [
            (build_http_request(src, TARGET, 40000 + i % 20000, path=f"/p{i % 7}"), T0 + i * step)
            for i in range(count)
        ]

    def test_boundary(self) -> None:
        settings = DetectionSettings()
        n = settings.http_flood_threshold
        assert run(self.requests(n - 1), HttpFloodDetector(settings), settings).detections == []
        at = run(self.requests(n), HttpFloodDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0],
            self.NAME,
            ATTACKER,
            {Severity.MEDIUM},
            ThreatCategory.DENIAL_OF_SERVICE,
        )
        evidence = at.detections[0].evidence_dict()
        assert evidence["http_requests"] == n and evidence["unique_paths"] == 7
        assert evidence["target_host"] == "example.test"

    def test_window_edge(self) -> None:
        settings = DetectionSettings()
        n, window = settings.http_flood_threshold, settings.http_flood_window_seconds
        assert (
            len(
                run(
                    self.requests(n, step=(window - 0.01) / (n - 1)),
                    HttpFloodDetector(settings),
                    settings,
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.requests(n, step=(window + 0.01) / (n - 1)),
                HttpFloodDetector(settings),
                settings,
            ).detections
            == []
        )

    @pytest.mark.parametrize(("multiple", "severity"), [(2, Severity.MEDIUM), (3, Severity.HIGH)])
    def test_severity_tracks_volume(self, multiple: int, severity: Severity) -> None:
        settings = no_cooldown()
        count = settings.http_flood_threshold * multiple
        found = run(self.requests(count), HttpFloodDetector(settings), settings).detections
        assert (
            found[-1].evidence_dict()["http_requests"] == count and found[-1].severity is severity
        )

    def test_http_responses_do_not_count(self) -> None:
        settings = DetectionSettings()
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        items: list[Item] = [
            (build_tcp(TARGET, ATTACKER, 80, 40000, flags="PA", payload=response), T0 + i * 0.001)
            for i in range(settings.http_flood_threshold * 2)
        ]
        assert run(items, HttpFloodDetector(settings), settings).detections == []


# ====================================================================== DNS


class TestDnsAnomalyMatrix:
    NAME = "dns_anomaly"
    RESOLVER = "192.168.50.1"

    def queries(
        self, names: Sequence[str], step: float = 0.01, qtype: int = 1, start: float = T0
    ) -> list[Item]:
        return [
            (
                build_dns_query(
                    ATTACKER, self.RESOLVER, name, src_port=40000 + i % 20000, qtype=qtype
                ),
                start + i * step,
            )
            for i, name in enumerate(names)
        ]

    @staticmethod
    def encoded(i: int, parent: str, length: int = 56) -> str:
        rng = random.Random(i)
        return (
            "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(length))
            + "."
            + parent
        )

    def test_flood_boundary_on_query_count(self) -> None:
        settings = DetectionSettings()
        n = settings.dns_query_threshold
        names = [f"host{i % 3}.example.com" for i in range(n)]
        assert (
            run(self.queries(names[:-1]), DnsAnomalyDetector(settings), settings).detections == []
        )
        at = run(self.queries(names), DnsAnomalyDetector(settings), settings)
        assert len(at.detections) == 1
        assert_valid(
            at.detections[0], self.NAME, ATTACKER, {Severity.MEDIUM}, ThreatCategory.EXFILTRATION
        )
        evidence = at.detections[0].evidence_dict()
        assert evidence["dns_queries"] == n and evidence["unique_domains"] == 3

    def test_flood_boundary_on_distinct_names(self) -> None:
        settings = DetectionSettings()
        n = settings.dns_unique_domain_threshold
        names = [f"n{i}.example.com" for i in range(n)]
        assert (
            run(self.queries(names[:-1]), DnsAnomalyDetector(settings), settings).detections == []
        )
        at = run(self.queries(names), DnsAnomalyDetector(settings), settings)
        assert len(at.detections) == 1 and at.detections[0].evidence_dict()["unique_domains"] == n

    def test_flood_query_window_edge(self) -> None:
        settings = DetectionSettings()
        n, window = settings.dns_query_threshold, settings.dns_window_seconds
        names = [f"host{i % 3}.example.com" for i in range(n)]
        assert (
            len(
                run(
                    self.queries(names, step=(window - 0.01) / (n - 1)),
                    DnsAnomalyDetector(settings),
                    settings,
                ).detections
            )
            == 1
        )
        assert (
            run(
                self.queries(names, step=(window + 0.01) / (n - 1)),
                DnsAnomalyDetector(settings),
                settings,
            ).detections
            == []
        )

    def test_distinct_name_count_covers_profile_window_not_dns_window(self) -> None:
        """Documented limitation (docs/detection-engine.md, dns_anomaly): distinct
        names are counted over W (60 s by default), not dns_window_seconds (30 s).
        Pinned so a change is deliberate and the docs are updated with it."""
        settings = DetectionSettings()
        n = settings.dns_unique_domain_threshold
        spread = (settings.dns_window_seconds + 10) / (n - 1)  # spans 40 s: > dns window, < W
        names = [f"n{i}.example.com" for i in range(n)]
        assert (
            len(
                run(
                    self.queries(names, step=spread), DnsAnomalyDetector(settings), settings
                ).detections
            )
            == 1
        )

    def test_tunnelling_boundary(self) -> None:
        settings = DetectionSettings()
        minimum = DnsAnomalyDetector._MIN_SUSPICIOUS_QUERIES
        names = [self.encoded(i, "tunnel.example.org") for i in range(minimum)]
        assert (
            run(
                self.queries(names[:-1], qtype=16), DnsAnomalyDetector(settings), settings
            ).detections
            == []
        )
        at = run(self.queries(names, qtype=16), DnsAnomalyDetector(settings), settings)
        assert len(at.detections) == 1
        detection = at.detections[0]
        assert_valid(detection, self.NAME, ATTACKER, {Severity.HIGH}, ThreatCategory.EXFILTRATION)
        evidence = detection.evidence_dict()
        assert evidence["suspicious_queries"] == minimum
        assert evidence["parent_domain"] == "example.org"
        assert evidence["max_label_length"] == 56 and evidence["query_type"] == "TXT"

    @pytest.mark.parametrize("parent", ["exfil.test", "data.badcorp.net"])
    def test_tunnel_evidence_names_the_actual_parent(self, parent: str) -> None:
        settings = DetectionSettings()
        names = [self.encoded(i, parent, length=53 + i % 8) for i in range(30)]
        found = run(self.queries(names), DnsAnomalyDetector(settings), settings).detections
        from sentinelx.features.profiles import parent_domain

        assert found and found[0].evidence_dict()["parent_domain"] == parent_domain(parent)
        assert "query_type" not in found[0].evidence_dict()  # A records

    def test_tunnel_concentration_boundary(self) -> None:
        settings = DetectionSettings()
        minimum = DnsAnomalyDetector._MIN_SUSPICIOUS_QUERIES
        concentrated = int(minimum * 0.6)

        def traffic(on_parent: int) -> list[Item]:
            noise = [self.encoded(i, f"cdn{i}.example{i}.com") for i in range(minimum - on_parent)]
            tunnel = [self.encoded(100 + i, "tunnel.example.org") for i in range(on_parent)]
            return self.queries(noise + tunnel)

        assert (
            len(run(traffic(concentrated), DnsAnomalyDetector(settings), settings).detections) == 1
        )
        assert (
            run(traffic(concentrated - 1), DnsAnomalyDetector(settings), settings).detections == []
        )

    def test_long_label_threshold_is_exact(self) -> None:
        settings = DetectionSettings()
        minimum = DnsAnomalyDetector._MIN_SUSPICIOUS_QUERIES
        length = settings.dns_long_label_length

        def names(label_length: int) -> list[str]:
            # Low-entropy labels ("aaaa...017"), so only their length can make them suspicious.
            return [f"{'a' * (label_length - 3)}{i:03d}.t.example.org" for i in range(minimum)]

        assert (
            len(run(self.queries(names(length)), DnsAnomalyDetector(settings), settings).detections)
            == 1
        )
        assert (
            run(self.queries(names(length - 1)), DnsAnomalyDetector(settings), settings).detections
            == []
        )

    def test_nxdomain_responses_alone_do_not_fire(self) -> None:
        """Responses are skipped: the volume path counts the client's *queries*.
        NXDOMAIN rcodes are decoded but are not a detection signal on their own."""
        settings = DetectionSettings()
        responses: list[Item] = [
            (build_dns_response(self.RESOLVER, ATTACKER, f"dga{i}.test", rcode=3), T0 + i * 0.001)
            for i in range(settings.dns_query_threshold * 2)
        ]
        assert run(responses, DnsAnomalyDetector(settings), settings).detections == []

    def test_ordinary_resolution_is_silent(self) -> None:
        settings = DetectionSettings()
        names = ["www.example.com", "mail.example.com", "api.github.com", "cdn.jsdelivr.net"]
        items = self.queries(
            [names[i % 4] for i in range(settings.dns_query_threshold - 1)], step=0.05
        )
        assert run(items, DnsAnomalyDetector(settings), settings).detections == []


# =================================================================== policy


class TestDenylistMatrix:
    NAME = "denylist"

    @pytest.mark.parametrize(
        ("network", "src", "dst", "listed", "action"),
        [
            ("203.0.113.0/24", "203.0.113.9", TARGET, "203.0.113.9", ActionType.BLOCK_IP),
            ("198.51.100.99/32", TARGET, "198.51.100.99", "198.51.100.99", ActionType.ALERT),
            (
                "2001:db8:bad::/48",
                "2001:db8:bad::7",
                "2001:db8:1::1",
                "2001:db8:bad::7",
                ActionType.BLOCK_IP,
            ),
        ],
    )
    def test_listed_address_detected(
        self, network: str, src: str, dst: str, listed: str, action: ActionType
    ) -> None:
        settings = DetectionSettings(denylist_networks=[network])
        packet = PacketEvent(
            timestamp=T0,
            src_ip=src,
            dst_ip=dst,
            protocol=Protocol.UDP,
            length=60,
            src_port=1,
            dst_port=2,
        )
        found = run([packet], DenylistDetector(settings), settings).detections
        assert len(found) == 1
        assert_valid(
            found[0], self.NAME, listed, {Severity.HIGH}, ThreatCategory.MALICIOUS_REPUTATION
        )
        assert found[0].recommended_action is action
        assert found[0].evidence_dict()["denylist_match"] == network

    def test_unlisted_neighbours_are_silent(self) -> None:
        settings = DetectionSettings(denylist_networks=["203.0.113.8/30"])
        items = [
            PacketEvent(
                timestamp=T0 + i,
                src_ip=f"203.0.113.{i}",
                dst_ip=TARGET,
                protocol=Protocol.ICMP,
                length=60,
            )
            for i in (7, 12, 255)
        ]
        items.append(
            PacketEvent(
                timestamp=T0 + 5,
                src_ip="::ffff:203.0.113.9",
                dst_ip="::1",
                protocol=Protocol.ICMPV6,
                length=60,
            )
        )
        assert run(items, DenylistDetector(settings), settings).detections == []

    def test_runtime_update_and_add(self) -> None:
        detector = DenylistDetector(DetectionSettings())
        packet = PacketEvent(
            timestamp=T0, src_ip="192.0.2.44", dst_ip=TARGET, protocol=Protocol.ICMP, length=60
        )
        assert run([packet], detector).detections == []
        detector.add("192.0.2.0/24", reason="intel feed")
        found = run([packet], detector).detections
        assert found and "intel feed" in found[0].tags
        detector.update(["198.51.100.0/24"])
        assert run([packet], detector).detections == []
        with pytest.raises(ValueError):
            detector.update(["not-a-network"])
        assert detector.networks == ["198.51.100.0/24"]

    def test_repeat_packets_deduplicated_by_cooldown(self) -> None:
        settings = DetectionSettings(denylist_networks=["203.0.113.0/24"])
        items = [
            PacketEvent(
                timestamp=T0 + i,
                src_ip="203.0.113.5",
                dst_ip=TARGET,
                protocol=Protocol.ICMP,
                length=60,
            )
            for i in range(30)
        ]
        result = run(items, DenylistDetector(settings), settings)
        assert len(result.detections) == 1 and result.engine.suppressed_cooldown == 29


class TestTcpFlagAnomalyMatrix:
    NAME = "tcp_flag_anomaly"

    @pytest.mark.parametrize(
        ("spec", "kind", "confidence"),
        [
            ("", "NULL", 0.85),
            ("FPU", "XMAS", 0.85),
            ("SF", "SYN+FIN", 0.85),
            ("SR", "SYN+RST", 0.65),
            ("F", "FIN without connection", 0.65),
        ],
    )
    def test_boundary_and_kind(self, spec: str, kind: str, confidence: float) -> None:
        minimum = TcpFlagAnomalyDetector._MIN_PACKETS

        def packets(count: int) -> list[Item]:
            return [
                (build_tcp(ATTACKER, TARGET, 40000 + i, 80 + i, flags=spec), T0 + i)
                for i in range(count)
            ]

        assert run(packets(minimum - 1), TcpFlagAnomalyDetector()).detections == []
        found = run(packets(minimum), TcpFlagAnomalyDetector()).detections
        assert len(found) == 1
        assert_valid(
            found[0], self.NAME, ATTACKER, {Severity.MEDIUM}, ThreatCategory.PROTOCOL_ANOMALY
        )
        evidence = found[0].evidence_dict()
        assert evidence["flag_combination"] == kind and evidence["anomalous_packets"] == minimum
        assert found[0].confidence == confidence

    def test_counts_are_per_source(self) -> None:
        minimum = TcpFlagAnomalyDetector._MIN_PACKETS
        items: list[Item] = []
        for i in range(minimum - 1):
            items.append((build_tcp("198.51.100.1", TARGET, 1, 80, flags=""), T0 + i))
            items.append((build_tcp("198.51.100.2", TARGET, 1, 80, flags=""), T0 + i))
        assert run(items, TcpFlagAnomalyDetector()).detections == []

    def test_conforming_teardown_is_silent(self) -> None:
        items: list[Item] = []
        for i in range(10):
            items += [
                (build_tcp("10.0.0.5", TARGET, 40000 + i, 443, flags="S"), T0 + i),
                (build_tcp(TARGET, "10.0.0.5", 443, 40000 + i, flags="SA"), T0 + i + 0.01),
                (build_tcp("10.0.0.5", TARGET, 40000 + i, 443, flags="A"), T0 + i + 0.02),
                (build_tcp("10.0.0.5", TARGET, 40000 + i, 443, flags="FA"), T0 + i + 0.5),
                (build_tcp(TARGET, "10.0.0.5", 443, 40000 + i, flags="FA"), T0 + i + 0.51),
                (build_tcp(TARGET, "10.0.0.5", 443, 40000 + i, flags="RA"), T0 + i + 0.52),
            ]
        assert run(items, TcpFlagAnomalyDetector()).detections == []

    def test_evidence_count_tracks_input(self) -> None:
        settings = no_cooldown()
        items: list[Item] = [
            (build_tcp(ATTACKER, TARGET, 1, 80, flags=""), T0 + i) for i in range(9)
        ]
        found = run(items, TcpFlagAnomalyDetector(settings), settings).detections
        assert [d.evidence_dict()["anomalous_packets"] for d in found] == list(range(3, 10))


# ================================================================== anomaly


def _udp_second(second: int, packets: int, rng: random.Random, sources: int = 20) -> list[Item]:
    return [
        (
            build_udp(f"10.20.0.{rng.randrange(sources)}", "10.20.1.1", 40000, 9000, b"\x00" * 50),
            T0 + second + rng.random(),
        )
        for _ in range(packets)
    ]


class TestStatisticalAnomalyMatrix:
    NAME = "statistical_anomaly"
    ANOMALY = AnomalySettings(min_samples=30)

    def baseline(self, seconds: int, rng: random.Random, start: int = 0) -> list[Item]:
        # A packet exactly on the second aligns the detector's 1 s intervals with
        # whole seconds, so each interval's packet count is known.
        items: list[Item] = [
            (build_udp("10.20.0.1", "10.20.1.1", 40000, 9000, b"\x00" * 50), T0 + start)
        ]
        for second in range(start, start + seconds):
            items += _udp_second(second, rng.randint(55, 65), rng)
        return items

    def detector(self) -> StatisticalAnomalyDetector:
        return StatisticalAnomalyDetector(self.ANOMALY)

    def ordered(self, items: list[Item]) -> list[Item]:
        return sorted(
            items, key=lambda item: item[1] if isinstance(item, tuple) else item.timestamp
        )

    def test_steady_traffic_is_silent(self) -> None:
        rng = random.Random(1)
        assert run(self.ordered(self.baseline(150, rng)), self.detector()).detections == []

    @pytest.mark.parametrize("spike_pps", [400, 1500])
    def test_spike_detected_with_evidence_describing_it(self, spike_pps: int) -> None:
        rng = random.Random(2)
        items = self.baseline(60, rng)
        noisy = "10.20.9.9"
        for second in range(60, 63):
            items += _udp_second(second, 60, rng)
            items += [
                (
                    build_udp(noisy, "10.20.1.1", 40001, 9000, b"\x00" * 50),
                    T0 + second + rng.random(),
                )
                for _ in range(spike_pps)
            ]
        items += self.baseline(3, rng, start=63)
        found = run(self.ordered(items), self.detector()).detections
        assert found, "spike not detected"
        first = found[0]
        assert_valid(
            first, self.NAME, noisy, {Severity.MEDIUM, Severity.HIGH}, ThreatCategory.ANOMALY
        )
        evidence = first.evidence_dict()
        assert evidence["metric"] == "packets_per_second"
        assert evidence["top_contributor"]["source"] == noisy
        assert first.packet_count == spike_pps + 60  # the spike interval, not a canned value
        assert evidence["anomaly_score"] >= self.ANOMALY.anomaly_threshold
        assert 55 <= evidence["baseline"]["mean"] <= 65
        assert first.recommended_action is ActionType.ALERT and first.confidence <= 0.85

    def test_warmup_boundary(self) -> None:
        min_samples = self.ANOMALY.min_samples

        def traffic(normal_seconds: int) -> list[Item]:
            generator = random.Random(4)
            items = self.baseline(normal_seconds, generator)
            items += [
                (
                    build_udp("10.20.9.9", "10.20.1.1", 40001, 9000, b"\x00" * 50),
                    T0 + normal_seconds + generator.random(),
                )
                for _ in range(2000)
            ]
            items += self.baseline(2, generator, start=normal_seconds + 1)
            return self.ordered(items)

        # The spike interval is closed (and scored) after `normal_seconds` intervals.
        assert run(traffic(min_samples - 1), self.detector()).detections == []
        assert run(traffic(min_samples), self.detector()).detections

    def test_clock_step_back_is_not_a_spike(self) -> None:
        """Regression: packets after a backwards time step piled into one interval
        and were scored as a huge rate once time caught up."""
        rng = random.Random(5)
        items = self.ordered(self.baseline(90, rng, start=1000))
        items += self.ordered(self.baseline(60, rng, start=1080))  # steps back about 10 s
        assert run(items, self.detector()).detections == []

    def test_malformed_and_out_of_order_packets(self) -> None:
        detector = self.detector()
        result = run([*MALFORMED, *reversed(MALFORMED)], detector)
        assert result.detections == [] and detector.intervals >= 0


def test_engine_cooldown_survives_clock_step_back() -> None:
    """Regression: a detection stamped before a backwards time step suppressed the
    same (detector, source) pair until packet time caught up with it."""
    settings = DetectionSettings()
    n = settings.icmp_flood_threshold
    late = [(build_icmp(ATTACKER, TARGET, sequence=i), T0 + 10_000 + i * 0.001) for i in range(n)]
    early = [(build_icmp(ATTACKER, TARGET, sequence=i), T0 + i * 0.001) for i in range(n)]
    found = run([*late, *early], IcmpFloodDetector(settings), settings).detections
    assert len(found) == 2


class TestMlAnomalyMatrix:
    NAME = "ml_anomaly"

    @pytest.fixture(scope="class")
    @classmethod
    def bundle(cls):  # type: ignore[no-untyped-def]
        pytest.importorskip("sklearn")
        from sentinelx.anomaly.ml import collect_training_vectors, train_model

        frames = sorted(
            (
                f
                for seed in (1, 2, 3)
                for f in get_scenario("normal_traffic", seed=seed, packet_count=2500).frames
            ),
            key=lambda f: f.timestamp,
        )
        return train_model(collect_training_vectors(frames), seed=1)

    def test_attack_detected_as_lead_with_evidence(self, bundle) -> None:  # type: ignore[no-untyped-def]
        from sentinelx.anomaly.ml import MlAnomalyDetector

        frames = [(f.data, f.timestamp) for f in get_scenario("tcp_port_scan", ports=300).frames]
        found = run(frames, MlAnomalyDetector(bundle)).detections
        attacker, target = "203.0.113.45", "192.168.10.50"
        # The scanner is rare; so is the victim answering hundreds of ports with RSTs.
        assert {d.source_ip for d in found} >= {attacker}
        for detection in found:
            source = attacker if detection.source_ip == attacker else target
            assert_valid(
                detection,
                self.NAME,
                source,
                {Severity.LOW, Severity.MEDIUM},
                ThreatCategory.ANOMALY,
            )
            assert detection.recommended_action is ActionType.ALERT and detection.confidence <= 0.6
            assert detection.evidence_dict()["anomaly_score"] >= AnomalySettings().ml_min_score

    def test_benign_and_malformed_are_harmless(self, bundle) -> None:  # type: ignore[no-untyped-def]
        from sentinelx.anomaly.ml import MlAnomalyDetector

        detector = MlAnomalyDetector(bundle)
        run(MALFORMED * 20, detector)  # asserts no detector errors
        benign = run(benign_traffic(seed=4), MlAnomalyDetector(bundle)).detections
        # Held-out normal traffic: the model may flag a few leads, never most sources.
        assert len({d.source_ip for d in benign}) <= 3
