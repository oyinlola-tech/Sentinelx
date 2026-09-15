"""Regressions found by attacking a live SentinelX stack with real tools.

A Docker Compose stack captured traffic inside the API container while other
containers on its private network ran nmap, hping3, dig and an HTTP flood against it.
The detections were real, but several named the wrong source or missed the attack:

* the target of a ping flood was reported as an ICMP flood source, for its echo
  replies, and the statistical anomaly split the blame with it;
* hping3's SYN flood against an open port was not reported, because the port
  answered every SYN with a SYN-ACK and the detector took that for a busy client;
* the target's profile collected the flooder's kernel resets as "refused
  connections", and brute-force evidence reported every reset a source had ever
  received ("the server reset 4001 of these sessions");
* SentinelX's own connection pool to its PostgreSQL server was reported as a brute
  force against PostgreSQL, and the response engine proposed blocking the sensor.
"""

from __future__ import annotations

from collections.abc import Callable

from sentinelx.common.models import Detection
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.features.extractor import FeatureExtractor
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.system.self_traffic import OwnServiceTraffic, storage_endpoints
from sentinelx.testing.scenarios import BASE_TIME, build_icmp, build_tcp, get_scenario
from tests.conftest import frames_from

Run = Callable[..., list[Detection]]

ATTACKER, TARGET = "172.22.0.5", "172.22.0.4"


def by_source(detections: list[Detection]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for detection in detections:
        found.setdefault(detection.source_ip, set()).add(detection.detector)
    return found


def ping_flood(
    *, replies: bool, requests: bool = True, count: int = 600
) -> list[tuple[bytes, float]]:
    packets: list[tuple[bytes, float]] = []
    for i in range(count):
        ts = BASE_TIME + i * 0.01
        if requests:
            packets.append((build_icmp(ATTACKER, TARGET, identifier=7, sequence=i), ts))
        if replies:
            packets.append(
                (build_icmp(TARGET, ATTACKER, icmp_type=0, identifier=7, sequence=i), ts + 0.0002)
            )
    return packets


class TestPingFloodAttribution:
    def test_the_target_answering_a_ping_flood_is_not_a_source(self, run_detection: Run) -> None:
        found = by_source(run_detection(frames_from(ping_flood(replies=True))))
        assert "icmp_flood" in found.get(ATTACKER, set())
        assert TARGET not in found, found

    def test_unsolicited_echo_replies_still_count(self, run_detection: Run) -> None:
        # Reflection: a flood of replies to a host that never sent a request.
        found = by_source(run_detection(frames_from(ping_flood(replies=True, requests=False))))
        assert "icmp_flood" in found.get(TARGET, set())

    def test_the_anomaly_blames_the_requester_not_the_replier(self) -> None:
        from sentinelx.anomaly.statistical import IntervalSample

        decoder = PacketDecoder()
        extractor = FeatureExtractor()
        sample = IntervalSample(start=BASE_TIME)
        for data, ts in ping_flood(replies=True, count=200):
            packet = decoder.decode(data, ts)
            assert packet is not None
            context = extractor.process(packet)
            sample.observe(packet, solicited_reply=context.solicited_reply)
        source, count, total = sample.top_contributor("icmp_per_second") or ("", 0, 0)
        assert (source, count, total) == (ATTACKER, 200, 200)
        assert sample.icmp == 400  # the rate itself still counts every packet


def syn_flood_on_open_port(count: int = 800) -> list[tuple[bytes, float]]:
    """hping3 -S: the port answers each SYN, the flooder's kernel resets the SYN-ACK."""
    packets: list[tuple[bytes, float]] = []
    for i in range(count):
        ts = BASE_TIME + i * 0.002
        port = 30000 + i
        packets += [
            (build_tcp(ATTACKER, TARGET, port, 8000, flags="S"), ts),
            (build_tcp(TARGET, ATTACKER, 8000, port, flags="SA"), ts + 0.0001),
            (build_tcp(ATTACKER, TARGET, port, 8000, flags="R"), ts + 0.0002),
        ]
    return packets


class TestSynFloodAgainstAnOpenPort:
    def test_is_detected_on_the_flooder(self, run_detection: Run) -> None:
        detections = run_detection(frames_from(syn_flood_on_open_port()))
        found = by_source(detections)
        assert "syn_flood" in found.get(ATTACKER, set())
        assert TARGET not in found, found
        flood = next(d for d in detections if d.detector == "syn_flood")
        evidence = {item.key: item.value for item in flood.evidence}
        assert evidence["handshake_completion"] == 0.0
        assert evidence["syn_ack_ratio"] > 0.9

    def test_a_scan_right_before_the_flood_does_not_hide_it(self, run_detection: Run) -> None:
        # nmap -sS -p 1-1000, then hping3 -S -p 8000, from one address.
        scan = [
            (build_tcp(ATTACKER, TARGET, 40000, port, flags="S"), BASE_TIME - 3 + port * 0.001)
            for port in range(1, 1001)
        ]
        detections = run_detection(frames_from(scan + syn_flood_on_open_port()))
        found = by_source(detections)
        assert {"tcp_port_scan", "syn_flood"} <= found.get(ATTACKER, set())
        flood = next(d for d in detections if d.detector == "syn_flood")
        assert flood.destination_port == 8000
        assert int(flood.evidence_dict()["syn_count"]) >= DetectionSettings().syn_flood_threshold

    def test_a_scan_alone_is_not_a_flood(self, run_detection: Run) -> None:
        scan = [
            (build_tcp(ATTACKER, TARGET, 40000, port, flags="S"), BASE_TIME + port * 0.001)
            for port in range(1, 3001)
        ]
        assert "syn_flood" not in by_source(run_detection(frames_from(scan))).get(ATTACKER, set())

    def test_the_flooders_resets_are_not_refusals_on_the_target(self) -> None:
        decoder = PacketDecoder()
        extractor = FeatureExtractor()
        for data, ts in syn_flood_on_open_port(200):
            packet = decoder.decode(data, ts)
            assert packet is not None
            extractor.process(packet)
        target = extractor.profiles[TARGET]
        attacker = extractor.profiles[ATTACKER]
        assert len(target.refused_connections) == 0
        assert len(attacker.syn_ack_received) == 200
        assert len(attacker.handshakes_completed) == 0


class TestBruteForceEvidence:
    def test_server_resets_count_only_the_attacked_service(self, run_detection: Run) -> None:
        scenario = get_scenario("ssh_brute_force", attacker=ATTACKER, target=TARGET)
        # Before the attack, the same source hit 300 closed ports on the same host.
        refusals: list[tuple[bytes, float]] = []
        for i in range(300):
            ts = BASE_TIME - 5 + i * 0.001
            refusals += [
                (build_tcp(ATTACKER, TARGET, 50000 + i, 1000 + i, flags="S"), ts),
                (build_tcp(TARGET, ATTACKER, 1000 + i, 50000 + i, flags="RA"), ts + 0.0001),
            ]
        frames = frames_from(refusals) + scenario.frames
        detections = run_detection(frames, DetectionSettings(detection_cooldown_seconds=0))
        brute = [d for d in detections if d.detector == "ssh_brute_force"]
        assert brute
        for detection in brute:
            evidence = {item.key: item.value for item in detection.evidence}
            attempts = int(evidence["failed_attempts"])
            assert int(evidence.get("server_resets", 0)) <= attempts, evidence


class TestOwnStorageTraffic:
    DB = "postgresql://sentinelx:secret@postgres:5432/sentinelx"
    REDIS = "redis://:secret@redis:6379/0"

    def own(self, resolved: dict[str, list[str]], local: frozenset[str]) -> OwnServiceTraffic:
        return OwnServiceTraffic(
            [self.DB, self.REDIS, "sqlite+aiosqlite:///./sentinelx.db"],
            local_addresses=lambda: local,
            resolve=lambda host: resolved[host],
        )

    def test_endpoints_come_from_the_storage_urls(self) -> None:
        assert storage_endpoints(
            [self.DB, self.REDIS, "sqlite+aiosqlite:///x.db", "postgresql+asyncpg://db"]
        ) == [("postgres", 5432), ("redis", 6379), ("db", 5432)]

    def test_only_this_hosts_connections_to_its_own_storage_match(self) -> None:
        own = self.own({"postgres": ["172.22.0.3"], "redis": ["172.22.0.2"]}, frozenset({TARGET}))
        assert own.matches(TARGET, "172.22.0.3", 5432)
        assert own.matches(TARGET, "172.22.0.2", 6379)
        assert not own.matches(ATTACKER, "172.22.0.3", 5432)  # anyone else is analysed
        assert not own.matches(TARGET, "172.22.0.3", 22)  # other services on that host
        assert not own.matches(TARGET, "203.0.113.9", 5432)  # other databases

    def test_names_are_resolved_only_for_traffic_from_this_host(self) -> None:
        lookups: list[str] = []

        def resolve(host: str) -> list[str]:
            lookups.append(host)
            return ["172.22.0.3"]

        own = OwnServiceTraffic(
            [self.DB], local_addresses=lambda: frozenset({TARGET}), resolve=resolve
        )
        assert not own.matches(ATTACKER, "172.22.0.3", 5432)
        assert lookups == []
        assert own.matches(TARGET, "172.22.0.3", 5432)
        assert own.matches(TARGET, "172.22.0.3", 5432)
        assert lookups == ["postgres"]  # cached

    def test_a_failed_lookup_matches_nothing(self) -> None:
        def resolve(host: str) -> list[str]:
            raise OSError("name not known")

        own = OwnServiceTraffic(
            [self.DB], local_addresses=lambda: frozenset({TARGET}), resolve=resolve
        )
        assert not own.matches(TARGET, "172.22.0.3", 5432)

    def test_the_engine_drops_and_counts_own_traffic_detections(self, run_detection: Run) -> None:
        own = self.own({"postgres": ["172.22.0.3"], "redis": ["172.22.0.2"]}, frozenset({TARGET}))
        settings = DetectionSettings()
        # SentinelX's pool: 60 short PostgreSQL sessions from the sensor host.
        pool = get_scenario("ssh_brute_force", attacker=TARGET, target="172.22.0.3", port=5432)
        engine = DetectionEngine(settings, own_traffic=own.matches)
        assert run_detection(pool.frames, settings, engine) == []
        assert engine.suppressed_own_traffic > 0
        assert engine.stats()["suppressed_own_traffic"] == engine.suppressed_own_traffic
        # The same sessions from any other address are still a brute force.
        attack = get_scenario("ssh_brute_force", attacker=ATTACKER, target="172.22.0.3", port=5432)
        engine = DetectionEngine(settings, own_traffic=own.matches)
        assert "auth_brute_force" in {
            d.detector for d in run_detection(attack.frames, settings, engine)
        }
