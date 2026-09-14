"""Detector behaviour: every detector has positive, negative and edge-case tests.

Positive cases use the synthetic scenarios (known ground truth).  Negative cases
use traffic that shares a surface feature with the attack but not its shape - the
false positives a naive detector would produce.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from sentinelx.capture.base import RawFrame
from sentinelx.common.enums import ActionType, Severity
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.testing.scenarios import (
    BASE_TIME,
    build_dns_query,
    build_http_request,
    build_icmp,
    build_tcp,
    build_udp,
    get_scenario,
)
from tests.conftest import frames_from

Run = Callable[..., list]  # type: ignore[type-arg]


def detectors_fired(detections: list) -> set[str]:  # type: ignore[type-arg]
    return {d.detector for d in detections}


# ============================================================ every detection


@pytest.mark.parametrize("name", ["tcp_port_scan", "horizontal_scan", "udp_scan", "ssh_brute_force", "syn_flood",
                                  "icmp_flood", "http_flood", "dns_tunneling", "dns_flood", "mixed_intrusion"])
def test_scenario_detected_on_correct_source_with_evidence(run_detection: Run, name: str) -> None:
    scenario = get_scenario(name)
    detections = run_detection(scenario.frames)
    assert scenario.expected_detectors <= detectors_fired(detections)
    for detection in detections:
        assert detection.evidence, f"{detection.detector} emitted no evidence"
        assert all(item.description for item in detection.evidence)
        assert 0 < detection.confidence < 1
        if scenario.expected_source:
            assert detection.source_ip == scenario.expected_source


@pytest.mark.parametrize("seed", [1, 7, 42, 99])
def test_normal_traffic_produces_no_detections(run_detection: Run, seed: int) -> None:
    assert run_detection(get_scenario("normal_traffic", seed=seed, packet_count=1500).frames) == []


# ================================================================ port scan


class TestTcpPortScan:
    def test_evidence_matches_observed_traffic(self, run_detection: Run) -> None:
        detections = [d for d in run_detection(get_scenario("tcp_port_scan", ports=150).frames) if d.detector == "tcp_port_scan"]
        final = detections[-1]
        evidence = final.evidence_dict()
        assert evidence["unique_destination_ports"] >= 100
        assert evidence["syn_ratio"] > 0.95
        assert final.recommended_action is ActionType.TEMPORARY_BLOCK

    def test_escalates_to_critical_as_scan_grows(self, run_detection: Run) -> None:
        detections = [d for d in run_detection(get_scenario("tcp_port_scan", ports=220).frames) if d.detector == "tcp_port_scan"]
        assert len(detections) >= 2
        assert detections[0].severity is Severity.HIGH
        assert detections[-1].severity is Severity.CRITICAL
        assert detections[-1].confidence > detections[0].confidence

    def test_busy_client_completing_handshakes_is_not_a_scan(self, run_detection: Run) -> None:
        packets: list[tuple[bytes, float]] = []
        now = BASE_TIME
        for port in range(8000, 8060):  # 60 ports, but every handshake completes
            now += 0.01
            packets += [
                (build_tcp("10.0.0.5", "10.0.0.9", 40000 + port, port, flags="S"), now),
                (build_tcp("10.0.0.9", "10.0.0.5", port, 40000 + port, flags="SA"), now + 0.001),
                (build_tcp("10.0.0.5", "10.0.0.9", 40000 + port, port, flags="A"), now + 0.002),
                (build_tcp("10.0.0.5", "10.0.0.9", 40000 + port, port, flags="PA", payload=b"x" * 40), now + 0.003),
            ]
        assert "tcp_port_scan" not in detectors_fired(run_detection(frames_from(packets)))

    def test_just_below_threshold_is_silent(self, run_detection: Run) -> None:
        threshold = DetectionSettings().port_scan_unique_ports
        scenario = get_scenario("tcp_port_scan", ports=threshold - 1)
        assert "tcp_port_scan" not in detectors_fired(run_detection(scenario.frames))

    def test_exactly_at_threshold_fires(self, run_detection: Run) -> None:
        threshold = DetectionSettings().port_scan_unique_ports
        assert "tcp_port_scan" in detectors_fired(run_detection(get_scenario("tcp_port_scan", ports=threshold).frames))

    def test_slow_scan_outside_window_is_not_detected(self, run_detection: Run) -> None:
        """Documented limitation: a scan slower than the window evades this detector."""
        settings = DetectionSettings()
        packets = [(build_tcp("203.0.113.9", "10.0.0.1", 50000, port, flags="S"), BASE_TIME + i * (settings.port_scan_window_seconds / 3))
                   for i, port in enumerate(range(1, 60))]
        assert "tcp_port_scan" not in detectors_fired(run_detection(frames_from(packets), settings))

    def test_threshold_is_configurable(self, run_detection: Run) -> None:
        scenario = get_scenario("tcp_port_scan", ports=40)
        strict = DetectionSettings(port_scan_unique_ports=100)
        assert "tcp_port_scan" not in detectors_fired(run_detection(scenario.frames, strict))


class TestHorizontalScan:
    def test_sweep_is_not_misreported_as_vertical_scan(self, run_detection: Run) -> None:
        fired = detectors_fired(run_detection(get_scenario("horizontal_scan").frames))
        assert "horizontal_scan" in fired and "tcp_port_scan" not in fired

    def test_sensitive_port_sweep_is_critical(self, run_detection: Run) -> None:
        detections = [d for d in run_detection(get_scenario("horizontal_scan", port=445).frames) if d.detector == "horizontal_scan"]
        assert detections[0].severity is Severity.CRITICAL

    def test_few_hosts_is_silent(self, run_detection: Run) -> None:
        assert run_detection(get_scenario("horizontal_scan", hosts=10).frames) == []


class TestUdpScan:
    def test_dns_resolver_replying_to_many_clients_is_not_a_scan(self, run_detection: Run) -> None:
        packets = [(build_udp("10.0.0.53", f"10.0.1.{i % 250 + 1}", 53, 30000 + i, b"\x00" * 20), BASE_TIME + i * 0.01) for i in range(300)]
        assert run_detection(frames_from(packets)) == []

    def test_below_threshold_is_silent(self, run_detection: Run) -> None:
        assert run_detection(get_scenario("udp_scan", ports=10).frames) == []


# ============================================================== brute force


class TestBruteForce:
    def test_evidence_counts_attempts(self, run_detection: Run) -> None:
        detections = [d for d in run_detection(get_scenario("ssh_brute_force", attempts=30).frames) if d.detector == "ssh_brute_force"]
        assert detections and detections[0].destination_port == 22
        assert detections[0].evidence_dict()["failed_attempts"] >= DetectionSettings().brute_force_attempts

    def test_non_ssh_auth_service_reported_as_auth_brute_force(self, run_detection: Run) -> None:
        packets: list[tuple[bytes, float]] = []
        now = BASE_TIME
        for i in range(30):
            now += 0.5
            port = 41000 + i
            packets += [
                (build_tcp("198.51.100.4", "10.0.0.20", port, 3389, flags="S"), now),
                (build_tcp("10.0.0.20", "198.51.100.4", 3389, port, flags="SA"), now + 0.01),
                (build_tcp("198.51.100.4", "10.0.0.20", port, 3389, flags="A"), now + 0.02),
                (build_tcp("10.0.0.20", "198.51.100.4", 3389, port, flags="R"), now + 0.1),
            ]
        assert "auth_brute_force" in detectors_fired(run_detection(frames_from(packets)))

    def test_long_lived_sessions_are_not_brute_force(self, run_detection: Run) -> None:
        packets: list[tuple[bytes, float]] = []
        now = BASE_TIME
        for i in range(30):
            now += 20
            port = 42000 + i
            packets += [
                (build_tcp("10.0.0.7", "10.0.0.20", port, 22, flags="S"), now),
                (build_tcp("10.0.0.20", "10.0.0.7", 22, port, flags="SA"), now + 0.01),
                (build_tcp("10.0.0.7", "10.0.0.20", port, 22, flags="A"), now + 0.02),
                (build_tcp("10.0.0.7", "10.0.0.20", port, 22, flags="FA"), now + 15),  # 15s session
            ]
        assert run_detection(frames_from(packets)) == []

    def test_fin_then_rst_counts_one_attempt_not_two(self, run_detection: Run) -> None:
        threshold = DetectionSettings().brute_force_attempts
        packets: list[tuple[bytes, float]] = []
        now = BASE_TIME
        for i in range(threshold // 2 + 1):  # would cross the threshold only if double counted
            now += 0.5
            port = 43000 + i
            packets += [
                (build_tcp("198.51.100.5", "10.0.0.20", port, 22, flags="S"), now),
                (build_tcp("10.0.0.20", "198.51.100.5", 22, port, flags="SA"), now + 0.01),
                (build_tcp("198.51.100.5", "10.0.0.20", port, 22, flags="A"), now + 0.02),
                (build_tcp("10.0.0.20", "198.51.100.5", 22, port, flags="FA"), now + 0.1),
                (build_tcp("198.51.100.5", "10.0.0.20", port, 22, flags="R"), now + 0.11),
            ]
        assert run_detection(frames_from(packets)) == []


# =================================================================== floods


class TestFloods:
    def test_syn_flood_recommends_rate_limit(self, run_detection: Run) -> None:
        detections = [d for d in run_detection(get_scenario("syn_flood").frames) if d.detector == "syn_flood"]
        assert detections[0].recommended_action is ActionType.RATE_LIMIT

    def test_answered_syns_are_not_a_flood(self, run_detection: Run) -> None:
        packets: list[tuple[bytes, float]] = []
        for i in range(700):
            ts = BASE_TIME + i * 0.01
            packets += [(build_tcp("10.0.0.8", "10.0.0.80", 20000 + i, 80, flags="S"), ts),
                        (build_tcp("10.0.0.80", "10.0.0.8", 80, 20000 + i, flags="SA"), ts + 0.001)]
        assert "syn_flood" not in detectors_fired(run_detection(frames_from(packets)))

    def test_icmp_below_threshold_is_silent(self, run_detection: Run) -> None:
        assert run_detection(get_scenario("icmp_flood", count=150).frames) == []

    def test_ordinary_ping_is_silent(self, run_detection: Run) -> None:
        packets = [(build_icmp("10.0.0.1", "10.0.0.2", sequence=i), BASE_TIME + i) for i in range(60)]
        assert run_detection(frames_from(packets)) == []

    def test_http_flood_positive_and_moderate_rate_negative(self, run_detection: Run) -> None:
        assert "http_flood" in detectors_fired(run_detection(get_scenario("http_flood").frames))
        moderate = [(build_http_request("10.0.0.3", "10.0.0.100", 40000 + i), BASE_TIME + i * 0.1) for i in range(200)]
        assert run_detection(frames_from(moderate)) == []

    def test_connection_rate_threshold_edge(self, run_detection: Run) -> None:
        settings = DetectionSettings(connection_rate_threshold=50, port_scan_unique_ports=10_000, syn_flood_threshold=10_000)
        just_under = [(build_tcp("10.9.9.9", "10.0.0.1", 30000 + i, 443, flags="S"), BASE_TIME + i * 0.01) for i in range(49)]
        assert run_detection(frames_from(just_under), settings) == []
        at = [(build_tcp("10.9.9.9", "10.0.0.1", 30000 + i, 443, flags="S"), BASE_TIME + i * 0.01) for i in range(50)]
        assert "connection_rate" in detectors_fired(run_detection(frames_from(at), settings))


# ====================================================================== DNS


class TestDns:
    def test_tunnel_evidence_names_parent_domain(self, run_detection: Run) -> None:
        detections = [d for d in run_detection(get_scenario("dns_tunneling").frames) if d.detector == "dns_anomaly"]
        assert detections[0].evidence_dict()["parent_domain"] == "example.test"

    def test_long_names_spread_across_many_domains_are_not_a_tunnel(self, run_detection: Run) -> None:
        packets = [(build_dns_query("10.0.0.66", "10.0.0.1", f"{'a' * 55}{i}.cdn{i}.net"), BASE_TIME + i * 0.2) for i in range(60)]
        assert run_detection(frames_from(packets)) == []

    def test_normal_repeated_lookups_are_silent(self, run_detection: Run) -> None:
        names = ["www.example.com", "api.example.com", "mail.example.com"]
        packets = [(build_dns_query("10.0.0.66", "10.0.0.1", names[i % 3]), BASE_TIME + i * 0.1) for i in range(250)]
        assert run_detection(frames_from(packets)) == []


# =================================================================== policy


class TestPolicyDetectors:
    def test_denylisted_source_detected_and_attributed(self, run_detection: Run) -> None:
        settings = DetectionSettings(denylist_networks=["203.0.113.0/24"])
        packets = [(build_tcp("203.0.113.66", "10.0.0.1", 5555, 443, flags="S"), BASE_TIME)]
        detections = run_detection(frames_from(packets), settings)
        assert detections[0].detector == "denylist" and detections[0].source_ip == "203.0.113.66"
        assert detections[0].recommended_action is ActionType.BLOCK_IP

    def test_outbound_to_denylisted_destination_is_attributed_to_listed_host(self, run_detection: Run) -> None:
        settings = DetectionSettings(denylist_networks=["198.51.100.99/32"])
        detections = run_detection(frames_from([(build_tcp("10.0.0.5", "198.51.100.99", 5555, 443, flags="S"), BASE_TIME)]), settings)
        assert detections[0].source_ip == "198.51.100.99"
        assert detections[0].recommended_action is ActionType.ALERT

    def test_empty_denylist_never_fires(self, run_detection: Run) -> None:
        assert run_detection(frames_from([(build_tcp("203.0.113.66", "10.0.0.1", 1, 2, flags="S"), BASE_TIME)])) == []

    @pytest.mark.parametrize("flags", ["", "FPU", "SF"])
    def test_illegal_flag_combinations(self, run_detection: Run, flags: str) -> None:
        packets = [(build_tcp("198.51.100.8", "10.0.0.1", 40000, 80 + i, flags=flags), BASE_TIME + i) for i in range(3)]
        assert "tcp_flag_anomaly" in detectors_fired(run_detection(frames_from(packets)))

    def test_single_illegal_packet_is_tolerated(self, run_detection: Run) -> None:
        assert run_detection(frames_from([(build_tcp("198.51.100.8", "10.0.0.1", 1, 80, flags=""), BASE_TIME)])) == []


# =================================================================== engine


class TestEnginePolicy:
    def test_allowlisted_source_is_suppressed(self, run_detection: Run) -> None:
        settings = DetectionSettings(allowlist_networks=["203.0.113.0/24"])
        engine = DetectionEngine(settings)
        assert run_detection(get_scenario("tcp_port_scan").frames, settings, engine) == []
        assert engine.suppressed_allowlist > 0

    def test_cooldown_collapses_repeats_but_allows_escalation(self, run_detection: Run) -> None:
        engine = DetectionEngine(DetectionSettings())
        detections = run_detection(get_scenario("icmp_flood", count=1200).frames, engine=engine)
        icmp = [d for d in detections if d.detector == "icmp_flood"]
        assert 1 <= len(icmp) <= 4  # not ~1000
        assert engine.suppressed_cooldown > 500

    def test_detector_exception_is_isolated(self, run_detection: Run) -> None:
        from sentinelx.detection.base import Detector

        class Exploding(Detector):
            name = "exploding"

            def inspect(self, context):  # type: ignore[no-untyped-def]
                raise RuntimeError("boom")

        engine = DetectionEngine(DetectionSettings())
        engine.add_detector(Exploding())
        detections = run_detection(get_scenario("icmp_flood").frames, engine=engine)
        assert "icmp_flood" in detectors_fired(detections)
        assert engine.detector_errors > 0

    def test_detection_without_evidence_is_rejected(self, run_detection: Run) -> None:
        from sentinelx.detection.base import Detector

        class Unexplained(Detector):
            name = "unexplained"

            def inspect(self, context):  # type: ignore[no-untyped-def]
                return self.build(context=context, title="bad", description="no evidence", evidence=[], confidence=0.9)

        engine = DetectionEngine(DetectionSettings(), detectors=[Unexplained()])
        assert run_detection(get_scenario("icmp_flood", count=5).frames, engine=engine) == []
        assert engine.detector_errors == 5

    def test_disabled_detector_and_modes(self, run_detection: Run) -> None:
        from sentinelx.common.enums import DetectionMode

        assert DetectionEngine(DetectionSettings(mode=DetectionMode.DISABLED)).detectors == []
        signature_only = DetectionEngine(DetectionSettings(mode=DetectionMode.SIGNATURE_ONLY))
        assert {d.name for d in signature_only.detectors} == {"denylist", "tcp_flag_anomaly"}
        engine = DetectionEngine(DetectionSettings(disabled_detectors=["icmp_flood"]))
        assert run_detection(get_scenario("icmp_flood").frames, engine=engine) == []


def test_frames_type_is_rawframe() -> None:
    assert isinstance(get_scenario("icmp_flood", count=1).frames[0], RawFrame)


class TestDocumentedEvasions:
    """Pin the known limitations, so a change that alters them is noticed and documented."""

    def test_slow_port_scan_evades_window_detector(self, run_detection: Run) -> None:
        assert "tcp_port_scan" not in detectors_fired(run_detection(get_scenario("slow_port_scan").frames))

    def test_low_rate_brute_force_evades_threshold(self, run_detection: Run) -> None:
        assert not {"ssh_brute_force", "auth_brute_force"} & detectors_fired(run_detection(get_scenario("low_rate_brute_force").frames))

    def test_port_scan_window_setting_is_honoured(self, run_detection: Run) -> None:
        """Regression: the scan window was once silently the longest detector window."""
        frames = get_scenario("slow_port_scan").frames
        assert "tcp_port_scan" not in detectors_fired(run_detection(frames, DetectionSettings(port_scan_window_seconds=15)))
        wide = DetectionSettings(port_scan_window_seconds=90, brute_force_window_seconds=90)
        assert "tcp_port_scan" in detectors_fired(run_detection(frames, wide))
