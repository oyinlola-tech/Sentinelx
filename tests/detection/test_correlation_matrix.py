"""Correlation engine matrix: grouping, windows, duplicates, escalation, patterns, caps."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from sentinelx.capture import MockCapture
from sentinelx.common.enums import IncidentStatus, RiskBand, Severity, ThreatCategory
from sentinelx.common.models import Detection, RiskAssessment
from sentinelx.config.settings import CorrelationSettings, Settings
from sentinelx.correlation import PATTERNS, CorrelationEngine
from sentinelx.correlation.engine import MAX_AFFECTED, MAX_MEMBERS
from sentinelx.events.bus import EventBus, EventType
from sentinelx.firewall import MemoryFirewall
from sentinelx.pipeline import Pipeline
from sentinelx.testing import get_scenario
from sentinelx.testing.scenarios import BASE_TIME

C = ThreatCategory
#: Capture time deliberately years before "now": correlation must follow it, not the wall clock.
T0 = datetime(2021, 6, 1, 8, 0, tzinfo=UTC)
SOURCE = "198.51.100.30"


def det(
    detector: str = "tcp_port_scan",
    category: ThreatCategory = C.RECONNAISSANCE,
    *,
    severity: Severity = Severity.MEDIUM,
    source: str = SOURCE,
    destination: str | None = "203.0.113.10",
    port: int | None = 22,
    at: float = 0.0,
) -> Detection:
    return Detection(
        detector=detector,
        category=category,
        severity=severity,
        confidence=0.8,
        title=detector.replace("_", " "),
        description="",
        source_ip=source,
        destination_ip=destination,
        destination_port=port,
        timestamp=T0 + timedelta(seconds=at),
    )


def risk(score: float = 50.0) -> RiskAssessment:
    return RiskAssessment(
        score=score, band=RiskBand.from_score(score), contributions={"x": score}, rationale=["x"]
    )


class TestGrouping:
    def test_related_detections_from_one_source_in_window_form_one_incident(self) -> None:
        engine = CorrelationEngine()
        assert engine.correlate(det("tcp_port_scan", at=0), risk()) is None
        created = engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, at=30), risk())
        assert created is not None and created.created
        updated = engine.correlate(det("icmp_flood", C.DENIAL_OF_SERVICE, at=60), risk())
        assert updated is not None and not updated.created
        assert updated.incident.incident_id == created.incident.incident_id
        assert updated.incident.detection_count == 3 and len(engine.open_incidents()) == 1

    def test_same_detector_twice_is_not_corroboration(self) -> None:
        engine = CorrelationEngine()
        assert engine.correlate(det(at=0), risk()) is None
        assert engine.correlate(det(at=1), risk()) is None  # a different detection, same detector
        assert engine.open_incidents() == []

    def test_unrelated_sources_stay_separate(self) -> None:
        engine = CorrelationEngine()
        assert engine.correlate(det("tcp_port_scan", source="198.51.100.1"), risk()) is None
        assert (
            engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, source="198.51.100.2"), risk())
            is None
        )
        assert engine.open_incidents() == []
        engine.correlate(
            det("icmp_flood", C.DENIAL_OF_SERVICE, source="198.51.100.1", at=1), risk()
        )
        engine.correlate(det("syn_flood", C.DENIAL_OF_SERVICE, source="198.51.100.2", at=1), risk())
        incidents = engine.open_incidents()
        assert len(incidents) == 2
        assert {frozenset(i.affected_sources) for i in incidents} == {
            frozenset({"198.51.100.1"}),
            frozenset({"198.51.100.2"}),
        }

    def test_group_by_destination_splits_one_source(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(group_by_destination=True))
        engine.correlate(det("tcp_port_scan", destination="203.0.113.1"), risk())
        assert (
            engine.correlate(
                det("ssh_brute_force", C.BRUTE_FORCE, destination="203.0.113.2"), risk()
            )
            is None
        )

    def test_detections_outside_the_window_do_not_correlate(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(window_seconds=60))
        engine.correlate(det("tcp_port_scan", at=0), risk())
        assert engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, at=61), risk()) is None
        assert engine.open_incidents() == []

    def test_open_incident_closes_after_window_and_new_activity_starts_a_new_one(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(window_seconds=60))
        engine.correlate(det("tcp_port_scan", at=0), risk())
        first = engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, at=10), risk())
        assert first is not None
        engine.correlate(det("icmp_flood", C.DENIAL_OF_SERVICE, at=65), risk())  # extends: 55s gap
        assert engine.open_incidents()[0].incident_id == first.incident.incident_id
        assert (
            engine.correlate(det("tcp_port_scan", at=200), risk()) is None
        )  # closed, pending again
        assert engine.open_incidents() == []
        second = engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, at=210), risk())
        assert second is not None and second.created
        assert second.incident.incident_id != first.incident.incident_id
        assert first.incident.status is IncidentStatus.OPEN  # closure is not an analyst verdict

    def test_standalone_critical_detection_opens_an_incident(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate(det(severity=Severity.CRITICAL), risk(90))
        assert result is not None and result.created
        assert (
            engine.correlate(det(severity=Severity.HIGH, source="198.51.100.9"), risk(99)) is None
        )

    def test_disabled_correlation_never_groups(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(enabled=False))
        for index, name in enumerate(["a", "b", "c"]):
            assert engine.correlate(det(name, at=index), risk(99)) is None


class TestDuplicates:
    def test_redelivered_detection_is_not_double_counted_in_an_open_incident(self) -> None:
        """Regression: the same detection_id was appended again, inflating the count."""
        engine = CorrelationEngine()
        first, second = det("tcp_port_scan"), det("ssh_brute_force", C.BRUTE_FORCE, at=1)
        engine.correlate(first, risk())
        result = engine.correlate(second, risk())
        assert result is not None
        again = engine.correlate(second, risk(99))
        assert again is not None and not again.created and not again.severity_changed
        incident = again.incident
        assert incident.detection_count == 2 and len(incident.detection_ids) == 2
        assert len(incident.timeline) == 2 and incident.risk.score == result.incident.risk.score

    def test_redelivered_detection_does_not_corroborate_itself_while_pending(self) -> None:
        """Regression: with min_detections=1 a duplicate turned one brute-force detection
        into a 'sustained_brute_force' incident and escalated its severity."""
        engine = CorrelationEngine(CorrelationSettings(min_detections=1))
        single = det("ssh_brute_force", C.BRUTE_FORCE)
        created = engine.correlate(single, risk())
        assert created is not None and created.incident.correlation_rule == "multiple_detections"
        again = engine.correlate(single, risk())
        assert again is not None and again.incident.detection_count == 1
        assert again.incident.correlation_rule == "multiple_detections"
        assert again.incident.severity is Severity.MEDIUM

        pending = CorrelationEngine()
        assert pending.correlate(single, risk()) is None
        assert pending.correlate(single, risk()) is None  # redelivered while still pending
        opened = pending.correlate(det("rdp_brute_force", C.BRUTE_FORCE, at=1), risk())
        assert opened is not None and opened.created
        assert opened.incident.detection_count == 2
        assert sorted(opened.incident.detection_ids) == sorted({*opened.incident.detection_ids})
        assert len(opened.incident.timeline) == 2


class TestEscalation:
    def test_severity_and_risk_escalate_as_stages_arrive(self) -> None:
        engine = CorrelationEngine()
        engine.correlate(det("tcp_port_scan", severity=Severity.LOW), risk(40))
        opened = engine.correlate(det("udp_scan", severity=Severity.LOW, at=5), risk(45))
        assert opened is not None
        assert opened.incident.correlation_rule == "sustained_reconnaissance"
        assert opened.incident.severity is Severity.MEDIUM  # the pattern's floor
        risk_before = opened.incident.risk.score

        brute = engine.correlate(
            det("ssh_brute_force", C.BRUTE_FORCE, severity=Severity.HIGH, at=20), risk(70)
        )
        assert brute is not None and brute.severity_changed
        assert (
            brute.previous_severity is Severity.MEDIUM
            and brute.incident.severity is Severity.CRITICAL
        )
        assert brute.incident.correlation_rule == "recon_to_credential_attack"
        assert brute.incident.title == "Potential host compromise attempt"
        assert brute.previous_risk == risk_before and brute.incident.risk.score > risk_before
        assert "pattern" in brute.incident.risk.contributions

        quieter = engine.correlate(det("tcp_port_scan", severity=Severity.INFO, at=30), risk(5))
        assert quieter is not None and not quieter.severity_changed
        assert quieter.incident.severity is Severity.CRITICAL  # never de-escalates

    def test_incident_risk_is_worst_member_plus_documented_bonuses(self) -> None:
        engine = CorrelationEngine()
        engine.correlate(det("tcp_port_scan"), risk(30))
        result = engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, at=1), risk(80))
        assert result is not None
        contributions = result.incident.risk.contributions
        assert contributions == {
            "highest_detection": 80.0,
            "corroboration": 4.0,
            "category_breadth": 3.0,
            "pattern": 15.0,
        }
        assert result.incident.risk.score == 100.0  # 102 capped
        assert any("capped at 100" in line for line in result.incident.risk.rationale)

    async def test_pipeline_publishes_incident_updates_and_escalations(
        self, settings: Settings
    ) -> None:
        bus = EventBus()
        pipeline = Pipeline(settings, bus=bus, firewall=MemoryFirewall())
        pipeline.response.guard._local_addresses = lambda: set()
        await pipeline.start()
        events: list[tuple[EventType, dict[str, object]]] = []

        async def consume() -> None:
            async with bus.subscribe("correlation-matrix") as stream:
                async for event in stream:
                    events.append((event.type, event.payload))

        consumer = asyncio.create_task(consume())
        await asyncio.sleep(0)
        report = await pipeline.run(MockCapture(get_scenario("mixed_intrusion").frames))
        await asyncio.sleep(0.05)
        consumer.cancel()
        await pipeline.stop()

        opened = [p for t, p in events if t is EventType.INCIDENT_OPENED]
        updated = [p for t, p in events if t is EventType.INCIDENT_UPDATED]
        assert len(opened) == 1 and updated, [t.value for t, _ in events][:20]
        incident_id = opened[0]["incident_id"]
        assert all(p["incident_id"] == incident_id for p in updated)
        counts = [int(p["detection_count"]) for p in [opened[0], *updated]]  # type: ignore[call-overload]
        assert counts == sorted(counts)
        assert all(len(p["linked_detection_ids"]) == 1 for p in updated)  # type: ignore[arg-type]
        detection_times = {
            r.detection.detection_id: r.detection.timestamp for r in report.detections
        }
        incident = next(iter(report.incidents.values()))
        assert incident.first_seen == min(detection_times[i] for i in incident.detection_ids)
        assert incident.last_seen == max(detection_times[i] for i in incident.detection_ids)
        assert incident.last_seen.timestamp() < BASE_TIME + 3600  # capture time, not wall clock


class TestPatterns:
    @pytest.mark.parametrize(
        ("members", "expected"),
        [
            ([C.RECONNAISSANCE, C.BRUTE_FORCE], "recon_to_credential_attack"),
            (
                [C.BRUTE_FORCE, C.RECONNAISSANCE, C.MALICIOUS_REPUTATION],
                "recon_to_credential_attack",
            ),
            ([C.MALICIOUS_REPUTATION, C.DENIAL_OF_SERVICE], "known_bad_actor_activity"),
            ([C.RECONNAISSANCE, C.DENIAL_OF_SERVICE], "recon_and_disruption"),
            ([C.EXFILTRATION, C.PROTOCOL_ANOMALY], "possible_exfiltration"),
            ([C.BRUTE_FORCE, C.BRUTE_FORCE], "sustained_brute_force"),
            ([C.RECONNAISSANCE, C.RECONNAISSANCE], "sustained_reconnaissance"),
            ([C.DENIAL_OF_SERVICE, C.DENIAL_OF_SERVICE], "denial_of_service"),
            ([C.DENIAL_OF_SERVICE, C.BRUTE_FORCE], "sustained_brute_force"),
            ([C.PROTOCOL_ANOMALY, C.POLICY_VIOLATION], "multiple_detections"),
            ([C.ANOMALY, C.LATERAL_MOVEMENT], "multiple_detections"),
        ],
    )
    def test_pattern_matches_only_when_its_categories_are_present(
        self, members: list[ThreatCategory], expected: str
    ) -> None:
        engine = CorrelationEngine()
        result = None
        for index, category in enumerate(members):
            result = engine.correlate(det(f"detector_{index}", category, at=index), risk())
        assert result is not None and result.incident.correlation_rule == expected
        pattern = next((p for p in PATTERNS if p.name == expected), None)
        if pattern is not None:
            assert result.incident.severity.rank >= pattern.severity_floor.rank
            assert result.incident.title == pattern.title

    def test_single_detection_patterns_require_their_minimum_count(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(min_detections=1))
        for index, category in enumerate((C.MALICIOUS_REPUTATION, C.EXFILTRATION, C.BRUTE_FORCE)):
            result = engine.correlate(
                det(category.value, category, source=f"198.51.100.{index}"), risk()
            )
            assert result is not None and result.incident.correlation_rule == "multiple_detections"

    def test_every_pattern_is_exercised(self) -> None:
        exercised = {
            "recon_to_credential_attack", "known_bad_actor_activity", "recon_and_disruption",
            "possible_exfiltration", "sustained_brute_force", "sustained_reconnaissance",
            "denial_of_service",
        }  # fmt: skip
        assert exercised == {p.name for p in PATTERNS}


class TestClosureCapsAndTime:
    def test_analyst_closure_stops_correlation_into_the_incident(self) -> None:
        engine = CorrelationEngine()
        engine.correlate(det("tcp_port_scan"), risk())
        first = engine.correlate(det("ssh_brute_force", C.BRUTE_FORCE, at=1), risk())
        assert first is not None
        assert engine.close_incident(first.incident.incident_id, IncidentStatus.FALSE_POSITIVE)
        assert first.incident.status is IncidentStatus.FALSE_POSITIVE
        assert not engine.close_incident(first.incident.incident_id, IncidentStatus.RESOLVED)
        assert engine.correlate(det("icmp_flood", C.DENIAL_OF_SERVICE, at=2), risk()) is None
        again = engine.correlate(det("udp_scan", at=3), risk())
        assert again is not None and again.created
        assert again.incident.incident_id != first.incident.incident_id
        assert first.incident.detection_count == 2

    def test_member_timeline_and_id_caps_are_enforced(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(window_seconds=10_000))
        total = MAX_MEMBERS + 205
        worst_index = 7
        result = None
        for index in range(total):
            score = 99.0 if index == worst_index else 20.0
            result = engine.correlate(det(f"detector_{index % 3}", at=index), risk(score))
        assert result is not None
        incident = result.incident
        members = engine._members[incident.incident_id]
        assert len(members) <= MAX_MEMBERS and len(incident.timeline) <= MAX_MEMBERS
        assert len(incident.detection_ids) <= MAX_MEMBERS
        assert incident.detection_count == total
        assert incident.risk.contributions["highest_detection"] == 99.0  # worst member kept
        assert incident.detection_ids[-1] == members[-1][0].detection_id

    def test_affected_sets_are_capped(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(window_seconds=10_000))
        for index in range(MAX_AFFECTED + 150):
            engine.correlate(
                det(
                    f"detector_{index % 2}",
                    destination=f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}",
                    port=1 + index,
                    at=index,
                ),
                risk(),
            )
        incident = engine.open_incidents()[0]
        assert len(incident.affected_destinations) <= MAX_AFFECTED
        assert len(incident.affected_services) <= MAX_AFFECTED

    def test_open_incident_capacity_is_bounded(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(max_open_incidents=2))
        for offset, source in enumerate(["198.51.100.1", "198.51.100.2", "198.51.100.3"]):
            engine.correlate(det("a", source=source, at=offset * 10), risk())
            engine.correlate(det("b", source=source, at=offset * 10 + 1), risk())
        assert {next(iter(i.affected_sources)) for i in engine.open_incidents()} == {
            "198.51.100.2",
            "198.51.100.3",
        }

    def test_timestamps_are_capture_time(self) -> None:
        engine = CorrelationEngine(CorrelationSettings(window_seconds=120))
        engine.correlate(det("tcp_port_scan", at=100), risk())
        result = engine.correlate(
            det("ssh_brute_force", C.BRUTE_FORCE, at=40), risk()
        )  # out of order
        assert result is not None
        incident = result.incident
        assert incident.first_seen == T0 + timedelta(seconds=40)
        assert incident.last_seen == T0 + timedelta(seconds=100)
        assert [e["timestamp"] for e in incident.timeline] == sorted(
            e["timestamp"] for e in incident.timeline
        )
        later = engine.correlate(det("icmp_flood", C.DENIAL_OF_SERVICE, at=210), risk())
        assert later is not None and later.incident.incident_id == incident.incident_id
        assert incident.last_seen == T0 + timedelta(seconds=210)
        assert incident.duration_seconds == 170
