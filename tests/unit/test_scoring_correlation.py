from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinelx.common.enums import RiskBand, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.config.settings import CorrelationSettings, ScoringSettings
from sentinelx.correlation.engine import CorrelationEngine
from sentinelx.scoring.engine import RiskContext, RiskEngine

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def make(
    detector: str = "tcp_port_scan",
    *,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.8,
    category: ThreatCategory = ThreatCategory.RECONNAISSANCE,
    source: str = "203.0.113.5",
    port: int | None = 8080,
    at: float = 0.0,
) -> Detection:
    return Detection(
        detector=detector,
        category=category,
        severity=severity,
        confidence=confidence,
        title=detector,
        description="d",
        source_ip=source,
        destination_ip="10.0.0.1",
        destination_port=port,
        evidence=[Evidence("k", 1, "reason")],
        timestamp=T0 + timedelta(seconds=at),
    )


class TestRiskEngine:
    def test_contributions_sum_to_score_and_are_explained(self) -> None:
        risk = RiskEngine().assess(make())
        assert risk.score == pytest.approx(sum(risk.contributions.values()), abs=0.2)
        assert len(risk.rationale) == len(risk.contributions)
        assert risk.band is RiskBand.from_score(risk.score)

    def test_severity_is_monotonic(self) -> None:
        scores = [RiskEngine().assess(make(severity=s, port=None)).score for s in Severity]
        assert scores == sorted(scores)

    def test_repetition_and_history_raise_score(self) -> None:
        engine = RiskEngine()
        first = engine.assess(make(port=None))
        engine.assess(make("ssh_brute_force", category=ThreatCategory.BRUTE_FORCE, port=None, at=1))
        again = engine.assess(make(port=None, at=2))
        assert again.score > first.score
        assert "frequency" in again.contributions and "history" in again.contributions

    def test_history_expires(self) -> None:
        engine = RiskEngine(ScoringSettings(history_window_seconds=60))
        engine.assess(make(port=None))
        later = engine.assess(make(port=None, at=3600))
        assert "frequency" not in later.contributions

    def test_intel_sensitive_target_and_correlation_factors(self) -> None:
        risk = RiskEngine().assess(
            make(port=22),
            RiskContext(intel_score=1.0, intel_sources=("local_denylist",), correlated_detectors=3),
        )
        assert {"threat_intel", "sensitive_target", "correlation"} <= risk.contributions.keys()
        assert any("local_denylist" in line for line in risk.rationale)

    def test_score_is_capped_at_100_and_says_so(self) -> None:
        risk = RiskEngine().assess(
            make(severity=Severity.CRITICAL, confidence=0.98, port=22),
            RiskContext(intel_score=1.0, correlated_detectors=5),
        )
        assert risk.score == 100.0 and any("capped" in line for line in risk.rationale)

    def test_allowlist_reduces_score_but_never_below_zero(self) -> None:
        risk = RiskEngine().assess(
            make(severity=Severity.LOW, confidence=0.1, port=None), RiskContext(allowlisted=True)
        )
        assert risk.score == 0.0 and risk.contributions["allowlist"] < 0

    def test_weights_are_configurable(self) -> None:
        heavy = RiskEngine(ScoringSettings(severity_weight=90)).assess(make(port=None))
        light = RiskEngine(ScoringSettings(severity_weight=10)).assess(make(port=None))
        assert heavy.score > light.score

    def test_previous_responses_are_counted(self) -> None:
        engine = RiskEngine()
        engine.record_response("203.0.113.5")
        assert "previous_responses" in engine.assess(make(port=None)).contributions


class TestCorrelation:
    def assess(self, engine: RiskEngine, detection: Detection):  # type: ignore[no-untyped-def]
        return detection, engine.assess(detection)

    def test_single_detection_does_not_open_incident(self) -> None:
        correlation, risk = CorrelationEngine(), RiskEngine()
        assert correlation.correlate(*self.assess(risk, make())) is None

    def test_recon_then_brute_force_is_named_host_compromise(self) -> None:
        correlation, risk = CorrelationEngine(), RiskEngine()
        correlation.correlate(*self.assess(risk, make()))
        result = correlation.correlate(
            *self.assess(
                risk, make("ssh_brute_force", category=ThreatCategory.BRUTE_FORCE, port=22, at=30)
            )
        )
        assert result is not None and result.created
        incident = result.incident
        assert incident.title == "Potential host compromise attempt"
        assert incident.correlation_rule == "recon_to_credential_attack"
        assert incident.severity is Severity.CRITICAL
        assert incident.detection_count == 2 and incident.affected_services == {8080, 22}
        assert len(incident.timeline) == 2

    def test_incident_extends_and_reports_severity_change(self) -> None:
        correlation, risk = CorrelationEngine(), RiskEngine()
        correlation.correlate(*self.assess(risk, make(severity=Severity.LOW, confidence=0.5)))
        created = correlation.correlate(
            *self.assess(risk, make("udp_scan", severity=Severity.LOW, confidence=0.5, at=5))
        )
        assert created is not None and created.incident.severity is Severity.MEDIUM
        extended = correlation.correlate(
            *self.assess(risk, make("ssh_brute_force", category=ThreatCategory.BRUTE_FORCE, at=10))
        )
        assert extended is not None and not extended.created and extended.severity_changed
        assert extended.incident.detection_count == 3

    def test_incident_risk_is_at_least_worst_member(self) -> None:
        correlation, risk = CorrelationEngine(), RiskEngine()
        a = make(severity=Severity.MEDIUM)
        b = make(
            "icmp_flood", severity=Severity.HIGH, category=ThreatCategory.DENIAL_OF_SERVICE, at=1
        )
        ra, rb = risk.assess(a), risk.assess(b)
        correlation.correlate(a, ra)
        result = correlation.correlate(b, rb)
        assert result is not None and result.incident.risk.score >= max(ra.score, rb.score)

    def test_different_sources_are_not_merged(self) -> None:
        correlation, risk = CorrelationEngine(), RiskEngine()
        correlation.correlate(*self.assess(risk, make(source="203.0.113.1")))
        assert (
            correlation.correlate(*self.assess(risk, make("udp_scan", source="203.0.113.2", at=1)))
            is None
        )

    def test_detections_outside_window_do_not_correlate(self) -> None:
        correlation, risk = CorrelationEngine(CorrelationSettings(window_seconds=60)), RiskEngine()
        correlation.correlate(*self.assess(risk, make()))
        assert correlation.correlate(*self.assess(risk, make("udp_scan", at=500))) is None

    def test_standalone_critical_detection_opens_incident(self) -> None:
        correlation = CorrelationEngine()
        detection = make(severity=Severity.CRITICAL, confidence=0.98, port=22)
        risk = RiskEngine().assess(detection, RiskContext(intel_score=1.0))
        assert correlation.correlate(detection, risk) is not None

    def test_disabled_correlation(self) -> None:
        correlation, risk = CorrelationEngine(CorrelationSettings(enabled=False)), RiskEngine()
        for i, name in enumerate(["a", "b", "c"]):
            assert correlation.correlate(*self.assess(risk, make(name, at=i))) is None
