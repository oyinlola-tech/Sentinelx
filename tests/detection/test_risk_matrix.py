"""Risk engine matrix: determinism, per-factor direction, bounds and explainability."""

from __future__ import annotations

import math
import random
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from sentinelx.common.enums import RiskBand, Severity, ThreatCategory
from sentinelx.common.models import Detection, RiskAssessment
from sentinelx.config.settings import ScoringSettings
from sentinelx.scoring import RiskContext, RiskEngine

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
SEVERITIES = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def detection(
    *,
    detector: str = "tcp_port_scan",
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.5,
    source: str = "198.51.100.20",
    port: int | None = 8081,
    destination: str | None = "203.0.113.10",
    at: datetime = T0,
) -> Detection:
    return Detection(
        detector=detector,
        category=ThreatCategory.RECONNAISSANCE,
        severity=severity,
        confidence=confidence,
        title=detector,
        description="",
        source_ip=source,
        destination_ip=destination,
        destination_port=port,
        timestamp=at,
    )


def score(det: Detection, context: RiskContext | None = None, **weights: float) -> RiskAssessment:
    return RiskEngine(ScoringSettings(**weights)).assess(det, context)


def assert_explained(assessment: RiskAssessment) -> None:
    """Contributions sum (before clamping) to the score; each has a rationale line."""
    raw = sum(assessment.contributions.values())
    tolerance = 0.05 + 0.005 * len(assessment.contributions)  # 1dp score, 2dp parts
    assert abs(max(0.0, min(100.0, raw)) - assessment.score) <= tolerance, assessment
    assert 0.0 <= assessment.score <= 100.0
    assert assessment.band is RiskBand.from_score(assessment.score)
    assert all(math.isfinite(v) for v in assessment.contributions.values())
    points = [
        float(m.group(1))
        for line in assessment.rationale
        if (m := re.match(r"^([+-]-?\d+\.\d)", line))
    ]
    assert len(points) == len(assessment.contributions), assessment.rationale
    for value, (name, contribution) in zip(points, assessment.contributions.items(), strict=True):
        assert abs(abs(value) - abs(contribution)) <= 0.051, (name, value, contribution)
    capped = any(line.startswith("score capped") for line in assessment.rationale)
    if raw > 100.0 + tolerance:
        assert capped
    if capped:
        assert raw > 100.0 - tolerance


class TestDeterminism:
    def test_same_inputs_give_the_same_score_and_rationale(self) -> None:
        context = RiskContext(intel_score=0.4, intel_sources=("feed",), correlated_detectors=2)
        runs = []
        for _ in range(3):
            engine = RiskEngine()
            first = engine.assess(detection(), context)
            second = engine.assess(detection(detector="ssh_brute_force", port=22), context)
            runs.append((first.score, first.contributions, first.rationale, second.score))
        assert runs[0] == runs[1] == runs[2]

    def test_documented_example_of_a_default_score(self) -> None:
        assessment = score(detection(severity=Severity.HIGH, confidence=0.9, port=22))
        # 45*3/4 + 20*0.9 + 10 (ssh is a sensitive port)
        assert assessment.contributions == {
            "severity": 33.75,
            "confidence": 18.0,
            "sensitive_target": 10.0,
        }
        assert assessment.score == 61.8 and assessment.band is RiskBand.from_score(61.8)
        assert_explained(assessment)


class TestFactorDirection:
    def test_severity_increases_score_monotonically(self) -> None:
        scores = [score(detection(severity=s)).score for s in SEVERITIES]
        assert scores == sorted(scores) and len(set(scores)) == len(scores)

    def test_confidence_increases_score(self) -> None:
        scores = [score(detection(confidence=c)).score for c in (0.0, 0.25, 0.5, 0.75, 1.0)]
        assert scores == sorted(scores) and len(set(scores)) == 5

    def test_repetition_adds_up_to_saturation_then_stops(self) -> None:
        engine = RiskEngine(ScoringSettings(frequency_saturation=4))
        scores = [engine.assess(detection(at=T0 + timedelta(seconds=i))).score for i in range(8)]
        assert scores[0] < scores[1] < scores[2] < scores[3] < scores[4]
        assert scores[4] == scores[5] == scores[6] == scores[7]
        assert "frequency" not in RiskEngine().assess(detection()).contributions

    def test_other_detectors_from_the_source_add_history(self) -> None:
        engine = RiskEngine(ScoringSettings(history_saturation=3))
        baseline = RiskEngine().assess(detection(detector="target")).score
        history_points = []
        for index in range(5):
            engine.assess(
                detection(detector=f"other_{index}", at=T0 + timedelta(seconds=2 * index))
            )
            scored = engine.assess(
                detection(detector="target", at=T0 + timedelta(seconds=2 * index + 1))
            )
            history_points.append(scored.contributions["history"])
        a, b, c, d, e = history_points
        assert a < b < c == d == e  # saturates at three distinct other detectors
        assert scored.score > baseline

    def test_history_is_per_source_and_expires_with_the_window(self) -> None:
        engine = RiskEngine(ScoringSettings(history_window_seconds=60))
        engine.assess(detection(detector="earlier"))
        other_source = engine.assess(
            detection(source="198.51.100.99", at=T0 + timedelta(seconds=1))
        )
        assert "history" not in other_source.contributions
        within = engine.assess(detection(at=T0 + timedelta(seconds=59)))
        assert "history" in within.contributions
        later = RiskEngine(ScoringSettings(history_window_seconds=60))
        later.assess(detection(detector="earlier"))
        expired = later.assess(detection(at=T0 + timedelta(seconds=61)))
        assert "history" not in expired.contributions

    def test_a_detection_is_never_its_own_history(self) -> None:
        assessment = RiskEngine().assess(detection())
        assert "frequency" not in assessment.contributions
        assert "history" not in assessment.contributions

    def test_correlation_membership_increases_score_until_three(self) -> None:
        scores = [score(detection(), RiskContext(correlated_detectors=n)).score for n in range(6)]
        assert scores[0] < scores[1] < scores[2] < scores[3] == scores[4] == scores[5]

    def test_threat_intel_denylist_increases_score(self) -> None:
        scores = [score(detection(), RiskContext(intel_score=s)).score for s in (0, 0.3, 0.7, 1)]
        assert scores == sorted(scores) and len(set(scores)) == 4
        named = score(detection(), RiskContext(intel_score=1.0, intel_sources=("abuse-feed",)))
        assert any("abuse-feed" in line for line in named.rationale)

    def test_asset_criticality_sensitive_port_or_declared_host(self) -> None:
        plain = score(detection(port=8081)).score
        assert score(detection(port=3389)).score > plain
        crown = RiskContext(sensitive_destinations=frozenset({"203.0.113.10"}))
        assert score(detection(port=8081), crown).score > plain
        other = RiskContext(sensitive_destinations=frozenset({"203.0.113.99"}))
        assert score(detection(port=8081), other).score == plain
        assert score(detection(port=None, destination=None)).score == plain

    def test_previous_responses_increase_score_capped_at_ten(self) -> None:
        engine = RiskEngine()
        points = []
        for index in range(4):
            assessment = engine.assess(
                detection(
                    detector=f"d{index}", source="198.51.100.77", at=T0 + timedelta(hours=2 * index)
                )
            )
            points.append(assessment.contributions.get("previous_responses", 0.0))
            engine.record_response("198.51.100.77")
        assert points == [0.0, 5.0, 10.0, 10.0]

    def test_allowlisted_source_is_reduced_but_never_below_zero(self) -> None:
        plain = score(detection(severity=Severity.HIGH))
        allowed = score(detection(severity=Severity.HIGH), RiskContext(allowlisted=True))
        assert allowed.score < plain.score and allowed.contributions["allowlist"] == -40.0
        floor = score(
            detection(severity=Severity.INFO, confidence=0.1), RiskContext(allowlisted=True)
        )
        assert floor.score == 0.0
        assert_explained(allowed)

    @pytest.mark.parametrize(
        ("weight", "factor", "context", "det"),
        [
            ("severity_weight", "severity", RiskContext(), detection()),
            ("confidence_weight", "confidence", RiskContext(), detection()),
            ("intel_weight", "threat_intel", RiskContext(intel_score=0.8), detection()),
            ("correlation_weight", "correlation", RiskContext(correlated_detectors=2), detection()),
            ("sensitive_target_weight", "sensitive_target", RiskContext(), detection(port=22)),
            (
                "allowlist_penalty",
                "allowlist",
                RiskContext(allowlisted=True),
                detection(severity=Severity.CRITICAL, confidence=1.0),
            ),
        ],
    )
    def test_configured_weights_scale_their_factor(
        self, weight: str, factor: str, context: RiskContext, det: Detection
    ) -> None:
        low = score(det, context, **{weight: 5.0})
        high = score(det, context, **{weight: 50.0})
        assert abs(high.contributions[factor]) > abs(low.contributions[factor])
        if factor == "allowlist":
            assert high.score < low.score
        else:
            assert high.score > low.score
        zero = score(det, context, **{weight: 0.0})
        assert zero.contributions.get(factor, 0.0) in (0.0, -0.0)


class TestBounds:
    @pytest.mark.parametrize(
        ("context", "expected_intel"),
        [
            (RiskContext(intel_score=float("nan")), None),
            (RiskContext(intel_score=float("-inf")), None),
            (RiskContext(intel_score=-3.0), None),
            (RiskContext(intel_score=float("inf")), 15.0),
            (RiskContext(intel_score=5.0), 15.0),  # regression: was worth 75 points
            (RiskContext(intel_score=1e308), 15.0),
        ],
    )
    def test_out_of_range_intel_is_clamped_to_its_weight(
        self, context: RiskContext, expected_intel: float | None
    ) -> None:
        assessment = score(detection(), context)
        assert assessment.contributions.get("threat_intel") == expected_intel
        assert "inf" not in " ".join(assessment.rationale) and "nan" not in " ".join(
            assessment.rationale
        )
        assert_explained(assessment)

    def test_negative_correlated_count_never_subtracts(self) -> None:
        """Regression: correlated_detectors=-10 subtracted 50 points."""
        assessment = score(detection(), RiskContext(correlated_detectors=-10))
        assert "correlation" not in assessment.contributions
        assert assessment.score == score(detection()).score

    def test_non_finite_confidence_and_weights_are_rejected_at_the_boundary(self) -> None:
        for bad in (float("nan"), float("inf"), -0.1, 1.01):
            with pytest.raises(ValueError, match="confidence"):
                detection(confidence=bad)
        for field in ("severity_weight", "intel_weight", "allowlist_penalty"):
            with pytest.raises(ValidationError):
                ScoringSettings(**{field: float("nan")})
            with pytest.raises(ValidationError):
                ScoringSettings(**{field: 101})
        with pytest.raises(ValidationError):
            ScoringSettings(history_window_seconds=0)
        with pytest.raises(ValueError, match="0-100"):
            RiskAssessment(score=float("nan"), band=RiskBand.LOW, contributions={}, rationale=[])

    def test_extreme_counts_stay_within_bounds(self) -> None:
        engine = RiskEngine(ScoringSettings(frequency_saturation=1, history_saturation=1))
        for index in range(2000):
            engine.record_response("198.51.100.5")
            assessment = engine.assess(
                detection(
                    detector=f"d{index % 50}",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    port=22,
                    source="198.51.100.5",
                    at=T0 + timedelta(milliseconds=index),
                ),
                RiskContext(intel_score=1.0, correlated_detectors=10**12),
            )
            assert 0.0 <= assessment.score <= 100.0
        assert assessment.score == 100.0 and any("capped" in r for r in assessment.rationale)
        assert engine.source_summary("198.51.100.5")["detections"] == 500  # history is bounded

    def test_tracked_sources_are_bounded(self) -> None:
        engine = RiskEngine(max_sources=100)
        for index in range(1000):
            engine.assess(detection(source=f"198.51.{index // 250}.{index % 250}"))
        assert len(engine._history) <= 100

    def test_seeded_random_inputs_always_score_between_0_and_100(self) -> None:
        rng = random.Random(20260915)
        specials = [float("nan"), float("inf"), float("-inf"), -1e308, 1e308, -5.0, 0.0, 1.0, 7.5]
        for _ in range(3):
            engine = RiskEngine(
                ScoringSettings(
                    **{
                        name: rng.uniform(0, 100)
                        for name in (
                            "severity_weight",
                            "confidence_weight",
                            "frequency_weight",
                            "history_weight",
                            "intel_weight",
                            "correlation_weight",
                            "sensitive_target_weight",
                            "allowlist_penalty",
                        )
                    },
                    frequency_saturation=rng.randint(1, 50),
                    history_saturation=rng.randint(1, 50),
                    history_window_seconds=rng.choice([1.0, 60.0, 3600.0, 1e9]),
                )
            )
            clock = T0
            for _ in range(700):
                clock += timedelta(seconds=rng.choice([0, 0.001, 1, 30, 4000]))
                intel = rng.choice(specials) if rng.random() < 0.3 else rng.random()
                context = RiskContext(
                    intel_score=intel,
                    intel_sources=("feed",) if intel else (),
                    allowlisted=rng.random() < 0.2,
                    correlated_detectors=rng.choice([-(10**9), -1, 0, 1, 2, 3, 10**9]),
                    sensitive_destinations=frozenset({"203.0.113.10"})
                    if rng.random() < 0.3
                    else frozenset(),
                )
                if rng.random() < 0.1:
                    engine.record_response(f"198.51.100.{rng.randint(0, 3)}")
                assessment = engine.assess(
                    detection(
                        detector=f"det_{rng.randint(0, 12)}",
                        severity=rng.choice(SEVERITIES),
                        confidence=rng.random(),
                        source=f"198.51.100.{rng.randint(0, 3)}",
                        port=rng.choice([None, 0, 22, 443, 65535]),
                        at=clock,
                    ),
                    context,
                )
                assert_explained(assessment)


class TestExplanations:
    def test_every_factor_has_a_rationale_line_that_matches_its_points(self) -> None:
        engine = RiskEngine()
        engine.assess(detection(detector="ssh_brute_force"))
        engine.assess(detection(at=T0 + timedelta(seconds=1)))
        engine.record_response("198.51.100.20")
        assessment = engine.assess(
            detection(
                severity=Severity.HIGH, confidence=0.8, port=22, at=T0 + timedelta(seconds=2)
            ),
            RiskContext(
                intel_score=0.5, intel_sources=("feed",), allowlisted=True, correlated_detectors=1
            ),
        )
        assert set(assessment.contributions) == {
            "severity",
            "confidence",
            "frequency",
            "history",
            "correlation",
            "threat_intel",
            "sensitive_target",
            "previous_responses",
            "allowlist",
        }
        assert_explained(assessment)
        text = assessment.explain()
        assert text.startswith(f"Risk {assessment.score:.0f}/100") and "ssh_brute_force" in text

    def test_capped_scores_say_so(self) -> None:
        assessment = score(
            detection(severity=Severity.CRITICAL, confidence=1.0, port=22),
            RiskContext(intel_score=1.0, correlated_detectors=3),
        )
        assert assessment.score == 100.0
        assert assessment.rationale[-1].startswith("score capped at 100 (uncapped total 105.0)")
        assert_explained(assessment)

    def test_assessment_timestamp_does_not_depend_on_detection_order(self) -> None:
        later = detection(at=T0 + timedelta(days=1))
        engine = RiskEngine()
        engine.assess(later)
        # An older (out-of-order) detection is scored, not rejected, and stays bounded.
        earlier = engine.assess(replace(later, timestamp=T0, detection_id="older"))
        assert 0 <= earlier.score <= 100
