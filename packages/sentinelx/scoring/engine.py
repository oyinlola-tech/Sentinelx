"""Centralised risk scoring.

Turns a detection plus its context into a 0-100 score with a written rationale.

The score is an **additive, clamped, weighted sum**.  That was chosen over a
multiplicative or learned model because every point can be traced to a named
factor.  An analyst who disagrees with a score can see exactly which factor to
argue with, and an operator can re-weight a factor in configuration without
retraining anything.

Factors (weights in :class:`~sentinelx.config.settings.ScoringSettings`):

========================  ==================================================
severity                  detector's severity, 0-4 scaled onto its weight
confidence                how sure the detector is, 0-1
frequency                 repeats of this detector for this source
history                   other detections for this source in the last hour
threat intelligence       reputation verdict from intel providers
correlation               how many distinct detectors agree on this source
sensitive target          destination is a high-value service port
allowlist (negative)      source is allowlisted but was still detected
previous responses        source was already blocked or rate limited before
========================  ==================================================
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from sentinelx.common.enums import RiskBand, Severity
from sentinelx.common.models import Detection, RiskAssessment
from sentinelx.common.netutils import SENSITIVE_PORTS, service_name
from sentinelx.config.settings import ScoringSettings

__all__ = ["RiskContext", "RiskEngine", "SourceHistory"]


@dataclass(slots=True)
class SourceHistory:
    """What the risk engine remembers about one source."""

    detections: deque[tuple[float, str, int]] = field(default_factory=lambda: deque(maxlen=500))
    """(epoch seconds, detector, severity rank) for recent detections."""

    responses: int = 0
    """Preventive actions previously taken against this source."""

    last_score: float = 0.0


@dataclass(frozen=True, slots=True)
class RiskContext:
    """External facts about a detection that the engine cannot infer on its own."""

    intel_score: float = 0.0
    """0-1 reputation badness from threat-intel providers."""

    intel_sources: tuple[str, ...] = ()
    allowlisted: bool = False
    correlated_detectors: int = 0
    """Distinct detectors in the same open incident, excluding this one."""

    sensitive_destinations: frozenset[str] = frozenset()
    """Operator-declared crown-jewel addresses."""


class RiskEngine:
    """Scores detections and remembers per-source history.

    Example:
        >>> engine = RiskEngine(ScoringSettings())
        >>> assessment = engine.assess(detection)
        >>> assessment.score, assessment.band
        (91.0, <RiskBand.CRITICAL: 'critical'>)
        >>> print(assessment.explain())
    """

    def __init__(self, settings: ScoringSettings | None = None, max_sources: int = 50_000) -> None:
        self.settings = settings or ScoringSettings()
        self._history: dict[str, SourceHistory] = {}
        self._max_sources = max_sources

    def assess(self, detection: Detection, context: RiskContext | None = None) -> RiskAssessment:
        """Score a detection and record it in the source's history.

        Recording happens *after* scoring, so a detection never counts as its own
        history.
        """
        context = context or RiskContext()
        s = self.settings
        now = detection.timestamp.timestamp()
        history = self._history_for(detection.source_ip)
        self._expire(history, now)

        contributions: dict[str, float] = {}
        rationale: list[str] = []

        # Severity: the detector's own judgement is the foundation.
        severity_points = s.severity_weight * (detection.severity.rank / Severity.CRITICAL.rank)
        contributions["severity"] = severity_points
        rationale.append(
            f"+{severity_points:.1f} severity {detection.severity.value} "
            f"({detection.severity.rank}/{Severity.CRITICAL.rank})"
        )

        confidence_points = s.confidence_weight * detection.confidence
        contributions["confidence"] = confidence_points
        rationale.append(f"+{confidence_points:.1f} detector confidence {detection.confidence:.0%}")

        same_detector = sum(1 for _, name, _ in history.detections if name == detection.detector)
        if same_detector:
            points = s.frequency_weight * min(same_detector / s.frequency_saturation, 1.0)
            contributions["frequency"] = points
            rationale.append(
                f"+{points:.1f} repetition: {detection.detector} already fired "
                f"{same_detector} time(s) for this source"
            )

        other_detectors = {name for _, name, _ in history.detections if name != detection.detector}
        if other_detectors:
            points = s.history_weight * min(len(other_detectors) / s.history_saturation, 1.0)
            contributions["history"] = points
            rationale.append(
                f"+{points:.1f} source history: previously triggered "
                f"{', '.join(sorted(other_detectors))}"
            )

        if context.correlated_detectors:
            points = s.correlation_weight * min(context.correlated_detectors / 3, 1.0)
            contributions["correlation"] = points
            rationale.append(
                f"+{points:.1f} correlated with {context.correlated_detectors} other "
                f"detector(s) in an open incident"
            )

        if context.intel_score > 0:
            points = s.intel_weight * context.intel_score
            contributions["threat_intel"] = points
            sources = f" ({', '.join(context.intel_sources)})" if context.intel_sources else ""
            rationale.append(f"+{points:.1f} threat intelligence reputation {context.intel_score:.0%}{sources}")

        port = detection.destination_port
        if (port is not None and port in SENSITIVE_PORTS) or (
            detection.destination_ip in context.sensitive_destinations
        ):
            points = s.sensitive_target_weight
            contributions["sensitive_target"] = points
            label = (
                f"port {port} ({service_name(port) or 'unknown'})"
                if port in SENSITIVE_PORTS
                else f"host {detection.destination_ip}"
            )
            rationale.append(f"+{points:.1f} sensitive target: {label}")

        if history.responses:
            points = min(5.0 * history.responses, 10.0)
            contributions["previous_responses"] = points
            rationale.append(
                f"+{points:.1f} source was already the subject of {history.responses} "
                f"preventive response(s) and returned"
            )

        if context.allowlisted:
            contributions["allowlist"] = -s.allowlist_penalty
            rationale.append(f"-{s.allowlist_penalty:.1f} source is allowlisted")

        raw = sum(contributions.values())
        score = round(max(0.0, min(100.0, raw)), 1)
        if raw > 100:
            rationale.append(f"score capped at 100 (uncapped total {raw:.1f})")

        history.detections.append((now, detection.detector, detection.severity.rank))
        history.last_score = score

        return RiskAssessment(
            score=score,
            band=RiskBand.from_score(score),
            contributions={k: round(v, 2) for k, v in contributions.items()},
            rationale=rationale,
        )

    # ---------------------------------------------------------------- history

    def record_response(self, source_ip: str) -> None:
        """Note that a preventive action was taken, for future scoring."""
        self._history_for(source_ip).responses += 1

    def source_summary(self, source_ip: str) -> dict[str, object]:
        history = self._history.get(source_ip)
        if history is None:
            return {"source_ip": source_ip, "detections": 0, "responses": 0, "last_score": 0.0}
        return {
            "source_ip": source_ip,
            "detections": len(history.detections),
            "detectors": sorted({name for _, name, _ in history.detections}),
            "responses": history.responses,
            "last_score": history.last_score,
        }

    def _history_for(self, source_ip: str) -> SourceHistory:
        history = self._history.get(source_ip)
        if history is None:
            if len(self._history) >= self._max_sources:
                # Oldest-inserted first; history is advisory, so losing the
                # coldest entries under pressure is acceptable.
                for key in list(self._history)[: self._max_sources // 10]:
                    del self._history[key]
            history = SourceHistory()
            self._history[source_ip] = history
        return history

    def _expire(self, history: SourceHistory, now: float) -> None:
        cutoff = now - self.settings.history_window_seconds
        while history.detections and history.detections[0][0] < cutoff:
            history.detections.popleft()

    def reset(self) -> None:
        self._history.clear()
