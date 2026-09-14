"""Event correlation.

Folds separate detections into incidents.  Three unrelated-looking alerts - a port
scan, SSH failures, a traffic spike - from one source within minutes are one story,
and reporting them as one incident is both more accurate and less exhausting for
the analyst who has to read them.

Grouping key is the source address by default (optionally the destination too).
An incident stays open while new related detections keep arriving within
``window_seconds`` of the last one.

Incident titles come from **kill-chain patterns**: an ordered table of category
combinations, most specific first.  Reconnaissance followed by credential attacks
is named for what it most plausibly is, rather than just "multiple detections".
The pattern that matched is stored as ``correlation_rule`` so the naming is itself
explainable.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinelx.common.enums import IncidentStatus, RiskBand, Severity, ThreatCategory
from sentinelx.common.models import Detection, Incident, RiskAssessment, new_id
from sentinelx.config.settings import CorrelationSettings
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["PATTERNS", "CorrelationEngine", "CorrelationResult", "IncidentPattern"]

log = get_logger(__name__)

C = ThreatCategory


@dataclass(frozen=True, slots=True)
class IncidentPattern:
    """A named combination of categories that suggests a specific narrative."""

    name: str
    title: str
    summary: str
    requires: frozenset[ThreatCategory]
    min_detections: int = 2
    severity_floor: Severity = Severity.MEDIUM
    risk_bonus: float = 0.0


#: Most specific first; the first pattern whose requirements are met wins.
PATTERNS: tuple[IncidentPattern, ...] = (
    IncidentPattern(
        name="recon_to_credential_attack",
        title="Potential host compromise attempt",
        summary="Reconnaissance followed by credential attacks against the same environment.",
        requires=frozenset({C.RECONNAISSANCE, C.BRUTE_FORCE}),
        severity_floor=Severity.CRITICAL,
        risk_bonus=15.0,
    ),
    IncidentPattern(
        name="known_bad_actor_activity",
        title="Activity from a known-malicious source",
        summary="A source with bad reputation is also exhibiting attack behaviour.",
        requires=frozenset({C.MALICIOUS_REPUTATION}),
        min_detections=2,
        severity_floor=Severity.HIGH,
        risk_bonus=10.0,
    ),
    IncidentPattern(
        name="recon_and_disruption",
        title="Reconnaissance with service disruption",
        summary="A source mapped the network and then generated flood traffic.",
        requires=frozenset({C.RECONNAISSANCE, C.DENIAL_OF_SERVICE}),
        severity_floor=Severity.HIGH,
        risk_bonus=10.0,
    ),
    IncidentPattern(
        name="possible_exfiltration",
        title="Possible data exfiltration",
        summary="Covert-channel indicators together with other suspicious behaviour.",
        requires=frozenset({C.EXFILTRATION}),
        min_detections=2,
        severity_floor=Severity.HIGH,
        risk_bonus=10.0,
    ),
    IncidentPattern(
        name="sustained_brute_force",
        title="Sustained credential attack",
        summary="Repeated credential-guessing activity from one source.",
        requires=frozenset({C.BRUTE_FORCE}),
        severity_floor=Severity.HIGH,
        risk_bonus=5.0,
    ),
    IncidentPattern(
        name="sustained_reconnaissance",
        title="Sustained reconnaissance",
        summary="Multiple scanning techniques used by one source.",
        requires=frozenset({C.RECONNAISSANCE}),
        severity_floor=Severity.MEDIUM,
        risk_bonus=5.0,
    ),
    IncidentPattern(
        name="denial_of_service",
        title="Denial-of-service activity",
        summary="Flooding behaviour sustained across more than one detector.",
        requires=frozenset({C.DENIAL_OF_SERVICE}),
        severity_floor=Severity.HIGH,
        risk_bonus=5.0,
    ),
)

_GENERIC = IncidentPattern(
    name="multiple_detections",
    title="Multiple suspicious detections",
    summary="Several detections from one source within the correlation window.",
    requires=frozenset(),
)


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """What happened to an incident as a result of one detection."""

    incident: Incident
    created: bool
    severity_changed: bool
    previous_severity: Severity | None = None


class CorrelationEngine:
    """Groups detections into incidents.

    Incident risk is derived from the risk assessments passed in with each
    detection, so correlation never recomputes a score.
    """

    def __init__(self, settings: CorrelationSettings | None = None) -> None:
        self.settings = settings or CorrelationSettings()
        self._members: dict[str, list[tuple[Detection, RiskAssessment]]] = {}
        """Incident id -> member detections with their assessments."""
        self._open: dict[str, Incident] = {}
        """Group key -> open incident."""
        self._pending: dict[str, list[tuple[Detection, RiskAssessment]]] = {}
        """Group key -> detections not yet numerous enough for an incident."""
        self.incidents_created = 0

    # ------------------------------------------------------------ correlation

    def correlate(self, detection: Detection, risk: RiskAssessment) -> CorrelationResult | None:
        """Fold a detection in.

        Returns:
            The affected incident, or ``None`` if the detection is still waiting
            for enough related activity to form one.
        """
        if not self.settings.enabled:
            return None
        now = detection.timestamp
        key = self._group_key(detection)
        self._close_expired(now.timestamp())

        incident = self._open.get(key)
        if incident is not None:
            return self._extend(incident, detection, risk)

        pending = self._pending.setdefault(key, [])
        cutoff = now.timestamp() - self.settings.window_seconds
        pending[:] = [(d, r) for d, r in pending if d.timestamp.timestamp() >= cutoff]
        pending.append((detection, risk))

        distinct = {d.detector for d, _ in pending}
        # An incident needs corroboration: either several distinct detectors, or
        # a single detection severe enough to warrant one on its own.
        standalone = (
            risk.score >= self.settings.standalone_risk_threshold
            and detection.severity is Severity.CRITICAL
        )
        if len(distinct) < self.settings.min_detections and not standalone:
            return None

        incident = self._create(key, pending)
        del self._pending[key]
        return CorrelationResult(incident=incident, created=True, severity_changed=False)

    def _group_key(self, detection: Detection) -> str:
        parts: list[str] = []
        if self.settings.group_by_source:
            parts.append(detection.source_ip)
        if self.settings.group_by_destination:
            parts.append(detection.destination_ip or "*")
        return "|".join(parts) or detection.source_ip

    def _create(self, key: str, members: list[tuple[Detection, RiskAssessment]]) -> Incident:
        if len(self._open) >= self.settings.max_open_incidents:
            oldest = min(self._open, key=lambda k: self._open[k].last_seen)
            self._close(oldest, IncidentStatus.OPEN, reason="capacity")

        detections = [d for d, _ in members]
        categories = {d.category for d in detections}
        pattern = self._match(categories, len(detections))
        severity = self._severity(detections, pattern)
        risk = self._risk(members, pattern)

        incident = Incident(
            incident_id=new_id(),
            title=pattern.title,
            summary=self._summary(pattern, detections),
            severity=severity,
            risk=risk,
            detection_ids=[d.detection_id for d in detections],
            affected_sources={d.source_ip for d in detections},
            affected_destinations={d.destination_ip for d in detections if d.destination_ip},
            affected_services={d.destination_port for d in detections if d.destination_port},
            categories=categories,
            first_seen=min(d.timestamp for d in detections),
            last_seen=max(d.timestamp for d in detections),
            correlation_rule=pattern.name,
            timeline=[self._timeline_entry(d, r) for d, r in members],
        )
        incident.timeline.sort(key=lambda entry: str(entry["timestamp"]))
        self._open[key] = incident
        self._members[incident.incident_id] = list(members)
        self.incidents_created += 1
        metrics.incidents_opened.labels(severity=severity.value).inc()
        metrics.open_incidents.set(len(self._open))
        log.info(
            "incident_opened",
            incident=incident.incident_id,
            title=incident.title,
            risk=risk.score,
            detections=incident.detection_count,
            rule=pattern.name,
        )
        return incident

    def _extend(
        self, incident: Incident, detection: Detection, risk: RiskAssessment
    ) -> CorrelationResult:
        members = self._members.setdefault(incident.incident_id, [])
        members.append((detection, risk))
        previous = incident.severity

        incident.detection_ids.append(detection.detection_id)
        incident.affected_sources.add(detection.source_ip)
        if detection.destination_ip:
            incident.affected_destinations.add(detection.destination_ip)
        if detection.destination_port:
            incident.affected_services.add(detection.destination_port)
        incident.categories.add(detection.category)
        incident.last_seen = max(incident.last_seen, detection.timestamp)
        incident.timeline.append(self._timeline_entry(detection, risk))

        detections = [d for d, _ in members]
        pattern = self._match(incident.categories, len(detections))
        incident.title = pattern.title
        incident.correlation_rule = pattern.name
        incident.summary = self._summary(pattern, detections)
        incident.severity = max(self._severity(detections, pattern), previous, key=lambda s: s.rank)
        incident.risk = self._risk(members, pattern)

        changed = incident.severity is not previous
        if changed:
            log.info(
                "incident_escalated",
                incident=incident.incident_id,
                previous=previous.value,
                severity=incident.severity.value,
            )
        return CorrelationResult(
            incident=incident,
            created=False,
            severity_changed=changed,
            previous_severity=previous if changed else None,
        )

    # --------------------------------------------------------------- analysis

    def _match(self, categories: set[ThreatCategory], count: int) -> IncidentPattern:
        for pattern in PATTERNS:
            if pattern.requires <= categories and count >= pattern.min_detections:
                return pattern
        return _GENERIC

    @staticmethod
    def _severity(detections: list[Detection], pattern: IncidentPattern) -> Severity:
        highest = max((d.severity for d in detections), key=lambda s: s.rank)
        return highest if highest.rank >= pattern.severity_floor.rank else pattern.severity_floor

    def _risk(
        self, members: list[tuple[Detection, RiskAssessment]], pattern: IncidentPattern
    ) -> RiskAssessment:
        """Incident risk: the worst member, plus corroboration, plus pattern bonus.

        Taking the maximum rather than the mean keeps one critical detection from
        being diluted by several minor ones that happened to arrive with it.
        """
        worst_detection, worst = max(members, key=lambda pair: pair[1].score)
        distinct_detectors = {d.detector for d, _ in members}
        distinct_categories = {d.category for d, _ in members}

        contributions = {"highest_detection": worst.score}
        rationale = [f"{worst.score:.1f} highest member risk ({worst_detection.title})"]

        corroboration = min(4.0 * (len(distinct_detectors) - 1), 12.0)
        if corroboration:
            contributions["corroboration"] = corroboration
            rationale.append(
                f"+{corroboration:.1f} {len(distinct_detectors)} distinct detectors agree"
            )

        breadth = min(3.0 * (len(distinct_categories) - 1), 9.0)
        if breadth:
            contributions["category_breadth"] = breadth
            rationale.append(
                f"+{breadth:.1f} spans {len(distinct_categories)} categories: "
                f"{', '.join(sorted(c.value for c in distinct_categories))}"
            )

        if pattern.risk_bonus:
            contributions["pattern"] = pattern.risk_bonus
            rationale.append(f"+{pattern.risk_bonus:.1f} matches pattern '{pattern.name}'")

        raw = sum(contributions.values())
        score = round(max(0.0, min(100.0, raw)), 1)
        if raw > 100:
            rationale.append(f"capped at 100 (uncapped {raw:.1f})")
        return RiskAssessment(
            score=score,
            band=RiskBand.from_score(score),
            contributions={k: round(v, 2) for k, v in contributions.items()},
            rationale=rationale,
        )

    @staticmethod
    def _summary(pattern: IncidentPattern, detections: list[Detection]) -> str:
        sources = sorted({d.source_ip for d in detections})
        services = sorted({d.destination_port for d in detections if d.destination_port})
        titles = sorted({d.title for d in detections})
        source_text = sources[0] if len(sources) == 1 else f"{len(sources)} sources"
        service_text = f" against {len(services)} service(s)" if services else ""
        return (
            f"{pattern.summary} {len(detections)} detection(s) from {source_text}{service_text}: "
            f"{'; '.join(titles)}."
        )

    @staticmethod
    def _timeline_entry(detection: Detection, risk: RiskAssessment) -> dict[str, object]:
        return {
            "timestamp": detection.timestamp.isoformat(),
            "detection_id": detection.detection_id,
            "detector": detection.detector,
            "title": detection.title,
            "severity": detection.severity.value,
            "risk": risk.score,
            "source_ip": detection.source_ip,
            "destination_ip": detection.destination_ip,
            "destination_port": detection.destination_port,
        }

    # -------------------------------------------------------------- lifecycle

    def _close_expired(self, now: float) -> None:
        window = self.settings.window_seconds
        for key in [k for k, inc in self._open.items() if now - inc.last_seen.timestamp() > window]:
            self._close(key, IncidentStatus.OPEN, reason="window_elapsed")

    def _close(self, key: str, status: IncidentStatus, *, reason: str) -> None:
        """Stop correlating into an incident.

        The incident's *status* is an analyst decision and is left untouched:
        "no longer receiving detections" is not "resolved".
        """
        incident = self._open.pop(key, None)
        if incident is None:
            return
        self._members.pop(incident.incident_id, None)
        metrics.open_incidents.set(len(self._open))
        log.debug(
            "incident_correlation_closed",
            incident=incident.incident_id,
            reason=reason,
            status=status.value,
        )

    def open_incidents(self) -> list[Incident]:
        return sorted(self._open.values(), key=lambda inc: inc.risk.score, reverse=True)

    def correlated_detector_count(self, detection: Detection) -> int:
        """Distinct *other* detectors already in this detection's open incident or pending group."""
        key = self._group_key(detection)
        incident = self._open.get(key)
        if incident is not None:
            names = {d.detector for d, _ in self._members.get(incident.incident_id, [])}
        else:
            names = {d.detector for d, _ in self._pending.get(key, [])}
        names.discard(detection.detector)
        return len(names)

    def reset(self) -> None:
        self._open.clear()
        self._pending.clear()
        self._members.clear()
        self.incidents_created = 0
        metrics.open_incidents.set(0)
