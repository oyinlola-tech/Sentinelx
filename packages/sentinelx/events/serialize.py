"""Canonical JSON shapes for domain objects.

One function per object, used by the event bus, storage, the REST API and the CLI
``--json`` output alike.  Having exactly one serialiser is what keeps the
dashboard's TypeScript types (``apps/dashboard/src/lib/types.ts``) honest: there is
no second, subtly different shape to drift from.
"""

from __future__ import annotations

from typing import Any

from sentinelx.common.models import Detection, Incident, RiskAssessment

__all__ = ["detection_to_dict", "incident_to_dict", "risk_to_dict"]


def risk_to_dict(risk: RiskAssessment) -> dict[str, Any]:
    return {
        "score": risk.score,
        "band": risk.band.value,
        "contributions": risk.contributions,
        "rationale": risk.rationale,
        "assessed_at": risk.assessed_at.isoformat(),
    }


def detection_to_dict(detection: Detection, risk: RiskAssessment | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "detection_id": detection.detection_id,
        "detector": detection.detector,
        "rule_name": detection.rule_name,
        "category": detection.category.value,
        "severity": detection.severity.value,
        "confidence": detection.confidence,
        "title": detection.title,
        "description": detection.description,
        "source_ip": detection.source_ip,
        "destination_ip": detection.destination_ip,
        "source_port": detection.source_port,
        "destination_port": detection.destination_port,
        "protocol": detection.protocol.value if detection.protocol else None,
        "evidence": [item.as_dict() for item in detection.evidence],
        "recommended_action": detection.recommended_action.value,
        "recommended_duration_seconds": detection.recommended_duration_seconds,
        "observation_window_seconds": detection.observation_window_seconds,
        "packet_count": detection.packet_count,
        "tags": list(detection.tags),
        "timestamp": detection.timestamp.isoformat(),
    }
    if risk is not None:
        data["risk"] = risk_to_dict(risk)
    return data


def incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "risk": risk_to_dict(incident.risk),
        "detection_ids": list(incident.detection_ids),
        "detection_count": incident.detection_count,
        "affected_sources": sorted(incident.affected_sources),
        "affected_destinations": sorted(incident.affected_destinations),
        "affected_services": sorted(incident.affected_services),
        "categories": sorted(c.value for c in incident.categories),
        "correlation_rule": incident.correlation_rule,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "duration_seconds": round(incident.duration_seconds, 3),
        "timeline": incident.timeline,
    }
