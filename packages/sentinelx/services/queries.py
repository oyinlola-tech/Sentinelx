"""Read models for the API and CLI.

Joins stored history (database) with live state (the running pipeline) into the
shapes the dashboard renders.  No detection logic lives here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sentinelx.pipeline import Pipeline
from sentinelx.storage.audit import audit_to_dict
from sentinelx.storage.database import Database
from sentinelx.storage.models import (
    BlockRecord,
    DetectionRecord,
    IncidentRecord,
    ResponseActionRecord,
)
from sentinelx.storage.repositories import (
    AnalyticsRepository,
    AuditRepository,
    BlockRepository,
    DetectionFilter,
    DetectionRepository,
    IncidentRepository,
    Page,
    ResponseActionRepository,
    TelemetryRepository,
)

__all__ = [
    "QueryService",
    "action_to_dict",
    "block_to_dict",
    "detection_record_to_dict",
    "incident_record_to_dict",
    "page_to_dict",
]


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


def detection_record_to_dict(record: DetectionRecord) -> dict[str, Any]:
    return {
        "detection_id": record.detection_id,
        "timestamp": _iso(record.timestamp),
        "detector": record.detector,
        "rule_name": record.rule_name,
        "category": record.category,
        "severity": record.severity,
        "confidence": record.confidence,
        "title": record.title,
        "description": record.description,
        "source_ip": record.source_ip,
        "destination_ip": record.destination_ip,
        "source_port": record.source_port,
        "destination_port": record.destination_port,
        "protocol": record.protocol,
        "evidence": record.evidence,
        "recommended_action": record.recommended_action,
        "risk": record.risk or {"score": record.risk_score, "band": record.risk_band, "contributions": {}, "rationale": []},
        "observation_window_seconds": record.observation_window_seconds,
        "packet_count": record.packet_count,
        "tags": record.tags,
        "incident_id": record.incident_id,
        "status": record.status,
        "reviewed_by": record.reviewed_by,
        "reviewed_at": _iso(record.reviewed_at),
        "replay_id": record.replay_id,
    }


def incident_record_to_dict(record: IncidentRecord) -> dict[str, Any]:
    return {
        "incident_id": record.incident_id,
        "title": record.title,
        "summary": record.summary,
        "severity": record.severity,
        "status": record.status,
        "risk": record.risk,
        "categories": record.categories,
        "affected_sources": record.affected_sources,
        "affected_destinations": record.affected_destinations,
        "affected_services": record.affected_services,
        "correlation_rule": record.correlation_rule,
        "detection_count": record.detection_count,
        "timeline": record.timeline,
        "first_seen": _iso(record.first_seen),
        "last_seen": _iso(record.last_seen),
        "assigned_to": record.assigned_to,
        "notes": record.notes,
        "replay_id": record.replay_id,
        "updated_at": _iso(record.updated_at),
    }


def action_to_dict(record: ResponseActionRecord) -> dict[str, Any]:
    return {
        "decision_id": record.decision_id,
        "decided_at": _iso(record.decided_at),
        "action": record.action,
        "target": record.target,
        "reason": record.reason,
        "outcome": record.outcome,
        "executed": record.executed,
        "dry_run": record.dry_run,
        "requires_approval": record.requires_approval,
        "duration_seconds": record.duration_seconds,
        "detection_id": record.detection_id,
        "incident_id": record.incident_id,
        "error": record.error,
    }


def block_to_dict(record: BlockRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "network": record.network,
        "created_at": _iso(record.created_at),
        "expires_at": _iso(record.expires_at),
        "removed_at": _iso(record.removed_at),
        "active": record.active,
        "rate_limited": record.rate_limited,
        "reason": record.reason,
        "removal_reason": record.removal_reason,
        "backend": record.backend,
    }


def page_to_dict(page: Page[Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"items": items, "total": page.total, "limit": page.limit, "offset": page.offset}


class QueryService:
    def __init__(self, database: Database, pipeline: Pipeline) -> None:
        self.database = database
        self.pipeline = pipeline

    # ----------------------------------------------------------- detections

    async def detections(self, filters: DetectionFilter, *, limit: int, offset: int, order: str) -> dict[str, Any]:
        async with self.database.session() as session:
            page = await DetectionRepository(session).page(filters, limit=limit, offset=offset, order=order)
        return page_to_dict(page, [detection_record_to_dict(r) for r in page.items])

    async def detection(self, detection_id: str) -> dict[str, Any] | None:
        async with self.database.session() as session:
            record = await DetectionRepository(session).get(detection_id)
            if record is None:
                return None
            actions = await ResponseActionRepository(session).page(detection_id=detection_id)
        data = detection_record_to_dict(record)
        data["actions"] = [action_to_dict(a) for a in actions.items]
        return data

    async def set_detection_status(self, detection_id: str, status: str, reviewer: str) -> dict[str, Any] | None:
        async with self.database.session() as session:
            record = await DetectionRepository(session).set_status(detection_id, status, reviewer)
            return detection_record_to_dict(record) if record else None

    # ------------------------------------------------------------ incidents

    async def incidents(self, **filters: Any) -> dict[str, Any]:
        async with self.database.session() as session:
            page = await IncidentRepository(session).page(**filters)
        return page_to_dict(page, [incident_record_to_dict(r) for r in page.items])

    async def incident(self, incident_id: str) -> dict[str, Any] | None:
        async with self.database.session() as session:
            repo = IncidentRepository(session)
            record = await repo.get(incident_id)
            if record is None:
                return None
            detections = await repo.detections(incident_id)
            actions = await ResponseActionRepository(session).page(incident_id=incident_id)
            detection_ids = [d.detection_id for d in detections]
            detection_actions: list[ResponseActionRecord] = []
            for detection_id in detection_ids[:50]:
                detection_actions.extend((await ResponseActionRepository(session).page(detection_id=detection_id)).items)
        data = incident_record_to_dict(record)
        data["detections"] = [detection_record_to_dict(d) for d in detections]
        all_actions = {a.decision_id: a for a in [*actions.items, *detection_actions]}
        data["actions"] = [action_to_dict(a) for a in sorted(all_actions.values(), key=lambda a: a.decided_at)]
        top = max(detections, key=lambda d: d.risk_score, default=None)
        data["recommended_action"] = top.recommended_action if top else "alert"
        return data

    async def update_incident(self, incident_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.database.session() as session:
            record = await IncidentRepository(session).get(incident_id)
            if record is None:
                return None
            for key, value in changes.items():
                if value is not None:
                    setattr(record, key, value)
            return incident_record_to_dict(record)

    # ---------------------------------------------------------------- threats

    async def threats(self, *, since: datetime, limit: int = 100) -> list[dict[str, Any]]:
        """Detections grouped by source: the "who is attacking us" view."""
        async with self.database.session() as session:
            page = await DetectionRepository(session).page(DetectionFilter(since=since), limit=500, order="risk")
            active_blocks = {b.network for b in await BlockRepository(session).active()}
        grouped: dict[str, dict[str, Any]] = {}
        for record in page.items:
            entry = grouped.setdefault(record.source_ip, {
                "source_ip": record.source_ip, "detections": 0, "max_risk": 0.0, "severities": {}, "categories": set(),
                "detectors": set(), "destinations": set(), "first_seen": record.timestamp, "last_seen": record.timestamp,
                "top_detection": detection_record_to_dict(record), "incident_ids": set(), "statuses": {},
            })
            entry["detections"] += 1
            entry["max_risk"] = max(entry["max_risk"], record.risk_score)
            entry["severities"][record.severity] = entry["severities"].get(record.severity, 0) + 1
            entry["statuses"][record.status] = entry["statuses"].get(record.status, 0) + 1
            entry["categories"].add(record.category)
            entry["detectors"].add(record.detector)
            if record.destination_ip:
                entry["destinations"].add(record.destination_ip)
            if record.incident_id:
                entry["incident_ids"].add(record.incident_id)
            entry["first_seen"] = min(entry["first_seen"], record.timestamp)
            entry["last_seen"] = max(entry["last_seen"], record.timestamp)
        output = []
        for entry in grouped.values():
            output.append({
                **entry,
                "categories": sorted(entry["categories"]),
                "detectors": sorted(entry["detectors"]),
                "destinations": sorted(entry["destinations"])[:20],
                "incident_ids": sorted(entry["incident_ids"]),
                "first_seen": _iso(entry["first_seen"]),
                "last_seen": _iso(entry["last_seen"]),
                "blocked": f"{entry['source_ip']}/32" in active_blocks or f"{entry['source_ip']}/128" in active_blocks,
                "history": self.pipeline.risk.source_summary(entry["source_ip"]),
            })
        output.sort(key=lambda item: item["max_risk"], reverse=True)
        return output[:limit]

    # --------------------------------------------------------------- firewall

    async def firewall(self) -> dict[str, Any]:
        response = self.pipeline.response
        live = await response.blocked(refresh=True)
        async with self.database.session() as session:
            history = await BlockRepository(session).history(limit=200)
            actions = await ResponseActionRepository(session).page(limit=200)
        return {
            "status": response.status(),
            "health": await response.firewall.health(),
            "active": [entry.as_dict() for entry in live],
            "history": [block_to_dict(r) for r in history.items],
            "actions": [action_to_dict(a) for a in actions.items],
            "pending_approvals": [p.as_dict() for p in response.pending.values()],
        }

    async def actions(self, **filters: Any) -> dict[str, Any]:
        async with self.database.session() as session:
            page = await ResponseActionRepository(session).page(**filters)
        return page_to_dict(page, [action_to_dict(a) for a in page.items])

    # ---------------------------------------------------------------- network

    async def network(self) -> dict[str, Any]:
        extractor = self.pipeline.extractor
        async with self.database.session() as session:
            summaries = await TelemetryRepository(session).summaries(datetime.now(UTC) - timedelta(hours=24))
        return {
            "state": extractor.state(),
            "top_sources": extractor.top_sources(15),
            "top_destinations": extractor.top_destinations(15),
            "protocols": extractor.stats.protocol_distribution(),
            "traffic": [
                {"bucket_start": _iso(s.bucket_start), "packets": s.packets, "bytes": s.bytes_total,
                 "packets_per_second": s.packets_per_second, "detections": s.detections, "protocols": s.protocols}
                for s in summaries
            ],
        }

    # -------------------------------------------------------------- analytics

    async def analytics(self, *, hours: int) -> dict[str, Any]:
        since = datetime.now(UTC) - timedelta(hours=hours)
        bucket = 5 if hours <= 6 else 60 if hours <= 72 else 360
        async with self.database.session() as session:
            repo = AnalyticsRepository(session)
            summary = await repo.summary(since)
            timeline = await repo.timeline(since, bucket, self.database.dialect)
            metrics = await TelemetryRepository(session).metrics(since)
        detection = self.pipeline.detection.stats()
        return {
            **summary,
            "hours": hours,
            "bucket_minutes": bucket,
            "timeline": timeline,
            "detector_performance": detection["per_detector"],
            "engine": {k: v for k, v in detection.items() if k != "per_detector"},
            "system": [
                {"timestamp": _iso(m.timestamp), "cpu_percent": m.cpu_percent, "memory_bytes": m.memory_bytes,
                 "packets_processed": m.packets_processed, "packets_dropped": m.packets_dropped}
                for m in metrics[-500:]
            ],
        }

    async def overview(self) -> dict[str, Any]:
        pipeline = self.pipeline
        since = datetime.now(UTC) - timedelta(hours=24)
        async with self.database.session() as session:
            summary = await AnalyticsRepository(session).summary(since)
            open_incidents = await IncidentRepository(session).page(statuses=["open", "investigating"], limit=5)
            critical = await IncidentRepository(session).page(statuses=["open", "investigating"], severities=["critical"], limit=1)
            recent = await DetectionRepository(session).page(DetectionFilter(), limit=8)
        report = pipeline.last_report
        stats = pipeline.extractor.stats
        top_risk = max((i.risk_score for i in open_incidents.items), default=0.0)
        return {
            "packets_processed": stats.packets,
            "bytes_processed": stats.bytes_total,
            "packets_per_second": round(report.packets_per_second, 1) if report and report.finished_at is None else None,
            "active_flows": len(pipeline.extractor.flows),
            "tracked_sources": len(pipeline.extractor.profiles),
            "detections_24h": summary["detections"],
            "by_severity_24h": summary["by_severity"],
            "open_incidents": open_incidents.total,
            "critical_incidents": critical.total,
            "blocked_sources": len(await pipeline.response.blocked()),
            "pending_approvals": len(pipeline.response.pending),
            "current_risk": top_risk,
            "top_incidents": [incident_record_to_dict(i) for i in open_incidents.items],
            "recent_detections": [detection_record_to_dict(d) for d in recent.items],
            "protocols": stats.protocol_distribution(),
        }

    async def audit(self, **filters: Any) -> dict[str, Any]:
        async with self.database.session() as session:
            page = await AuditRepository(session).page(**filters)
        return page_to_dict(page, [audit_to_dict(e) for e in page.items])
