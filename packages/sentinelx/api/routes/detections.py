"""Detections, incidents, alerts and threats."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request

from sentinelx.api.schemas import DetectionStatusRequest, IncidentUpdateRequest
from sentinelx.api.security import Analyst, PlatformDep, Viewer, client_ip
from sentinelx.common.enums import IncidentStatus, Severity, ThreatCategory
from sentinelx.events.bus import EventType
from sentinelx.storage.repositories import DetectionFilter

router = APIRouter()

SeverityList = list[Severity]


@router.get("/detections", tags=["detections"])
async def list_detections(
    principal: Viewer,
    platform: PlatformDep,
    severity: SeverityList = Query(default=[]),
    detector: list[str] = Query(default=[], max_length=50),
    category: list[ThreatCategory] = Query(default=[]),
    status: list[Literal["new", "acknowledged", "false_positive", "resolved"]] = Query(default=[]),
    source_ip: str | None = Query(default=None, max_length=64),
    destination_ip: str | None = Query(default=None, max_length=64),
    protocol: str | None = Query(default=None, max_length=16),
    incident_id: str | None = Query(default=None, max_length=64),
    replay_id: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    min_risk: float | None = Query(default=None, ge=0, le=100),
    q: str | None = Query(default=None, max_length=200, description="Free-text search"),
    order: Literal["newest", "oldest", "risk"] = "newest",
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    filters = DetectionFilter(
        severities=[s.value for s in severity],
        detectors=detector,
        categories=[c.value for c in category],
        statuses=list(status),
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        incident_id=incident_id,
        replay_id=replay_id,
        since=since,
        until=until,
        min_risk=min_risk,
        search=q,
    )
    return await queries.detections(filters, limit=limit, offset=offset, order=order)


@router.get("/detections/{detection_id}", tags=["detections"])
async def get_detection(
    detection_id: str, principal: Viewer, platform: PlatformDep
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    detection = await queries.detection(detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="detection not found")
    return detection


@router.patch(
    "/detections/{detection_id}",
    tags=["detections"],
    summary="Triage: acknowledge, resolve or mark false positive",
)
async def update_detection(
    detection_id: str,
    body: DetectionStatusRequest,
    principal: Analyst,
    request: Request,
    platform: PlatformDep,
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    detection = await queries.set_detection_status(detection_id, body.status, principal.username)
    if detection is None:
        raise HTTPException(status_code=404, detail="detection not found")
    await platform.audit.record(
        actor=principal.username,
        action="TRIAGE_DETECTION",
        target=detection_id,
        source="api",
        client_ip=client_ip(request),
        details={"status": body.status},
    )
    return detection


@router.get("/incidents", tags=["incidents"])
async def list_incidents(
    principal: Viewer,
    platform: PlatformDep,
    status: list[IncidentStatus] = Query(default=[]),
    severity: SeverityList = Query(default=[]),
    min_risk: float | None = Query(default=None, ge=0, le=100),
    replay_id: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    return await queries.incidents(
        statuses=[s.value for s in status],
        severities=[s.value for s in severity],
        min_risk=min_risk,
        replay_id=replay_id,
        since=since,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}", tags=["incidents"])
async def get_incident(
    incident_id: str, principal: Viewer, platform: PlatformDep
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    incident = await queries.incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.patch("/incidents/{incident_id}", tags=["incidents"])
async def update_incident(
    incident_id: str,
    body: IncidentUpdateRequest,
    principal: Analyst,
    request: Request,
    platform: PlatformDep,
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    changes = body.model_dump(exclude_none=True, mode="json")
    if not changes:
        raise HTTPException(status_code=422, detail="no changes supplied")
    incident = await queries.update_incident(incident_id, **changes)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    await platform.audit.record(
        actor=principal.username,
        action="UPDATE_INCIDENT",
        target=incident_id,
        source="api",
        client_ip=client_ip(request),
        details={k: v for k, v in changes.items() if k != "notes"}
        | ({"notes_changed": True} if "notes" in changes else {}),
    )
    # Other open dashboards refresh the incident instead of showing a stale status.
    await platform.bus.publish(
        EventType.INCIDENT_UPDATED, {**incident, "updated_by": principal.username}
    )
    return incident


@router.get(
    "/alerts",
    tags=["alerts"],
    summary="Items needing attention: high-risk untriaged detections and pending approvals",
)
async def alerts(
    principal: Viewer, platform: PlatformDep, hours: int = Query(default=24, ge=1, le=720)
) -> dict[str, Any]:
    pipeline, _, _, queries = platform.require()
    threshold = platform.settings.response.webhook_min_risk
    detections = await queries.detections(
        DetectionFilter(
            statuses=["new"], min_risk=threshold, since=datetime.now(UTC) - timedelta(hours=hours)
        ),
        limit=100,
        offset=0,
        order="risk",
    )
    return {
        "risk_threshold": threshold,
        "detections": detections,
        "pending_approvals": [p.as_dict() for p in pipeline.response.pending_actions()],
    }


@router.get("/threats", tags=["threats"], summary="Detections grouped by source address")
async def threats(
    principal: Viewer,
    platform: PlatformDep,
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    _, _, _, queries = platform.require()
    return await queries.threats(since=datetime.now(UTC) - timedelta(hours=hours), limit=limit)
