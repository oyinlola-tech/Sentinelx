"""System status, sensors, interfaces, metrics and audit."""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response

from sentinelx import __version__
from sentinelx.api.schemas import SensorStartRequest
from sentinelx.api.security import Admin, Analyst, PlatformDep, Viewer, client_ip
from sentinelx.common.enums import UserRole
from sentinelx.common.netutils import parse_ip
from sentinelx.services.platform import without_location
from sentinelx.telemetry.metrics import render_metrics

router = APIRouter()


@router.get("/system/health", tags=["system"], summary="Unauthenticated liveness probe")
async def health(platform: PlatformDep) -> dict[str, Any]:
    # Deliberately minimal: an unauthenticated endpoint must not disclose topology.
    report = await platform.health()
    return {"status": report["status"], "version": __version__}


@router.get("/system/status", tags=["system"])
async def status(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    report = dict(await platform.health())  # the report is cached and shared: copy it
    if not principal.can(UserRole.ADMIN):
        # Where the database lives (a file path, or host and user) is for administrators.
        report["components"] = {
            **report["components"],
            "database": without_location(report["components"]["database"]),
        }
    pipeline, _, _, _ = platform.require()
    report["pipeline"] = pipeline.status()
    report["bootstrap_admin_pending"] = platform.bootstrap_password is not None
    return report


@router.get(
    "/system/capabilities",
    tags=["system"],
    summary="What this host can do: live capture, PCAP replay, firewall control, blocking",
)
async def capabilities(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    return await platform.capabilities()


@router.get("/sensors", tags=["sensors"])
async def sensors(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    _, sensor, _, _ = platform.require()
    return [sensor.status()]


@router.get("/interfaces", tags=["sensors"])
async def interfaces(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    _, sensor, _, _ = platform.require()
    return sensor.interfaces()


@router.post("/sensors/start", tags=["sensors"], summary="Start live capture")
async def start_sensor(
    body: SensorStartRequest, principal: Admin, request: Request, platform: PlatformDep
) -> dict[str, Any]:
    _, sensor, _, _ = platform.require()
    interface = body.interface or platform.settings.capture.interface
    try:
        result = await sensor.start(interface, body.bpf_filter)
    except Exception as exc:
        await platform.audit.record(
            actor=principal.username,
            action="START_CAPTURE",
            target=interface,
            source="api",
            outcome="failure",
            client_ip=client_ip(request),
            reason=str(exc),
        )
        raise
    await platform.audit.record(
        actor=principal.username,
        action="START_CAPTURE",
        target=interface,
        source="api",
        client_ip=client_ip(request),
        details={"bpf_filter": body.bpf_filter},
    )
    return result


@router.post("/sensors/stop", tags=["sensors"])
async def stop_sensor(principal: Admin, request: Request, platform: PlatformDep) -> dict[str, Any]:
    _, sensor, _, _ = platform.require()
    result = await sensor.stop()
    await platform.audit.record(
        actor=principal.username,
        action="STOP_CAPTURE",
        target=result.get("interface"),
        source="api",
        client_ip=client_ip(request),
    )
    return result


@router.get(
    "/metrics", tags=["metrics"], summary="Prometheus exposition format", response_class=Response
)
async def prometheus(request: Request, platform: PlatformDep) -> Response:
    if not platform.settings.telemetry.metrics_enabled:
        raise HTTPException(status_code=404, detail="metrics are disabled")
    token = platform.settings.api.metrics_token
    if token:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        # Compare the raw header bytes (Starlette decodes headers as Latin-1) with the
        # UTF-8 token: str comparison raises on non-ASCII input.
        if not hmac.compare_digest(supplied.encode("latin-1"), token.encode()):
            raise HTTPException(status_code=401, detail="metrics token required")
    else:
        # Without a token, only a scraper on this host may read metrics. A request that
        # arrived through a proxy (the dashboard's /api rewrite, nginx) also appears to
        # come from loopback, so any forwarding header disqualifies it.
        forwarded = any(
            name in request.headers for name in ("x-forwarded-for", "forwarded", "x-real-ip")
        )
        try:
            loopback = not forwarded and parse_ip(client_ip(request)).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise HTTPException(
                status_code=403,
                detail="set API__METRICS_TOKEN to expose metrics to remote scrapers",
            )
    return Response(render_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/metrics/summary", tags=["metrics"])
async def metrics_summary(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    pipeline, sensor, _, _ = platform.require()
    report = pipeline.last_report
    return {
        "process": (await platform.health())["process"],
        "pipeline": {
            "decoder": pipeline.decoder.stats(),
            "features": pipeline.extractor.state(),
            "detection": {
                k: v for k, v in pipeline.detection.stats().items() if k != "per_detector"
            },
        },
        "last_run": report.as_dict() if report else None,
        "capture": sensor.status().get("capture"),
        "event_bus": platform.bus.stats(),
    }


@router.get("/audit", tags=["audit"])
async def audit(
    principal: Analyst,
    platform: PlatformDep,
    actor: str | None = Query(default=None, max_length=64),
    action: str | None = Query(default=None, max_length=64),
    target: str | None = Query(default=None, max_length=512),
    since: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    return await queries.audit(
        actor=actor, action=action, target=target, since=since, limit=limit, offset=offset
    )
