"""Configuration and statistics."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from sentinelx import __version__
from sentinelx.api.schemas import ConfigUpdateRequest
from sentinelx.api.security import Admin, Analyst, PlatformDep, Viewer

router = APIRouter()


@router.get("/config", tags=["config"], summary="Effective settings with secrets removed")
async def get_config(principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    return platform.config.view()


@router.patch("/config/{section}", tags=["config"], summary="Change runtime-editable settings")
async def update_config(
    section: str,
    body: ConfigUpdateRequest,
    principal: Admin,
    request: Request,
    platform: PlatformDep,
) -> dict[str, Any]:
    source = "dashboard" if request.headers.get("x-sentinelx-client") == "dashboard" else "api"
    return await platform.config.update(
        section,
        body.changes,
        actor=principal.username,
        source=source,
        confirmation=body.confirmation,
    )


@router.get("/stats/overview", tags=["statistics"])
async def overview(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    _, sensor, _, queries = platform.require()
    data = await queries.overview()
    data["sensor"] = sensor.status()
    data["safety"] = platform.settings.safety_banner()
    data["health"] = (await platform.health())["status"]
    data["version"] = __version__
    data["api_docs"] = platform.settings.api.docs_enabled
    return data


@router.get("/stats/network", tags=["statistics"])
async def network(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    _, sensor, _, queries = platform.require()
    data = await queries.network()
    data["interfaces"] = sensor.interfaces()
    return data


@router.get("/stats/analytics", tags=["statistics"])
async def analytics(
    principal: Viewer, platform: PlatformDep, hours: int = Query(default=24, ge=1, le=24 * 90)
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    return await queries.analytics(hours=hours)
