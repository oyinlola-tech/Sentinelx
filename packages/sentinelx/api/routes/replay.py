"""PCAP Lab: capture files, synthetic fixtures and replays."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile

from sentinelx.api.schemas import ReplayRequest, ScenarioRequest
from sentinelx.api.security import Analyst, PlatformDep, Viewer
from sentinelx.testing import write_pcap
from sentinelx.testing.scenarios import SCENARIOS, get_scenario

router = APIRouter(tags=["replay"])


@router.get("/replay/files")
async def files(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    _, _, replay, _ = platform.require()
    return replay.list_files()


@router.get("/replay/files/inspect")
async def inspect(principal: Viewer, platform: PlatformDep, path: str = Query(min_length=1, max_length=512)) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    return await replay.inspect(path)


@router.post("/replay/upload", status_code=201)
async def upload(file: UploadFile, principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    _, _, replay, _ = platform.require()

    async def chunks() -> AsyncIterator[bytes]:
        while chunk := await file.read(1024 * 1024):
            yield chunk

    return await replay.store_upload(file.filename or "upload.pcap", chunks(), actor=principal.username)


@router.get("/replay/scenarios", summary="Synthetic traffic fixtures available for generation")
async def scenarios(principal: Viewer) -> list[dict[str, Any]]:
    return [{"name": name, "description": (builder.__doc__ or "").strip().split("\n")[0]} for name, builder in SCENARIOS.items()]


@router.post("/replay/scenarios/{name}", status_code=201, summary="Write a synthetic scenario to a PCAP file")
async def generate(name: str, body: ScenarioRequest, principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    """Generates a capture *file* for testing. Nothing is transmitted on the network."""
    if name not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"unknown scenario; available: {', '.join(sorted(SCENARIOS))}")
    _, _, replay, _ = platform.require()
    try:
        scenario = await asyncio.to_thread(get_scenario, name, **body.params)
    except TypeError as exc:
        raise HTTPException(status_code=422, detail=f"invalid parameters for {name}: {exc}") from exc
    if scenario.packet_count > 2_000_000:
        raise HTTPException(status_code=422, detail="scenario too large")
    relative = f"fixtures/{name}.pcap"
    target = replay.directory / relative
    await asyncio.to_thread(write_pcap, target, scenario.frames)
    await platform.audit.record(actor=principal.username, action="GENERATE_FIXTURE", target=relative, source="api",
                                details={"params": body.params, "packets": scenario.packet_count})
    return {
        "path": relative, "scenario": name, "packets": scenario.packet_count, "description": scenario.description,
        "expected_detectors": sorted(scenario.expected_detectors), "expected_source": scenario.expected_source,
        "benign": scenario.benign,
    }


@router.post("/replay", status_code=202)
async def start(body: ReplayRequest, principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    return await replay.start(body.path, actor=principal.username, speed=body.speed, limit=body.limit)


@router.get("/replay")
async def recent(principal: Viewer, platform: PlatformDep, limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
    _, _, replay, _ = platform.require()
    return await replay.recent(limit)


@router.get("/replay/{replay_id}")
async def get(replay_id: str, principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    record = await replay.get(replay_id)
    if record is None:
        raise HTTPException(status_code=404, detail="replay not found")
    return record


@router.post("/replay/{replay_id}/cancel")
async def cancel(replay_id: str, principal: Analyst, request: Request, platform: PlatformDep) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    if not await replay.cancel(replay_id, actor=principal.username):
        raise HTTPException(status_code=409, detail="replay is not running")
    return {"replay_id": replay_id, "status": "cancelling"}
