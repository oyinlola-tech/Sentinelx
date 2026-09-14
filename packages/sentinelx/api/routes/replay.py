"""PCAP Lab: capture files, synthetic fixtures and replays."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from sentinelx.api.schemas import ReplayRequest, ScenarioRequest
from sentinelx.api.security import Analyst, PlatformDep, Viewer
from sentinelx.testing import write_pcap
from sentinelx.testing.scenarios import SCENARIOS, get_scenario, validate_scenario_params

router = APIRouter(tags=["replay"])


@router.get("/replay/files")
async def files(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    _, _, replay, _ = platform.require()
    return replay.list_files()


@router.get("/replay/files/inspect")
async def inspect(
    principal: Viewer, platform: PlatformDep, path: str = Query(min_length=1, max_length=512)
) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    return await replay.inspect(path)


_UPLOAD_TYPES = frozenset(
    {"application/octet-stream", "application/vnd.tcpdump.pcap", "application/x-pcapng"}
)


@router.post(
    "/replay/upload",
    status_code=201,
    summary="Upload a capture file as the raw request body",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            },
        }
    },
)
async def upload(
    request: Request,
    principal: Analyst,
    platform: PlatformDep,
    filename: str = Query(default="upload.pcap", min_length=1, max_length=200),
) -> dict[str, Any]:
    """Stream a pcap or pcapng file to the capture directory.

    The body is the file itself, not a multipart form. Authentication and the size
    limit are checked before a single body byte is read, so an unauthenticated or
    oversized upload never reaches the disk.
    """
    _, _, replay, _ = platform.require()
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type not in _UPLOAD_TYPES:
        raise HTTPException(status_code=415, detail="send the capture as application/octet-stream")
    limit = replay.upload_limit_bytes
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if int(declared) > limit:
            raise HTTPException(
                status_code=413, detail=f"upload exceeds the {limit // 1_048_576} MB limit"
            )

    async def chunks() -> AsyncIterator[bytes]:
        async for chunk in request.stream():
            yield chunk

    return await replay.store_upload(filename, chunks(), actor=principal.username)


@router.get("/replay/scenarios", summary="Synthetic traffic fixtures available for generation")
async def scenarios(principal: Viewer) -> list[dict[str, Any]]:
    return [
        {"name": name, "description": (builder.__doc__ or "").strip().split("\n")[0]}
        for name, builder in SCENARIOS.items()
    ]


@router.post(
    "/replay/scenarios/{name}", status_code=201, summary="Write a synthetic scenario to a PCAP file"
)
async def generate(
    name: str, body: ScenarioRequest, principal: Analyst, platform: PlatformDep
) -> dict[str, Any]:
    """Generates a capture *file* for testing. Nothing is transmitted on the network."""
    if name not in SCENARIOS:
        raise HTTPException(
            status_code=404, detail=f"unknown scenario; available: {', '.join(sorted(SCENARIOS))}"
        )
    _, _, replay, _ = platform.require()
    try:
        # Parameters are validated and bounded before anything is generated.
        validate_scenario_params(name, body.params)
        scenario = await asyncio.to_thread(get_scenario, name, **body.params)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"invalid parameters for {name}: {exc}"
        ) from exc
    relative = f"fixtures/{name}.pcap"
    target = replay.directory / relative
    await asyncio.to_thread(write_pcap, target, scenario.frames)
    await platform.audit.record(
        actor=principal.username,
        action="GENERATE_FIXTURE",
        target=relative,
        source="api",
        details={"params": body.params, "packets": scenario.packet_count},
    )
    return {
        "path": relative,
        "scenario": name,
        "packets": scenario.packet_count,
        "description": scenario.description,
        "expected_detectors": sorted(scenario.expected_detectors),
        "expected_source": scenario.expected_source,
        "benign": scenario.benign,
    }


@router.post("/replay", status_code=202)
async def start(body: ReplayRequest, principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    return await replay.start(
        body.path, actor=principal.username, speed=body.speed, limit=body.limit
    )


@router.get("/replay")
async def recent(
    principal: Viewer, platform: PlatformDep, limit: int = Query(default=50, ge=1, le=200)
) -> list[dict[str, Any]]:
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
async def cancel(
    replay_id: str, principal: Analyst, request: Request, platform: PlatformDep
) -> dict[str, Any]:
    _, _, replay, _ = platform.require()
    if not await replay.cancel(replay_id, actor=principal.username):
        raise HTTPException(status_code=409, detail="replay is not running")
    return {"replay_id": replay_id, "status": "cancelling"}
