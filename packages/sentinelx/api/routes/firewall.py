"""Firewall, blocking, approvals and allowlist.

Only administrators can change firewall state. Every operation passes through the
response engine, so the safety guard and dry-run setting apply to it exactly as
they apply to automatic responses.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from sentinelx.api.schemas import (
    AllowlistRequest,
    BlockRequest,
    RejectRequest,
    SafetyCheckRequest,
    UnblockRequest,
)
from sentinelx.api.security import Admin, Analyst, PlatformDep, Viewer
from sentinelx.common.enums import ActionType
from sentinelx.response.engine import decision_payload

router = APIRouter(tags=["firewall"])


@router.get("/firewall")
async def firewall_overview(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    return await queries.firewall()


@router.get("/firewall/blocked")
async def blocked(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    pipeline, _, _, _ = platform.require()
    return [entry.as_dict() for entry in await pipeline.response.blocked(refresh=True)]


@router.get("/firewall/actions")
async def actions(
    principal: Viewer,
    platform: PlatformDep,
    target: str | None = Query(default=None, max_length=64),
    outcome: list[str] = Query(default=[], max_length=10),
    include_alerts: bool = Query(
        default=False,
        description="Include stored alert rows (current versions do not store alerts; see /alerts)",
    ),
    include_replays: bool = Query(default=False, description="Include decisions from replays"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> dict[str, Any]:
    _, _, _, queries = platform.require()
    return await queries.actions(
        target=target,
        outcomes=outcome,
        include_alerts=include_alerts,
        include_replays=include_replays,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/firewall/check", summary="Preview whether the safety guard would permit acting on a target"
)
async def check(
    body: SafetyCheckRequest, principal: Analyst, platform: PlatformDep
) -> dict[str, Any]:
    pipeline, _, _, _ = platform.require()
    report = pipeline.response.guard.evaluate(body.target).as_dict()
    report["dry_run"] = platform.settings.response.dry_run
    return report


@router.post("/firewall/block")
async def block(
    body: BlockRequest, principal: Admin, request: Request, platform: PlatformDep
) -> dict[str, Any]:
    pipeline, _, _, _ = platform.require()
    if body.rate_limit:
        action = ActionType.RATE_LIMIT
    else:
        action = ActionType.TEMPORARY_BLOCK if body.duration_seconds else ActionType.BLOCK_IP
    decision = await pipeline.response.manual_action(
        action,
        body.target,
        actor=principal.username,
        reason=body.reason,
        duration=body.duration_seconds,
        source=_source(request),
    )
    return _decision(decision)


@router.post("/firewall/unblock")
async def unblock(
    body: UnblockRequest, principal: Admin, request: Request, platform: PlatformDep
) -> dict[str, Any]:
    pipeline, _, _, _ = platform.require()
    decision = await pipeline.response.manual_action(
        ActionType.UNBLOCK_IP,
        body.target,
        actor=principal.username,
        reason=body.reason,
        source=_source(request),
    )
    return _decision(decision)


@router.get("/firewall/approvals")
async def approvals(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    pipeline, _, _, _ = platform.require()
    return [p.as_dict() for p in pipeline.response.pending_actions()]


@router.post("/firewall/approvals/{action_id}/approve")
async def approve(action_id: str, principal: Admin, platform: PlatformDep) -> dict[str, Any]:
    pipeline, _, _, _ = platform.require()
    try:
        decision = await pipeline.response.approve(action_id, actor=principal.username)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="no pending action with that id") from exc
    return _decision(decision)


@router.post("/firewall/approvals/{action_id}/reject")
async def reject(
    action_id: str, body: RejectRequest, principal: Admin, platform: PlatformDep
) -> dict[str, Any]:
    pipeline, _, _, _ = platform.require()
    try:
        pending = await pipeline.response.reject(
            action_id, actor=principal.username, reason=body.reason
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="no pending action with that id") from exc
    return pending.as_dict()


@router.get("/firewall/allowlist")
async def get_allowlist(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    return {
        "response_allowlist": platform.settings.response.allowlist_networks,
        "detection_allowlist": platform.settings.detection.allowlist_networks,
        "management_addresses": platform.settings.response.management_addresses,
    }


@router.put(
    "/firewall/allowlist", summary="Replace the never-block allowlist (loopback is always retained)"
)
async def put_allowlist(
    body: AllowlistRequest, principal: Admin, request: Request, platform: PlatformDep
) -> dict[str, Any]:
    await platform.config.update(
        "response",
        {"allowlist_networks": body.networks},
        actor=principal.username,
        source=_source(request),
    )
    return {"response_allowlist": platform.settings.response.allowlist_networks}


def _source(request: Request) -> str:
    return "dashboard" if request.headers.get("x-sentinelx-client") == "dashboard" else "api"


def _decision(decision: Any) -> dict[str, Any]:
    payload = decision_payload(decision)
    if decision.error:
        payload["http_note"] = (
            "the request was valid but the action was not carried out; see 'error'"
        )
    return payload
