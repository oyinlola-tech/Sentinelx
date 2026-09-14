"""Custom detection rules."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from sentinelx.api.schemas import RuleDefinitionRequest, RuleEnabledRequest, RuleTestRequest
from sentinelx.api.security import Admin, Analyst, PlatformDep, Viewer
from sentinelx.services.rules import RuleService
from sentinelx.testing.scenarios import SCENARIOS

router = APIRouter(tags=["rules"])


def _source(request: Request) -> str:
    return "dashboard" if request.headers.get("x-sentinelx-client") == "dashboard" else "api"


@router.get("/rules")
async def list_rules(principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    return {"rules": await platform.rules.list_rules(), "load_problems": platform.rules.load_problems}


@router.get("/rules/fields", summary="Fields and operators available in rule conditions")
async def fields(principal: Viewer) -> dict[str, Any]:
    return {
        "fields": RuleService.fields(),
        "operators": ["==", "!=", ">", ">=", "<", "<=", "in", "not in", "contains", "startswith", "endswith", "in_network"],
        "scenarios": sorted(SCENARIOS),
    }


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, principal: Viewer, platform: PlatformDep) -> dict[str, Any]:
    rule = await platform.rules.get(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule


@router.post("/rules/validate")
async def validate(body: RuleDefinitionRequest, principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    return platform.rules.validate(body.definition)


@router.post("/rules/test", summary="Run a rule in isolation against a scenario, a PCAP, or its embedded tests")
async def test(body: RuleTestRequest, principal: Analyst, platform: PlatformDep) -> dict[str, Any]:
    if body.scenario and body.scenario not in SCENARIOS:
        raise HTTPException(status_code=422, detail=f"unknown scenario; available: {', '.join(sorted(SCENARIOS))}")
    pcap = None
    if body.pcap_path:
        _, _, replay, _ = platform.require()
        pcap = replay.resolve(body.pcap_path)
    return await platform.rules.test(body.definition, scenario=body.scenario, pcap_path=pcap)


@router.post("/rules", status_code=201)
async def create_rule(body: RuleDefinitionRequest, principal: Admin, request: Request, platform: PlatformDep) -> dict[str, Any]:
    return await platform.rules.create(body.definition, actor=principal.username, source=_source(request))


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, body: RuleDefinitionRequest, principal: Admin, request: Request, platform: PlatformDep) -> dict[str, Any]:
    try:
        return await platform.rules.update(rule_id, body.definition, actor=principal.username, source=_source(request))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rule not found") from exc


@router.patch("/rules/{rule_id}/enabled")
async def set_enabled(rule_id: str, body: RuleEnabledRequest, principal: Admin, request: Request, platform: PlatformDep) -> dict[str, Any]:
    try:
        return await platform.rules.set_enabled(rule_id, body.enabled, actor=principal.username, source=_source(request))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rule not found") from exc


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, principal: Admin, request: Request, platform: PlatformDep) -> None:
    try:
        await platform.rules.delete(rule_id, actor=principal.username, source=_source(request))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rule not found") from exc


@router.get("/detectors", summary="Built-in and rule detectors with their live counters")
async def detectors(principal: Viewer, platform: PlatformDep) -> list[dict[str, Any]]:
    pipeline, _, _, _ = platform.require()
    return [{**d.info().as_dict(), **d.stats()} for d in pipeline.detection.detectors]


@router.patch("/detectors/{name}/enabled")
async def toggle_detector(name: str, body: RuleEnabledRequest, principal: Admin, request: Request, platform: PlatformDep) -> dict[str, Any]:
    pipeline, _, _, _ = platform.require()
    if name.startswith("rule:"):
        raise HTTPException(status_code=422, detail="use /rules/{rule_id}/enabled for rule detectors")
    if not pipeline.detection.set_enabled(name, body.enabled):
        raise HTTPException(status_code=404, detail="detector not found")
    disabled = set(platform.settings.detection.disabled_detectors)
    disabled.discard(name) if body.enabled else disabled.add(name)
    await platform.config.update("detection", {"disabled_detectors": sorted(disabled)}, actor=principal.username,
                                 source=_source(request))
    return {"name": name, "enabled": body.enabled}
