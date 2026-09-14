"""Security operations: detections, incidents, threats, blocking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.text import Text

from sentinelx.cli.output import (
    console,
    emit_json,
    err,
    risk_text,
    safety_panel,
    severity_text,
    table,
)
from sentinelx.cli.runtime import actor, load_settings, platform_context, run
from sentinelx.common.enums import ActionType
from sentinelx.storage.repositories import DetectionFilter

JsonOption = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


def _ago(iso: str | None) -> str:
    if not iso:
        return "-"
    moment = datetime.fromisoformat(iso)
    seconds = (datetime.now(UTC) - moment).total_seconds()
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{int(seconds // size)}{unit} ago"
    return f"{int(seconds)}s ago"


def register(app: typer.Typer) -> None:
    @app.command(rich_help_panel="Investigate")
    def detections(
        severity: Annotated[list[str], typer.Option("--severity", "-s", help="Filter; repeatable.")] = [],  # noqa: B006
        source: Annotated[str | None, typer.Option("--source", help="Source IP.")] = None,
        detector: Annotated[list[str], typer.Option("--detector", "-d")] = [],  # noqa: B006
        hours: Annotated[int, typer.Option(help="Look back this many hours.")] = 24,
        limit: Annotated[int, typer.Option(min=1, max=500)] = 25,
        detection_id: Annotated[str | None, typer.Option("--id", help="Show one detection with full evidence.")] = None,
        as_json: JsonOption = False,
    ) -> None:
        """List recent detections, or explain one with --id."""
        settings = load_settings()

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                _, _, _, queries = platform.require()
                if detection_id:
                    return await queries.detection(detection_id)
                filters = DetectionFilter(severities=severity, detectors=detector, source_ip=source,
                                          since=datetime.now(UTC) - timedelta(hours=hours))
                return await queries.detections(filters, limit=limit, offset=0, order="newest")

        result = run(main)
        if as_json:
            emit_json(result)
            return
        if detection_id:
            if result is None:
                err.print(f"detection {detection_id} not found")
                raise typer.Exit(1)
            _explain(result)
            return
        rows = [
            (d["detection_id"][:10], _ago(d["timestamp"]), severity_text(d["severity"]), risk_text(d["risk"].get("score")),
             d["title"], d["source_ip"], d.get("destination_ip"), d["detector"], d["status"])
            for d in result["items"]
        ]
        console.print(table(f"Detections (last {hours}h)", ["ID", "When", "Severity", "Risk", "Threat", "Source", "Target", "Detector", "Status"],
                            rows, caption=f"{len(rows)} of {result['total']} - explain one with: sentinelx detections --id <ID>"))

    @app.command(rich_help_panel="Investigate")
    def incidents(
        status: Annotated[list[str], typer.Option("--status")] = [],  # noqa: B006
        limit: Annotated[int, typer.Option(min=1, max=500)] = 25,
        incident_id: Annotated[str | None, typer.Option("--id", help="Show one incident with its timeline.")] = None,
        as_json: JsonOption = False,
    ) -> None:
        """List correlated incidents, or show one with --id."""
        settings = load_settings()

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                _, _, _, queries = platform.require()
                if incident_id:
                    return await queries.incident(incident_id)
                return await queries.incidents(statuses=status, limit=limit)

        result = run(main)
        if as_json:
            emit_json(result)
            return
        if incident_id:
            if result is None:
                err.print(f"incident {incident_id} not found")
                raise typer.Exit(1)
            _incident(result)
            return
        rows = [
            (i["incident_id"][:10], severity_text(i["severity"]), risk_text(i["risk"].get("score")), i["title"],
             ", ".join(i["affected_sources"][:3]), i["detection_count"], i["status"], _ago(i["last_seen"]))
            for i in result["items"]
        ]
        console.print(table("Incidents", ["ID", "Severity", "Risk", "Title", "Sources", "Detections", "Status", "Last seen"], rows,
                            caption=f"{len(rows)} of {result['total']}"))

    @app.command(rich_help_panel="Investigate")
    def threats(hours: int = 24, limit: int = 25, as_json: JsonOption = False) -> None:
        """Sources ranked by the risk of what they did."""
        settings = load_settings()

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                _, _, _, queries = platform.require()
                return await queries.threats(since=datetime.now(UTC) - timedelta(hours=hours), limit=limit)

        result = run(main)
        if as_json:
            emit_json(result)
            return
        rows = [
            (t["source_ip"], risk_text(t["max_risk"]), t["detections"], ", ".join(t["categories"]),
             ", ".join(t["detectors"][:3]), "yes" if t["blocked"] else "no", _ago(t["last_seen"]))
            for t in result
        ]
        console.print(table(f"Threat sources (last {hours}h)", ["Source", "Max risk", "Detections", "Categories", "Detectors", "Blocked", "Last seen"], rows))

    @app.command(rich_help_panel="Respond")
    def blocked(as_json: JsonOption = False) -> None:
        """Addresses the firewall currently blocks."""
        settings = load_settings()

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                _, _, _, queries = platform.require()
                return await queries.firewall()

        result = run(main)
        if as_json:
            emit_json({k: result[k] for k in ("status", "health", "active")})
            return
        console.print(safety_panel(settings.safety_banner()))
        rows = [(b["network"], "rate limit" if b["rate_limited"] else "block",
                 f"{int(b['remaining_seconds'])}s" if b["remaining_seconds"] is not None else "permanent", b["comment"])
                for b in result["active"]]
        console.print(table(f"Active blocks ({result['status']['firewall_backend']})", ["Network", "Type", "Expires", "Reason"], rows))
        history = [(h["network"], "active" if h["active"] else "removed", _ago(h["created_at"]), h["reason"][:60])
                   for h in result["history"][:10]]
        if history:
            console.print(table("Recent block history", ["Network", "State", "Created", "Reason"], history))

    @app.command(rich_help_panel="Respond")
    def block(
        target: Annotated[str | None, typer.Argument(help="IP address or CIDR.")] = None,
        reason: Annotated[str | None, typer.Option("--reason", "-r")] = None,
        duration: Annotated[int | None, typer.Option("--duration", "-t", help="Seconds; omit for permanent.", min=30)] = None,
        rate_limit: Annotated[bool, typer.Option("--rate-limit", help="Rate limit instead of block.")] = False,
        yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
        as_json: JsonOption = False,
    ) -> None:
        """Block (or rate limit) an address. Honours DRY_RUN and the safety guard."""
        target = target or typer.prompt("Address or CIDR to block")
        reason = reason or typer.prompt("Reason (recorded in the audit log)")
        settings = load_settings()
        _respond(settings, ActionType.RATE_LIMIT if rate_limit else ActionType.TEMPORARY_BLOCK if duration else ActionType.BLOCK_IP,
                 target, reason, duration, yes, as_json)

    @app.command(rich_help_panel="Respond")
    def unblock(
        target: Annotated[str | None, typer.Argument(help="IP address or CIDR.")] = None,
        reason: Annotated[str | None, typer.Option("--reason", "-r")] = None,
        yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
        as_json: JsonOption = False,
    ) -> None:
        """Remove a block."""
        target = target or typer.prompt("Address or CIDR to unblock")
        reason = reason or typer.prompt("Reason (recorded in the audit log)")
        settings = load_settings()
        _respond(settings, ActionType.UNBLOCK_IP, target, reason, None, yes, as_json)


def _respond(settings: Any, action: ActionType, target: str, reason: str, duration: int | None, yes: bool, as_json: bool) -> None:
    if not as_json:
        console.print(safety_panel(settings.safety_banner()))
    enforcing = settings.prevention_active or not settings.response.dry_run
    question = f"This will {action.value.replace('_', ' ')} {target} on the {settings.response.firewall_backend} firewall. Continue?"
    if enforcing and not yes and not typer.confirm(question):
        raise typer.Exit(1)

    async def main() -> Any:
        async with platform_context(settings, persist=False) as platform:
            pipeline, _, _, _ = platform.require()
            preview = pipeline.response.guard.evaluate(target)
            decision = await pipeline.response.manual_action(action, target, actor=actor(), reason=reason, duration=duration, source="cli")
            return preview, decision

    preview, decision = run(main)
    from sentinelx.response.engine import decision_payload

    payload = decision_payload(decision)
    if as_json:
        emit_json(payload)
    else:
        style = {"executed": "green", "simulated": "yellow", "failed": "red"}.get(decision.outcome, "")
        console.print(Panel(Text(f"{decision.outcome.upper()}: {decision.reason}" + (f"\n{decision.error}" if decision.error else ""), style=style),
                            title=f"{action.value} {target}", expand=False))
        if not preview.allowed and action is not ActionType.UNBLOCK_IP:
            err.print(f"[dim]safety guard: {preview.reason}[/]")
    if decision.error:
        raise typer.Exit(1)


def _explain(detection: dict[str, Any]) -> None:
    risk = detection["risk"]
    lines = Text()
    lines.append(f"{detection['title']}\n", style="bold")
    lines.append(f"{detection['description']}\n\n")
    lines.append("Risk      ", style="dim")
    lines.append_text(risk_text(risk.get("score")))
    lines.append(f"/100 ({risk.get('band')})\n")
    lines.append("Severity  ", style="dim")
    lines.append_text(severity_text(detection["severity"]))
    lines.append(f"  confidence {detection['confidence']:.0%}\n")
    lines.append("Source    ", style="dim")
    lines.append(f"{detection['source_ip']}  ->  {detection.get('destination_ip') or '-'}:{detection.get('destination_port') or '-'}\n")
    lines.append("Detector  ", style="dim")
    lines.append(f"{detection['detector']}{'  (rule: ' + detection['rule_name'] + ')' if detection.get('rule_name') else ''}\n\n")
    lines.append("Evidence\n", style="bold")
    for item in detection["evidence"]:
        lines.append(f"  - {item['description']}\n")
    lines.append("\nWhy this score\n", style="bold")
    for reason in risk.get("rationale", []):
        lines.append(f"  {reason}\n")
    lines.append("\nRecommended action  ", style="bold")
    lines.append(detection["recommended_action"].upper())
    console.print(Panel(lines, title=f"Detection {detection['detection_id'][:10]}", expand=False))
    if detection.get("actions"):
        rows = [(a["action"], a["outcome"], a["reason"][:70]) for a in detection["actions"]]
        console.print(table("Response decisions", ["Action", "Outcome", "Reason"], rows))


def _incident(incident: dict[str, Any]) -> None:
    risk = incident["risk"]
    body = Text()
    body.append(f"{incident['title']}\n", style="bold")
    body.append(f"{incident['summary']}\n\n")
    body.append("Risk  ", style="dim")
    body.append_text(risk_text(risk.get("score")))
    body.append(f"/100   status {incident['status']}   rule {incident.get('correlation_rule')}\n")
    body.append(f"Sources {', '.join(incident['affected_sources'])}   targets {', '.join(incident['affected_destinations'][:5])}\n")
    body.append(f"Services {', '.join(str(p) for p in incident['affected_services'][:10])}\n\n")
    body.append("Why this score\n", style="bold")
    for reason in risk.get("rationale", []):
        body.append(f"  {reason}\n")
    body.append(f"\nRecommended action  {incident.get('recommended_action', 'alert').upper()}", style="bold")
    console.print(Panel(body, title=f"Incident {incident['incident_id'][:10]}", expand=False))
    rows = [(_ago(t["timestamp"]), severity_text(t["severity"]), risk_text(t["risk"]), t["title"], t.get("destination_port"))
            for t in incident["timeline"]]
    console.print(table("Timeline", ["When", "Severity", "Risk", "Detection", "Port"], rows))
    if incident.get("actions"):
        console.print(table("Actions taken", ["Action", "Target", "Outcome"],
                            [(a["action"], a["target"], a["outcome"]) for a in incident["actions"]]))
