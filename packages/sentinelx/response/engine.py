"""The response engine.

Decides what to do about a detection or incident, and - only when explicitly
permitted - does it.

Decision matrix for *automatic* (detector-driven) preventive actions:

==================  =========  ==========================================
``RESPONSE_MODE``   ``DRY_RUN``  outcome
==================  =========  ==========================================
detect_only         any        recorded as ``skipped``; nothing applied
manual_approval     any        queued ``pending_approval`` for an admin
automatic           true       recorded as ``simulated``; nothing applied
automatic           false      safety guard, then applied to the firewall
==================  =========  ==========================================

*Manual* actions (an admin running ``sentinelx block`` or pressing Block in the
dashboard) skip the mode check, because a human made the decision, but they still
honour ``DRY_RUN`` and always pass the safety guard.

Non-preventive actions (alert, log, webhook) are always performed.

Every decision, whether executed, simulated, refused or queued, is published on the
event bus and handed to the audit sink.  There is no silent path.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from sentinelx.common.enums import ActionType, ResponseMode
from sentinelx.common.errors import FirewallError, SafetyViolationError
from sentinelx.common.models import Detection, Incident, ResponseDecision, RiskAssessment, new_id
from sentinelx.common.netutils import parse_network
from sentinelx.config.settings import ResponseSettings, ScoringSettings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.firewall.base import BlockEntry, FirewallAdapter
from sentinelx.response.safety import SafetyGuard
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["AuditSink", "PendingAction", "ResponseEngine"]

log = get_logger(__name__)

#: Receives one audit record per decision. Storage supplies the real implementation.
AuditSink = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(slots=True)
class PendingAction:
    """A preventive action awaiting administrator approval."""

    action: ActionType
    target: str
    reason: str
    risk: float
    duration_seconds: int | None
    detection_id: str | None
    incident_id: str | None
    evidence: list[str]
    action_id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action": self.action.value,
            "target": self.target,
            "reason": self.reason,
            "risk": self.risk,
            "duration_seconds": self.duration_seconds,
            "detection_id": self.detection_id,
            "incident_id": self.incident_id,
            "evidence": self.evidence,
            "created_at": self.created_at.isoformat(),
        }


def decision_payload(decision: ResponseDecision) -> dict[str, Any]:
    return {
        "decision_id": decision.decision_id,
        "action": decision.action.value,
        "target": decision.target,
        "reason": decision.reason,
        "outcome": decision.outcome,
        "executed": decision.executed,
        "dry_run": decision.dry_run,
        "requires_approval": decision.requires_approval,
        "duration_seconds": decision.duration_seconds,
        "detection_id": decision.detection_id,
        "incident_id": decision.incident_id,
        "error": decision.error,
        "decided_at": decision.decided_at.isoformat(),
    }


class ResponseEngine:
    """Decides on and carries out responses.

    Args:
        settings: response configuration (mode, dry run, limits).
        scoring: thresholds that gate automatic prevention.
        firewall: adapter used for enforcement.
        bus: event bus for decisions; optional for library use.
        audit: coroutine receiving audit records; optional for library use.
        guard: safety guard; built from ``settings`` if omitted.
    """

    def __init__(
        self,
        settings: ResponseSettings,
        firewall: FirewallAdapter,
        *,
        scoring: ScoringSettings | None = None,
        bus: EventBus | None = None,
        audit: AuditSink | None = None,
        guard: SafetyGuard | None = None,
        on_response: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.scoring = scoring or ScoringSettings()
        self.firewall = firewall
        self.bus = bus
        self._audit = audit
        self._on_response = on_response
        self._blocks: dict[str, BlockEntry] = {}
        self.guard = guard or SafetyGuard(settings, active_block_count=lambda: len(self._blocks))
        self.pending: dict[str, PendingAction] = {}
        self.decisions: list[ResponseDecision] = []
        self._reaper: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._firewall_ready = False

    # ------------------------------------------------------------- lifecycle

    async def start(self, known_expiries: dict[str, datetime] | None = None) -> None:
        """Prepare the firewall (only when it will be used) and start the expiry reaper.

        Args:
            known_expiries: expiry times recorded before a restart, by network. Backends
                that cannot store an expiry themselves (pf, Windows Firewall) report
                blocks without one; this restores the deadline so they still expire.
        """
        if self.settings.prevention_active or self.settings.mode is ResponseMode.MANUAL_APPROVAL:
            await self._ensure_firewall_ready()
        known = known_expiries or {}
        try:
            for entry in await self.firewall.list_blocked():
                if entry.expires_at is None and entry.network in known:
                    entry = replace(entry, expires_at=known[entry.network])
                self._blocks[entry.network] = entry
        except FirewallError as exc:
            log.warning("firewall_list_failed", error=str(exc))
        metrics.blocked_addresses.set(len(self._blocks))
        if self._reaper is None or self._reaper.done():
            self._reaper = asyncio.create_task(self._reap_expired(), name="response-reaper")
        log.info(
            "response_engine_started",
            mode=self.settings.mode.value,
            dry_run=self.settings.dry_run,
            backend=self.firewall.backend,
            prevention_active=self.settings.prevention_active,
        )

    async def stop(self) -> None:
        reaper, self._reaper = self._reaper, None
        if reaper is not None:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper

    # ------------------------------------------------------ automatic path

    async def handle_detection(
        self, detection: Detection, risk: RiskAssessment
    ) -> list[ResponseDecision]:
        """Decide how to respond to a scored detection."""
        decisions: list[ResponseDecision] = []
        evidence = [item.description for item in detection.evidence]

        alert = ResponseDecision(
            action=ActionType.ALERT,
            target=detection.source_ip,
            reason=f"{detection.title} (risk {risk.score:.0f})",
            executed=True,
            dry_run=False,
            detection_id=detection.detection_id,
        )
        decisions.append(await self._finalise(alert, source="engine"))

        if self.settings.webhook_url and risk.score >= self.settings.webhook_min_risk:
            decisions.append(await self._webhook(detection, risk))

        action = detection.recommended_action
        if not action.is_preventive or action is ActionType.UNBLOCK_IP:
            return decisions
        if risk.score < self.scoring.auto_block_threshold:
            decision = ResponseDecision(
                action=action,
                target=detection.source_ip,
                reason=(
                    f"not applied: risk {risk.score:.0f} is below the automatic response "
                    f"threshold of {self.scoring.auto_block_threshold:.0f}"
                ),
                executed=False,
                dry_run=False,
                detection_id=detection.detection_id,
            )
            decisions.append(await self._finalise(decision, source="engine", record=False))
            return decisions

        duration = (
            min(
                detection.recommended_duration_seconds or self.settings.default_block_seconds,
                self.settings.max_block_seconds,
            )
            if action in (ActionType.TEMPORARY_BLOCK, ActionType.RATE_LIMIT)
            else None
        )
        reason = f"{detection.title}: risk {risk.score:.0f}/100 from {detection.source_ip}"
        decisions.append(
            await self._automatic(
                action,
                detection.source_ip,
                reason,
                risk.score,
                duration,
                detection_id=detection.detection_id,
                evidence=evidence,
            )
        )
        return decisions

    async def handle_incident(self, incident: Incident) -> list[ResponseDecision]:
        """Respond to an incident whose risk crosses the automatic threshold."""
        if incident.risk.score < self.scoring.auto_block_threshold:
            return []
        decisions = []
        for source in sorted(incident.affected_sources):
            if self._block_key(source) in self._blocks:
                continue
            reason = f"incident '{incident.title}' risk {incident.risk.score:.0f}/100"
            decisions.append(
                await self._automatic(
                    ActionType.TEMPORARY_BLOCK,
                    source,
                    reason,
                    incident.risk.score,
                    self.settings.default_block_seconds,
                    incident_id=incident.incident_id,
                    evidence=incident.risk.rationale,
                )
            )
        return decisions

    async def _automatic(
        self,
        action: ActionType,
        target: str,
        reason: str,
        risk: float,
        duration: int | None,
        *,
        detection_id: str | None = None,
        incident_id: str | None = None,
        evidence: list[str] | None = None,
    ) -> ResponseDecision:
        mode = self.settings.mode
        base = ResponseDecision(
            action=action,
            target=target,
            reason=reason,
            executed=False,
            dry_run=self.settings.dry_run,
            duration_seconds=duration,
            detection_id=detection_id,
            incident_id=incident_id,
        )
        if self._block_key(target) in self._blocks and action in (
            ActionType.BLOCK_IP,
            ActionType.TEMPORARY_BLOCK,
        ):
            return await self._finalise(
                replace(base, dry_run=False, reason=f"{reason}; already blocked"),
                source="engine",
                record=False,
            )

        if mode is ResponseMode.DETECT_ONLY:
            return await self._finalise(
                replace(
                    base, dry_run=False, reason=f"{reason}; not applied (RESPONSE_MODE=detect_only)"
                ),
                source="engine",
            )

        # Refuse unsafe targets before queueing, so an admin is never asked to
        # approve something that cannot legally be done.
        try:
            self.guard.check(target)
        except SafetyViolationError as exc:
            return await self._finalise(
                replace(base, error=f"safety guard: {exc.reason}"), source="engine"
            )

        if mode is ResponseMode.MANUAL_APPROVAL:
            pending = PendingAction(
                action=action,
                target=target,
                reason=reason,
                risk=risk,
                duration_seconds=duration,
                detection_id=detection_id,
                incident_id=incident_id,
                evidence=evidence or [],
            )
            if not any(p.target == target and p.action is action for p in self.pending.values()):
                self.pending[pending.action_id] = pending
                if self.bus:
                    await self.bus.publish(EventType.RESPONSE_PENDING_APPROVAL, pending.as_dict())
            return await self._finalise(replace(base, requires_approval=True), source="engine")

        return await self._execute(base, source="engine")

    # --------------------------------------------------------- manual path

    async def manual_action(
        self,
        action: ActionType,
        target: str,
        *,
        actor: str,
        reason: str,
        duration: int | None = None,
        source: str = "api",
    ) -> ResponseDecision:
        """Carry out an administrator's explicit request.

        Honours ``DRY_RUN`` and the safety guard, but not ``RESPONSE_MODE``.
        """
        if duration is not None:
            duration = max(1, min(int(duration), self.settings.max_block_seconds))
        if action is ActionType.TEMPORARY_BLOCK and duration is None:
            duration = self.settings.default_block_seconds
        base = ResponseDecision(
            action=action,
            target=target,
            reason=reason or f"manual {action.value} by {actor}",
            executed=False,
            dry_run=self.settings.dry_run,
            duration_seconds=duration,
        )
        if action is ActionType.UNBLOCK_IP:
            return await self._execute(base, source=source, actor=actor)
        try:
            self.guard.check(target)
        except SafetyViolationError as exc:
            return await self._finalise(
                replace(base, error=f"safety guard: {exc.reason}"), source=source, actor=actor
            )
        return await self._execute(base, source=source, actor=actor)

    async def approve(self, action_id: str, *, actor: str) -> ResponseDecision:
        """Approve a queued action.

        Raises:
            KeyError: when no pending action has that id.
        """
        pending = self.pending.pop(action_id)
        return await self.manual_action(
            pending.action,
            pending.target,
            actor=actor,
            reason=f"approved: {pending.reason}",
            duration=pending.duration_seconds,
            source="approval",
        )

    async def reject(self, action_id: str, *, actor: str, reason: str = "") -> PendingAction:
        pending = self.pending.pop(action_id)
        await self._audit_record(
            {
                "action": "REJECT_RESPONSE",
                "actor": actor,
                "target": pending.target,
                "reason": reason or "rejected by administrator",
                "source": "approval",
                "details": pending.as_dict(),
            }
        )
        return pending

    # ------------------------------------------------------------ execution

    async def _execute(
        self, decision: ResponseDecision, *, source: str, actor: str = "system"
    ) -> ResponseDecision:
        if decision.dry_run:
            return await self._finalise(
                replace(decision, reason=f"{decision.reason} [DRY RUN - not applied]"),
                source=source,
                actor=actor,
            )
        try:
            async with self._lock:
                result = await self._apply(decision)
        except (FirewallError, SafetyViolationError, ValueError) as exc:
            return await self._finalise(
                replace(decision, error=str(exc)), source=source, actor=actor
            )
        return await self._finalise(replace(decision, executed=result), source=source, actor=actor)

    async def _ensure_firewall_ready(self) -> None:
        """Create the firewall table/chain once, the first time it is needed.

        Prevention can be enabled at runtime, and administrators can block manually in
        any mode, so setup cannot happen only at start-up.
        """
        if self._firewall_ready:
            return
        try:
            await self.firewall.setup()
        except FirewallError as exc:
            log.error("firewall_setup_failed", backend=self.firewall.backend, error=str(exc))
            raise
        self._firewall_ready = True

    @staticmethod
    def _block_key(target: str) -> str:
        """Registry key for a target: its canonical network (``1.2.3.4`` -> ``1.2.3.4/32``)."""
        try:
            return str(parse_network(target))
        except ValueError:
            return target

    async def _apply(self, decision: ResponseDecision) -> bool:
        action = decision.action
        await self._ensure_firewall_ready()
        if action in (ActionType.BLOCK_IP, ActionType.TEMPORARY_BLOCK, ActionType.QUARANTINE):
            network = self.guard.check(decision.target)
            entry = await self.firewall.block(
                network, duration=decision.duration_seconds, comment=decision.reason[:120]
            )
            self._blocks[entry.network] = entry
            metrics.blocked_addresses.set(len(self._blocks))
            if self._on_response:
                self._on_response(decision.target)
            if self.bus:
                await self.bus.publish(
                    EventType.IP_BLOCKED,
                    {
                        **entry.as_dict(),
                        "reason": decision.reason,
                        "backend": self.firewall.backend,
                    },
                )
            return True
        if action is ActionType.RATE_LIMIT:
            network = self.guard.check(decision.target)
            entry = await self.firewall.rate_limit(
                network,
                packets_per_second=self.settings.rate_limit_packets_per_second,
                duration=decision.duration_seconds,
            )
            self._blocks[entry.network] = entry
            metrics.blocked_addresses.set(len(self._blocks))
            if self._on_response:
                self._on_response(decision.target)
            if self.bus:
                await self.bus.publish(
                    EventType.IP_BLOCKED,
                    {
                        **entry.as_dict(),
                        "reason": decision.reason,
                        "backend": self.firewall.backend,
                    },
                )
            return True
        if action is ActionType.UNBLOCK_IP:
            network = parse_network(decision.target)
            removed = await self.firewall.unblock(network)
            self._blocks.pop(str(network), None)
            metrics.blocked_addresses.set(len(self._blocks))
            if self.bus:
                await self.bus.publish(
                    EventType.IP_UNBLOCKED,
                    {"network": str(network), "reason": decision.reason, "removed": removed},
                )
            return removed
        raise ValueError(f"{action.value} is not an executable preventive action")

    async def _finalise(
        self, decision: ResponseDecision, *, source: str, actor: str = "system", record: bool = True
    ) -> ResponseDecision:
        """Store, count, publish and audit a decision.

        ``record=False`` is for non-actions (below threshold, already blocked):
        they are kept in :attr:`decisions` and counted, but neither published nor
        audited - the audit log records what was done or attempted, not every
        occasion on which nothing happened.
        """
        self.decisions.append(decision)
        if len(self.decisions) > 5000:
            del self.decisions[:1000]
        metrics.responses.labels(action=decision.action.value, outcome=decision.outcome).inc()
        if decision.action is ActionType.ALERT:
            return decision  # alerts are the detection itself; auditing each would duplicate it
        if not record:
            return decision
        payload = decision_payload(decision)
        if self.bus:
            await self.bus.publish(EventType.RESPONSE_DECIDED, payload)
        if decision.action.is_preventive:
            log.info(
                "response_decision",
                **{k: payload[k] for k in ("action", "target", "outcome", "reason")},
                actor=actor,
            )
            await self._audit_record(
                {
                    "action": decision.action.value.upper(),
                    "actor": actor,
                    "target": decision.target,
                    "reason": decision.reason,
                    "source": source,
                    "outcome": decision.outcome,
                    "details": payload,
                }
            )
        return decision

    async def _audit_record(self, record: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            await self._audit(record)
        except Exception:
            # Losing an audit record is serious, but must not reverse a firewall
            # change already made. Log loudly so it cannot pass unnoticed.
            log.exception(
                "audit_write_failed", action=record.get("action"), target=record.get("target")
            )

    async def _webhook(self, detection: Detection, risk: RiskAssessment) -> ResponseDecision:
        import httpx

        body = {
            "type": "sentinelx.detection",
            "title": detection.title,
            "detector": detection.detector,
            "severity": detection.severity.value,
            "risk": risk.score,
            "risk_band": risk.band.value,
            "source_ip": detection.source_ip,
            "destination_ip": detection.destination_ip,
            "evidence": [item.description for item in detection.evidence],
            "timestamp": detection.timestamp.isoformat(),
        }
        decision = ResponseDecision(
            action=ActionType.WEBHOOK,
            target=webhook_display(self.settings.webhook_url),
            reason=detection.title,
            executed=False,
            dry_run=False,
            detection_id=detection.detection_id,
        )
        try:
            await check_webhook_destination(
                self.settings.webhook_url,
                allow_private=self.settings.webhook_allow_private_addresses,
            )
            async with httpx.AsyncClient(
                timeout=self.settings.webhook_timeout_seconds, follow_redirects=False
            ) as client:
                response = await client.post(self.settings.webhook_url, json=body)
                response.raise_for_status()
        except (httpx.HTTPError, WebhookRejectedError) as exc:
            reason = str(exc) if isinstance(exc, WebhookRejectedError) else type(exc).__name__
            metrics.webhook_failures.inc()
            log.warning("webhook_failed", target=decision.target, error=reason)
            return await self._finalise(
                replace(decision, error=f"webhook failed: {reason}"),
                source="engine",
                record=False,
            )
        return await self._finalise(replace(decision, executed=True), source="engine", record=False)

    # --------------------------------------------------------------- expiry

    async def _reap_expired(self) -> None:
        """Remove temporary blocks whose time is up, every few seconds."""
        while True:
            await asyncio.sleep(5)
            try:
                await self.expire_due()
            except Exception:  # the reaper must survive anything and keep running
                log.exception("expiry_reaper_failed")

    async def expire_due(self) -> int:
        """Unblock every temporary block whose expiry has passed. Returns how many.

        nftables also expires elements in the kernel; this keeps the registry in step
        and enforces expiry for backends that cannot (iptables, pf, Windows Firewall).

        Runs under the same lock as blocking, and re-checks each entry after taking it,
        so a block an administrator placed while this was pending is never removed. A
        failed unblock keeps the entry (so it is retried) and is audited as failed; it
        is never reported as done.
        """
        now = datetime.now(UTC)
        due = [e for e in self._blocks.values() if e.expires_at and e.expires_at <= now]
        expired = 0
        for entry in due:
            async with self._lock:
                if self._blocks.get(entry.network) is not entry:
                    continue  # replaced or removed while waiting for the lock
                try:
                    await self.firewall.unblock(parse_network(entry.network))
                except (FirewallError, ValueError) as exc:
                    log.warning("expiry_unblock_failed", network=entry.network, error=str(exc))
                    await self._audit_record(
                        {
                            "action": "UNBLOCK_IP",
                            "actor": "system",
                            "target": entry.network,
                            "reason": "temporary block expired",
                            "source": "engine",
                            "outcome": "failed",
                            "details": {"error": str(exc)[:500], "will_retry": True},
                        }
                    )
                    continue
                self._blocks.pop(entry.network, None)
                metrics.blocked_addresses.set(len(self._blocks))
            expired += 1
            if self.bus:
                await self.bus.publish(
                    EventType.IP_UNBLOCKED,
                    {"network": entry.network, "reason": "temporary block expired"},
                )
            await self._audit_record(
                {
                    "action": "UNBLOCK_IP",
                    "actor": "system",
                    "target": entry.network,
                    "reason": "temporary block expired",
                    "source": "engine",
                    "outcome": "executed",
                }
            )
        return expired

    # ---------------------------------------------------------------- views

    async def blocked(self, *, refresh: bool = False) -> list[BlockEntry]:
        if refresh:
            try:
                live = {entry.network: entry for entry in await self.firewall.list_blocked()}
                for network, entry in live.items():
                    self._blocks.setdefault(network, entry)
                if self.firewall.backend != "null":
                    for network in [n for n in self._blocks if n not in live]:
                        self._blocks.pop(network)
            except FirewallError as exc:
                log.warning("firewall_list_failed", error=str(exc))
        return sorted(self._blocks.values(), key=lambda e: e.created_at, reverse=True)

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.settings.mode.value,
            "dry_run": self.settings.dry_run,
            "prevention_active": self.settings.prevention_active,
            "firewall_backend": self.firewall.backend,
            "active_blocks": len(self._blocks),
            "pending_approvals": len(self.pending),
            "safety_refusals": self.guard.refusals,
            "auto_block_threshold": self.scoring.auto_block_threshold,
            "allowlist": self.guard.allowlist,
        }


class WebhookRejectedError(Exception):
    """The webhook destination is not allowed (for example, a private address)."""


def webhook_display(url: str) -> str:
    """A webhook URL safe to show and log: scheme and host only.

    Chat and incident webhooks carry their secret in the path or query, and URLs can
    embed ``user:password@``; none of that belongs in a dashboard or an audit record.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if not parts.hostname:
        return ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}/…"


async def check_webhook_destination(url: str, *, allow_private: bool) -> None:
    """Refuse to send to loopback, private, link-local or reserved addresses.

    Resolved at send time, so a hostname cannot be pointed at an internal service
    after validation. (A DNS answer that changes between this check and the connection
    is not prevented; set ``webhook_allow_private_addresses`` only for trusted hosts.)

    Raises:
        WebhookRejectedError: when any resolved address is not a public address.
    """
    if allow_private:
        return
    import ipaddress
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, parts.port or 443, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise WebhookRejectedError(f"cannot resolve webhook host {host!r}") from exc
    for info in infos:
        address = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        if not address.is_global or address.is_multicast:
            raise WebhookRejectedError(
                f"webhook host {host!r} resolves to non-public address {address}; set "
                "RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES=true to allow internal receivers"
            )
