"""Audit logging.

Audit writes go straight to the database, *not* through the event bus.  The bus
drops events when a subscriber falls behind, which is the right trade-off for
dashboard updates and the wrong one for an audit trail.  If an audit write fails,
the failure propagates to the caller (for administrative actions, the API returns
an error) or is logged at error level (for engine actions, which must not be
reversed by an audit failure).
"""

from __future__ import annotations

from typing import Any

from sentinelx.events.bus import EventBus, EventType
from sentinelx.storage.database import Database
from sentinelx.storage.models import AuditEvent
from sentinelx.storage.repositories import AuditRepository
from sentinelx.telemetry.logging import get_logger, redact_secrets

__all__ = ["AuditService", "audit_to_dict"]

log = get_logger(__name__)


def audit_to_dict(record: AuditEvent) -> dict[str, Any]:
    return {
        "id": record.id,
        "timestamp": record.timestamp.isoformat(),
        "actor": record.actor,
        "action": record.action,
        "target": record.target,
        "reason": record.reason,
        "source": record.source,
        "outcome": record.outcome,
        "client_ip": record.client_ip,
        "details": record.details,
    }


class AuditService:
    def __init__(self, database: Database, bus: EventBus | None = None) -> None:
        self.database = database
        self.bus = bus

    async def record(
        self,
        *,
        actor: str,
        action: str,
        target: str | None = None,
        reason: str = "",
        source: str = "system",
        outcome: str = "success",
        client_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write an audit event.

        ``details`` passes through the same secret-redaction as logs, so a caller
        that audits a settings change cannot accidentally persist a password.
        """
        clean_details = redact_secrets(None, "audit", dict(details or {}))
        record = AuditEvent(
            actor=actor[:128],
            action=action.upper()[:64],
            target=(target or None) and str(target)[:512],
            reason=reason[:2000],
            source=source[:32],
            outcome=outcome[:32],
            client_ip=client_ip,
            details=clean_details,
        )
        async with self.database.session() as session:
            await AuditRepository(session).add(record)
        payload = audit_to_dict(record)
        log.info(
            "audit",
            actor=record.actor,
            action=record.action,
            target=record.target,
            outcome=record.outcome,
            source=record.source,
        )
        if self.bus is not None:
            await self.bus.publish(EventType.AUDIT_EVENT, payload)
        return payload

    async def sink(self, record: dict[str, Any]) -> None:
        """Adapter matching :data:`sentinelx.response.engine.AuditSink`."""
        await self.record(
            actor=str(record.get("actor", "system")),
            action=str(record.get("action", "RESPONSE")),
            target=record.get("target"),
            reason=str(record.get("reason", "")),
            source=str(record.get("source", "engine")),
            outcome=str(record.get("outcome", "success")),
            details=record.get("details") or {},
        )
