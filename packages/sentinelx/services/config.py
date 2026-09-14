"""Runtime configuration.

A defined subset of settings can be changed while the platform runs, from the
dashboard or ``sentinelx config set``.  Everything else - database URL, secrets,
listen address, firewall backend - is environment-only and needs a restart,
because changing it live would be unsafe or meaningless.

Changes are validated by the same Pydantic models used at startup (so the dashboard
cannot set a value the environment could not), applied to the running components,
persisted so they survive restarts, and audited with a before/after diff.

**Enabling prevention** (``response.mode=automatic`` with ``response.dry_run=false``)
requires the caller to pass the exact confirmation phrase in
:data:`PREVENTION_CONFIRMATION`.  The dashboard shows a warning dialog that asks the
operator to type it; the API refuses the change without it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ValidationError

from sentinelx.common.enums import ResponseMode
from sentinelx.common.errors import ConfigurationError
from sentinelx.config.settings import (
    CorrelationSettings,
    DetectionSettings,
    ResponseSettings,
    ScoringSettings,
    Settings,
)
from sentinelx.events.bus import EventBus, EventType
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database
from sentinelx.storage.repositories import SettingRepository
from sentinelx.telemetry.logging import get_logger

__all__ = ["EDITABLE", "PREVENTION_CONFIRMATION", "WINDOW_FIELDS", "ConfigService", "redact_url"]

log = get_logger(__name__)

PREVENTION_CONFIRMATION = "ENABLE PREVENTION"

#: section -> fields that may change at runtime. Absent fields are environment-only.
EDITABLE: dict[str, set[str]] = {
    "detection": set(DetectionSettings.model_fields) - {"max_tracked_sources"},
    "scoring": set(ScoringSettings.model_fields),
    "correlation": set(CorrelationSettings.model_fields),
    "anomaly": {"enabled", "anomaly_threshold", "min_samples", "sigma_saturation", "ml_min_score"},
    "response": {
        "mode",
        "dry_run",
        "default_block_seconds",
        "max_block_seconds",
        "max_blocked_addresses",
        "max_block_prefix_hosts",
        "allowlist_networks",
        "management_addresses",
        "webhook_url",
        "webhook_min_risk",
        "webhook_timeout_seconds",
        "rate_limit_packets_per_second",
    },
    "storage": {"retention_days", "audit_retention_days", "metrics_retention_days"},
    "telemetry": {"log_level"},
    "capture": {"interface", "bpf_filter", "home_networks"},
}

#: Windows sized at construction; changing them rebuilds traffic state.
WINDOW_FIELDS = {
    "port_scan_window_seconds",
    "brute_force_window_seconds",
    "connection_rate_window_seconds",
    "icmp_flood_window_seconds",
    "dns_window_seconds",
    "http_flood_window_seconds",
}


class ConfigService:
    def __init__(
        self, settings: Settings, database: Database, audit: AuditService, bus: EventBus
    ) -> None:
        self.settings = settings
        self.database = database
        self.audit = audit
        self.bus = bus
        self.listeners: list[Callable[[str, set[str]], None]] = []
        """Called with (section, changed fields) after a change is applied. Components
        that pre-parse settings at construction (allowlists, window sizes) refresh here."""

    def view(self) -> dict[str, Any]:
        """Current settings with secrets removed, plus what is editable."""
        data = self.settings.model_dump(mode="json")
        data["api"].pop("jwt_secret", None)
        data["api"].pop("bootstrap_admin_password", None)
        data["storage"]["database_url"] = redact_url(self.settings.storage.database_url)
        data["storage"]["redis_url"] = redact_url(self.settings.storage.redis_url)
        if data["response"].get("webhook_url"):
            data["response"]["webhook_url"] = data["response"]["webhook_url"].split("?")[0]
        return {
            "settings": data,
            "editable": {section: sorted(fields) for section, fields in EDITABLE.items()},
            "safety": {
                "banner": self.settings.safety_banner(),
                "prevention_active": self.settings.prevention_active,
                "confirmation_phrase": PREVENTION_CONFIRMATION,
                "firewall_backend": self.settings.response.firewall_backend,
            },
        }

    async def load_overrides(self) -> None:
        """Apply persisted runtime changes on startup. Invalid ones are skipped and logged."""
        async with self.database.session() as session:
            stored = await SettingRepository(session).all()
        for section, values in stored.items():
            try:
                self._apply(section, values, allow_prevention=True)
            except (ConfigurationError, ValidationError) as exc:
                log.error("stored_setting_invalid", section=section, error=str(exc))
        if stored:
            log.info(
                "setting_overrides_loaded",
                sections=sorted(stored),
                banner=self.settings.safety_banner(),
            )

    async def update(
        self,
        section: str,
        changes: dict[str, Any],
        *,
        actor: str,
        source: str,
        confirmation: str | None = None,
    ) -> dict[str, Any]:
        """Validate, apply, persist and audit a change to one section.

        Raises:
            ConfigurationError: for unknown sections, non-editable fields, invalid
                values, or enabling prevention without the confirmation phrase.
        """
        before_banner = self.settings.safety_banner()
        before = (
            getattr(self.settings, section).model_dump(mode="json")
            if hasattr(self.settings, section)
            else {}
        )
        enabling = self._would_enable_prevention(section, changes)
        if enabling and confirmation != PREVENTION_CONFIRMATION:
            raise ConfigurationError(
                f"enabling prevention allows SentinelX to modify this host's firewall automatically; "
                f"resend with confirmation '{PREVENTION_CONFIRMATION}'"
            )
        try:
            applied = self._apply(section, changes, allow_prevention=enabling)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()
            )
            raise ConfigurationError(f"invalid {section} settings: {problems}") from exc

        async with self.database.session() as session:
            repo = SettingRepository(session)
            existing = (await repo.all()).get(section, {})
            await repo.set(section, {**existing, **applied}, actor)

        diff = {
            key: {"from": before.get(key), "to": value}
            for key, value in applied.items()
            if before.get(key) != value
        }
        await self.audit.record(
            actor=actor,
            action="ENABLE_PREVENTION" if enabling else "UPDATE_SETTINGS",
            target=section,
            source=source,
            details={"changes": diff},
        )
        after_banner = self.settings.safety_banner()
        if before_banner != after_banner:
            log.warning(
                "safety_posture_changed", before=before_banner, after=after_banner, actor=actor
            )
        await self.bus.publish(
            EventType.CONFIG_CHANGED,
            {"section": section, "changes": diff, "safety": after_banner, "actor": actor},
        )
        return self.view()

    def _would_enable_prevention(self, section: str, changes: dict[str, Any]) -> bool:
        if section != "response":
            return False
        mode = ResponseMode(changes.get("mode", self.settings.response.mode))
        dry_run = changes.get("dry_run", self.settings.response.dry_run)
        return (
            mode is ResponseMode.AUTOMATIC
            and dry_run is False
            and not self.settings.prevention_active
        )

    def _apply(
        self, section: str, changes: dict[str, Any], *, allow_prevention: bool
    ) -> dict[str, Any]:
        if section not in EDITABLE:
            raise ConfigurationError(f"section '{section}' cannot be changed at runtime")
        illegal = sorted(set(changes) - EDITABLE[section])
        if illegal:
            raise ConfigurationError(
                f"not editable at runtime (set via environment and restart): {', '.join(illegal)}"
            )
        current: BaseModel = getattr(self.settings, section)
        validated = type(current).model_validate({**current.model_dump(), **changes})
        if (
            isinstance(validated, ResponseSettings)
            and validated.prevention_active
            and not allow_prevention
        ):
            raise ConfigurationError(
                "stored settings would enable prevention; refusing to apply them without confirmation"
            )
        applied = {}
        for key in changes:
            value = getattr(validated, key)
            setattr(current, key, value)  # mutate in place: running components hold this object
            applied[key] = validated.model_dump(mode="json")[key]
        for listener in self.listeners:
            listener(section, set(changes))
        if section == "telemetry" and "log_level" in changes:
            import logging

            logging.getLogger().setLevel(getattr(logging, str(changes["log_level"])))
        return applied


def redact_url(url: str) -> str:
    """A connection URL with its password hidden, for display."""
    from sqlalchemy.engine.url import make_url

    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "[unparseable url]"
