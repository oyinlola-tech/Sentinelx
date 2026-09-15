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

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, ValidationError

from sentinelx.common.errors import ConfigurationError
from sentinelx.config.settings import (
    CorrelationSettings,
    DetectionSettings,
    ResponseSettings,
    ScoringSettings,
    Settings,
)
from sentinelx.events.bus import EventBus, EventType
from sentinelx.response.engine import webhook_display
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database
from sentinelx.storage.repositories import SettingRepository
from sentinelx.telemetry.logging import get_logger

__all__ = [
    "EDITABLE",
    "PREVENTION_CONFIRMATION",
    "WINDOW_FIELDS",
    "ConfigService",
    "redact_url",
    "redacted_settings",
]

log = get_logger(__name__)

PREVENTION_CONFIRMATION = "ENABLE PREVENTION"

#: Response fields where an explicit environment value beats a stored runtime override.
ENVIRONMENT_WINS = frozenset({"mode", "dry_run"})

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
        #: Reports whether the configured firewall can actually be changed. Set by the
        #: platform; enabling prevention is refused while it reports a failure.
        self.firewall_probe: Callable[[], Awaitable[dict[str, object]]] | None = None
        self.listeners: list[Callable[[str, set[str]], None]] = []
        """Called with (section, changed fields) after a change is applied. Components
        that pre-parse settings at construction (allowlists, window sizes) refresh here."""

    def view(self) -> dict[str, Any]:
        """Current settings with secrets removed, plus what is editable."""
        return {
            "settings": redacted_settings(self.settings),
            "editable": {section: sorted(fields) for section, fields in EDITABLE.items()},
            "safety": {
                "banner": self.settings.safety_banner(),
                "prevention_active": self.settings.prevention_active,
                "confirmation_phrase": PREVENTION_CONFIRMATION,
                "firewall_backend": self.settings.response.firewall_backend,
            },
        }

    async def load_overrides(self) -> None:
        """Apply persisted runtime changes on startup. Invalid ones are skipped and logged.

        Stored values normally win over the environment, so a threshold tuned in the
        dashboard survives a restart. The safety posture is the exception: when the
        environment explicitly sets ``RESPONSE_MODE`` or ``DRY_RUN``, that value wins,
        so an operator can always switch prevention off by editing the environment
        and restarting, whatever was enabled at runtime.
        """
        async with self.database.session() as session:
            stored = await SettingRepository(session).all()
        explicit_response = self.settings.response.model_fields_set & ENVIRONMENT_WINS
        for section, values in stored.items():
            if section == "response" and explicit_response:
                ignored = sorted(explicit_response & set(values))
                if ignored:
                    log.warning(
                        "stored_setting_overridden_by_environment",
                        section=section,
                        fields=ignored,
                        effect="the environment's safety posture applies",
                    )
                values = {k: v for k, v in values.items() if k not in explicit_response}
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
                f"this change allows SentinelX to modify this host's firewall; "
                f"resend with confirmation '{PREVENTION_CONFIRMATION}'"
            )
        if enabling and self.firewall_probe is not None:
            # Do not announce PREVENTION ACTIVE for a firewall that cannot be changed
            # (missing privileges, missing binary): every block would fail.
            health = await self.firewall_probe()
            if not health.get("ok"):
                detail = health.get("error") or health.get("reason") or health.get("state")
                raise ConfigurationError(
                    f"the {health.get('backend', 'configured')} firewall cannot be used on this "
                    f"host ({detail}); prevention was not enabled. Run 'sentinelx capabilities' "
                    "for what is missing"
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

        # The diff goes to the audit log and to every connected dashboard, so values
        # are shown the way the configuration view shows them (webhook URLs can carry
        # tokens in their path or query).
        diff = {
            key: {"from": _display(key, before.get(key)), "to": _display(key, value)}
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
        """True when ``changes`` would let SentinelX modify the firewall where it cannot now.

        That is switching dry run off (manual blocks and approvals become real) or
        switching automatic prevention on. Both need the confirmation phrase.
        """
        if section != "response":
            return False
        current = self.settings.response
        try:
            trial = ResponseSettings.model_validate({**current.model_dump(), **changes})
        except ValidationError:
            return False  # _apply reports the validation error itself
        enforcement_on = current.dry_run and not trial.dry_run
        prevention_on = trial.prevention_active and not current.prevention_active
        return enforcement_on or prevention_on

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
        was_active = self.settings.prevention_active
        validated = type(current).model_validate({**current.model_dump(), **changes})
        # Only *switching prevention on* needs confirmation. Changes made while it is
        # already on (adding an allowlist entry, say) must not be refused.
        if (
            isinstance(validated, ResponseSettings)
            and validated.prevention_active
            and not was_active
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


_SECRET_MARKERS = ("secret", "token", "password", "api_key", "apikey", "credential")
#: Settings whose names contain a marker but hold no secret (durations, policy).
_NOT_SECRET = frozenset(
    {"access_token_ttl_seconds", "refresh_token_ttl_seconds", "password_min_length"}
)


def _is_secret(key: str) -> bool:
    return key not in _NOT_SECRET and any(marker in key.lower() for marker in _SECRET_MARKERS)


def redacted_settings(settings: Settings) -> dict[str, Any]:
    """Settings as JSON with every secret removed: the one view the API and CLI show."""
    data = settings.model_dump(mode="json")
    _redact_secrets(data)
    data["storage"]["database_url"] = redact_url(settings.storage.database_url)
    data["storage"]["redis_url"] = redact_url(settings.storage.redis_url)
    if data["response"].get("webhook_url"):
        data["response"]["webhook_url"] = webhook_display(data["response"]["webhook_url"])
    return data


def _redact_secrets(data: dict[str, Any]) -> None:
    """Remove every secret-looking field, recursively (a denylist of *patterns*).

    New secret settings are hidden by default as long as their names say what they
    are; the test suite checks that known secrets never appear in the view.
    """
    for key in list(data):
        value = data[key]
        if isinstance(value, dict):
            _redact_secrets(value)
        elif _is_secret(key):
            data[key] = "[redacted]" if value else ""


def _display(key: str, value: Any) -> Any:
    """A setting value as it may be shown to any dashboard user."""
    if not value:
        return value
    if key == "webhook_url":
        return webhook_display(str(value))
    if _is_secret(key):
        return "[redacted]"
    return value


def redact_url(url: str) -> str:
    """A connection URL with its password hidden, for display."""
    from sqlalchemy.engine.url import make_url

    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "[unparseable url]"
