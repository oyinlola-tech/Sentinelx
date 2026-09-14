"""The composition root.

Builds every component once, in dependency order, and owns their lifecycle.  The
API server and the CLI both construct a :class:`Platform`, which is what makes "the
CLI and the dashboard use the same core services" literally true: there is one
object graph, and two front-ends over it.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx import __version__
from sentinelx.common.netutils import parse_networks
from sentinelx.config.settings import Settings
from sentinelx.detection.policy import DenylistDetector
from sentinelx.events.bus import EventBus, EventType
from sentinelx.features.extractor import FeatureExtractor
from sentinelx.firewall import FirewallAdapter, create_firewall
from sentinelx.pipeline import Pipeline
from sentinelx.services.auth import AuthService
from sentinelx.services.config import WINDOW_FIELDS, ConfigService
from sentinelx.services.queries import QueryService
from sentinelx.services.replay import ReplayService
from sentinelx.services.rules import RuleService
from sentinelx.services.sensor import SensorService
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database
from sentinelx.storage.persister import EventPersister
from sentinelx.storage.redis_state import SharedState
from sentinelx.storage.repositories import BlockRepository, RetentionRepository
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import ProcessSampler, metrics
from sentinelx.threat_intel import LocalAllowlistProvider, LocalDenylistProvider, ThreatIntelService

__all__ = ["Platform"]

log = get_logger(__name__)


class Platform:
    def __init__(self, settings: Settings, *, firewall: FirewallAdapter | None = None) -> None:
        self.settings = settings
        self.bus = EventBus(queue_size=5000)
        self.database = Database(settings.storage)
        self.state = SharedState(settings.storage)
        self.audit = AuditService(self.database, self.bus)
        self.config = ConfigService(settings, self.database, self.audit, self.bus)
        self.auth = AuthService(settings.api, self.database, self.state)
        self.rules = RuleService(settings, self.database, self.audit, self.bus)
        self._firewall_override = firewall
        self.pipeline: Pipeline | None = None
        self.sensor: SensorService | None = None
        self.replay: ReplayService | None = None
        self.queries: QueryService | None = None
        self.persister: EventPersister | None = None
        self.intel: ThreatIntelService | None = None
        self.bootstrap_password: str | None = None
        self._background: list[asyncio.Task[None]] = []
        self._sampler = ProcessSampler()
        self.started = False

    async def start(
        self,
        *,
        create_schema: bool | None = None,
        persist: bool = True,
        background: bool = True,
        bootstrap: bool = True,
    ) -> None:
        """Start everything. Order matters and is commented where it does.

        Args:
            create_schema: see :meth:`Database.connect`.
            persist: write pipeline events to the database.
            background: run the health publisher and retention loops. Short-lived
                CLI commands turn this off.
            bootstrap: create the first administrator if no users exist.
        """
        await self.database.connect(create_schema=create_schema)
        await self.state.connect()
        # Overrides are applied before the pipeline exists, so components that parse
        # settings at construction (allowlists, windows) see the effective values.
        await self.config.load_overrides()

        intel_dir = Path(self.settings.rules_directory) / "intel"
        self.intel = ThreatIntelService(
            [
                LocalAllowlistProvider(path=intel_dir / "allowlist.txt"),
                LocalDenylistProvider(path=intel_dir / "denylist.txt"),
            ]
        )
        firewall = self._firewall_override or create_firewall(self.settings.response)
        self.pipeline = Pipeline(
            self.settings, bus=self.bus, firewall=firewall, audit=self.audit.sink, intel=self.intel
        )
        self._attach_anomaly_detectors(self.pipeline)
        self.config.listeners.append(self._on_settings_changed)

        await self.rules.sync_files()
        self.rules.attach(self.pipeline.detection)
        active = await self.rules.apply()

        known_expiries = await self._recorded_block_expiries()
        await self.pipeline.start(known_expiries)
        await self._reconcile_block_records()
        if persist:
            self.persister = EventPersister(self.database, self.bus, self.settings)
            await self.persister.start()
        self.sensor = SensorService(self.settings, self.pipeline, self.bus)
        self.replay = ReplayService(self.settings, self.database, self.bus, self.rules, self.audit)
        self.queries = QueryService(self.database, self.pipeline)
        if bootstrap:
            self.bootstrap_password = await self.auth.ensure_bootstrap_admin()

        if background:
            self._background.append(asyncio.create_task(self._health_loop(), name="health"))
            self._background.append(asyncio.create_task(self._retention_loop(), name="retention"))
        self.started = True
        log.info(
            "platform_started",
            version=__version__,
            rules=active,
            safety=self.settings.safety_banner(),
            database=self.database.dialect,
            redis_degraded=self.state.degraded,
        )

    def _attach_anomaly_detectors(self, pipeline: Pipeline) -> None:
        anomaly = self.settings.anomaly
        if anomaly.enabled:
            from sentinelx.anomaly import StatisticalAnomalyDetector

            pipeline.detection.add_detector(
                StatisticalAnomalyDetector(anomaly, self.settings.detection)
            )
        if anomaly.ml_enabled:
            from sentinelx.anomaly.ml import MlAnomalyDetector, load_model

            try:
                bundle = load_model(Path(anomaly.ml_model_path))
            except Exception as exc:
                # ML is optional; a missing or untrusted model must not stop detection.
                log.error("ml_model_unavailable", error=str(exc), effect="ML detector disabled")
            else:
                pipeline.detection.add_detector(
                    MlAnomalyDetector(bundle, anomaly, self.settings.detection)
                )

    def _on_settings_changed(self, section: str, fields: set[str]) -> None:
        pipeline = self.pipeline
        if pipeline is None:
            return
        if section == "response" and fields & {"allowlist_networks", "management_addresses"}:
            guard = pipeline.response.guard
            guard.update_allowlist(self.settings.response.allowlist_networks)
            guard.update_management(self.settings.response.management_addresses)
        if section == "detection":
            if "allowlist_networks" in fields:
                pipeline.detection.update_allowlist(self.settings.detection.allowlist_networks)
            if "denylist_networks" in fields:
                denylist = pipeline.detection.get("denylist")
                if isinstance(denylist, DenylistDetector):
                    denylist.update(self.settings.detection.denylist_networks)
            if fields & WINDOW_FIELDS:
                pipeline.extractor = FeatureExtractor(self.settings.detection)
                log.warning(
                    "feature_windows_rebuilt", reason="window settings changed; traffic state reset"
                )
        if section == "capture" and "home_networks" in fields:
            from sentinelx.parser.decoder import PacketDecoder

            pipeline.decoder = PacketDecoder(parse_networks(self.settings.capture.home_networks))

    async def stop(self) -> None:
        for task in self._background:
            task.cancel()
        for task in self._background:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._background.clear()
        if self.sensor is not None and self.sensor.running:
            await self.sensor.stop()
        if self.replay is not None:
            await self.replay.shutdown()
        if self.persister is not None:
            await self.persister.stop()
        if self.pipeline is not None:
            await self.pipeline.stop()
        await self.state.close()
        await self.database.close()
        self.started = False
        log.info("platform_stopped")

    # ------------------------------------------------------------- background

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(5)
            try:
                await self.bus.publish(EventType.SYSTEM_HEALTH, await self.health())
            except Exception:
                log.exception("health_publish_failed")

    async def _retention_loop(self) -> None:
        await asyncio.sleep(60)
        while True:
            try:
                await self.run_retention()
            except Exception:
                log.exception("retention_failed")
            await asyncio.sleep(6 * 3600)

    async def run_retention(self) -> dict[str, int]:
        storage = self.settings.storage
        async with self.database.session() as session:
            purged = await RetentionRepository(session).purge(
                retention_days=storage.retention_days,
                audit_days=storage.audit_retention_days,
                metrics_days=storage.metrics_retention_days,
            )
        if any(purged.values()):
            log.info("retention_purged", **purged)
        return purged

    # ------------------------------------------------------------------ status

    async def _recorded_block_expiries(self) -> dict[str, datetime]:
        """Expiry deadlines of blocks recorded as active, keyed by network."""
        async with self.database.session() as session:
            records = await BlockRepository(session).active()
        expiries: dict[str, datetime] = {}
        for record in records:
            if record.expires_at is not None:
                expires = record.expires_at
                expiries[record.network] = (
                    expires if expires.tzinfo else expires.replace(tzinfo=UTC)
                )
        return expiries

    async def _reconcile_block_records(self) -> None:
        """Mark recorded blocks inactive when the firewall no longer enforces them.

        A block can end while SentinelX is stopped (nftables expires elements in the
        kernel, an operator flushes the table); the history must not keep showing it.
        """
        if self.pipeline is None:
            return
        enforced = {entry.network for entry in await self.pipeline.response.blocked()}
        async with self.database.session() as session:
            repository = BlockRepository(session)
            for record in await repository.active():
                if record.network not in enforced:
                    await repository.deactivate(
                        record.network, removal_reason="no longer present in the firewall"
                    )

    async def health(self) -> dict[str, Any]:
        process = self._sampler.sample()
        database = await self.database.health()
        redis = await self.state.health()
        pipeline = self.pipeline
        firewall = await pipeline.response.firewall.health() if pipeline else {"ok": False}
        components = {
            "database": database,
            "redis": redis,
            "firewall": firewall,
            "event_bus": self.bus.stats(),
            "persister": {
                "ok": self.persister is None or self.persister.failed_batches == 0,
                "written": self.persister.written if self.persister else 0,
                "failed_batches": self.persister.failed_batches if self.persister else 0,
            },
            "sensor": self.sensor.status() if self.sensor else None,
            "rules": {
                "ok": not self.rules.load_problems,
                "problems": self.rules.load_problems[:20],
            },
        }
        # Redis degraded mode is a warning, not an outage: the platform still works.
        status = "ok" if database["ok"] else "error"
        if status == "ok" and (
            redis.get("degraded") or self.rules.load_problems or not firewall.get("ok", True)
        ):
            status = "degraded"
        metrics.queue_depth.set(self.bus.stats()["handler_backlog"])
        return {
            "status": status,
            "version": __version__,
            "sensor": self.settings.sensor_name,
            "environment": self.settings.environment,
            "safety": self.settings.safety_banner(),
            "prevention_active": self.settings.prevention_active,
            "process": process,
            "components": components,
        }

    def require(self) -> tuple[Pipeline, SensorService, ReplayService, QueryService]:
        if (
            self.pipeline is None
            or self.sensor is None
            or self.replay is None
            or self.queries is None
        ):
            raise RuntimeError("platform has not been started")
        return self.pipeline, self.sensor, self.replay, self.queries
