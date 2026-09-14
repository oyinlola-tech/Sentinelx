"""Rule management.

Two origins of rules share one store:

* **file** rules live in ``RULES_DIRECTORY`` and are version-controlled. They are
  synced into the database at startup. Their definition can only change by
  editing the file; from the dashboard they can only be enabled or disabled.
* **api** rules are created in the dashboard or API and live only in the database.

Every definition is re-validated whenever it is loaded, so a rule that was valid
under an older version of the language cannot slip into the engine unchecked.
Changes are applied to the running engine immediately.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import yaml

from sentinelx.common.errors import RuleValidationError
from sentinelx.config.settings import Settings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.events.bus import EventBus, EventType
from sentinelx.signatures import (
    Rule,
    RuleDetector,
    load_rules,
    parse_rule_document,
    run_rule_on_frames,
    run_rule_on_pcap,
    run_rule_tests,
)
from sentinelx.signatures.dsl import FIELDS
from sentinelx.signatures.rules import rule_to_yaml
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database
from sentinelx.storage.models import RuleRecord
from sentinelx.storage.repositories import RuleRepository
from sentinelx.telemetry.logging import get_logger
from sentinelx.testing import get_scenario

__all__ = ["RuleService", "max_rule_window"]

log = get_logger(__name__)


def max_rule_window(settings: Settings) -> float:
    detection = settings.detection
    return max(
        detection.port_scan_window_seconds,
        detection.brute_force_window_seconds,
        detection.connection_rate_window_seconds,
        detection.icmp_flood_window_seconds,
        detection.dns_window_seconds,
        detection.http_flood_window_seconds,
    )


class RuleService:
    def __init__(
        self, settings: Settings, database: Database, audit: AuditService, bus: EventBus
    ) -> None:
        self.settings = settings
        self.database = database
        self.audit = audit
        self.bus = bus
        self.engines: list[DetectionEngine] = []
        self.load_problems: list[str] = []

    @property
    def max_window(self) -> float:
        return max_rule_window(self.settings)

    # ------------------------------------------------------------- parsing

    def parse(self, definition: str, *, source: str = "api") -> Rule:
        """Parse and fully validate one rule from YAML.

        Raises:
            RuleValidationError: listing every problem found.
        """
        try:
            document = yaml.safe_load(definition)
        except yaml.YAMLError as exc:
            raise RuleValidationError("rule", [f"not valid YAML: {exc}"]) from exc
        rules, problems = parse_rule_document(
            document, source=source, max_window_seconds=self.max_window
        )
        if problems:
            raise RuleValidationError(rules[0].name if rules else "rule", problems)
        if len(rules) != 1:
            raise RuleValidationError("rule", [f"expected exactly one rule, found {len(rules)}"])
        return rules[0]

    def validate(self, definition: str) -> dict[str, Any]:
        """Validation result for the editor. Never raises for bad input."""
        try:
            rule = self.parse(definition)
        except RuleValidationError as exc:
            return {"valid": False, "problems": exc.problems, "rule": None}
        return {"valid": True, "problems": [], "rule": self._describe_rule(rule)}

    # --------------------------------------------------------------- storage

    async def sync_files(self) -> None:
        """Load file rules into the database, keeping each rule's enabled flag."""
        directory = Path(self.settings.rules_directory)
        result = load_rules(directory, max_window_seconds=self.max_window)
        self.load_problems = result.problems
        for problem in result.problems:
            log.error("rule_file_invalid", problem=problem)
        async with self.database.session() as session:
            repo = RuleRepository(session)
            existing = {record.rule_id: record for record in await repo.all()}
            file_ids = set()
            for rule in result.rules:
                file_ids.add(rule.id)
                record = existing.get(rule.id)
                if record is not None and record.origin == "api":
                    self.load_problems.append(
                        f"{rule.source}: rule id '{rule.id}' is already used by an API rule; file rule skipped"
                    )
                    continue
                await repo.upsert(
                    rule.id,
                    name=rule.name,
                    definition=rule_to_yaml(rule),
                    origin="file",
                    source_path=rule.source,
                    enabled=record.enabled if record is not None else rule.enabled,
                )
            for rule_id, record in existing.items():
                if record.origin == "file" and rule_id not in file_ids:
                    await repo.delete(rule_id)  # file removed from disk
        log.info(
            "rules_synced",
            files=len(result.files),
            rules=len(result.rules),
            problems=len(result.problems),
        )

    async def active_rules(self) -> list[Rule]:
        rules: list[Rule] = []
        async with self.database.session() as session:
            records = await RuleRepository(session).all()
        for record in records:
            try:
                rule = self.parse(record.definition, source=record.source_path or record.origin)
            except RuleValidationError as exc:
                log.error("stored_rule_invalid", rule_id=record.rule_id, problems=exc.problems)
                continue
            rule.enabled = record.enabled
            rules.append(rule)
        return rules

    def attach(self, engine: DetectionEngine) -> None:
        if engine not in self.engines:
            self.engines.append(engine)

    async def apply(self) -> int:
        """Rebuild rule detectors in every attached engine."""
        rules = await self.active_rules()
        for engine in self.engines:
            for detector in [d for d in engine.detectors if d.name.startswith("rule:")]:
                engine.remove_detector(detector.name)
            for rule in rules:
                engine.add_detector(RuleDetector(rule, self.settings.detection))
        return sum(1 for rule in rules if rule.enabled)

    # ------------------------------------------------------------ operations

    async def list_rules(self) -> list[dict[str, Any]]:
        async with self.database.session() as session:
            records = await RuleRepository(session).all()
        stats = {d.name: d.stats() for engine in self.engines[:1] for d in engine.detectors}
        output = []
        for record in records:
            try:
                rule = self.parse(record.definition, source=record.source_path or record.origin)
                description, problems = self._describe_rule(rule), []
            except RuleValidationError as exc:
                description, problems = {}, exc.problems
            output.append(
                {
                    "rule_id": record.rule_id,
                    "name": record.name,
                    "enabled": record.enabled,
                    "origin": record.origin,
                    "source_path": record.source_path,
                    "definition": record.definition,
                    "updated_at": record.updated_at.isoformat(),
                    "updated_by": record.updated_by,
                    "valid": not problems,
                    "problems": problems,
                    "stats": stats.get(f"rule:{record.rule_id}"),
                    **description,
                }
            )
        return output

    async def get(self, rule_id: str) -> dict[str, Any] | None:
        return next((rule for rule in await self.list_rules() if rule["rule_id"] == rule_id), None)

    async def create(self, definition: str, *, actor: str, source: str) -> dict[str, Any]:
        rule = self.parse(definition)
        async with self.database.session() as session:
            repo = RuleRepository(session)
            if await repo.get(rule.id) is not None:
                raise RuleValidationError(rule.name, [f"a rule with id '{rule.id}' already exists"])
            await repo.upsert(
                rule.id,
                name=rule.name,
                definition=rule_to_yaml(rule),
                origin="api",
                enabled=rule.enabled,
                updated_by=actor,
            )
        await self._changed(
            "CREATE_RULE",
            rule.id,
            actor,
            source,
            {"condition": rule.condition, "action": rule.action.value},
        )
        return await self.get(rule.id) or {}

    async def update(
        self, rule_id: str, definition: str, *, actor: str, source: str
    ) -> dict[str, Any]:
        rule = self.parse(definition)
        async with self.database.session() as session:
            repo = RuleRepository(session)
            record = await repo.get(rule_id)
            if record is None:
                raise KeyError(rule_id)
            if record.origin == "file":
                raise RuleValidationError(
                    rule.name,
                    [f"'{rule_id}' is defined in {record.source_path}; edit the file instead"],
                )
            if rule.id != rule_id:
                raise RuleValidationError(
                    rule.name, ["renaming a rule changes its id; create a new rule instead"]
                )
            await repo.upsert(
                rule_id, name=rule.name, definition=rule_to_yaml(rule), updated_by=actor
            )
        await self._changed(
            "UPDATE_RULE",
            rule_id,
            actor,
            source,
            {"condition": rule.condition, "action": rule.action.value},
        )
        return await self.get(rule_id) or {}

    async def set_enabled(
        self, rule_id: str, enabled: bool, *, actor: str, source: str
    ) -> dict[str, Any]:
        async with self.database.session() as session:
            repo = RuleRepository(session)
            if await repo.get(rule_id) is None:
                raise KeyError(rule_id)
            await repo.upsert(rule_id, enabled=enabled, updated_by=actor)
        await self._changed(
            "ENABLE_RULE" if enabled else "DISABLE_RULE", rule_id, actor, source, {}
        )
        return await self.get(rule_id) or {}

    async def delete(self, rule_id: str, *, actor: str, source: str) -> None:
        async with self.database.session() as session:
            repo = RuleRepository(session)
            record: RuleRecord | None = await repo.get(rule_id)
            if record is None:
                raise KeyError(rule_id)
            if record.origin == "file":
                raise RuleValidationError(
                    record.name,
                    [
                        f"'{rule_id}' is defined in {record.source_path}; delete it there or disable it"
                    ],
                )
            await repo.delete(rule_id)
        await self._changed("DELETE_RULE", rule_id, actor, source, {})

    async def test(
        self, definition: str, *, scenario: str | None = None, pcap_path: Path | None = None
    ) -> dict[str, Any]:
        rule = self.parse(definition)
        if pcap_path is not None:
            result = await run_rule_on_pcap(rule, pcap_path, self.settings.detection)
            return {"target": pcap_path.name, **result.as_dict()}
        if scenario is not None:
            frames = get_scenario(scenario).frames
            result = await asyncio.to_thread(
                run_rule_on_frames, rule, frames, self.settings.detection
            )
            return {"target": scenario, **result.as_dict()}
        outcomes = await asyncio.to_thread(run_rule_tests, rule, self.settings.detection)
        return {
            "target": "embedded tests",
            "tests": [o.as_dict() for o in outcomes],
            "passed": all(o.passed for o in outcomes),
            "count": len(outcomes),
        }

    async def _changed(
        self, action: str, rule_id: str, actor: str, source: str, details: dict[str, Any]
    ) -> None:
        active = await self.apply()
        await self.audit.record(
            actor=actor, action=action, target=rule_id, source=source, details=details
        )
        await self.bus.publish(
            EventType.RULE_CHANGED, {"rule_id": rule_id, "action": action, "active_rules": active}
        )

    @staticmethod
    def _describe_rule(rule: Rule) -> dict[str, Any]:
        return {
            "description": rule.description,
            "condition": rule.condition,
            "within_seconds": rule.within,
            "severity": rule.severity.value,
            "category": rule.category.value,
            "confidence": rule.confidence,
            "action": rule.action.value,
            "duration": rule.duration,
            "tags": rule.tags,
            "tests": [t.model_dump() for t in rule.tests],
        }

    @staticmethod
    def fields() -> list[dict[str, str]]:
        return [
            {"name": spec.name, "kind": spec.kind.value, "description": spec.description}
            for spec in FIELDS.values()
        ]
