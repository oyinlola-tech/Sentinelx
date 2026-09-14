"""Rule definitions, loading and validation.

Rule file format (YAML, loaded with a restricted safe loader: no tags, aliases or deep nesting)::

    rules:
      - name: SSH Brute Force
        enabled: true
        description: Repeated short-lived SSH sessions from one source.
        condition: protocol == TCP and destination_port == 22 and short_sessions > 20
        within: 60s
        severity: high
        category: brute_force
        action: temporary_block
        duration: 900
        tests:
          - scenario: ssh_brute_force
            expect: match
          - scenario: normal_traffic
            expect: no_match

A single rule may also be written under a top-level ``rule:`` key.

Validation is deliberately strict, and reports *every* problem at once:

* unknown fields, wrong operator/type pairings and malformed values;
* ``within`` longer than the feature engine retains (the rule could never see
  that much history, so it would silently under-count);
* **a preventive action on a rule with no count threshold.** ``protocol == TCP``
  with ``action: block_ip`` would block every TCP speaker on the network. A rule
  that can block must include at least one ``>`` / ``>=`` comparison on a counted
  behaviour with a value of 2 or more, and must not be satisfiable by a bare
  ``or`` branch lacking one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinelx.common.enums import ActionType, Severity, ThreatCategory
from sentinelx.common.errors import RuleValidationError
from sentinelx.signatures.dsl import (
    FIELDS,
    And,
    Comparison,
    ConditionSyntaxError,
    FieldKind,
    Node,
    Or,
    parse_condition,
    validate_semantics,
)

__all__ = [
    "LoadResult",
    "Rule",
    "RuleTest",
    "load_rule_yaml",
    "load_rules",
    "parse_duration",
    "parse_rule_document",
    "rule_to_yaml",
    "slugify",
    "validate_rule",
]

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*$", re.IGNORECASE)
_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}
MAX_RULE_FILE_BYTES = 1_048_576


def parse_duration(value: str | int | float) -> float:
    """Parse ``60``, ``60s``, ``5m``, ``1h`` or ``500ms`` into seconds.

    Raises:
        ValueError: for anything else.
    """
    if isinstance(value, bool):
        raise ValueError(f"invalid duration {value!r}")
    if isinstance(value, (int, float)):
        seconds = float(value)
    else:
        match = _DURATION_RE.match(str(value))
        if match is None:
            raise ValueError(f"invalid duration {value!r}; use e.g. 30s, 5m or 1h")
        unit = match.group(2).lower() if match.group(2) else None
        seconds = float(match.group(1)) * _UNITS[unit]
    if seconds <= 0:
        raise ValueError(f"duration must be positive, got {value!r}")
    return seconds


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return slug[:64] or "rule"


class RuleTest(BaseModel):
    """An embedded expectation, run by ``sentinelx rules test``."""

    model_config = ConfigDict(extra="forbid")

    scenario: str
    expect: Literal["match", "no_match"]
    params: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    """A validated custom detection rule."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    name: str = Field(min_length=3, max_length=120)
    id: str = ""
    description: str = Field(default="", max_length=2000)
    enabled: bool = True
    condition: str = Field(min_length=1, max_length=2000)
    within: float = Field(default=60.0, description="Observation window in seconds.")
    severity: Severity = Severity.MEDIUM
    category: ThreatCategory = ThreatCategory.POLICY_VIOLATION
    confidence: float = Field(default=0.8, ge=0.05, le=0.99)
    action: ActionType = ActionType.ALERT
    duration: int | None = Field(default=None, ge=30, le=86_400)
    tags: list[str] = Field(default_factory=list, max_length=20)
    references: list[str] = Field(default_factory=list, max_length=20)
    tests: list[RuleTest] = Field(default_factory=list, max_length=50)
    source: str = Field(default="inline", description="File path or 'api'.")

    @field_validator("within", mode="before")
    @classmethod
    def _within(cls, value: Any) -> float:
        return parse_duration(value)

    @field_validator("action")
    @classmethod
    def _action(cls, value: ActionType) -> ActionType:
        if value is ActionType.UNBLOCK_IP:
            raise ValueError("rules may not unblock addresses")
        return value

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = slugify(self.name)

    @property
    def is_preventive(self) -> bool:
        return self.action.is_preventive

    def ast(self) -> Node:
        return parse_condition(self.condition)


def _has_selective_threshold(node: Node) -> bool:
    """True when *every* way of satisfying the condition passes a count threshold.

    For ``a or b`` both branches must be selective, since either alone matches.
    For ``a and b`` one selective conjunct suffices. A negated subtree is never
    selective: ``not short_sessions < 50`` is logically a threshold, but reasoning
    about negations is exactly where a safety check should be conservative.
    """
    if isinstance(node, Comparison):
        spec = FIELDS.get(node.field)
        return (
            spec is not None
            and spec.kind is FieldKind.COUNT
            and node.operator in {">", ">="}
            and isinstance(node.value, (int, float))
            and not isinstance(node.value, bool)
            and node.value >= 2
        )
    if isinstance(node, And):
        return any(_has_selective_threshold(item) for item in node.items)
    if isinstance(node, Or):
        return all(_has_selective_threshold(item) for item in node.items)
    return False  # Not: negations are never trusted as selective


def validate_rule(rule: Rule, *, max_window_seconds: float) -> list[str]:
    """Return every semantic problem with a rule (empty when valid)."""
    problems: list[str] = []
    try:
        node = rule.ast()
    except ConditionSyntaxError as exc:
        return [f"condition: {exc}"]
    problems.extend(f"condition: {problem}" for problem in validate_semantics(node))
    from sentinelx.testing.scenarios import validate_scenario_params

    for index, test in enumerate(rule.tests, start=1):
        try:
            validate_scenario_params(test.scenario, test.params)
        except ValueError as exc:
            problems.append(f"tests[{index}]: {exc}")
    if rule.within > max_window_seconds:
        problems.append(
            f"within {rule.within:g}s exceeds the {max_window_seconds:g}s of history the feature engine keeps; "
            f"shorten it or raise the detection window settings"
        )
    if rule.is_preventive and not _has_selective_threshold(node):
        problems.append(
            f"action '{rule.action.value}' requires the condition to include a count threshold "
            f"(e.g. 'short_sessions >= 20') on every branch; without one this rule could block "
            f"every source matching '{rule.condition}'"
        )
    if rule.action is ActionType.TEMPORARY_BLOCK and rule.duration is None:
        problems.append("action 'temporary_block' requires 'duration' (seconds)")
    return problems


def parse_rule_document(
    document: Any, *, source: str, max_window_seconds: float
) -> tuple[list[Rule], list[str]]:
    """Build rules from a parsed YAML document. Returns ``(rules, problems)``."""
    if isinstance(document, dict) and "rule" in document and "rules" not in document:
        entries: Any = [document["rule"]]
    elif isinstance(document, dict) and "rules" in document:
        entries = document["rules"]
    else:
        return [], [f"{source}: expected a top-level 'rules:' list or 'rule:' mapping"]
    if not isinstance(entries, list):
        return [], [f"{source}: 'rules' must be a list"]

    rules: list[Rule] = []
    problems: list[str] = []
    for index, entry in enumerate(entries):
        label = f"{source} rule #{index + 1}"
        if not isinstance(entry, dict):
            problems.append(f"{label}: must be a mapping")
            continue
        label = f"{source} rule '{entry.get('name', index + 1)}'"
        try:
            rule = Rule.model_validate({**entry, "source": source})
        except ValidationError as exc:
            for error in exc.errors():
                location = ".".join(str(part) for part in error["loc"]) or "rule"
                problems.append(f"{label}: {location}: {error['msg']}")
            continue
        issues = validate_rule(rule, max_window_seconds=max_window_seconds)
        if issues:
            problems.extend(f"{label}: {issue}" for issue in issues)
            continue
        rules.append(rule)
    return rules, problems


@dataclass(slots=True)
class LoadResult:
    rules: list[Rule]
    problems: list[str]
    files: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems

    def raise_for_problems(self) -> None:
        if self.problems:
            raise RuleValidationError("rules", self.problems)


MAX_YAML_DEPTH = 32


class _RuleYamlLoader(yaml.SafeLoader):
    """``SafeLoader`` without anchors, aliases or deep nesting.

    Aliases let a few hundred bytes expand into gigabytes once the parsed document is
    copied (the "billion laughs" pattern), and deep nesting exhausts the parser's
    recursion. Rules need neither.
    """

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise yaml.YAMLError("YAML anchors and aliases are not allowed in rules")
        self._depth += 1
        try:
            if self._depth > MAX_YAML_DEPTH:
                raise yaml.YAMLError(f"YAML nested deeper than {MAX_YAML_DEPTH} levels")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def load_rule_yaml(text: str) -> Any:
    """Parse rule YAML safely: no tags, no aliases, bounded depth.

    Raises:
        yaml.YAMLError: for invalid or disallowed YAML.
    """
    # Cheap pre-check for flow-style nesting ("[[[[..."), which the YAML scanner would
    # otherwise tokenise in full before the composer's depth limit is reached.
    depth = deepest = 0
    for char in text:
        if char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "]}":
            depth = max(depth - 1, 0)
    if deepest > MAX_YAML_DEPTH:
        raise yaml.YAMLError(f"YAML nested deeper than {MAX_YAML_DEPTH} levels")
    return yaml.load(text, Loader=_RuleYamlLoader)  # noqa: S506 - restricted SafeLoader subclass


def load_rules(path: Path, *, max_window_seconds: float) -> LoadResult:
    """Load every ``*.yml``/``*.yaml`` file under ``path`` (or one file).

    Invalid rules are excluded and reported; valid rules in the same file still load,
    so one typo does not disable an entire rule set.  Duplicate ids are problems.
    """
    files = sorted(path.rglob("*.y*ml")) if path.is_dir() else [path] if path.exists() else []
    rules: list[Rule] = []
    problems: list[str] = []
    seen: dict[str, str] = {}
    for file in files:
        if file.suffix not in {".yml", ".yaml"}:
            continue
        if file.stat().st_size > MAX_RULE_FILE_BYTES:
            problems.append(f"{file}: larger than {MAX_RULE_FILE_BYTES} bytes")
            continue
        try:
            document = load_rule_yaml(file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            problems.append(f"{file}: not valid YAML ({exc})")
            continue
        loaded, issues = parse_rule_document(
            document, source=str(file), max_window_seconds=max_window_seconds
        )
        problems.extend(issues)
        for rule in loaded:
            if rule.id in seen:
                problems.append(f"{file}: rule id '{rule.id}' duplicates one in {seen[rule.id]}")
                continue
            seen[rule.id] = str(file)
            rules.append(rule)
    return LoadResult(rules=rules, problems=problems, files=[str(f) for f in files])


def rule_to_yaml(rule: Rule) -> str:
    data = rule.model_dump(mode="json", exclude={"source"}, exclude_defaults=False)
    data["within"] = f"{rule.within:g}s"
    if not data["tests"]:
        data.pop("tests")
    return yaml.safe_dump({"rules": [data]}, sort_keys=False, allow_unicode=True)
