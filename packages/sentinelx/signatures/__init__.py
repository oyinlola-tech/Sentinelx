"""Custom detection rules: language, loading, detector and test runner."""

from sentinelx.signatures.detector import RuleDetector
from sentinelx.signatures.dsl import FIELDS, ConditionSyntaxError, parse_condition
from sentinelx.signatures.rules import (
    LoadResult,
    Rule,
    RuleTest,
    load_rules,
    parse_rule_document,
    validate_rule,
)
from sentinelx.signatures.runner import run_rule_on_frames, run_rule_on_pcap, run_rule_tests

__all__ = [
    "FIELDS",
    "ConditionSyntaxError",
    "LoadResult",
    "Rule",
    "RuleDetector",
    "RuleTest",
    "load_rules",
    "parse_condition",
    "parse_rule_document",
    "run_rule_on_frames",
    "run_rule_on_pcap",
    "run_rule_tests",
    "validate_rule",
]
