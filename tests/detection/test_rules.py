from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx.common.enums import ActionType
from sentinelx.signatures import (
    ConditionSyntaxError,
    Rule,
    load_rules,
    parse_condition,
    run_rule_on_frames,
    run_rule_tests,
)
from sentinelx.signatures.dsl import And, Comparison, Not, Or, evaluate, validate_semantics
from sentinelx.signatures.rules import parse_duration, parse_rule_document, validate_rule
from sentinelx.testing import get_scenario, write_pcap

REPO_RULES = Path(__file__).resolve().parents[2] / "rules"


class TestParser:
    def test_precedence_not_binds_tighter_than_and_than_or(self) -> None:
        node = parse_condition("protocol == TCP or destination_port == 22 and not ttl > 5")
        assert isinstance(node, Or)
        assert isinstance(node.items[1], And) and isinstance(node.items[1].items[1], Not)

    def test_values_lists_strings_booleans(self) -> None:
        node = parse_condition(
            'destination_port in [22, 2222] and http_host endswith ".test" and handshake_complete == false'
        )
        assert isinstance(node, And)
        first, second, third = node.items
        assert isinstance(first, Comparison) and first.value == (22, 2222)
        assert isinstance(second, Comparison) and second.value == ".test"
        assert isinstance(third, Comparison) and third.value is False

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "protocol ==",
            "== TCP",
            "protocol TCP",
            "(protocol == TCP",
            "protocol == TCP)",
            "protocol == TCP and",
            "destination_port in []",
            "destination_port in [1, [2]]",
            "protocol == TCP; import os",
            "__import__('os').system('id')",
            "protocol == `id`",
            "handshake_complete",
            "not not not handshake_complete",
        ],
    )
    def test_rejects_malformed_and_code_like_input(self, text: str) -> None:
        with pytest.raises(ConditionSyntaxError):
            parse_condition(text)

    def test_resource_limits(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="characters"):
            parse_condition("ttl > 1 and " * 300 + "ttl > 1")
        with pytest.raises(ConditionSyntaxError, match="deeper"):
            parse_condition("(" * 40 + "ttl > 1" + ")" * 40)
        with pytest.raises(ConditionSyntaxError, match="list exceeds"):
            parse_condition("destination_port in [" + ",".join(["1"] * 150) + "]")

    def test_error_reports_position(self) -> None:
        with pytest.raises(ConditionSyntaxError) as excinfo:
            parse_condition("protocol == TCP and ttl ! 5")
        assert excinfo.value.position == 24


class TestSemantics:
    @pytest.mark.parametrize(
        ("text", "fragment"),
        [
            ("protocl == TCP", "unknown field"),
            ("protocol > 5", "numeric field"),
            ("destination_port contains 22", "text field"),
            ("destination_port in 22", "needs a list"),
            ('source_ip in_network "not-a-net"', "not a valid network"),
            ("destination_port == ssh", "compare with a number"),
            ("handshake_complete == yes", "true or false"),
        ],
    )
    def test_type_errors(self, text: str, fragment: str) -> None:
        problems = validate_semantics(parse_condition(text))
        assert any(fragment in p for p in problems), problems

    def test_all_problems_reported_together(self) -> None:
        assert (
            len(
                validate_semantics(parse_condition("nope == 1 and protocol > 3 and ttl contains x"))
            )
            >= 3
        )


class TestEvaluation:
    def evaluate(self, text: str, values: dict[str, object]) -> tuple[bool, list[str]]:
        matched: list[tuple[Comparison, object]] = []
        result = evaluate(parse_condition(text), values.get, matched)
        return result, [c.field for c, _ in matched]

    def test_string_comparison_is_case_insensitive(self) -> None:
        assert self.evaluate("protocol == TCP", {"protocol": "tcp"})[0]

    def test_missing_value_never_matches_even_inequality(self) -> None:
        assert not self.evaluate("dns_query_name != x", {})[0]

    def test_in_network(self) -> None:
        assert self.evaluate(
            'source_ip in_network ["10.0.0.0/8", "2001:db8::/32"]', {"source_ip": "2001:db8::5"}
        )[0]
        assert not self.evaluate('source_ip in_network "10.0.0.0/8"', {"source_ip": "11.0.0.1"})[0]
        assert not self.evaluate('source_ip in_network "10.0.0.0/8"', {"source_ip": "garbage"})[0]

    def test_short_circuit_avoids_resolving_later_fields(self) -> None:
        resolved: list[str] = []

        def resolve(name: str) -> object:
            resolved.append(name)
            return {"protocol": "udp"}.get(name)

        evaluate(parse_condition("protocol == TCP and short_sessions > 5"), resolve)
        assert resolved == ["protocol"]

    def test_evidence_excludes_negated_matches(self) -> None:
        result, fields = self.evaluate(
            "ttl > 1 and not protocol == udp", {"ttl": 64, "protocol": "tcp"}
        )
        assert result and fields == ["ttl"]


class TestRuleValidation:
    def rule(self, **overrides: object) -> Rule:
        base: dict[str, object] = {
            "name": "Test Rule",
            "condition": "protocol == TCP and short_sessions >= 20",
            "within": "60s",
        }
        return Rule.model_validate({**base, **overrides})

    def test_block_without_count_threshold_is_refused(self) -> None:
        problems = validate_rule(
            self.rule(condition="protocol == TCP", action="block_ip"), max_window_seconds=60
        )
        assert any("count threshold" in p for p in problems)

    @pytest.mark.parametrize(
        "condition",
        [
            "short_sessions >= 20 or protocol == TCP",  # one branch is unthresholded
            "not short_sessions < 20",  # negations are not trusted
            "short_sessions >= 1",  # threshold too small to be selective
            "short_sessions != 0",
        ],
    )
    def test_unselective_preventive_conditions_are_refused(self, condition: str) -> None:
        problems = validate_rule(
            self.rule(condition=condition, action="block_ip"), max_window_seconds=60
        )
        assert any("count threshold" in p for p in problems)

    def test_selective_preventive_rule_is_accepted(self) -> None:
        rule = self.rule(
            condition="(short_sessions >= 20 or failed_attempts > 50) and destination_port == 22",
            action="temporary_block",
            duration=900,
        )
        assert validate_rule(rule, max_window_seconds=60) == []

    def test_alert_rule_needs_no_threshold(self) -> None:
        assert (
            validate_rule(
                self.rule(condition="tls_is_legacy_version == true", action="log"),
                max_window_seconds=60,
            )
            == []
        )

    def test_window_longer_than_feature_history_is_refused(self) -> None:
        assert any(
            "exceeds" in p for p in validate_rule(self.rule(within="10m"), max_window_seconds=60)
        )

    def test_temporary_block_requires_duration(self) -> None:
        assert any(
            "duration" in p
            for p in validate_rule(self.rule(action="temporary_block"), max_window_seconds=60)
        )

    def test_rules_cannot_unblock(self) -> None:
        with pytest.raises(ValueError, match="unblock"):
            self.rule(action="unblock_ip")

    @pytest.mark.parametrize(
        ("value", "seconds"), [("30s", 30), ("5m", 300), ("1h", 3600), ("500ms", 0.5), (45, 45)]
    )
    def test_durations(self, value: str | int, seconds: float) -> None:
        assert parse_duration(value) == seconds

    @pytest.mark.parametrize("value", ["", "-5s", "0", "ten seconds", "5d", True])
    def test_invalid_durations(self, value: object) -> None:
        with pytest.raises(ValueError):
            parse_duration(value)  # type: ignore[arg-type]

    def test_unknown_keys_are_rejected(self) -> None:
        rules, problems = parse_rule_document(
            {"rules": [{"name": "abc", "condition": "ttl > 1", "exec": "id"}]},
            source="x",
            max_window_seconds=60,
        )
        assert rules == [] and any("exec" in p for p in problems)


class TestLoading:
    def test_repository_rules_all_valid(self) -> None:
        result = load_rules(REPO_RULES, max_window_seconds=60)
        assert result.problems == [] and len(result.rules) >= 5

    def test_every_repository_rule_has_positive_and_negative_tests_that_pass(self) -> None:
        for rule in load_rules(REPO_RULES, max_window_seconds=60).rules:
            expectations = {t.expect for t in rule.tests}
            assert "no_match" in expectations, f"{rule.id} has no negative test"
            if rule.action is not ActionType.LOG:
                assert "match" in expectations, f"{rule.id} has no positive test"
            failures = [o.as_dict() for o in run_rule_tests(rule) if not o.passed]
            assert failures == [], failures

    def test_invalid_rule_excluded_but_file_siblings_load(self, tmp_path: Path) -> None:
        (tmp_path / "r.yml").write_text(
            "rules:\n  - name: Good One\n    condition: ttl > 1\n  - name: Bad One\n    condition: ttl >\n",
            encoding="utf-8",
        )
        result = load_rules(tmp_path, max_window_seconds=60)
        assert [r.id for r in result.rules] == ["good_one"] and len(result.problems) == 1

    def test_duplicate_ids_and_invalid_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "a.yml").write_text(
            "rule:\n  name: Same Name\n  condition: ttl > 1\n", encoding="utf-8"
        )
        (tmp_path / "b.yml").write_text(
            "rule:\n  name: Same Name\n  condition: ttl > 2\n", encoding="utf-8"
        )
        (tmp_path / "c.yml").write_text("rules: [unclosed\n", encoding="utf-8")
        (tmp_path / "d.yml").write_text(
            "!!python/object/apply:os.system ['id']\n", encoding="utf-8"
        )
        result = load_rules(tmp_path, max_window_seconds=60)
        assert len(result.rules) == 1
        assert any("duplicates" in p for p in result.problems)
        assert (
            sum("not valid YAML" in p for p in result.problems) == 2
        )  # safe_load refuses python tags


class TestRuleDetection:
    def test_rule_detection_carries_rule_name_and_explicit_evidence(self) -> None:
        rule = Rule(
            name="Brute", condition="destination_port == 22 and short_sessions >= 20", within=60
        )
        result = run_rule_on_frames(rule, get_scenario("ssh_brute_force").frames)
        detection = result.detections[0]
        assert detection.detector == "rule:brute" and detection.rule_name == "Brute"
        keys = {e.key for e in detection.evidence}
        assert {"destination_port", "short_sessions", "rule"} <= keys
        assert any("in the last 60s" in e.description for e in detection.evidence)

    def test_within_narrows_counted_window(self) -> None:
        wide = Rule(name="Wide", condition="short_sessions >= 20", within=60)
        narrow = Rule(name="Narrow", condition="short_sessions >= 20", within=5)
        frames = get_scenario("ssh_brute_force").frames  # ~2 sessions per second at most
        assert run_rule_on_frames(wide, frames).matched
        assert not run_rule_on_frames(narrow, frames).matched

    async def test_run_on_pcap(self, tmp_path: Path) -> None:
        from sentinelx.signatures import run_rule_on_pcap

        path = tmp_path / "dns.pcap"
        write_pcap(path, get_scenario("dns_tunneling").frames)
        rule = Rule(
            name="Tunnel", condition="dns_label_length >= 40 and dns_query_count >= 50", within=30
        )
        result = await run_rule_on_pcap(rule, path)
        assert result.matched and result.sources == {"192.168.10.66": len(result.detections)}
