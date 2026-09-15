"""Rule engine matrix: loading, validation, condition semantics and code-execution safety.

Complements ``test_rules.py`` (parser basics, selectivity, repository rules) with
exhaustive tables: every field and operator evaluated against decoded traffic, every
class of invalid input, and hostile rule content.
"""

from __future__ import annotations

import ast
import os
import struct
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

import pytest

from sentinelx.common.enums import ActionType
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.features.extractor import FeatureContext, FeatureExtractor
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.signatures import FIELDS, ConditionSyntaxError, Rule, RuleDetector, load_rules
from sentinelx.signatures.detector import resolver_for
from sentinelx.signatures.dsl import comparisons, evaluate, parse_condition, validate_semantics
from sentinelx.signatures.rules import (
    MAX_RULE_FILE_BYTES,
    load_rule_yaml,
    parse_duration,
    parse_rule_document,
)
from sentinelx.testing.scenarios import (
    BASE_TIME,
    build_dns_query,
    build_dns_response,
    build_http_request,
    build_icmp,
    build_tcp,
    build_udp,
)

SIGNATURES = Path(__file__).resolve().parents[2] / "packages" / "sentinelx" / "signatures"
ATTACKER = "198.51.100.9"
VICTIM = "203.0.113.10"


def document(**fields: object) -> tuple[list[str], list[str]]:
    """Validate one rule entry; returns (loaded ids, problems)."""
    entry: dict[str, object] = {"name": "Matrix Rule", "condition": "ttl > 1", **fields}
    rules, problems = parse_rule_document(
        {"rules": [entry]}, source="matrix", max_window_seconds=60
    )
    return [r.id for r in rules], problems


def problems_for(condition: str) -> list[str]:
    return document(condition=condition)[1]


# ======================================================================= loading


class TestDirectoryLoading:
    def test_valid_and_invalid_files_mixed(self, tmp_path: Path) -> None:
        (tmp_path / "nested").mkdir()
        (tmp_path / "good.yml").write_text(
            "rules:\n  - name: Good One\n    condition: ttl > 1\n", encoding="utf-8"
        )
        (tmp_path / "nested" / "also-good.yaml").write_text(
            "rule:\n  name: Good Two\n  condition: destination_port == 22\n", encoding="utf-8"
        )
        (tmp_path / "syntax.yml").write_text("rules: [unclosed\n", encoding="utf-8")
        (tmp_path / "unknown-field.yml").write_text(
            "rule:\n  name: Bad Field\n  condition: ttl > 1\n  run: id\n", encoding="utf-8"
        )
        (tmp_path / "bad-condition.yml").write_text(
            "rule:\n  name: Bad Cond\n  condition: nope == 1\n", encoding="utf-8"
        )
        (tmp_path / "latin1.yml").write_bytes(b"rule:\n  name: Caf\xe9\n  condition: ttl > 1\n")
        (tmp_path / "notes.txt").write_text("rules: [this is not a rule file", encoding="utf-8")
        (tmp_path / "top-level-list.yml").write_text("- name: x\n", encoding="utf-8")

        result = load_rules(tmp_path, max_window_seconds=60)

        assert sorted(r.id for r in result.rules) == ["good_one", "good_two"]
        joined = "\n".join(result.problems)
        assert "syntax.yml: not valid YAML" in joined
        assert "unknown-field.yml" in joined and "run" in joined
        assert "bad-condition.yml" in joined and "unknown field 'nope'" in joined
        assert "latin1.yml: not valid YAML" in joined  # non-UTF-8 bytes
        assert "top-level-list.yml" in joined and "expected a top-level" in joined
        assert "notes.txt" not in joined
        assert not result.ok

    def test_non_regular_and_unreadable_files_are_problems_not_crashes(
        self, tmp_path: Path
    ) -> None:
        """Regression: a dangling symlink, a directory named ``*.yml`` or an unreadable
        file raised out of ``load_rules`` and discarded every other rule."""
        (tmp_path / "good.yml").write_text(
            "rule:\n  name: Survivor\n  condition: ttl > 1\n", encoding="utf-8"
        )
        (tmp_path / "dangling.yml").symlink_to(tmp_path / "missing-target.yml")
        (tmp_path / "directory.yml").mkdir()
        locked = tmp_path / "locked.yml"
        locked.write_text("rule:\n  name: Locked\n  condition: ttl > 1\n", encoding="utf-8")
        locked.chmod(0)
        try:
            result = load_rules(tmp_path, max_window_seconds=60)
        finally:
            locked.chmod(0o600)

        assert [r.id for r in result.rules] == ["survivor"]
        joined = "\n".join(result.problems)
        assert "dangling.yml: not a regular file" in joined
        assert "directory.yml: not a regular file" in joined
        if os.geteuid() != 0:  # root reads mode-000 files
            assert "locked.yml: cannot be read" in joined

    def test_oversized_file_is_refused_without_parsing(self, tmp_path: Path) -> None:
        big = tmp_path / "big.yml"
        big.write_text("# " + "x" * MAX_RULE_FILE_BYTES + "\n", encoding="utf-8")
        result = load_rules(tmp_path, max_window_seconds=60)
        assert result.rules == [] and any("larger than" in p for p in result.problems)

    def test_duplicate_ids_in_one_file_keep_the_first(self, tmp_path: Path) -> None:
        (tmp_path / "dup.yml").write_text(
            "rules:\n"
            "  - name: Same Rule\n    condition: ttl > 1\n"
            "  - name: same rule\n    condition: ttl > 2\n"
            "  - name: Other\n    id: same_rule\n    condition: ttl > 3\n",
            encoding="utf-8",
        )
        result = load_rules(tmp_path, max_window_seconds=60)
        assert [r.condition for r in result.rules] == ["ttl > 1"]
        assert sum("duplicates" in p for p in result.problems) == 2

    def test_missing_path_loads_nothing(self, tmp_path: Path) -> None:
        result = load_rules(tmp_path / "absent", max_window_seconds=60)
        assert result.rules == [] and result.problems == [] and result.files == []


class TestYamlHardening:
    @pytest.mark.parametrize(
        ("text", "fragment"),
        [
            ('a: &a ["x","x"]\nb: &b [*a,*a]\nc: [*b,*b]\n', "anchors and aliases"),
            ("base: &base {condition: ttl > 1}\nrule:\n  <<: *base\n  name: Merge\n", "anchors"),
            ("rules:\n  - " + "[" * 40 + "]" * 40 + "\n", "nested deeper"),
            (
                "a:\n" + "".join("  " * i + f"k{i}:\n" for i in range(1, 50)) + "  " * 50 + "v\n",
                "nested deeper",
            ),
            ("!!python/object/apply:os.system ['id']\n", "constructor"),
            ("rule: !!python/name:os.system\n", "constructor"),
            ("rule: !!python/object/new:subprocess.Popen [['id']]\n", "constructor"),
        ],
    )
    def test_dangerous_yaml_is_refused(self, text: str, fragment: str) -> None:
        import yaml

        with pytest.raises(yaml.YAMLError) as excinfo:
            load_rule_yaml(text)
        assert fragment in str(excinfo.value).lower()

    def test_flow_nesting_bomb_is_rejected_before_scanning(self) -> None:
        import time

        import yaml

        started = time.perf_counter()
        with pytest.raises(yaml.YAMLError, match="nested deeper"):
            load_rule_yaml("[" * 500_000)
        assert time.perf_counter() - started < 2.0


# ==================================================================== validation


class TestFieldValidation:
    @pytest.mark.parametrize(
        ("fields", "fragment"),
        [
            ({"severity": "catastrophic"}, "severity"),
            ({"severity": 5}, "severity"),
            ({"action": "shutdown"}, "action"),
            ({"action": "execute"}, "action"),
            ({"action": "BLOCK_IP"}, "action"),
            ({"action": "unblock_ip"}, "may not unblock"),
            ({"category": "apt"}, "category"),
            ({"confidence": float("nan")}, "confidence"),
            ({"confidence": 0}, "confidence"),
            ({"confidence": 1.5}, "confidence"),
            ({"duration": 29, "action": "log"}, "duration"),
            ({"duration": 86_401, "action": "log"}, "duration"),
            ({"duration": float("nan"), "action": "log"}, "duration"),
            ({"duration": "fifteen", "action": "log"}, "duration"),
            ({"within": -1}, "positive"),
            ({"within": 0}, "positive"),
            ({"within": "0s"}, "positive"),
            ({"within": "5d"}, "invalid duration"),
            ({"within": "1e3s"}, "invalid duration"),
            ({"within": float("nan")}, "finite"),  # regression: YAML .nan was accepted
            ({"within": float("inf")}, "finite"),
            ({"within": 1e308}, "exceeds"),
            ({"within": "10m"}, "exceeds"),
            ({"name": "ab"}, "name"),
            ({"name": "x" * 121}, "name"),
            ({"tags": [str(i) for i in range(21)]}, "tags"),
            ({"shell": "rm -rf /"}, "shell"),
            ({"__class__": "x"}, "__class__"),
            ({"tests": [{"scenario": "no_such_scenario", "expect": "match"}]}, "unknown scenario"),
            ({"tests": [{"scenario": "ssh_brute_force", "expect": "maybe"}]}, "expect"),
            (
                {"tests": [{"scenario": "ssh_brute_force", "expect": "match", "params": {"x": 1}}]},
                "no parameter",
            ),
            ({"condition": ""}, "condition"),
            ({"condition": "x" * 2001}, "condition"),
        ],
    )
    def test_invalid_rule_fields_are_rejected(
        self, fields: dict[str, object], fragment: str
    ) -> None:
        loaded, problems = document(**fields)
        assert loaded == [] and any(fragment in p for p in problems), problems

    def test_yaml_nan_window_is_rejected_end_to_end(self, tmp_path: Path) -> None:
        (tmp_path / "nan.yml").write_text(
            "rule:\n  name: NaN Window\n  condition: short_sessions >= 5\n  within: .nan\n",
            encoding="utf-8",
        )
        result = load_rules(tmp_path, max_window_seconds=60)
        assert result.rules == [] and any("finite" in p for p in result.problems)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_parse_duration_rejects_non_finite(self, value: float) -> None:
        with pytest.raises(ValueError, match="finite"):
            parse_duration(value)

    def test_every_action_enum_value_is_accepted_or_explicitly_refused(self) -> None:
        for action in ActionType:
            condition = "short_sessions >= 20"
            extra: dict[str, object] = (
                {"duration": 300} if action is ActionType.TEMPORARY_BLOCK else {}
            )
            loaded, problems = document(action=action.value, condition=condition, **extra)
            if action is ActionType.UNBLOCK_IP:
                assert loaded == [] and any("unblock" in p for p in problems)
            else:
                assert loaded == ["matrix_rule"], (action, problems)


class TestConditionValidation:
    @pytest.mark.parametrize(
        ("condition", "fragment"),
        [
            # ports
            ("destination_port == 65536", "not a valid port"),
            ("destination_port == -1", "not a valid port"),
            ("source_port in [22, 70000]", "not a valid port"),
            ("destination_port == 22.5", "not a valid port"),
            ('destination_port == "22"', "compare with a number"),
            ("destination_port == ssh", "compare with a number"),
            ('destination_port in ["22", 23]', "is not a number"),
            ("destination_port in [true]", "is not a number"),
            ("destination_port == true", "compare with a number"),
            # addresses and networks
            ('source_ip == "999.1.1.1"', "not a valid IP address"),
            ('destination_ip != "10.0.0.256"', "not a valid IP address"),
            ('source_ip in ["10.0.0.1", "nope"]', "not a valid IP address"),
            ('source_ip == "10.0.0.0/8"', "use in_network"),
            ('source_ip == "2001:db8::g"', "not a valid IP address"),
            ('source_ip == "2001:db8:::1"', "not a valid IP address"),
            ('source_ip in_network "999.1.1.0/24"', "not a valid network"),
            ('source_ip in_network "10.0.0.0/33"', "not a valid network"),
            ('source_ip in_network "2001:db8::/129"', "not a valid network"),
            ('source_ip in_network "fe80::zz/64"', "not a valid network"),
            ('source_ip in_network ["10.0.0.0/8", "x"]', "not a valid network"),
            ('destination_port in_network "10.0.0.0/8"', "needs an address field"),
            ("source_ip > 5", "numeric field"),
            ('source_ip contains "10."', "text field"),
            # thresholds
            ("short_sessions > -5", "cannot be negative"),
            ("packet_count >= -1", "cannot be negative"),
            ("syn_count == -3", "cannot be negative"),
            ("short_sessions > many", "needs a number"),
            ("short_sessions > true", "needs a number"),
            ("packet_count == true", "compare with a number"),
            # booleans, strings, unknown fields
            ("handshake_complete == 1", "true or false"),
            ("handshake_complete in [yes]", "list only true or false"),
            ("protocol > 1", "numeric field"),
            ("protocol contains 5", "text value"),
            ("tcp_flag == S", "unknown field"),
            ("packet.__class__.__mro__ == x", "unknown field"),
            ("__import__ == x", "unknown field"),
        ],
    )
    def test_invalid_conditions_are_reported(self, condition: str, fragment: str) -> None:
        loaded, problems = document(condition=condition)
        assert loaded == [] and any(fragment in p for p in problems), problems

    @pytest.mark.parametrize(
        "condition",
        [
            "destination_port == 0",  # port-0 traffic is itself a recon/evasion indicator
            "destination_port == 65535",
            "source_port in [0, 1, 65535]",
            "short_sessions > 0",
            "short_sessions > 99999999999999999999",  # never matches, but is not malformed
            'source_ip == "2001:DB8:0::1"',
            'source_ip in ["192.0.2.1", "::ffff:192.0.2.1"]',
            'source_ip in_network ["10.0.0.0/8", "2001:db8::/32"]',
            "handshake_complete in [true, false]",
            "syn_ratio > 0.5 and syn_ratio <= 1.0",
            "ttl < 0",  # a NUMBER field (not a count): allowed, merely never true
        ],
    )
    def test_boundary_conditions_are_accepted(self, condition: str) -> None:
        assert document(condition=condition) == (["matrix_rule"], [])

    @pytest.mark.parametrize(
        ("condition", "action"),
        [
            ("short_sessions > 0", "block_ip"),  # zero threshold matches any activity
            ("short_sessions >= 1", "rate_limit"),
            ("short_sessions > 99 or destination_port == 22", "quarantine"),
            ("not short_sessions <= 100", "block_ip"),
            ("syn_ratio > 0.9", "block_ip"),  # a ratio is not a count
        ],
    )
    def test_preventive_rules_need_a_real_count_threshold(
        self, condition: str, action: str
    ) -> None:
        loaded, problems = document(condition=condition, action=action)
        assert loaded == [] and any("count threshold" in p for p in problems)

    def test_every_problem_is_reported_at_once(self) -> None:
        problems = validate_semantics(
            parse_condition(
                'destination_port == 70000 and source_ip == "1.2.3" and nope == 1 and short_sessions > -1'
            )
        )
        assert len(problems) == 4


# ==================================================================== semantics


def tls_client_hello(sni: str, version: int = 0x0301) -> bytes:
    """A minimal TLS ClientHello record offering ``version`` with an SNI extension."""
    name = sni.encode()
    server_name = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(server_name)) + server_name
    body = (
        struct.pack("!H", version)
        + bytes(32)
        + b"\x00"
        + struct.pack("!HH", 2, 0x002F)
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!HH", version, len(handshake)) + handshake


def contexts(frames: list[tuple[bytes, float]]) -> list[FeatureContext]:
    decoder = PacketDecoder()
    extractor = FeatureExtractor(DetectionSettings())
    out = []
    for data, timestamp in frames:
        packet = decoder.decode(data, timestamp)
        assert packet is not None
        out.append(extractor.process(packet))
    return out


@pytest.fixture(scope="module")
def traffic() -> dict[str, FeatureContext]:
    """One decoded context per kind of traffic, after enough history to count."""
    t = BASE_TIME
    tcp = [
        (build_tcp(ATTACKER, VICTIM, 40000 + i, 1000 + i, flags="S", ttl=50), t + i * 0.01)
        for i in range(30)
    ]
    tcp.append((build_tcp(ATTACKER, VICTIM, 41000, 22, flags="S", ttl=50), t + 0.5))
    icmp = [(build_icmp(ATTACKER, VICTIM, sequence=i), t + i * 0.01) for i in range(12)]
    dns = [
        (
            build_dns_query(ATTACKER, VICTIM, f"{'a' * 45}{i}.tunnel.example.test", qtype=16),
            t + i * 0.01,
        )
        for i in range(8)
    ]
    http = [
        (
            build_http_request(
                ATTACKER, VICTIM, 50000 + i, method="POST", path="/login", host="shop.example.test"
            ),
            t + i * 0.01,
        )
        for i in range(5)
    ]
    tls = [
        (
            build_tcp(
                ATTACKER,
                VICTIM,
                51000,
                443,
                flags="PA",
                payload=tls_client_hello("legacy.example.test"),
            ),
            t,
        )
    ]
    udp = [(build_udp(ATTACKER, VICTIM, 5000, 6000 + i, b"x" * 10), t + i * 0.01) for i in range(7)]
    nxdomain = [(build_dns_response(VICTIM, ATTACKER, "missing.example.test", rcode=3), t)]
    return {
        "tcp": contexts(tcp)[-1],
        "icmp": contexts(icmp)[-1],
        "dns": contexts(dns)[-1],
        "http": contexts(http)[-1],
        "tls": contexts(tls)[-1],
        "udp": contexts(udp)[-1],
        "nxdomain": contexts(nxdomain)[-1],
    }


#: (traffic, condition that must hold, condition that must not hold)
FIELD_CASES: list[tuple[str, str, str]] = [
    ("tcp", "protocol == TCP", "protocol == udp"),
    ("udp", "protocol in [udp, icmp]", "protocol not in [UDP]"),
    ("tcp", f'source_ip == "{ATTACKER}"', f'source_ip != "{ATTACKER}"'),
    ("tcp", 'destination_ip in_network "203.0.113.0/24"', 'destination_ip in_network "10.0.0.0/8"'),
    ("tcp", 'source_ip not in ["192.0.2.1"]', f'source_ip not in ["{ATTACKER}"]'),
    ("tcp", "source_port >= 41000", "source_port < 41000"),
    ("tcp", "destination_port == 22", "destination_port in [80, 443]"),
    ("tcp", "packet_length > 50", "packet_length > 1500"),
    ("tls", "payload_length > 40", "payload_length <= 40"),
    ("tcp", "ttl == 50", "ttl != 50"),
    (
        "tcp",
        "direction in [inbound, outbound, internal, external, unknown]",
        "direction == sideways",
    ),
    ("tcp", "tcp_flags == S", "tcp_flags == SA"),
    ("tcp", "handshake_complete == false", "handshake_complete == true"),
    ("tcp", "flow_duration >= 0", "flow_duration > 3600"),
    ("tcp", "flow_packets == 1", "flow_packets > 1"),
    ("tcp", "packet_count == 31", "packet_count > 31"),
    ("tcp", "syn_count >= 31", "syn_count < 31"),
    ("tcp", "connection_attempts >= 0", "connection_attempts > 1000"),
    ("tcp", "failed_attempts == 0", "failed_attempts > 0"),
    ("tcp", "short_sessions == 0", "short_sessions >= 1"),
    ("tcp", "rst_count == 0", "rst_count > 0"),
    ("icmp", "icmp_count == 12", "icmp_count < 12"),
    ("dns", "dns_query_count == 8", "dns_query_count > 8"),
    ("http", "http_request_count == 5", "http_request_count != 5"),
    ("tcp", "unique_dst_ports == 31", "unique_dst_ports < 31"),
    ("tcp", "unique_dst_ips == 1", "unique_dst_ips > 1"),
    ("udp", "unique_udp_ports == 7", "unique_udp_ports > 7"),
    ("dns", "dns_unique_domains == 8", "dns_unique_domains < 8"),
    ("tcp", "syn_ratio > 0.99", "syn_ratio < 0.5"),
    ("tcp", "syn_ack_ratio == 0", "syn_ack_ratio > 0"),
    ("tcp", "refusal_ratio >= 0", "refusal_ratio > 1"),
    ("tcp", "packet_rate > 0", "packet_rate > 1000"),
    ("dns", 'dns_query_name endswith ".tunnel.example.test"', 'dns_query_name startswith "b"'),
    ("dns", "dns_query_name contains TUNNEL", 'dns_query_name contains "exfil"'),
    ("dns", "dns_query_type == TXT", "dns_query_type == A"),
    ("nxdomain", "dns_is_nxdomain == true", "dns_is_nxdomain != true"),
    ("dns", "dns_is_nxdomain == false", "dns_is_nxdomain == true"),
    ("dns", "dns_label_length >= 45", "dns_label_length > 63"),
    ("dns", "dns_name_entropy >= 0", "dns_name_entropy > 100"),
    ("http", "http_method in [GET, POST]", "http_method == get"),
    ("http", 'http_path startswith "/log"', 'http_path == "/"'),
    ("http", 'http_host endswith "example.test"', 'http_host contains "evil"'),
    ("http", 'http_user_agent contains "fixture"', 'http_user_agent contains "curl"'),
    ("tls", 'tls_sni == "legacy.example.test"', 'tls_sni endswith ".invalid"'),
    ("tls", "tls_version contains TLS", "tls_version == TLS1.3"),
    ("tls", "tls_is_legacy_version == true", "tls_is_legacy_version == false"),
    # absent values never satisfy anything, including negations of equality
    ("tcp", "not dns_query_name == x", "dns_query_name != x"),
    ("dns", "not tls_is_legacy_version == true", "tls_is_legacy_version == false"),
]


class TestFieldSemantics:
    @pytest.mark.parametrize(("kind", "true_condition", "false_condition"), FIELD_CASES)
    def test_condition_against_decoded_traffic(
        self,
        traffic: dict[str, FeatureContext],
        kind: str,
        true_condition: str,
        false_condition: str,
    ) -> None:
        resolve = resolver_for(traffic[kind], 60.0)
        for condition in (true_condition, false_condition):
            assert validate_semantics(parse_condition(condition)) == [], condition
        assert evaluate(parse_condition(true_condition), resolve), true_condition
        assert not evaluate(parse_condition(false_condition), resolve), false_condition

    def test_matrix_covers_every_field_and_operator(self) -> None:
        used = [c for _, cond, _ in FIELD_CASES for c in comparisons(parse_condition(cond))]
        used += [c for _, _, cond in FIELD_CASES for c in comparisons(parse_condition(cond))]
        assert {c.field for c in used} == set(FIELDS)
        assert {c.operator for c in used} == {
            "==", "!=", ">", ">=", "<", "<=", "in", "not in",
            "contains", "startswith", "endswith", "in_network",
        }  # fmt: skip

    def test_ipv6_addresses_compare_by_value_not_spelling(self) -> None:
        resolve: Callable[[str], object] = {"source_ip": "2001:db8::1"}.get
        assert evaluate(parse_condition('source_ip == "2001:DB8:0:0::1"'), resolve)
        assert evaluate(parse_condition('source_ip in ["192.0.2.1", "2001:db8:0::1"]'), resolve)
        assert not evaluate(parse_condition('source_ip != "2001:0db8::1"'), resolve)
        assert not evaluate(
            parse_condition('source_ip == "2001:db8::2"'), {"source_ip": "junk"}.get
        )


class TestBooleanStructure:
    VALUES: ClassVar = [
        (a, b, c) for a in (False, True) for b in (False, True) for c in (False, True)
    ]

    @staticmethod
    def resolver(a: bool, b: bool, c: bool) -> Callable[[str], object]:
        return {
            "ttl": 64 if a else 1,
            "destination_port": 22 if b else 80,
            "protocol": "tcp" if c else "udp",
        }.get

    @pytest.mark.parametrize(("a", "b", "c"), VALUES)
    def test_and_binds_tighter_than_or(self, a: bool, b: bool, c: bool) -> None:
        resolve = self.resolver(a, b, c)
        node = parse_condition("ttl > 5 or destination_port == 22 and protocol == TCP")
        assert evaluate(node, resolve) is (a or (b and c))
        grouped = parse_condition("(ttl > 5 or destination_port == 22) and protocol == TCP")
        assert evaluate(grouped, resolve) is ((a or b) and c)

    @pytest.mark.parametrize(("a", "b", "c"), VALUES)
    def test_not_binds_tightest_and_keywords_are_case_insensitive(
        self, a: bool, b: bool, c: bool
    ) -> None:
        resolve = self.resolver(a, b, c)
        node = parse_condition("NOT ttl > 5 AND destination_port == 22 OR not protocol == tcp")
        assert evaluate(node, resolve) is (((not a) and b) or (not c))
        assert evaluate(parse_condition("not (ttl > 5 or protocol == tcp)"), resolve) is not (
            a or c
        )


class TestRuntimeEnableDisable:
    def test_disabled_rule_loads_but_never_fires_until_enabled(
        self, traffic: dict[str, FeatureContext]
    ) -> None:
        rule = Rule(
            name="Toggle Me", condition="destination_port == 22 and syn_count >= 5", enabled=False
        )
        detector = RuleDetector(rule, DetectionSettings(detection_cooldown_seconds=0))
        engine = DetectionEngine(
            DetectionSettings(detection_cooldown_seconds=0), detectors=[detector]
        )
        context = traffic["tcp"]
        assert engine.evaluate(context) == [] and detector.evaluations == 0

        assert engine.set_enabled("rule:toggle_me", True)
        fired = engine.evaluate(context)
        assert [d.detector for d in fired] == ["rule:toggle_me"]

        assert engine.set_enabled("rule:toggle_me", False)
        assert engine.evaluate(context) == []


# ============================================================ no code execution


class TestNoCodeExecution:
    def test_rule_engine_source_has_no_dynamic_execution_primitives(self) -> None:
        forbidden_calls = {
            "eval",
            "exec",
            "compile",
            "__import__",
            "execfile",
            "globals",
            "locals",
            "vars",
        }
        for path in sorted(SIGNATURES.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import | ast.ImportFrom):
                    names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                    assert not {"importlib", "pickle", "marshal", "subprocess", "os"} & set(
                        names
                    ), path
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name):
                    assert func.id not in forbidden_calls, f"{path.name}:{node.lineno}"
                    if func.id in {"getattr", "setattr", "hasattr"}:
                        # Only constant attribute names: never one derived from rule text.
                        assert isinstance(node.args[1], ast.Constant), f"{path.name}:{node.lineno}"
                if isinstance(func, ast.Attribute):
                    assert func.attr not in {"format", "format_map", "system", "popen"}, (
                        f"{path.name}:{node.lineno}"
                    )
                    if func.attr == "load":  # yaml.load only with the restricted loader
                        assert any(k.arg == "Loader" for k in node.keywords), path

    @pytest.fixture
    def marker(self, tmp_path: Path) -> Path:
        return tmp_path / "pwned"

    def malicious_conditions(self, marker: Path) -> list[str]:
        return [
            f"__import__('os').system('touch {marker}')",
            f"ttl > 1 and __import__('os').system('touch {marker}') == 0",
            'ttl > 1 or "{{7*7}}" == 49',
            "{{7*7}} == 49",
            "${7*7} == 49",
            f"$(touch {marker}) == x",
            f"`touch {marker}` == x",
            "packet.__class__.__mro__ == x",
            "packet.__class__.__mro__[1].__subclasses__() == x",
            "ttl.__class__ == int",
            "protocol == TCP; import os",
            "lambda: 1 == 1",
            "ttl > (1).__class__",
            f"open('{marker}', 'w') == x",
            "ttl > 1 if True else 0",
            "protocol == %(x)s",
        ]

    def test_malicious_conditions_are_rejected_with_no_side_effect(self, marker: Path) -> None:
        for condition in self.malicious_conditions(marker):
            loaded, problems = document(condition=condition)
            assert loaded == [] and problems, condition
            with pytest.raises((ConditionSyntaxError, AssertionError)):
                node = parse_condition(condition)
                assert validate_semantics(node) == []  # parsed ones must fail validation
        assert not marker.exists()

    def test_unvalidated_rules_still_cannot_reach_attributes(
        self, traffic: dict[str, FeatureContext], marker: Path
    ) -> None:
        """Even bypassing validation, a field name is a table key, never an attribute."""
        rule = Rule(name="Sneaky", condition="packet.__class__.__mro__ == x or __dict__ != y")
        detector = RuleDetector(rule, DetectionSettings(detection_cooldown_seconds=0))
        assert detector.inspect(traffic["tcp"]) is None
        assert not marker.exists()

    def test_malicious_yaml_documents_are_rejected_with_no_side_effect(
        self, tmp_path: Path, marker: Path
    ) -> None:
        payloads = {
            "apply.yml": f"!!python/object/apply:os.system ['touch {marker}']\n",
            "nested.yml": f"rule:\n  name: X\n  condition: !!python/object/apply:os.system ['touch {marker}']\n",
            "new.yml": f"rules:\n  - !!python/object/new:subprocess.check_call [['touch', '{marker}']]\n",
            "module.yml": "rule:\n  name: !!python/module:os\n  condition: ttl > 1\n",
        }
        for name, text in payloads.items():
            (tmp_path / name).write_text(text, encoding="utf-8")
        result = load_rules(tmp_path, max_window_seconds=60)
        assert result.rules == [] and len(result.problems) == len(payloads)
        assert not marker.exists()

    def test_template_syntax_in_text_fields_stays_literal(
        self, traffic: dict[str, FeatureContext]
    ) -> None:
        rule = Rule(
            name="Template {{7*7}} ${7*7}",
            description="{0.__class__} %(x)s {{config}}",
            condition="destination_port == 22",
            tags=["{{7*7}}"],
        )
        detector = RuleDetector(rule, DetectionSettings(detection_cooldown_seconds=0))
        detection = detector.inspect(traffic["tcp"])
        assert detection is not None
        assert detection.title == "Template {{7*7}} ${7*7}"
        assert detection.description == "{0.__class__} %(x)s {{config}}"
        assert "49" not in detection.explain() and "{{7*7}}" in detection.tags
