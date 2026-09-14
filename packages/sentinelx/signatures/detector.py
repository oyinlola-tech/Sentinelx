"""Runs custom rules inside the detection engine.

Each enabled rule becomes one :class:`RuleDetector`.  It resolves fields lazily
from the packet, the flow and the source profile, narrowing counted features to
the rule's own ``within`` window.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any

from sentinelx.common.models import Detection, Evidence
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext
from sentinelx.signatures.dsl import FIELDS, FieldKind, Node, evaluate
from sentinelx.signatures.rules import Rule

__all__ = ["RuleDetector", "resolver_for"]


def _section(metadata: dict[str, Any], key: str) -> dict[str, Any]:
    value = metadata.get(key)
    return value if isinstance(value, dict) else {}


def resolver_for(context: FeatureContext, within: float) -> Any:
    """Build a caching field resolver for one packet and one window."""
    packet = context.packet
    profile = context.profile
    flow = context.flow
    cutoff = context.now - within
    source = profile.source_ip
    metadata = packet.metadata
    dns = _section(metadata, "dns")
    http = _section(metadata, "http")
    tls = _section(metadata, "tls")
    cache: dict[str, Any] = {}

    def packets_since() -> int:
        return profile.packet_times.count_since(cutoff)

    def syns_since() -> int:
        return profile.syn_packets.count_since(cutoff)

    table: dict[str, Any] = {
        "protocol": lambda: packet.protocol.value,
        "source_ip": lambda: packet.src_ip,
        "destination_ip": lambda: packet.dst_ip,
        "source_port": lambda: packet.src_port,
        "destination_port": lambda: packet.dst_port,
        "packet_length": lambda: packet.length,
        "payload_length": lambda: packet.payload_length,
        "ttl": lambda: packet.ttl,
        "direction": lambda: packet.direction.value,
        "tcp_flags": lambda: packet.tcp_flags.label() if packet.tcp_flags else None,
        "handshake_complete": lambda: flow.handshake_complete,
        "flow_duration": lambda: flow.duration,
        "flow_packets": lambda: flow.packets,
        "packet_count": packets_since,
        "syn_count": syns_since,
        "connection_attempts": lambda: profile.connections_started.count_since(cutoff),
        "failed_attempts": lambda: profile.refused_connections.count_since(cutoff),
        "short_sessions": lambda: profile.short_sessions.count_since(cutoff),
        "rst_count": lambda: profile.rst_received.count_since(cutoff),
        "icmp_count": lambda: profile.icmp_packets.count_since(cutoff),
        "dns_query_count": lambda: profile.dns_times.count_since(cutoff),
        "http_request_count": lambda: profile.http_times.count_since(cutoff),
        "unique_dst_ports": lambda: profile.dst_ports.unique_since(source, cutoff),
        "unique_dst_ips": lambda: profile.dst_ips.unique_since(source, cutoff),
        "unique_udp_ports": lambda: profile.udp_ports.unique_since(source, cutoff),
        "dns_unique_domains": lambda: profile.dns_queries.distinct_since(cutoff),
        "syn_ratio": lambda: (syns_since() / packets_since()) if packets_since() else 0.0,
        "syn_ack_ratio": lambda: (profile.syn_ack_received.count_since(cutoff) / syns_since()) if syns_since() else 0.0,
        "refusal_ratio": lambda: profile.refusal_ratio(),
        "packet_rate": lambda: packets_since() / within,
        "dns_query_name": lambda: dns.get("query_name"),
        "dns_query_type": lambda: dns.get("query_type"),
        "dns_is_nxdomain": lambda: dns.get("is_nxdomain") if dns else None,
        "dns_label_length": lambda: dns.get("max_label_length"),
        "dns_name_entropy": lambda: dns.get("name_entropy"),
        "http_method": lambda: http.get("method"),
        "http_path": lambda: http.get("path"),
        "http_host": lambda: http.get("host"),
        "http_user_agent": lambda: http.get("user_agent"),
        "tls_sni": lambda: tls.get("sni"),
        "tls_version": lambda: tls.get("version"),
        "tls_is_legacy_version": lambda: tls.get("is_legacy_version") if tls else None,
    }

    def resolve(name: str) -> Any:
        if name not in cache:
            getter = table.get(name)
            cache[name] = getter() if getter is not None else None
        return cache[name]

    return resolve


class RuleDetector(Detector):
    """A detector backed by one validated :class:`Rule`."""

    def __init__(self, rule: Rule, settings: DetectionSettings | None = None) -> None:
        super().__init__(settings)
        self.rule = rule
        self.name = f"rule:{rule.id}"
        self.description = rule.description or rule.condition
        self.category = rule.category
        self.default_severity = rule.severity
        self.references = tuple(rule.references)
        self.enabled = rule.enabled
        self._ast: Node = rule.ast()
        self.total_eval_seconds = 0.0

    def inspect(self, context: FeatureContext) -> Detection | None:
        self.evaluations += 1
        started = time.perf_counter()
        matched: list[tuple[Any, Any]] = []
        hit = evaluate(self._ast, resolver_for(context, self.rule.within), matched)
        self.total_eval_seconds += time.perf_counter() - started
        if not hit:
            return None

        evidence = [
            Evidence(
                key=comparison.field,
                value=observed,
                threshold=comparison.value if not isinstance(comparison.value, tuple) else list(comparison.value),
                description=_describe(comparison, observed, self.rule.within),
                weight=1.0 if FIELDS[comparison.field].kind is FieldKind.COUNT else 0.5,
            )
            for comparison, observed in matched
        ]
        evidence.append(
            Evidence(key="rule", value=self.rule.id, description=f"matched rule '{self.rule.name}': {self.rule.condition}", weight=0.3)
        )
        self.hits += 1
        detection = self.build(
            context=context,
            title=self.rule.name,
            description=self.rule.description or f"Traffic matched custom rule '{self.rule.name}'.",
            evidence=evidence,
            confidence=self.rule.confidence,
            severity=self.rule.severity,
            recommended_action=self.rule.action,
            observation_window=self.rule.within,
            packet_count=context.profile.packet_times.count_since(context.now - self.rule.within),
            tags=("rule", *self.rule.tags),
        )
        # rule_name is not a build() parameter and Detection is frozen.
        return replace(detection, rule_name=self.rule.name)

    def stats(self) -> dict[str, object]:
        return {
            **super().stats(),
            "rule_id": self.rule.id,
            "mean_eval_microseconds": round(1e6 * self.total_eval_seconds / self.evaluations, 2) if self.evaluations else 0.0,
        }


def _describe(comparison: Any, observed: Any, within: float) -> str:
    spec = FIELDS[comparison.field]
    if isinstance(observed, float):
        observed = round(observed, 3)
    if spec.kind is FieldKind.COUNT:
        return f"{comparison.field} = {observed} in the last {within:g}s (rule requires {comparison.operator} {comparison.value})"
    return f"{comparison.field} = {observed!r} (rule requires {comparison.describe()})"
