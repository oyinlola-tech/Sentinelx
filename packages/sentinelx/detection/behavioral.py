"""Behavioural detectors: credential guessing and floods.

These look at *rates and outcomes* rather than at any single packet.  Brute force
in particular cannot be seen in one packet at all - an SSH login attempt and an
SSH brute-force attempt are byte-for-byte the same shape.  What differs is that
the attacker does it dozens of times, each session ends almost immediately, and
each is torn down by the server.
"""

from __future__ import annotations

from sentinelx.common.enums import ActionType, Protocol, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.common.netutils import service_name
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext

__all__ = [
    "BruteForceDetector",
    "ConnectionRateDetector",
    "HttpFloodDetector",
    "IcmpFloodDetector",
    "SynFloodDetector",
]


class BruteForceDetector(Detector):
    """Repeated short-lived sessions against an authentication service.

    Reported as ``ssh_brute_force`` for port 22 (the overwhelmingly common case,
    and the name analysts search for) and ``auth_brute_force`` for the other
    configured services.

    Without payload inspection we cannot *see* a failed login.  The proxy used is
    a completed handshake followed by a teardown within seconds, repeated many
    times from one source to one service.  Legitimate users log in once and stay
    connected; automated guessing reconnects for every attempt.
    """

    name = "ssh_brute_force"
    description = "Many short-lived sessions to an authentication service from one source."
    category = ThreatCategory.BRUTE_FORCE
    default_severity = Severity.HIGH
    references = ("https://attack.mitre.org/techniques/T1110/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        flags = packet.tcp_flags
        # Evaluate at teardown - the moment a short session becomes countable.
        if flags is None or not (flags.rst or flags.fin):
            return None

        flow = context.flow
        service_port = flow.responder_port
        if service_port not in self.settings.brute_force_ports:
            return None

        attacker = flow.initiator_ip
        self.evaluations += 1
        profile = context.profile_of(attacker)
        if profile is None:
            return None

        window = self.settings.brute_force_window_seconds
        port = service_port
        count = sum(1 for p in profile.short_sessions.items() if p == port)
        if count < self.settings.brute_force_attempts:
            return None

        span = max(profile.short_sessions.span(), 0.001)
        service = service_name(port) or f"port {port}"
        rate_per_minute = count / span * 60 if span > 1 else float(count)
        refused = len(profile.refused_connections)
        detector_name = "ssh_brute_force" if port == 22 else "auth_brute_force"

        evidence = [
            Evidence(
                key="failed_attempts",
                value=count,
                threshold=self.settings.brute_force_attempts,
                description=(
                    f"{count} short-lived {service} sessions from {attacker} "
                    f"(threshold {self.settings.brute_force_attempts})"
                ),
                weight=1.0,
            ),
            Evidence(
                key="observation_window_seconds",
                value=round(span, 2),
                threshold=window,
                description=f"within {span:.1f} seconds ({rate_per_minute:.0f} attempts per minute)",
                weight=0.5,
            ),
            Evidence(
                key="session_pattern",
                value="connect-exchange-teardown",
                description=(
                    "each session completed a handshake and was torn down within seconds, "
                    "the pattern of repeated authentication failure"
                ),
                weight=0.8,
            ),
            Evidence(
                key="target_service",
                value=service,
                description=f"target is an authentication service ({service}) on {context.flow.responder_ip}",
                weight=0.6,
            ),
        ]
        if refused:
            evidence.append(
                Evidence(
                    key="server_resets",
                    value=refused,
                    description=f"the server reset {refused} of these sessions",
                    weight=0.5,
                )
            )

        confidence = self.scaled_confidence(
            count, self.settings.brute_force_attempts, floor=0.6, ceiling=0.95, saturation=4.0
        )
        severity = Severity.CRITICAL if count >= self.settings.brute_force_attempts * 4 else Severity.HIGH

        self.hits += 1
        detection = Detection(
            detector=detector_name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            title=f"{service.upper()} brute force" if port == 22 else f"Brute force against {service}",
            description=(
                f"{attacker} opened {count} short-lived {service} sessions to "
                f"{context.flow.responder_ip} in {span:.0f}s."
            ),
            source_ip=attacker,
            destination_ip=context.flow.responder_ip,
            destination_port=port,
            protocol=Protocol.TCP,
            evidence=evidence,
            recommended_action=ActionType.TEMPORARY_BLOCK,
            observation_window_seconds=round(span, 3),
            packet_count=len(profile.packets),
            tags=("brute_force", service),
        )
        return detection


class SynFloodDetector(Detector):
    """A high rate of half-open connections against one destination."""

    name = "syn_flood"
    description = "Sustained high rate of SYN packets that never complete a handshake."
    category = ThreatCategory.DENIAL_OF_SERVICE
    default_severity = Severity.HIGH
    references = ("https://attack.mitre.org/techniques/T1499/002/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        flags = context.packet.tcp_flags
        if flags is None or not flags.is_syn_only:
            return None
        self.evaluations += 1
        profile = context.profile
        syns = len(profile.syn_packets)
        if syns < self.settings.syn_flood_threshold:
            return None

        unique_ports = profile.dst_ports.unique_count(profile.source_ip, context.now)
        # Many SYNs to many ports is a scan (reported elsewhere); a flood hammers
        # few ports.
        if unique_ports > 5:
            return None
        syn_ack_ratio = profile.syn_ack_ratio()
        if syn_ack_ratio > 0.5:
            # The server is answering most of them: a busy client, not a flood.
            return None

        span = max(profile.syn_packets.span(), 0.001)
        rate = syns / span
        evidence = [
            Evidence(
                key="syn_count",
                value=syns,
                threshold=self.settings.syn_flood_threshold,
                description=f"{syns} SYN packets to {context.packet.dst_ip}:{context.packet.dst_port}",
                weight=1.0,
            ),
            Evidence(
                key="syn_rate",
                value=round(rate, 1),
                description=f"{rate:.0f} SYNs per second over {span:.1f} seconds",
                weight=0.8,
            ),
            Evidence(
                key="syn_ack_ratio",
                value=round(syn_ack_ratio, 3),
                description=f"only {syn_ack_ratio:.1%} answered - connections are left half-open",
                weight=0.7,
            ),
        ]
        self.hits += 1
        return self.build(
            context=context,
            title="SYN flood",
            description=f"{context.packet.src_ip} sent {syns} SYNs in {span:.1f}s without completing handshakes.",
            evidence=evidence,
            confidence=self.scaled_confidence(syns, self.settings.syn_flood_threshold, floor=0.65, ceiling=0.96),
            severity=Severity.CRITICAL if syns >= self.settings.syn_flood_threshold * 4 else Severity.HIGH,
            recommended_action=ActionType.RATE_LIMIT,
            observation_window=round(span, 3),
            packet_count=len(profile.packets),
            tags=("flood", "syn"),
        )


class ConnectionRateDetector(Detector):
    """Excessive connection attempts from one source, regardless of target."""

    name = "connection_rate"
    description = "Connection attempts from one source exceed the configured rate."
    category = ThreatCategory.DENIAL_OF_SERVICE
    default_severity = Severity.MEDIUM

    def inspect(self, context: FeatureContext) -> Detection | None:
        flags = context.packet.tcp_flags
        if flags is None or not flags.is_syn_only:
            return None
        self.evaluations += 1
        profile = context.profile
        window = self.settings.connection_rate_window_seconds
        cutoff = context.now - window
        attempts = sum(1 for ts in profile.connections_started.timestamps() if ts >= cutoff)
        if attempts < self.settings.connection_rate_threshold:
            return None

        rate = attempts / window
        evidence = [
            Evidence(
                key="connection_attempts",
                value=attempts,
                threshold=self.settings.connection_rate_threshold,
                description=(
                    f"{attempts} new connections in {window:.0f}s "
                    f"(threshold {self.settings.connection_rate_threshold})"
                ),
                weight=1.0,
            ),
            Evidence(
                key="connection_rate",
                value=round(rate, 1),
                description=f"{rate:.1f} connections per second",
                weight=0.7,
            ),
            Evidence(
                key="unique_destinations",
                value=profile.dst_ips.unique_count(profile.source_ip, context.now),
                description=(
                    f"spread across {profile.dst_ips.unique_count(profile.source_ip, context.now)} "
                    f"destination host(s)"
                ),
                weight=0.3,
            ),
        ]
        self.hits += 1
        return self.build(
            context=context,
            title="Abnormal connection rate",
            description=f"{context.packet.src_ip} opened {attempts} connections in {window:.0f}s.",
            evidence=evidence,
            confidence=self.scaled_confidence(attempts, self.settings.connection_rate_threshold, floor=0.55, ceiling=0.9),
            severity=Severity.HIGH if attempts >= self.settings.connection_rate_threshold * 3 else Severity.MEDIUM,
            recommended_action=ActionType.RATE_LIMIT,
            observation_window=window,
            packet_count=len(profile.packets),
            tags=("rate",),
        )


class IcmpFloodDetector(Detector):
    """High-rate ICMP from one source."""

    name = "icmp_flood"
    description = "ICMP packet rate from one source exceeds the configured threshold."
    category = ThreatCategory.DENIAL_OF_SERVICE
    default_severity = Severity.MEDIUM
    references = ("https://attack.mitre.org/techniques/T1498/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        if packet.protocol not in (Protocol.ICMP, Protocol.ICMPV6):
            return None
        self.evaluations += 1
        profile = context.profile
        window = self.settings.icmp_flood_window_seconds
        cutoff = context.now - window
        count = sum(1 for ts in profile.icmp_packets.timestamps() if ts >= cutoff)
        if count < self.settings.icmp_flood_threshold:
            return None

        span = max(profile.icmp_packets.span(), 0.001)
        rate = len(profile.icmp_packets) / span
        sizes = profile.packet_size_stats()
        evidence = [
            Evidence(
                key="icmp_packets",
                value=count,
                threshold=self.settings.icmp_flood_threshold,
                description=(
                    f"{count} ICMP packets to {packet.dst_ip} in {window:.0f}s "
                    f"(threshold {self.settings.icmp_flood_threshold})"
                ),
                weight=1.0,
            ),
            Evidence(
                key="icmp_rate",
                value=round(rate, 1),
                description=f"{rate:.0f} packets per second",
                weight=0.8,
            ),
        ]
        if sizes["stddev"] < 2.0 and sizes["mean"] > 0:
            evidence.append(
                Evidence(
                    key="uniform_packet_size",
                    value=sizes["mean"],
                    description=(
                        f"packets are uniform in size ({sizes['mean']:.0f} bytes), typical of "
                        f"generated rather than diagnostic traffic"
                    ),
                    weight=0.5,
                )
            )
        self.hits += 1
        return self.build(
            context=context,
            title="ICMP flood",
            description=f"{packet.src_ip} sent {count} ICMP packets to {packet.dst_ip} in {window:.0f}s.",
            evidence=evidence,
            confidence=self.scaled_confidence(count, self.settings.icmp_flood_threshold, floor=0.6, ceiling=0.95),
            severity=Severity.HIGH if count >= self.settings.icmp_flood_threshold * 3 else Severity.MEDIUM,
            recommended_action=ActionType.RATE_LIMIT,
            observation_window=window,
            packet_count=len(profile.packets),
            tags=("flood", "icmp"),
        )


class HttpFloodDetector(Detector):
    """Layer-7 request flood from one source."""

    name = "http_flood"
    description = "HTTP request rate from one source exceeds the configured threshold."
    category = ThreatCategory.DENIAL_OF_SERVICE
    default_severity = Severity.MEDIUM
    references = ("https://attack.mitre.org/techniques/T1499/002/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        http = context.packet.metadata.get("http")
        if not isinstance(http, dict) or not http.get("is_request"):
            return None
        self.evaluations += 1
        profile = context.profile
        window = self.settings.http_flood_window_seconds
        cutoff = context.now - window
        count = sum(1 for ts in profile.http_requests.timestamps() if ts >= cutoff)
        if count < self.settings.http_flood_threshold:
            return None

        unique_paths = len(set(profile.http_requests.items()))
        rate = count / window
        evidence = [
            Evidence(
                key="http_requests",
                value=count,
                threshold=self.settings.http_flood_threshold,
                description=(
                    f"{count} HTTP requests to {context.packet.dst_ip} in {window:.0f}s "
                    f"(threshold {self.settings.http_flood_threshold})"
                ),
                weight=1.0,
            ),
            Evidence(
                key="request_rate",
                value=round(rate, 1),
                description=f"{rate:.0f} requests per second",
                weight=0.8,
            ),
            Evidence(
                key="unique_paths",
                value=unique_paths,
                description=(
                    f"{unique_paths} distinct paths requested"
                    + (" - cache-busting variation" if unique_paths > count * 0.8 else "")
                ),
                weight=0.4,
            ),
        ]
        if http.get("host"):
            evidence.append(
                Evidence(
                    key="target_host",
                    value=http["host"],
                    description=f"targeting virtual host {http['host']}",
                    weight=0.2,
                )
            )
        self.hits += 1
        return self.build(
            context=context,
            title="HTTP request flood",
            description=f"{context.packet.src_ip} sent {count} HTTP requests in {window:.0f}s.",
            evidence=evidence,
            confidence=self.scaled_confidence(count, self.settings.http_flood_threshold, floor=0.6, ceiling=0.94),
            severity=Severity.HIGH if count >= self.settings.http_flood_threshold * 3 else Severity.MEDIUM,
            recommended_action=ActionType.RATE_LIMIT,
            observation_window=window,
            packet_count=len(profile.packets),
            tags=("flood", "http"),
        )
