"""Reconnaissance detectors.

Scanning is the easiest activity to detect and the easiest to detect *badly*.  A
naive "many ports = scan" rule fires on any busy server, any NAT gateway, and
every peer-to-peer client on the network.

What separates a scan from a busy host is not volume but **shape**:

* a scanner sends bare SYNs and rarely completes a handshake, so ``syn_ratio`` is
  near 1.0 and ``syn_ack_ratio`` near 0;
* it touches ports it has no reason to expect are open, so most attempts are
  refused with RST;
* it moves on immediately rather than exchanging data.

Every detector here tests the shape, not just the count, and puts both in the
evidence so an analyst can check the reasoning.
"""

from __future__ import annotations

from sentinelx.common.enums import ActionType, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.common.netutils import SENSITIVE_PORTS, service_name
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext

__all__ = ["HorizontalScanDetector", "TcpPortScanDetector", "UdpScanDetector"]


class TcpPortScanDetector(Detector):
    """Detects a vertical scan: many ports on one host from one source."""

    name = "tcp_port_scan"
    description = "Many distinct TCP ports probed on one host, with few completed handshakes."
    category = ThreatCategory.RECONNAISSANCE
    default_severity = Severity.HIGH
    references = ("https://attack.mitre.org/techniques/T1046/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        flags = packet.tcp_flags
        # Only evaluate on a bare SYN: that is the packet a scan is made of, and
        # it bounds the work to once per connection attempt rather than per packet.
        if flags is None or not flags.is_syn_only:
            return None

        self.evaluations += 1
        profile = context.profile
        now = context.now
        settings = self.settings

        unique_ports = profile.dst_ports.unique_count(profile.source_ip, now)
        if unique_ports < settings.port_scan_unique_ports:
            return None

        syn_ratio = profile.syn_ratio()
        if syn_ratio < settings.port_scan_min_syn_ratio:
            # High port count but handshakes are completing: a busy legitimate
            # client, not a scan. This single check removes most false positives.
            return None

        unique_hosts = profile.dst_ips.unique_count(profile.source_ip, now)
        # A source spread across many hosts is a sweep, which HorizontalScanDetector
        # reports with better-fitting evidence. Deferring avoids double-reporting
        # the same behaviour under two names.
        if unique_hosts > 1 and unique_ports / unique_hosts < 4:
            return None

        span = max(profile.dst_ports.span(profile.source_ip), 0.001)
        syn_ack_ratio = profile.syn_ack_ratio()
        refusal_ratio = profile.refusal_ratio()
        ports_touched = profile.dst_ports.unique_values(profile.source_ip, now)
        sensitive_hit = sorted(
            {int(port) for port in ports_touched if int(port) in SENSITIVE_PORTS}
        )

        confidence = self.scaled_confidence(
            unique_ports, settings.port_scan_unique_ports, floor=0.6, ceiling=0.97, saturation=4.0
        )
        # A source that never receives a SYN-ACK is scanning closed ports; that is
        # strong corroboration, so it lifts confidence.
        if syn_ack_ratio < 0.1:
            confidence = min(0.98, confidence + 0.05)

        severity = Severity.HIGH
        if unique_ports >= settings.port_scan_unique_ports * 5 or sensitive_hit:
            severity = Severity.CRITICAL

        evidence = [
            Evidence(
                key="unique_destination_ports",
                value=unique_ports,
                threshold=settings.port_scan_unique_ports,
                description=(
                    f"{unique_ports} distinct destination ports contacted on "
                    f"{packet.dst_ip} (threshold {settings.port_scan_unique_ports})"
                ),
                weight=1.0,
            ),
            Evidence(
                key="observation_window_seconds",
                value=round(span, 2),
                description=f"observed over {span:.1f} seconds",
                weight=0.3,
            ),
            Evidence(
                key="syn_ratio",
                value=round(syn_ratio, 3),
                threshold=settings.port_scan_min_syn_ratio,
                description=(
                    f"{syn_ratio:.0%} of this source's packets are bare SYNs - it opens "
                    f"connections but does not complete them"
                ),
                weight=0.9,
            ),
            Evidence(
                key="syn_ack_ratio",
                value=round(syn_ack_ratio, 3),
                description=(
                    f"only {syn_ack_ratio:.1%} of SYNs were answered with SYN-ACK, so most "
                    f"probed ports are closed"
                ),
                weight=0.7,
            ),
            Evidence(
                key="connection_attempts",
                value=len(profile.connections_started),
                description=f"{len(profile.connections_started)} connection attempts in the window",
                weight=0.5,
            ),
        ]
        if refusal_ratio > 0:
            evidence.append(
                Evidence(
                    key="refusal_ratio",
                    value=round(refusal_ratio, 3),
                    description=f"{refusal_ratio:.0%} of attempts were refused with RST",
                    weight=0.6,
                )
            )
        if sensitive_hit:
            named = ", ".join(
                f"{port} ({service_name(port) or 'unknown'})" for port in sensitive_hit[:6]
            )
            evidence.append(
                Evidence(
                    key="sensitive_ports_probed",
                    value=sensitive_hit,
                    description=f"probed high-value services: {named}",
                    weight=1.0,
                )
            )

        self.hits += 1
        return self.build(
            context=context,
            title="TCP port scan",
            description=(
                f"{packet.src_ip} probed {unique_ports} distinct TCP ports on {packet.dst_ip} "
                f"in {span:.1f}s without completing handshakes."
            ),
            evidence=evidence,
            confidence=confidence,
            severity=severity,
            recommended_action=ActionType.TEMPORARY_BLOCK,
            observation_window=round(span, 3),
            packet_count=len(profile.packets),
            tags=("scan", "vertical"),
        )


class HorizontalScanDetector(Detector):
    """Detects a sweep: one service probed across many hosts.

    This is how worms and lateral-movement tooling look for a vulnerable service.
    It is a different shape from a vertical scan - few ports, many hosts - so it
    needs its own thresholds rather than sharing the port-scan ones.
    """

    name = "horizontal_scan"
    description = "One TCP port probed across many destination hosts (a network sweep)."
    category = ThreatCategory.RECONNAISSANCE
    default_severity = Severity.HIGH
    references = ("https://attack.mitre.org/techniques/T1046/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        flags = context.packet.tcp_flags
        if flags is None or not flags.is_syn_only:
            return None

        self.evaluations += 1
        profile = context.profile
        now = context.now
        settings = self.settings

        unique_hosts = profile.dst_ips.unique_count(profile.source_ip, now)
        if unique_hosts < settings.horizontal_scan_unique_hosts:
            return None

        unique_ports = profile.dst_ports.unique_count(profile.source_ip, now)
        # The defining ratio: many hosts, few ports. Otherwise it is a vertical
        # scan (or a general sweep) that another detector describes better.
        if unique_ports > max(4, unique_hosts // 8):
            return None

        syn_ratio = profile.syn_ratio()
        if syn_ratio < settings.port_scan_min_syn_ratio:
            return None

        span = max(profile.dst_ips.span(profile.source_ip), 0.001)
        port = context.packet.dst_port
        service = service_name(port) if port else None
        severity = Severity.CRITICAL if port and port in SENSITIVE_PORTS else Severity.HIGH

        evidence = [
            Evidence(
                key="unique_destination_hosts",
                value=unique_hosts,
                threshold=settings.horizontal_scan_unique_hosts,
                description=(
                    f"{unique_hosts} distinct hosts contacted on port {port}"
                    + (f" ({service})" if service else "")
                ),
                weight=1.0,
            ),
            Evidence(
                key="unique_destination_ports",
                value=unique_ports,
                description=(
                    f"only {unique_ports} distinct port(s) used - the source is looking for "
                    f"one service, not exploring one host"
                ),
                weight=0.9,
            ),
            Evidence(
                key="observation_window_seconds",
                value=round(span, 2),
                description=f"observed over {span:.1f} seconds",
                weight=0.3,
            ),
            Evidence(
                key="syn_ratio",
                value=round(syn_ratio, 3),
                threshold=settings.port_scan_min_syn_ratio,
                description=f"{syn_ratio:.0%} bare SYNs - connections are not completed",
                weight=0.8,
            ),
        ]
        if service:
            evidence.append(
                Evidence(
                    key="targeted_service",
                    value=service,
                    description=f"the swept port is a known service ({service})",
                    weight=0.7,
                )
            )

        self.hits += 1
        return self.build(
            context=context,
            title="Horizontal network sweep",
            description=(
                f"{context.packet.src_ip} probed port {port} across {unique_hosts} hosts "
                f"in {span:.1f}s."
            ),
            evidence=evidence,
            confidence=self.scaled_confidence(
                unique_hosts,
                settings.horizontal_scan_unique_hosts,
                floor=0.62,
                ceiling=0.96,
                saturation=4.0,
            ),
            severity=severity,
            recommended_action=ActionType.TEMPORARY_BLOCK,
            observation_window=round(span, 3),
            packet_count=len(profile.packets),
            tags=("scan", "horizontal"),
        )


class UdpScanDetector(Detector):
    """Detects UDP port sweeps.

    UDP scanning is noisier to detect than TCP because there is no handshake to
    observe. The usable signals are the distinct-port count and the ICMP
    port-unreachable replies that closed UDP ports generate, so this detector
    uses both and says which it relied on.
    """

    name = "udp_scan"
    description = "Many distinct UDP ports probed, typically drawing ICMP unreachable replies."
    category = ThreatCategory.RECONNAISSANCE
    default_severity = Severity.MEDIUM
    references = ("https://attack.mitre.org/techniques/T1046/",)

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        if packet.dst_port is None or packet.protocol != "udp":
            return None

        self.evaluations += 1
        profile = context.profile
        now = context.now
        settings = self.settings

        unique_ports = profile.udp_ports.unique_count(profile.source_ip, now)
        if unique_ports < settings.udp_scan_unique_ports:
            return None

        span = max(profile.udp_ports.span(profile.source_ip), 0.001)
        # DNS and mDNS clients legitimately talk to many ports; exclude a source
        # whose UDP traffic is overwhelmingly DNS.
        dns_queries = len(profile.dns_queries)
        udp_total = profile.udp_ports.total_count(profile.source_ip, now)
        if udp_total and dns_queries / udp_total > 0.8:
            return None

        evidence = [
            Evidence(
                key="unique_udp_ports",
                value=unique_ports,
                threshold=settings.udp_scan_unique_ports,
                description=(
                    f"{unique_ports} distinct UDP ports contacted on {packet.dst_ip} "
                    f"(threshold {settings.udp_scan_unique_ports})"
                ),
                weight=1.0,
            ),
            Evidence(
                key="observation_window_seconds",
                value=round(span, 2),
                description=f"observed over {span:.1f} seconds",
                weight=0.3,
            ),
            Evidence(
                key="udp_packets",
                value=udp_total,
                description=f"{udp_total} UDP packets from this source in the window",
                weight=0.4,
            ),
        ]

        self.hits += 1
        return self.build(
            context=context,
            title="UDP port scan",
            description=(
                f"{packet.src_ip} probed {unique_ports} distinct UDP ports on {packet.dst_ip} "
                f"in {span:.1f}s."
            ),
            evidence=evidence,
            confidence=self.scaled_confidence(
                unique_ports,
                settings.udp_scan_unique_ports,
                floor=0.55,
                ceiling=0.9,
                saturation=4.0,
            ),
            severity=Severity.MEDIUM,
            recommended_action=ActionType.ALERT,
            observation_window=round(span, 3),
            packet_count=len(profile.packets),
            tags=("scan", "udp"),
        )
