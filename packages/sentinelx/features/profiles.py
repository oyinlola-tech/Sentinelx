"""Per-source and per-flow state.

Detectors do not each maintain their own counters.  They read from a single
:class:`SourceProfile`, which is updated once per packet.  That matters for three
reasons: the per-packet cost stays proportional to the number of *packets*, not to
the number of detectors; every detector sees a consistent view of the same moment;
and the same features feed both the rule engine and the anomaly/ML layer, so a
statistical model is never scoring different inputs from the rules beside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinelx.common.enums import Protocol
from sentinelx.common.models import FlowKey, PacketEvent
from sentinelx.common.windows import DistinctWindow, SlidingWindow, TimeSeriesCounter, UniqueWindow

__all__ = ["FlowState", "SourceProfile", "parent_domain"]


def parent_domain(name: str) -> str:
    """Registrable-ish parent: the last two labels, or three for pairs like ``co.uk``."""
    labels = [label for label in name.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-2]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_service_reply(src_port: int | None, dst_port: int) -> bool:
    """True when a UDP packet has the shape of a server answering a client.

    A DNS or NTP server replies *from* its well-known port *to* whatever
    ephemeral port each client used, so it naturally "contacts" hundreds of
    distinct ports. Counting those towards UDP-scan detection flagged every
    resolver on the network during testing.

    Trade-off, documented in docs/detection-engine.md: a scanner that forges a
    privileged source port (e.g. ``nmap -g 53``) against high ports is not
    counted here. The TCP detectors and the anomaly layer still see it.
    """
    return src_port is not None and src_port < 1024 <= dst_port


@dataclass(slots=True)
class FlowState:
    """What we know about one conversation.

    ``handshake_complete`` is the single most useful bit for separating scanning
    from legitimate traffic: a scanner sends SYNs and never finishes, while a real
    client completes the handshake before doing anything.
    """

    key: FlowKey
    """Canonical (direction-independent) key, so both halves share one state."""

    first_seen: float
    last_seen: float

    initiator_ip: str = ""
    """Who opened the conversation.

    Tracked separately because :attr:`key` is canonicalised and therefore does not
    preserve direction. Seeded from the first packet seen and corrected when a
    bare SYN arrives, since the SYN sender is definitively the initiator.
    """

    initiator_port: int = 0
    responder_ip: str = ""
    responder_port: int = 0
    """The service port - what the initiator was trying to reach."""

    direction_confirmed: bool = False
    """True once a SYN fixed the direction, rather than it being inferred."""

    packets: int = 0
    bytes_total: int = 0
    payload_bytes: int = 0
    syn_seen: bool = False
    syn_ack_seen: bool = False
    ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    short_session_recorded: bool = False
    """Guards against counting one teardown twice (FIN followed by RST)."""

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def handshake_complete(self) -> bool:
        return self.syn_seen and self.syn_ack_seen and self.ack_seen

    @property
    def refused(self) -> bool:
        """SYN answered by RST: the port is closed. A scan produces many of these."""
        return self.syn_seen and self.rst_seen and not self.syn_ack_seen

    @property
    def half_open(self) -> bool:
        """SYN sent, never completed. Characteristic of a SYN scan or SYN flood."""
        return self.syn_seen and not self.ack_seen and not self.rst_seen

    @property
    def short_lived(self) -> bool:
        """Completed but torn down fast - the shape of a failed authentication."""
        return self.handshake_complete and (self.rst_seen or self.fin_seen) and self.duration < 5.0


@dataclass(slots=True)
class SourceProfile:
    """Rolling behavioural profile of one source address.

    Every structure is sized to the longest detection window, so all features
    describe the same slice of time and the evidence in a detection is internally
    consistent ("94 ports in 12 seconds" refers to one window, not three).
    Event series are :class:`TimeSeriesCounter` so that detectors asking about
    shorter sub-windows get O(1) answers - see that class for why this matters.
    """

    source_ip: str
    window_seconds: float
    first_seen: float
    last_seen: float
    durations: tuple[float, ...] = ()
    """Every detector window, registered for O(1) sub-window counts."""

    dns_long_label: int = 52
    dns_high_entropy: float = 3.8

    packets: SlidingWindow[int] = field(init=False)
    packet_times: TimeSeriesCounter = field(init=False)
    dst_ports: UniqueWindow[str] = field(init=False)
    dst_ips: UniqueWindow[str] = field(init=False)
    udp_ports: UniqueWindow[str] = field(init=False)
    syn_packets: TimeSeriesCounter = field(init=False)
    syn_ack_received: TimeSeriesCounter = field(init=False)
    rst_received: TimeSeriesCounter = field(init=False)
    icmp_packets: TimeSeriesCounter = field(init=False)
    connections_started: TimeSeriesCounter = field(init=False)
    refused_connections: TimeSeriesCounter = field(init=False)
    dns_times: TimeSeriesCounter = field(init=False)
    http_times: TimeSeriesCounter = field(init=False)
    dns_queries: DistinctWindow[str] = field(init=False)
    dns_suspicious: DistinctWindow[str] = field(init=False)
    """Parent domains of queries whose leftmost label looks like encoded data."""
    http_requests: DistinctWindow[str] = field(init=False)
    short_sessions: DistinctWindow[int] = field(init=False)
    """Service port of each completed-but-brief session."""

    total_packets: int = 0
    total_bytes: int = 0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    detections_triggered: int = 0

    def __post_init__(self) -> None:
        window = self.window_seconds
        durations = tuple({*self.durations, window})
        self.packets = SlidingWindow(window)
        self.packet_times = TimeSeriesCounter(durations)
        self.dst_ports = UniqueWindow(window, max_keys=1)
        self.dst_ips = UniqueWindow(window, max_keys=1)
        self.udp_ports = UniqueWindow(window, max_keys=1)
        self.syn_packets = TimeSeriesCounter(durations)
        self.syn_ack_received = TimeSeriesCounter(durations)
        self.rst_received = TimeSeriesCounter(durations)
        self.icmp_packets = TimeSeriesCounter(durations)
        self.connections_started = TimeSeriesCounter(durations)
        self.refused_connections = TimeSeriesCounter(durations)
        self.dns_times = TimeSeriesCounter(durations)
        self.http_times = TimeSeriesCounter(durations)
        self.dns_queries = DistinctWindow(window)
        self.dns_suspicious = DistinctWindow(window)
        self.http_requests = DistinctWindow(window)
        self.short_sessions = DistinctWindow(window)

    # ------------------------------------------------------------------ update

    def observe(self, packet: PacketEvent) -> None:
        """Fold one packet sent *by* this source into the profile."""
        timestamp = packet.timestamp
        self.last_seen = timestamp
        self.total_packets += 1
        self.total_bytes += packet.length
        self.packets.add(timestamp, packet.length)
        self.packet_times.add(timestamp)
        self.protocol_counts[packet.protocol] = self.protocol_counts.get(packet.protocol, 0) + 1

        if packet.dst_ip:
            self.dst_ips.add(self.source_ip, packet.dst_ip, timestamp)

        if packet.protocol is Protocol.TCP and packet.dst_port is not None:
            self.dst_ports.add(self.source_ip, packet.dst_port, timestamp)
            flags = packet.tcp_flags
            if flags is not None and flags.is_syn_only:
                self.syn_packets.add(timestamp)
                self.connections_started.add(timestamp)
        elif packet.protocol is Protocol.UDP and packet.dst_port is not None:
            if not _is_service_reply(packet.src_port, packet.dst_port):
                self.udp_ports.add(self.source_ip, packet.dst_port, timestamp)
            dns = packet.metadata.get("dns")
            if isinstance(dns, dict) and not dns.get("is_response"):
                name = dns.get("query_name")
                if name:
                    self._observe_dns(timestamp, str(name), dns)
        elif packet.protocol in (Protocol.ICMP, Protocol.ICMPV6):
            self.icmp_packets.add(timestamp)

        http = packet.metadata.get("http")
        if isinstance(http, dict) and http.get("is_request"):
            self.http_requests.add(timestamp, str(http.get("path") or "/"))
            self.http_times.add(timestamp)

    def _observe_dns(self, timestamp: float, name: str, dns: dict[str, Any]) -> None:
        self.dns_queries.add(timestamp, name)
        self.dns_times.add(timestamp)
        # Classify once, here, using the parser's pre-computed label length and
        # entropy, so the tunnelling detector never re-scans the window per packet.
        label_length = dns.get("max_label_length") or 0
        entropy = dns.get("name_entropy") or 0.0
        leftmost = len(name.split(".", 1)[0])
        if label_length >= self.dns_long_label or (leftmost >= 20 and entropy >= self.dns_high_entropy):
            self.dns_suspicious.add(timestamp, parent_domain(name))

    def observe_reply(self, packet: PacketEvent) -> None:
        """Fold in a packet sent *to* this source.

        Replies are what reveal whether the source's attempts are succeeding -
        a wall of RSTs is the strongest confirmation that SYNs were a scan rather
        than a busy client.
        """
        flags = packet.tcp_flags
        if flags is None:
            return
        if flags.is_syn_ack:
            self.syn_ack_received.add(packet.timestamp)
        elif flags.rst:
            self.rst_received.add(packet.timestamp)
            self.refused_connections.add(packet.timestamp)

    def record_short_session(self, timestamp: float, port: int) -> None:
        """Record a completed-but-brief session, the signal for credential guessing."""
        self.short_sessions.add(timestamp, port)

    # ---------------------------------------------------------------- features

    def expire(self, now: float) -> None:
        """Drop everything outside the window. Called before reading features."""
        self.packets.expire(now)
        self.dns_queries.expire(now)
        self.dns_suspicious.expire(now)
        self.http_requests.expire(now)
        self.short_sessions.expire(now)
        for series in (
            self.packet_times, self.syn_packets, self.syn_ack_received, self.rst_received, self.icmp_packets,
            self.connections_started, self.refused_connections, self.dns_times, self.http_times,
        ):
            series.expire(now)

    @property
    def is_idle(self) -> bool:
        """True when nothing remains in any window - the profile can be evicted."""
        return not (self.packets or self.icmp_packets or self.dns_queries)

    def syn_ratio(self) -> float:
        """Fraction of this source's packets that are bare SYNs.

        Near 1.0 means the source almost never completes a connection.
        """
        total = len(self.packets)
        return len(self.syn_packets) / total if total else 0.0

    def syn_ack_ratio(self) -> float:
        """SYN-ACKs received per SYN sent.

        A scan against mostly-closed ports drives this towards 0.
        """
        syns = len(self.syn_packets)
        return len(self.syn_ack_received) / syns if syns else 0.0

    def refusal_ratio(self) -> float:
        """Fraction of connection attempts answered with RST."""
        attempts = len(self.connections_started)
        return len(self.refused_connections) / attempts if attempts else 0.0

    def packet_rate(self) -> float:
        return self.packets.rate()

    def packet_size_stats(self) -> dict[str, float]:
        """Mean, min and max packet size in the window.

        Floods are typically uniform in size; interactive traffic is not, so the
        spread is itself a signal.
        """
        sizes = list(self.packets.items())
        if not sizes:
            return {"mean": 0.0, "min": 0.0, "max": 0.0, "stddev": 0.0}
        count = len(sizes)
        mean = sum(sizes) / count
        variance = sum((size - mean) ** 2 for size in sizes) / count
        return {
            "mean": round(mean, 2),
            "min": float(min(sizes)),
            "max": float(max(sizes)),
            "stddev": round(variance**0.5, 2),
        }

    def protocol_distribution(self) -> dict[str, float]:
        total = sum(self.protocol_counts.values())
        if not total:
            return {}
        return {name: round(count / total, 4) for name, count in self.protocol_counts.items()}

    def snapshot(self, now: float) -> dict[str, Any]:
        """Every feature as a flat dictionary.

        This is the exact vector handed to the rule engine and to the anomaly
        detectors, so what a rule can test and what a model can learn from are the
        same set of facts.
        """
        self.expire(now)
        sizes = self.packet_size_stats()
        return {
            "source_ip": self.source_ip,
            "window_seconds": self.window_seconds,
            "packet_count": len(self.packets),
            "packet_rate": round(self.packet_rate(), 3),
            "observed_span": round(self.packets.span(), 3),
            "unique_dst_ports": self.dst_ports.unique_count(self.source_ip, now),
            "unique_dst_ips": self.dst_ips.unique_count(self.source_ip, now),
            "unique_udp_ports": self.udp_ports.unique_count(self.source_ip, now),
            "syn_count": len(self.syn_packets),
            "syn_ratio": round(self.syn_ratio(), 4),
            "syn_ack_ratio": round(self.syn_ack_ratio(), 4),
            "rst_count": len(self.rst_received),
            "refusal_ratio": round(self.refusal_ratio(), 4),
            "connection_attempts": len(self.connections_started),
            "failed_attempts": len(self.refused_connections),
            "short_sessions": len(self.short_sessions),
            "icmp_count": len(self.icmp_packets),
            "dns_query_count": len(self.dns_queries),
            "dns_suspicious_queries": len(self.dns_suspicious),
            "dns_unique_domains": self.dns_queries.distinct,
            "http_request_count": len(self.http_requests),
            "http_unique_paths": self.http_requests.distinct,
            "packet_size_mean": sizes["mean"],
            "packet_size_stddev": sizes["stddev"],
            "packet_size_max": sizes["max"],
            "protocol_distribution": self.protocol_distribution(),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "detections_triggered": self.detections_triggered,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }
