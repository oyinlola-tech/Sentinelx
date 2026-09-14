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
from sentinelx.common.windows import SlidingWindow, UniqueWindow

__all__ = ["FlowState", "SourceProfile"]


@dataclass(slots=True)
class FlowState:
    """What we know about one conversation.

    ``handshake_complete`` is the single most useful bit for separating scanning
    from legitimate traffic: a scanner sends SYNs and never finishes, while a real
    client completes the handshake before doing anything.
    """

    key: FlowKey
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes_total: int = 0
    payload_bytes: int = 0
    syn_seen: bool = False
    syn_ack_seen: bool = False
    ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

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

    All windows share the configured observation duration so that every feature
    describes the same slice of time, which is what makes the evidence in a
    detection internally consistent ("94 ports in 12 seconds" refers to one
    window, not three different ones).
    """

    source_ip: str
    window_seconds: float
    first_seen: float
    last_seen: float

    packets: SlidingWindow[int] = field(init=False)
    dst_ports: UniqueWindow[str] = field(init=False)
    dst_ips: UniqueWindow[str] = field(init=False)
    syn_packets: SlidingWindow[None] = field(init=False)
    syn_ack_received: SlidingWindow[None] = field(init=False)
    rst_received: SlidingWindow[None] = field(init=False)
    icmp_packets: SlidingWindow[None] = field(init=False)
    udp_ports: UniqueWindow[str] = field(init=False)
    dns_queries: SlidingWindow[str] = field(init=False)
    http_requests: SlidingWindow[str] = field(init=False)
    connections_started: SlidingWindow[None] = field(init=False)
    refused_connections: SlidingWindow[None] = field(init=False)
    short_sessions: SlidingWindow[int] = field(init=False)

    total_packets: int = 0
    total_bytes: int = 0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    detections_triggered: int = 0

    def __post_init__(self) -> None:
        window = self.window_seconds
        self.packets = SlidingWindow(window)
        self.dst_ports = UniqueWindow(window)
        self.dst_ips = UniqueWindow(window)
        self.syn_packets = SlidingWindow(window)
        self.syn_ack_received = SlidingWindow(window)
        self.rst_received = SlidingWindow(window)
        self.icmp_packets = SlidingWindow(window)
        self.udp_ports = UniqueWindow(window)
        self.dns_queries = SlidingWindow(window)
        self.http_requests = SlidingWindow(window)
        self.connections_started = SlidingWindow(window)
        self.refused_connections = SlidingWindow(window)
        self.short_sessions = SlidingWindow(window)

    # ------------------------------------------------------------------ update

    def observe(self, packet: PacketEvent) -> None:
        """Fold one packet sent *by* this source into the profile."""
        timestamp = packet.timestamp
        self.last_seen = timestamp
        self.total_packets += 1
        self.total_bytes += packet.length
        self.packets.add(timestamp, packet.length)
        self.protocol_counts[packet.protocol] = self.protocol_counts.get(packet.protocol, 0) + 1

        if packet.dst_ip:
            self.dst_ips.add(self.source_ip, packet.dst_ip, timestamp)

        if packet.protocol is Protocol.TCP and packet.dst_port is not None:
            self.dst_ports.add(self.source_ip, packet.dst_port, timestamp)
            flags = packet.tcp_flags
            if flags is not None and flags.is_syn_only:
                self.syn_packets.add(timestamp, None)
                self.connections_started.add(timestamp, None)
        elif packet.protocol is Protocol.UDP and packet.dst_port is not None:
            self.udp_ports.add(self.source_ip, packet.dst_port, timestamp)
            dns = packet.metadata.get("dns")
            if isinstance(dns, dict) and not dns.get("is_response"):
                name = dns.get("query_name")
                if name:
                    self.dns_queries.add(timestamp, str(name))
        elif packet.protocol in (Protocol.ICMP, Protocol.ICMPV6):
            self.icmp_packets.add(timestamp, None)

        http = packet.metadata.get("http")
        if isinstance(http, dict) and http.get("is_request"):
            self.http_requests.add(timestamp, str(http.get("path") or "/"))

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
            self.syn_ack_received.add(packet.timestamp, None)
        elif flags.rst:
            self.rst_received.add(packet.timestamp, None)
            self.refused_connections.add(packet.timestamp, None)

    def record_short_session(self, timestamp: float, port: int) -> None:
        """Record a completed-but-brief session, the signal for credential guessing."""
        self.short_sessions.add(timestamp, port)

    # ---------------------------------------------------------------- features

    def expire(self, now: float) -> None:
        """Drop everything outside the window. Called before reading features."""
        for window in (
            self.packets, self.syn_packets, self.syn_ack_received, self.rst_received,
            self.icmp_packets, self.dns_queries, self.http_requests,
            self.connections_started, self.refused_connections, self.short_sessions,
        ):
            window.expire(now)

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
            "dns_unique_domains": len(set(self.dns_queries.items())),
            "http_request_count": len(self.http_requests),
            "http_unique_paths": len(set(self.http_requests.items())),
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
