"""The feature-extraction pipeline stage.

Owns every :class:`SourceProfile` and :class:`FlowState`, updates them once per
packet, and exposes the result as a :class:`FeatureContext` that detectors read.

Memory is bounded on purpose.  An intrusion detection system is a natural target
for resource exhaustion - traffic from a million spoofed sources would create a
million profiles - so the number of tracked sources and flows is capped, and the
least recently seen entries are evicted when the cap is reached.  Eviction is
counted, so you can tell "quiet network" from "we are shedding state".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from sentinelx.common.enums import Protocol
from sentinelx.common.models import FlowKey, PacketEvent
from sentinelx.common.windows import EwmaBaseline
from sentinelx.config.settings import DetectionSettings
from sentinelx.features.profiles import FlowState, SourceProfile
from sentinelx.telemetry.metrics import metrics

__all__ = ["FeatureContext", "FeatureExtractor", "GlobalStats"]

#: How often (in packets) to sweep for expired state. A sweep is O(tracked), so
#: doing it every packet would be quadratic; every 2048 packets is negligible.
_SWEEP_INTERVAL = 2048

#: Flows with no packets for this long are considered finished.
_FLOW_IDLE_SECONDS = 120.0


@dataclass(slots=True)
class GlobalStats:
    """Network-wide counters, independent of any single source."""

    packets: int = 0
    bytes_total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    arp: int = 0
    other: int = 0
    started_at: float = 0.0
    last_packet_at: float = 0.0

    def observe(self, packet: PacketEvent) -> None:
        self.packets += 1
        self.bytes_total += packet.length
        if self.started_at == 0.0:
            self.started_at = packet.timestamp
        self.last_packet_at = packet.timestamp
        match packet.protocol:
            case Protocol.TCP:
                self.tcp += 1
            case Protocol.UDP:
                self.udp += 1
            case Protocol.ICMP | Protocol.ICMPV6:
                self.icmp += 1
            case Protocol.ARP:
                self.arp += 1
            case _:
                self.other += 1

    @property
    def span_seconds(self) -> float:
        return max(self.last_packet_at - self.started_at, 0.0)

    def protocol_distribution(self) -> dict[str, float]:
        total = self.packets or 1
        return {
            "tcp": round(self.tcp / total, 4),
            "udp": round(self.udp / total, 4),
            "icmp": round(self.icmp / total, 4),
            "arp": round(self.arp / total, 4),
            "other": round(self.other / total, 4),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes_total,
            "span_seconds": round(self.span_seconds, 3),
            "protocol_distribution": self.protocol_distribution(),
        }


@dataclass(slots=True)
class FeatureContext:
    """Everything a detector needs about one packet, in one object.

    Passing a context rather than a bare packet is what lets detectors stay
    stateless and cheap: the expensive aggregation happened once, upstream.
    """

    packet: PacketEvent
    profile: SourceProfile
    flow: FlowState
    stats: GlobalStats
    now: float
    profiles: dict[str, SourceProfile]
    """Every tracked profile. Needed when the packet's sender is not the party a
    detector cares about - e.g. a server's RST closing an attacker's session."""

    #: Populated lazily by :meth:`features` - built at most once per packet even
    #: when several detectors ask for it.
    _features: dict[str, Any] | None = None

    def profile_of(self, ip: str) -> SourceProfile | None:
        """The profile for any tracked address, not only this packet's sender."""
        if ip == self.profile.source_ip:
            return self.profile
        return self.profiles.get(ip)

    def features(self) -> dict[str, Any]:
        """The flattened feature vector for this source, at this instant."""
        if self._features is None:
            self._features = self.profile.snapshot(self.now)
            self._features["protocol"] = str(self.packet.protocol)
            self._features["destination_port"] = self.packet.dst_port
            self._features["destination_ip"] = self.packet.dst_ip
            self._features["source_port"] = self.packet.src_port
            self._features["packet_length"] = self.packet.length
            self._features["direction"] = str(self.packet.direction)
            self._features["flow_duration"] = round(self.flow.duration, 4)
            self._features["flow_packets"] = self.flow.packets
            self._features["handshake_complete"] = self.flow.handshake_complete
            if self.packet.tcp_flags is not None:
                self._features["tcp_flags"] = self.packet.tcp_flags.label()
        return self._features


class FeatureExtractor:
    """Maintains rolling state and produces a :class:`FeatureContext` per packet.

    Example:
        >>> extractor = FeatureExtractor(DetectionSettings())
        >>> context = extractor.process(packet)
        >>> context.features()["unique_dst_ports"]
        94
    """

    def __init__(self, settings: DetectionSettings | None = None) -> None:
        self.settings = settings or DetectionSettings()
        # One window long enough for every detector, so all features describe the
        # same slice of time. Individual detectors narrow it when they need to.
        self.window_seconds = max(
            self.settings.port_scan_window_seconds,
            self.settings.brute_force_window_seconds,
            self.settings.connection_rate_window_seconds,
            self.settings.icmp_flood_window_seconds,
            self.settings.dns_window_seconds,
            self.settings.http_flood_window_seconds,
        )
        self._durations = (
            self.settings.port_scan_window_seconds,
            self.settings.brute_force_window_seconds,
            self.settings.connection_rate_window_seconds,
            self.settings.icmp_flood_window_seconds,
            self.settings.dns_window_seconds,
            self.settings.http_flood_window_seconds,
        )
        self.max_sources = self.settings.max_tracked_sources
        self.max_flows = self.max_sources * 4

        self.profiles: dict[str, SourceProfile] = {}
        self.flows: dict[FlowKey, FlowState] = {}
        self.stats = GlobalStats()

        #: Network-wide baselines, used by the statistical anomaly detectors.
        self.baselines: dict[str, EwmaBaseline] = {}

        self.evicted_sources = 0
        self.evicted_flows = 0
        self._packets_since_sweep = 0

    # ------------------------------------------------------------- processing

    def process(self, packet: PacketEvent) -> FeatureContext:
        """Update all state for one packet and return the detector's view of it."""
        now = packet.timestamp
        self.stats.observe(packet)

        profile = self._profile_for(packet.src_ip, now)
        profile.observe(packet)

        flow = self._flow_for(packet, now)
        self._update_flow(flow, packet)

        # A reply teaches us about the *original* source, not the sender.
        if packet.tcp_flags is not None and (packet.tcp_flags.is_syn_ack or packet.tcp_flags.rst):
            peer = self.profiles.get(packet.dst_ip)
            if peer is not None:
                peer.observe_reply(packet)

        # A completed-then-quickly-reset session is the brute-force signal; it can
        # only be recognised at teardown, which is here.
        if (
            flow.short_lived
            and not flow.short_session_recorded
            and packet.tcp_flags is not None
            and (packet.tcp_flags.rst or packet.tcp_flags.fin)
        ):
            originator = self.profiles.get(flow.initiator_ip)
            if originator is not None and flow.responder_port:
                originator.record_short_session(now, flow.responder_port)
                # Record once per flow: a teardown is often FIN then RST, and
                # counting both would double every brute-force attempt.
                flow.short_session_recorded = True

        self._packets_since_sweep += 1
        if self._packets_since_sweep >= _SWEEP_INTERVAL:
            self._sweep(now)

        return FeatureContext(
            packet=packet,
            profile=profile,
            flow=flow,
            stats=self.stats,
            now=now,
            profiles=self.profiles,
        )

    def _profile_for(self, source_ip: str, now: float) -> SourceProfile:
        profile = self.profiles.get(source_ip)
        if profile is None:
            if len(self.profiles) >= self.max_sources:
                self._evict_sources(now)
            profile = SourceProfile(
                source_ip=source_ip,
                window_seconds=self.window_seconds,
                first_seen=now,
                last_seen=now,
                durations=self._durations,
                scan_window=self.settings.port_scan_window_seconds,
                dns_long_label=self.settings.dns_long_label_length,
                dns_high_entropy=self.settings.dns_high_entropy_threshold,
            )
            self.profiles[source_ip] = profile
        return profile

    def _flow_for(self, packet: PacketEvent, now: float) -> FlowState:
        # Canonical key so both directions of a conversation share one state.
        key = packet.flow_key.canonical()
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self._evict_flows(now)
            flow = FlowState(
                key=key,
                first_seen=now,
                last_seen=now,
                initiator_ip=packet.src_ip,
                initiator_port=packet.src_port or 0,
                responder_ip=packet.dst_ip,
                responder_port=packet.dst_port or 0,
            )
            self.flows[key] = flow
        return flow

    @staticmethod
    def _update_flow(flow: FlowState, packet: PacketEvent) -> None:
        flow.last_seen = packet.timestamp
        flow.packets += 1
        flow.bytes_total += packet.length
        flow.payload_bytes += packet.payload_length
        flags = packet.tcp_flags
        if flags is None:
            return
        if flags.is_syn_only:
            flow.syn_seen = True
            if not flow.direction_confirmed:
                # The SYN sender is the initiator, whatever the first packet we
                # happened to observe suggested.
                flow.initiator_ip = packet.src_ip
                flow.initiator_port = packet.src_port or 0
                flow.responder_ip = packet.dst_ip
                flow.responder_port = packet.dst_port or 0
                flow.direction_confirmed = True
        elif flags.is_syn_ack and not flow.direction_confirmed:
            # We joined mid-handshake: the SYN-ACK sender is the responder.
            flow.initiator_ip = packet.dst_ip
            flow.initiator_port = packet.dst_port or 0
            flow.responder_ip = packet.src_ip
            flow.responder_port = packet.src_port or 0
            flow.direction_confirmed = True
        elif flags.is_syn_ack:
            flow.syn_ack_seen = True
        elif flags.ack and not (flags.fin or flags.rst):
            flow.ack_seen = True
        if flags.fin:
            flow.fin_seen = True
        if flags.rst:
            flow.rst_seen = True

    # --------------------------------------------------------------- eviction

    def _sweep(self, now: float) -> None:
        """Drop state that has aged out. Bounded work, run periodically."""
        self._packets_since_sweep = 0

        idle_cutoff = now - _FLOW_IDLE_SECONDS
        stale_flows = [key for key, flow in self.flows.items() if flow.last_seen < idle_cutoff]
        for key in stale_flows:
            del self.flows[key]

        profile_cutoff = now - self.window_seconds * 2
        stale_profiles = [
            ip for ip, profile in self.profiles.items() if profile.last_seen < profile_cutoff
        ]
        for ip in stale_profiles:
            del self.profiles[ip]

        metrics.active_flows.set(len(self.flows))
        metrics.tracked_sources.set(len(self.profiles))

    def _evict_sources(self, now: float) -> None:
        """Make room by dropping idle, then least-recently-seen, profiles."""
        for ip in [ip for ip, profile in self.profiles.items() if profile.last_seen < now - self.window_seconds]:
            del self.profiles[ip]
            self.evicted_sources += 1
        if len(self.profiles) >= self.max_sources:
            ordered = sorted(self.profiles.items(), key=lambda item: item[1].last_seen)
            for ip, _ in ordered[: max(1, self.max_sources // 10)]:
                del self.profiles[ip]
                self.evicted_sources += 1

    def _evict_flows(self, now: float) -> None:
        for key in [k for k, flow in self.flows.items() if flow.last_seen < now - _FLOW_IDLE_SECONDS]:
            del self.flows[key]
            self.evicted_flows += 1
        if len(self.flows) >= self.max_flows:
            ordered = sorted(self.flows.items(), key=lambda item: item[1].last_seen)
            for key, _ in ordered[: max(1, self.max_flows // 10)]:
                del self.flows[key]
                self.evicted_flows += 1

    # ----------------------------------------------------------------- access

    def baseline(self, name: str, alpha: float = 0.05, min_samples: int = 60) -> EwmaBaseline:
        """Get or create a named baseline. Shared across detectors by name."""
        baseline = self.baselines.get(name)
        if baseline is None:
            baseline = EwmaBaseline(alpha=alpha, min_samples=min_samples)
            self.baselines[name] = baseline
        return baseline

    def top_sources(self, limit: int = 10) -> list[dict[str, Any]]:
        """Busiest sources by packet count in the current window."""
        now = self.stats.last_packet_at or time.time()
        entries = [
            {
                "source_ip": profile.source_ip,
                "packets": len(profile.packets),
                "bytes": profile.total_bytes,
                "unique_dst_ports": profile.dst_ports.unique_count(profile.source_ip, now),
                "unique_dst_ips": profile.dst_ips.unique_count(profile.source_ip, now),
                "packet_rate": round(profile.packet_rate(), 2),
            }
            for profile in self.profiles.values()
        ]
        entries.sort(key=lambda entry: entry["packets"], reverse=True)  # type: ignore[arg-type,return-value]
        return entries[:limit]

    def top_destinations(self, limit: int = 10) -> list[dict[str, Any]]:
        """Busiest destinations, aggregated across flows."""
        counter: dict[str, dict[str, int]] = {}
        for key, flow in self.flows.items():
            entry = counter.setdefault(key.dst_ip, {"packets": 0, "bytes": 0, "flows": 0})
            entry["packets"] += flow.packets
            entry["bytes"] += flow.bytes_total
            entry["flows"] += 1
        entries = [{"destination_ip": ip, **values} for ip, values in counter.items()]
        entries.sort(key=lambda entry: entry["packets"], reverse=True)  # type: ignore[arg-type,return-value]
        return entries[:limit]

    def state(self) -> dict[str, Any]:
        return {
            "tracked_sources": len(self.profiles),
            "active_flows": len(self.flows),
            "evicted_sources": self.evicted_sources,
            "evicted_flows": self.evicted_flows,
            "window_seconds": self.window_seconds,
            **self.stats.as_dict(),
        }

    def reset(self) -> None:
        """Drop all state. Used between replays so runs cannot contaminate each other."""
        self.profiles.clear()
        self.flows.clear()
        self.baselines.clear()
        self.stats = GlobalStats()
        self.evicted_sources = 0
        self.evicted_flows = 0
        self._packets_since_sweep = 0
