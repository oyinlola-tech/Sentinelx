"""Policy and protocol-anomaly detectors.

These fire on facts rather than statistics: a packet from a denylisted address,
or a TCP flag combination that no conforming stack ever sends.  They need no
window and no baseline, so they are cheap and they are precise.
"""

from __future__ import annotations

from sentinelx.common.enums import ActionType, Protocol, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.common.netutils import IPNetworkT, parse_ip, parse_networks
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext

__all__ = ["DenylistDetector", "TcpFlagAnomalyDetector"]


class DenylistDetector(Detector):
    """Traffic to or from an address on the configured denylist.

    Threat-intelligence providers can extend the list at runtime through
    :meth:`update`; see :mod:`sentinelx.threat_intel`.
    """

    name = "denylist"
    description = "Traffic involving an address on the local denylist."
    category = ThreatCategory.MALICIOUS_REPUTATION
    default_severity = Severity.HIGH

    def __init__(self, settings: DetectionSettings | None = None) -> None:
        super().__init__(settings)
        self._networks: list[IPNetworkT] = parse_networks(self.settings.denylist_networks)
        self._reasons: dict[str, str] = {}

    def update(self, networks: list[str], reason: str = "local denylist") -> None:
        """Replace the denylist. Invalid entries raise before anything changes."""
        parsed = parse_networks(networks)
        self._networks = parsed
        self._reasons = {str(net): reason for net in parsed}

    def add(self, network: str, reason: str = "local denylist") -> None:
        parsed = parse_networks([network])
        self._networks.extend(parsed)
        for net in parsed:
            self._reasons[str(net)] = reason

    @property
    def networks(self) -> list[str]:
        return [str(net) for net in self._networks]

    def inspect(self, context: FeatureContext) -> Detection | None:
        if not self._networks:
            return None
        self.evaluations += 1
        packet = context.packet
        for role, address in (("source", packet.src_ip), ("destination", packet.dst_ip)):
            try:
                ip = parse_ip(address)
            except ValueError:
                continue
            match = next(
                (net for net in self._networks if ip.version == net.version and ip in net), None
            )
            if match is None:
                continue
            # Repeats are suppressed by the engine's per-(detector, source) cooldown.
            reason = self._reasons.get(str(match), "local denylist")
            self.hits += 1
            listed_is_source = role == "source"
            return self.build(
                context=context,
                title="Denylisted address",
                description=(
                    f"{'Inbound traffic from' if listed_is_source else 'Outbound traffic to'} "
                    f"{address}, which matches denylist entry {match}."
                ),
                evidence=[
                    Evidence(
                        key="denylist_match",
                        value=str(match),
                        description=f"{address} is inside denylisted network {match} ({reason})",
                        weight=1.0,
                    ),
                    Evidence(
                        key="direction",
                        value=role,
                        description=f"the listed address is the {role} of this traffic",
                        weight=0.4,
                    ),
                    Evidence(
                        key="first_packet",
                        value=packet.summary(),
                        description=f"triggering packet: {packet.summary()}",
                        weight=0.2,
                    ),
                ],
                confidence=0.9,
                severity=Severity.HIGH,
                recommended_action=ActionType.BLOCK_IP if listed_is_source else ActionType.ALERT,
                # Attribute the finding to the listed party so blocking and
                # correlation act on the right address.
                source_ip=address,
                destination_ip=packet.dst_ip if listed_is_source else packet.src_ip,
                tags=("denylist", reason),
            )
        return None


class TcpFlagAnomalyDetector(Detector):
    """TCP flag combinations that conforming stacks never produce.

    NULL (no flags), FIN-only-without-a-connection, XMAS (FIN+PSH+URG) and SYN+FIN
    packets are used by scanners to fingerprint operating systems and slip past
    naive stateless filters.  There is no benign reason to send them.
    """

    name = "tcp_flag_anomaly"
    description = "Illegal or scan-associated TCP flag combinations (NULL, XMAS, SYN+FIN)."
    category = ThreatCategory.PROTOCOL_ANOMALY
    default_severity = Severity.MEDIUM
    references = ("https://attack.mitre.org/techniques/T1046/",)

    #: Illegal packets from one source before reporting. A single malformed
    #: packet can be line noise or a buggy middlebox; a handful is intentional.
    _MIN_PACKETS = 3

    def __init__(self, settings: DetectionSettings | None = None) -> None:
        super().__init__(settings)
        self._counts: dict[str, int] = {}

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        flags = packet.tcp_flags
        if packet.protocol is not Protocol.TCP or flags is None:
            return None
        self.evaluations += 1

        kind: str | None = None
        if flags.to_int() == 0:
            kind = "NULL"
        elif flags.fin and flags.psh and flags.urg and not flags.ack:
            kind = "XMAS"
        elif flags.syn and flags.fin:
            kind = "SYN+FIN"
        elif flags.syn and flags.rst:
            kind = "SYN+RST"
        elif flags.fin and not flags.ack and not context.flow.handshake_complete:
            kind = "FIN without connection"
        if kind is None:
            return None

        count = self._counts.get(packet.src_ip, 0) + 1
        self._counts[packet.src_ip] = count
        if len(self._counts) > 50_000:
            self._counts.clear()
        if count < self._MIN_PACKETS:
            return None

        self.hits += 1
        return self.build(
            context=context,
            title=f"TCP {kind} packets",
            description=f"{packet.src_ip} sent {count} TCP packets with an invalid flag combination ({kind}).",
            evidence=[
                Evidence(
                    key="flag_combination",
                    value=kind,
                    description=f"flags [{flags.label()}] form a {kind} packet, which no conforming TCP stack sends",
                    weight=1.0,
                ),
                Evidence(
                    key="anomalous_packets",
                    value=count,
                    threshold=self._MIN_PACKETS,
                    description=f"{count} such packets from this source",
                    weight=0.7,
                ),
            ],
            confidence=0.85 if kind in {"NULL", "XMAS", "SYN+FIN"} else 0.65,
            severity=Severity.MEDIUM,
            recommended_action=ActionType.ALERT,
            tags=("protocol", kind.lower().replace(" ", "_")),
        )
