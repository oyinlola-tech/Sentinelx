"""Core domain models shared by every layer.

These are the only packet-shaped objects allowed past the capture boundary.  Raw
Scapy/libpcap objects are converted in :mod:`sentinelx.parser` and never leak
further, so the capture implementation can be swapped without touching detection.

The models are frozen dataclasses rather than Pydantic models on purpose: they are
allocated once per packet on the hot path, and ``slots=True`` dataclasses are
markedly cheaper to build than validated Pydantic instances.  Pydantic is used at
the API boundary instead (:mod:`sentinelx.api.schemas`), where validation is worth
paying for.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Self

from sentinelx.common.enums import (
    ActionType,
    Direction,
    IncidentStatus,
    Protocol,
    RiskBand,
    Severity,
    ThreatCategory,
)

__all__ = [
    "Detection",
    "Evidence",
    "FlowKey",
    "Incident",
    "PacketEvent",
    "ResponseDecision",
    "RiskAssessment",
    "TcpFlags",
    "new_id",
    "utcnow",
]


def utcnow() -> datetime:
    """Timezone-aware current time. Never use naive ``datetime.now()``."""
    return datetime.now(UTC)


def new_id() -> str:
    """A short, sortable-enough unique identifier for events and incidents."""
    return uuid.uuid4().hex


# ============================================================ packet primitives


@dataclass(frozen=True, slots=True)
class TcpFlags:
    """Decoded TCP control bits.

    Kept as a value object rather than an int so that detectors read as
    ``flags.syn and not flags.ack`` instead of ``flags & 0x02``.
    """

    fin: bool = False
    syn: bool = False
    rst: bool = False
    psh: bool = False
    ack: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False

    @classmethod
    def from_int(cls, value: int) -> Self:
        """Decode the 8-bit TCP flags field."""
        return cls(
            fin=bool(value & 0x01),
            syn=bool(value & 0x02),
            rst=bool(value & 0x04),
            psh=bool(value & 0x08),
            ack=bool(value & 0x10),
            urg=bool(value & 0x20),
            ece=bool(value & 0x40),
            cwr=bool(value & 0x80),
        )

    def to_int(self) -> int:
        """Re-encode to the wire representation."""
        return (
            (self.fin << 0)
            | (self.syn << 1)
            | (self.rst << 2)
            | (self.psh << 3)
            | (self.ack << 4)
            | (self.urg << 5)
            | (self.ece << 6)
            | (self.cwr << 7)
        )

    @property
    def is_syn_only(self) -> bool:
        """A bare SYN - the first packet of a handshake, and of a SYN scan."""
        return self.syn and not (self.ack or self.rst or self.fin)

    @property
    def is_syn_ack(self) -> bool:
        return self.syn and self.ack

    def label(self) -> str:
        """Compact tcpdump-style label such as ``SA`` or ``S``."""
        bits = (
            ("F", self.fin),
            ("S", self.syn),
            ("R", self.rst),
            ("P", self.psh),
            ("A", self.ack),
            ("U", self.urg),
            ("E", self.ece),
            ("C", self.cwr),
        )
        return "".join(ch for ch, on in bits if on) or "."


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Identifies a conversation.

    Compared directionally.  Use :meth:`canonical` when you want both directions
    of the same conversation to hash identically.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol

    def reversed(self) -> FlowKey:
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def canonical(self) -> FlowKey:
        """Direction-independent form: the lexicographically smaller endpoint first."""
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port):
            return self
        return self.reversed()

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}/{self.protocol}"


@dataclass(frozen=True, slots=True)
class PacketEvent:
    """A normalised packet.

    This is the *only* packet representation the detection pipeline sees.  Fields
    that a given protocol does not have are ``None`` rather than zero, so that
    "port 0" and "no port" stay distinguishable.

    ``metadata`` carries protocol-specific decodes contributed by the parser
    registry (DNS query names, HTTP method/host, TLS SNI/JA3-style fingerprints).
    It is deliberately loose: adding a protocol parser must not require changing
    this class.
    """

    timestamp: float
    """Capture time as a UNIX epoch float (seconds, microsecond resolution)."""

    src_ip: str
    dst_ip: str
    protocol: Protocol
    length: int
    """Total frame length on the wire, in bytes."""

    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: TcpFlags | None = None
    ttl: int | None = None
    interface: str = "unknown"
    direction: Direction = Direction.UNKNOWN
    src_mac: str | None = None
    dst_mac: str | None = None
    payload_length: int = 0
    """Bytes above the transport header - 0 for a pure ACK or a bare SYN."""

    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def datetime(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=UTC)

    @property
    def flow_key(self) -> FlowKey:
        """Directional flow key; ports default to 0 for portless protocols."""
        return FlowKey(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port or 0,
            dst_port=self.dst_port or 0,
            protocol=self.protocol,
        )

    def summary(self) -> str:
        """One-line human description, used in CLI output and evidence trails."""
        src = f"{self.src_ip}:{self.src_port}" if self.src_port is not None else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port is not None else self.dst_ip
        flags = f" [{self.tcp_flags.label()}]" if self.tcp_flags else ""
        return f"{self.protocol.upper()} {src} -> {dst}{flags} len={self.length}"


# ================================================================= detection


@dataclass(frozen=True, slots=True)
class Evidence:
    """One verifiable observation supporting a detection.

    Evidence is what makes a detection explainable.  Each item pairs a
    machine-readable ``key``/``value`` with a sentence an analyst can read, plus
    the threshold it was compared against where one exists.  The dashboard renders
    these verbatim - no detection should ever reach a user as just "malicious".
    """

    key: str
    value: Any
    description: str
    threshold: Any | None = None
    weight: float = 1.0
    """Relative contribution to confidence, 0-1. Used by the risk engine."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "description": self.description,
            "threshold": self.threshold,
            "weight": self.weight,
        }


@dataclass(frozen=True, slots=True)
class Detection:
    """A normalised finding from any detector.

    Every detector - signature, threshold, behavioural, statistical, ML - returns
    this exact shape, which is what lets the risk engine, correlation engine and
    API stay detector-agnostic.
    """

    detector: str
    """Stable identifier of the producing detector, e.g. ``tcp_port_scan``."""

    category: ThreatCategory
    severity: Severity
    confidence: float
    """0.0-1.0. How sure the detector is that this is a true positive."""

    title: str
    description: str
    source_ip: str
    evidence: list[Evidence] = field(default_factory=list)
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: Protocol | None = None
    recommended_action: ActionType = ActionType.ALERT
    recommended_duration_seconds: int | None = None
    """How long a preventive action should last, when the source (a rule) specifies it."""
    timestamp: datetime = field(default_factory=utcnow)
    detection_id: str = field(default_factory=new_id)
    rule_name: str | None = None
    """Set when the detection came from a user-authored rule."""

    observation_window_seconds: float | None = None
    packet_count: int | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be within 0.0-1.0, got {self.confidence} "
                f"from detector {self.detector!r}"
            )
        if not self.source_ip:
            raise ValueError(f"detector {self.detector!r} produced a detection with no source_ip")

    def evidence_dict(self) -> dict[str, Any]:
        return {item.key: item.value for item in self.evidence}

    def explain(self) -> str:
        """Render the full reasoning as plain text, for CLI and logs."""
        lines = [
            f"Threat:     {self.title}",
            f"Detector:   {self.detector}",
            f"Category:   {self.category}",
            f"Severity:   {self.severity}  (confidence {self.confidence:.0%})",
            f"Source:     {self.source_ip}",
        ]
        if self.destination_ip:
            lines.append(f"Target:     {self.destination_ip}")
        lines.append("Evidence:")
        lines.extend(f"  - {item.description}" for item in self.evidence)
        lines.append(f"Recommends: {self.recommended_action}")
        return "\n".join(lines)


# ==================================================================== scoring


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """The outcome of risk scoring, including why the score is what it is.

    ``contributions`` records every factor that moved the score, so the number is
    auditable rather than magic.  It sums (with the base) to ``score`` before
    clamping.
    """

    score: float
    band: RiskBand
    contributions: dict[str, float]
    rationale: list[str]
    assessed_at: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError(f"risk score must be within 0-100, got {self.score}")

    def explain(self) -> str:
        parts = [f"Risk {self.score:.0f}/100 ({self.band})"]
        parts.extend(f"  {reason}" for reason in self.rationale)
        return "\n".join(parts)


# ================================================================== incidents


@dataclass(slots=True)
class Incident:
    """Several related detections grouped into one narrative.

    Mutable by design: the correlation engine keeps an incident open and folds new
    detections into it for as long as the correlation window allows.
    """

    incident_id: str
    title: str
    summary: str
    severity: Severity
    risk: RiskAssessment
    detection_ids: list[str]
    affected_sources: set[str]
    affected_destinations: set[str]
    affected_services: set[int]
    categories: set[ThreatCategory]
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    correlation_rule: str | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)

    @property
    def detection_count(self) -> int:
        return len(self.detection_ids)

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()


# =================================================================== response


@dataclass(frozen=True, slots=True)
class ResponseDecision:
    """What the response engine decided to do, and whether it actually did it.

    ``executed=False`` with ``dry_run=True`` is the default posture: the decision
    is recorded and shown to the operator, but no traffic is affected.
    """

    action: ActionType
    target: str
    reason: str
    executed: bool
    dry_run: bool
    requires_approval: bool = False
    duration_seconds: int | None = None
    detection_id: str | None = None
    incident_id: str | None = None
    error: str | None = None
    decided_at: datetime = field(default_factory=utcnow)
    decision_id: str = field(default_factory=new_id)

    @property
    def outcome(self) -> str:
        """Short status word for tables and logs."""
        if self.error:
            return "failed"
        if self.requires_approval:
            return "pending_approval"
        if self.dry_run:
            return "simulated"
        return "executed" if self.executed else "skipped"


def monotonic() -> float:
    """Monotonic clock for measuring durations. Not wall time; never persist it."""
    return time.monotonic()
