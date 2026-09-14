"""Shared vocabulary.

These enums are the contract between layers: the parser emits :class:`Protocol`,
detectors emit :class:`Severity` and :class:`ThreatCategory`, the response engine
consumes :class:`ActionType`.  They are plain ``str`` enums so they serialise to
readable JSON for the API and store as text in PostgreSQL without a mapping table.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "ActionType",
    "DetectionMode",
    "Direction",
    "IncidentStatus",
    "Protocol",
    "ResponseMode",
    "RiskBand",
    "Severity",
    "ThreatCategory",
    "UserRole",
]


class Protocol(StrEnum):
    """Transport/network protocol of a normalised packet."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    ARP = "arp"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    OTHER = "other"


class Direction(StrEnum):
    """Traffic direction relative to the monitored network.

    ``UNKNOWN`` is the honest default: direction can only be inferred when the
    sensor has been told which prefixes are "home" (``CAPTURE_HOME_NETWORKS``).
    """

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """How serious a detection is, before risk scoring weighs the context."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordinal 0-4, for sorting and for the risk engine's base score."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_rank(cls, rank: int) -> Severity:
        """Inverse of :attr:`rank`, clamped into range."""
        ordered = list(cls)
        return ordered[max(0, min(len(ordered) - 1, rank))]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RiskBand(StrEnum):
    """Human-facing band for a 0-100 risk score."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> RiskBand:
        """Map a 0-100 score onto its band.

        Boundaries match the documented scale: 0-20 informational, 21-40 low,
        41-60 medium, 61-80 high, 81-100 critical.
        """
        if score <= 20:
            return cls.INFORMATIONAL
        if score <= 40:
            return cls.LOW
        if score <= 60:
            return cls.MEDIUM
        if score <= 80:
            return cls.HIGH
        return cls.CRITICAL


class ThreatCategory(StrEnum):
    """What kind of activity a detection represents."""

    RECONNAISSANCE = "reconnaissance"
    BRUTE_FORCE = "brute_force"
    DENIAL_OF_SERVICE = "denial_of_service"
    EXFILTRATION = "exfiltration"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    POLICY_VIOLATION = "policy_violation"
    MALICIOUS_REPUTATION = "malicious_reputation"
    ANOMALY = "anomaly"
    LATERAL_MOVEMENT = "lateral_movement"
    OTHER = "other"


class ActionType(StrEnum):
    """A response the platform can take (or recommend)."""

    ALERT = "alert"
    LOG = "log"
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    TEMPORARY_BLOCK = "temporary_block"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    WEBHOOK = "webhook"
    NONE = "none"

    @property
    def is_preventive(self) -> bool:
        """True when the action changes traffic rather than only recording it.

        Preventive actions are the ones gated behind ``RESPONSE_MODE`` and
        ``DRY_RUN``; everything else is always safe to perform.
        """
        return self in _PREVENTIVE_ACTIONS


_PREVENTIVE_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.BLOCK_IP,
        ActionType.TEMPORARY_BLOCK,
        ActionType.RATE_LIMIT,
        ActionType.QUARANTINE,
        ActionType.UNBLOCK_IP,
    }
)


class DetectionMode(StrEnum):
    """Which families of detectors run."""

    DISABLED = "disabled"
    SIGNATURE_ONLY = "signature_only"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


class ResponseMode(StrEnum):
    """How much autonomy the response engine has.

    ``DETECT_ONLY`` is the default and the only mode that needs no operator
    decision; see :mod:`sentinelx.response.safety`.
    """

    DETECT_ONLY = "detect_only"
    MANUAL_APPROVAL = "manual_approval"
    AUTOMATIC = "automatic"


class IncidentStatus(StrEnum):
    """Lifecycle of a correlated incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class UserRole(StrEnum):
    """Authorisation roles, ordered least to most privileged."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}[self]

    def can_act_as(self, required: UserRole) -> bool:
        """True when this role satisfies ``required`` (roles are hierarchical)."""
        return self.rank >= required.rank
