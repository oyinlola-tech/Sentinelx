"""Exception hierarchy for SentinelX.

Every error raised deliberately by the platform derives from :class:`SentinelXError`
so that front-ends (API, CLI) can distinguish "our" failures from genuine bugs.
Each subclass maps onto one architectural layer, which keeps error handling at the
boundaries small and explicit.
"""

from __future__ import annotations

__all__ = [
    "BackendUnavailableError",
    "CaptureError",
    "ConfigurationError",
    "CorrelationError",
    "DetectionError",
    "FirewallError",
    "InterfaceNotFoundError",
    "ParserError",
    "PcapError",
    "PermissionDeniedError",
    "ResponseError",
    "RuleValidationError",
    "SafetyViolationError",
    "SentinelXError",
    "StorageError",
    "ThreatIntelError",
    "UploadQuotaExhaustedError",
    "UploadTooLargeError",
]


class SentinelXError(Exception):
    """Base class for all deliberate SentinelX failures."""


class ConfigurationError(SentinelXError):
    """Settings are missing, malformed, or mutually inconsistent."""


# --------------------------------------------------------------------- capture


class CaptureError(SentinelXError):
    """A packet source could not be opened, read, or closed cleanly."""


class InterfaceNotFoundError(CaptureError):
    """The requested network interface does not exist on this host."""

    def __init__(self, interface: str, available: list[str] | None = None) -> None:
        detail = f"interface {interface!r} not found"
        if available:
            detail += f"; available interfaces: {', '.join(sorted(available))}"
        super().__init__(detail)
        self.interface = interface
        self.available = available or []


class PermissionDeniedError(CaptureError):
    """Live capture needs a privilege this process lacks (CAP_NET_RAW, root, BPF
    device access, or Npcap access)."""


class BackendUnavailableError(CaptureError):
    """A capture backend cannot run on this host (missing kernel feature or library).

    Distinct from :class:`PermissionDeniedError` and from configuration errors such as
    an invalid BPF filter: only this error lets the live capture fall back to another
    backend.
    """


class PcapError(CaptureError):
    """A PCAP file is missing, unreadable, or not a capture file."""


class UploadTooLargeError(PcapError):
    """An upload is larger than the size limit or the space left in the upload quota."""


class UploadQuotaExhaustedError(PcapError):
    """The upload area is full; nothing more can be stored until uploads are deleted."""


# ---------------------------------------------------------------------- parser


class ParserError(SentinelXError):
    """A frame could not be decoded.

    Parsers should prefer returning partial results over raising: a malformed
    packet on the wire is an expected condition, not a program error.  This is
    reserved for programming errors such as a parser registered for the wrong
    protocol number.
    """


# ------------------------------------------------------------------- detection


class DetectionError(SentinelXError):
    """A detector failed while evaluating traffic."""


class RuleValidationError(DetectionError):
    """A rule file is syntactically or semantically invalid.

    Carries the offending rule name and the individual problems found so the CLI
    and the API can report every issue at once instead of one per run.
    """

    def __init__(self, rule_name: str, problems: list[str]) -> None:
        joined = "; ".join(problems)
        super().__init__(f"rule {rule_name!r} is invalid: {joined}")
        self.rule_name = rule_name
        self.problems = problems


class CorrelationError(SentinelXError):
    """The correlation engine could not build or update an incident."""


# -------------------------------------------------------------------- response


class ResponseError(SentinelXError):
    """A response action could not be carried out."""


class SafetyViolationError(ResponseError):
    """A response was refused because it would have breached a safety guard.

    Raised when, for example, a rule tries to block loopback, the management
    address, an allowlisted network, or a prefix wider than the configured
    maximum.  This is a *successful* refusal: the guard did its job.
    """

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(f"refusing to act on {target!r}: {reason}")
        self.target = target
        self.reason = reason


class FirewallError(ResponseError):
    """The firewall backend rejected or failed to apply a rule."""

    def __init__(self, message: str, *, command: str | None = None, stderr: str | None = None):
        super().__init__(message)
        self.command = command
        self.stderr = stderr


# --------------------------------------------------------------------- support


class StorageError(SentinelXError):
    """A database operation failed in a way the caller must handle."""


class ThreatIntelError(SentinelXError):
    """A threat-intelligence provider failed or returned unusable data."""
