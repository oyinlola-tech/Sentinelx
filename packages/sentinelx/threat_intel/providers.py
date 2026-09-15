"""Threat-intelligence providers.

Reputation lookups sit behind :class:`ThreatIntelProvider` so that no single feed
is baked in.  The platform runs entirely offline with the local providers.

Lookups run only when a detector has already fired, but the pipeline awaits them
before it processes the next packet, so a provider must answer quickly: each lookup
is time-bounded, and a failing provider is skipped rather than failing the detection.
"""

from __future__ import annotations

import abc
import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinelx.common.errors import ThreatIntelError
from sentinelx.common.netutils import IPNetworkT, parse_ip, parse_network
from sentinelx.telemetry.logging import get_logger

__all__ = [
    "IntelVerdict",
    "LocalAllowlistProvider",
    "LocalDenylistProvider",
    "ThreatIntelProvider",
    "ThreatIntelService",
    "load_network_file",
]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class IntelVerdict:
    """One provider's opinion of an address."""

    provider: str
    address: str
    score: float
    """0.0 (known good / unknown) to 1.0 (known malicious)."""

    trusted: bool = False
    """True when the provider vouches for the address (an allowlist hit)."""

    categories: tuple[str, ...] = ()
    description: str = ""
    matched: str | None = None
    """The list entry or feed indicator that matched."""

    checked_at: float = field(default_factory=time.time)


class ThreatIntelProvider(abc.ABC):
    """A source of reputation data."""

    name: str = "provider"

    @abc.abstractmethod
    async def lookup(self, address: str) -> IntelVerdict | None:
        """Return a verdict, or ``None`` when the provider knows nothing.

        Raises:
            ThreatIntelError: when the provider is unavailable. The service
                catches this and carries on with the remaining providers.
        """

    def describe(self) -> dict[str, object]:
        return {"name": self.name, "kind": type(self).__name__}


def load_network_file(path: Path) -> list[tuple[IPNetworkT, str]]:
    """Read a list file: one CIDR per line, optional ``# comment`` as its label.

    Invalid lines are reported together with their line numbers instead of being
    skipped silently - an ignored denylist entry is a gap nobody knows about.

    Raises:
        ThreatIntelError: listing every invalid line.
    """
    entries: list[tuple[IPNetworkT, str]] = []
    problems: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value, _, comment = line.partition("#")
        try:
            entries.append((parse_network(value.strip()), comment.strip()))
        except ValueError as exc:
            problems.append(f"line {number}: {exc}")
    if problems:
        raise ThreatIntelError(f"{path}: " + "; ".join(problems))
    return entries


class _NetworkListProvider(ThreatIntelProvider):
    def __init__(
        self, entries: list[tuple[str, str]] | None = None, path: Path | None = None
    ) -> None:
        self._entries: list[tuple[IPNetworkT, str]] = []
        self.path = path
        for value, label in entries or []:
            self._entries.append((parse_network(value), label))
        if path is not None and path.exists():
            self._entries.extend(load_network_file(path))

    def add(self, network: str, label: str = "") -> None:
        self._entries.append((parse_network(network), label))

    def remove(self, network: str) -> bool:
        target = parse_network(network)
        before = len(self._entries)
        self._entries = [(net, label) for net, label in self._entries if net != target]
        return len(self._entries) < before

    def entries(self) -> list[dict[str, str]]:
        return [{"network": str(net), "label": label} for net, label in self._entries]

    def _match(self, address: str) -> tuple[IPNetworkT, str] | None:
        try:
            ip = parse_ip(address)
        except ValueError:
            return None
        for network, label in self._entries:
            if ip.version == network.version and ip in network:
                return network, label
        return None

    def describe(self) -> dict[str, object]:
        return {
            **super().describe(),
            "entries": len(self._entries),
            "path": str(self.path) if self.path else None,
        }


class LocalDenylistProvider(_NetworkListProvider):
    """Operator-maintained list of known-bad networks."""

    name = "local_denylist"

    async def lookup(self, address: str) -> IntelVerdict | None:
        match = self._match(address)
        if match is None:
            return None
        network, label = match
        return IntelVerdict(
            provider=self.name,
            address=address,
            score=1.0,
            categories=("denylist",),
            description=label or "listed in local denylist",
            matched=str(network),
        )


class LocalAllowlistProvider(_NetworkListProvider):
    """Operator-maintained list of trusted networks."""

    name = "local_allowlist"

    async def lookup(self, address: str) -> IntelVerdict | None:
        match = self._match(address)
        if match is None:
            return None
        network, label = match
        return IntelVerdict(
            provider=self.name,
            address=address,
            score=0.0,
            trusted=True,
            categories=("allowlist",),
            description=label or "listed in local allowlist",
            matched=str(network),
        )


class ThreatIntelService:
    """Queries every provider and merges their verdicts.

    Merge rule: an allowlist verdict wins outright (the operator's explicit trust
    beats any feed); otherwise the highest badness score wins, and every
    contributing provider is recorded so the risk rationale can cite them.
    """

    def __init__(
        self, providers: list[ThreatIntelProvider] | None = None, timeout: float = 2.0
    ) -> None:
        self.providers = providers or []
        self.timeout = timeout
        self.failures: dict[str, int] = {}

    async def evaluate(
        self, address: str
    ) -> tuple[float, tuple[str, ...], bool, list[IntelVerdict]]:
        """Return ``(score, provider names, trusted, verdicts)`` for an address."""
        if not self.providers:
            return 0.0, (), False, []
        results = await asyncio.gather(
            *(self._safe_lookup(provider, address) for provider in self.providers)
        )
        verdicts = [v for v in results if v is not None]
        if any(v.trusted for v in verdicts):
            return 0.0, tuple(v.provider for v in verdicts if v.trusted), True, verdicts
        bad = [v for v in verdicts if v.score > 0]
        if not bad:
            return 0.0, (), False, verdicts
        return max(v.score for v in bad), tuple(v.provider for v in bad), False, verdicts

    async def _safe_lookup(
        self, provider: ThreatIntelProvider, address: str
    ) -> IntelVerdict | None:
        try:
            return await asyncio.wait_for(provider.lookup(address), timeout=self.timeout)
        except (ThreatIntelError, TimeoutError, ValueError) as exc:
            self.failures[provider.name] = self.failures.get(provider.name, 0) + 1
            log.warning(
                "threat_intel_lookup_failed",
                provider=provider.name,
                error=str(exc) or type(exc).__name__,
            )
            return None

    def get(self, name: str) -> ThreatIntelProvider | None:
        return next((p for p in self.providers if p.name == name), None)

    def describe(self) -> list[dict[str, object]]:
        return [{**p.describe(), "failures": self.failures.get(p.name, 0)} for p in self.providers]
