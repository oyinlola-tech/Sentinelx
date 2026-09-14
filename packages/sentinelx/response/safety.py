"""Safety guard for preventive actions.

Every block, rate limit or quarantine passes through :meth:`SafetyGuard.check`
before any firewall adapter sees it - automatic *and* manual.  An administrator
typing ``sentinelx block 127.0.0.1`` is refused exactly as a misfiring detector
would be.

Refusals raise :class:`SafetyViolationError`, are counted, and are audited.  They
are the guard working, not an error.

Protected, unconditionally:

* loopback, link-local, multicast, unspecified and reserved addresses;
* every address assigned to an interface on this host;
* configured management addresses (the operator's workstation, jump hosts);
* configured allowlist networks;
* any prefix covering more than ``max_block_prefix_hosts`` addresses;
* any prefix that *contains* a protected address - blocking 10.0.0.0/24 must fail
  if the sensor itself is 10.0.0.5, even though 10.0.0.0/24 is not itself listed;
* exceeding ``max_blocked_addresses`` concurrent blocks.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sentinelx.common.errors import SafetyViolationError
from sentinelx.common.netutils import (
    IPNetworkT,
    describe_network,
    is_special,
    parse_network,
    parse_networks,
)
from sentinelx.config.settings import ResponseSettings
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["SafetyGuard", "SafetyReport"]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SafetyReport:
    """Result of a dry evaluation, for the UI's "can I block this?" preview."""

    target: str
    allowed: bool
    network: str | None
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"target": self.target, "allowed": self.allowed, "network": self.network, "reason": self.reason}


class SafetyGuard:
    """Validates targets for preventive actions.

    Args:
        settings: response settings (allowlist, management addresses, limits).
        local_addresses: callable returning this host's addresses. Injected so
            tests do not depend on the machine they run on.
        active_block_count: callable returning how many blocks are in force.
    """

    def __init__(
        self,
        settings: ResponseSettings,
        *,
        local_addresses: Callable[[], set[str]] | None = None,
        active_block_count: Callable[[], int] | None = None,
    ) -> None:
        self.settings = settings
        self._allowlist = parse_networks(settings.allowlist_networks)
        self._management = parse_networks(settings.management_addresses)
        if local_addresses is None:
            from sentinelx.capture.live import local_addresses as _discover

            local_addresses = _discover
        self._local_addresses = local_addresses
        self._active_block_count = active_block_count or (lambda: 0)
        self.refusals = 0

    def update_allowlist(self, networks: list[str]) -> None:
        """Replace the allowlist. Loopback is always retained."""
        merged = list(dict.fromkeys([*networks, "127.0.0.0/8", "::1/128"]))
        self._allowlist = parse_networks(merged)
        self.settings.allowlist_networks = merged

    def update_management(self, networks: list[str]) -> None:
        """Replace the protected management addresses. Validates before applying."""
        self._management = parse_networks(networks)
        self.settings.management_addresses = list(networks)

    @property
    def allowlist(self) -> list[str]:
        return [str(net) for net in self._allowlist]

    def check(self, target: str) -> IPNetworkT:
        """Validate a target and return the parsed network to act on.

        Args:
            target: an address (``203.0.113.5``) or prefix (``203.0.113.0/28``).

        Raises:
            SafetyViolationError: naming the precise rule that refused it.
        """
        if not target or target != target.strip() or any(not ch.isprintable() or ch.isspace() for ch in target):
            # Reject rather than normalise: the raw target is written to the audit
            # log, and embedded newlines there would allow forged log entries.
            self._refuse(repr(target), "invalid_address", "target contains whitespace or control characters")
        try:
            network = parse_network(target, strict=False)
        except ValueError as exc:
            self._refuse(target, "invalid_address", str(exc))

        if network.prefixlen == 0:
            self._refuse(target, "default_route", "a /0 prefix would block all traffic")

        limit = self.settings.max_block_prefix_hosts
        if network.num_addresses > limit:
            self._refuse(
                target,
                "prefix_too_wide",
                f"{describe_network(network)} exceeds the maximum of {limit} addresses "
                f"(response.max_block_prefix_hosts)",
            )

        for address in (network.network_address, network.broadcast_address):
            if is_special(address):
                self._refuse(target, "special_address", f"{address} is loopback, link-local, multicast or reserved")

        for protected in self._allowlist:
            if network.version == protected.version and network.overlaps(protected):
                self._refuse(target, "allowlisted", f"{network} overlaps allowlisted network {protected}")

        for protected in self._management:
            if network.version == protected.version and network.overlaps(protected):
                self._refuse(target, "management_address", f"{network} overlaps management address {protected}")

        if self.settings.protect_management_addresses:
            for raw in self._local_addresses():
                try:
                    local = parse_network(raw)
                except ValueError:
                    continue
                if local.version == network.version and network.overlaps(local):
                    self._refuse(target, "local_address", f"{network} contains {local.network_address}, an address of this host")

        if self._active_block_count() >= self.settings.max_blocked_addresses:
            self._refuse(
                target,
                "block_limit_reached",
                f"{self.settings.max_blocked_addresses} blocks already active (response.max_blocked_addresses)",
            )
        return network

    def evaluate(self, target: str) -> SafetyReport:
        """Non-raising form of :meth:`check`, for previews. Does not count refusals."""
        before = self.refusals
        try:
            network = self.check(target)
        except SafetyViolationError as exc:
            self.refusals = before
            return SafetyReport(target=target, allowed=False, network=None, reason=exc.reason)
        return SafetyReport(target=target, allowed=True, network=str(network), reason="permitted")

    def _refuse(self, target: str, code: str, reason: str) -> None:
        self.refusals += 1
        metrics.safety_refusals.labels(reason=code).inc()
        log.warning("safety_refusal", target=target, rule=code, reason=reason)
        raise SafetyViolationError(target, reason)
