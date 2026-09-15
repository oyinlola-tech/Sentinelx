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
* IPv6 addresses carrying one of the above as an embedded IPv4 address
  (IPv4-mapped ``::ffff:127.0.0.1``, 6to4 ``2002:7f00:1::1``, Teredo, NAT64
  ``64:ff9b::/96``) - those are refused as if the IPv4 address itself were named;
* IPv6 zone identifiers (``fe80::1%eth0``): a zone is not part of an address a
  firewall matches on, and its text is free-form, so it must never reach one;
* exceeding ``max_blocked_addresses`` concurrent blocks.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Collection, Iterator
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
        return {
            "target": self.target,
            "allowed": self.allowed,
            "network": self.network,
            "reason": self.reason,
        }


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
        local_addresses: Callable[[], Collection[str]] | None = None,
        active_block_count: Callable[[], int] | None = None,
        operator_addresses: Callable[[], Collection[str]] | None = None,
    ) -> None:
        self.settings = settings
        self._allowlist = parse_networks(settings.allowlist_networks)
        self._management = parse_networks(settings.management_addresses)
        if local_addresses is None:
            from sentinelx.system.interfaces import cached_local_addresses

            local_addresses = cached_local_addresses
        self._local_addresses = local_addresses
        self._active_block_count = active_block_count or (lambda: 0)
        self._operator_addresses = operator_addresses or (lambda: ())
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
        return self._check(target, record=True)

    def _check(self, target: str, *, record: bool) -> IPNetworkT:
        """Validate a target and return the parsed network to act on.

        Args:
            target: an address (``203.0.113.5``) or prefix (``203.0.113.0/28``).

        Raises:
            SafetyViolationError: naming the precise rule that refused it.
        """
        if (
            not target
            or target != target.strip()
            or any(not ch.isprintable() or ch.isspace() for ch in target)
        ):
            # Reject rather than normalise: the raw target is written to the audit
            # log, and embedded newlines there would allow forged log entries.
            self._refuse(
                record,
                repr(target),
                "invalid_address",
                "target contains whitespace or control characters",
            )
        if "%" in target:
            self._refuse(
                record,
                target,
                "invalid_address",
                "IPv6 zone identifiers ('%...') cannot be blocked; give the address alone",
            )
        try:
            network = parse_network(target, strict=False)
        except ValueError as exc:
            self._refuse(record, target, "invalid_address", str(exc))

        if network.prefixlen == 0:
            self._refuse(record, target, "default_route", "a /0 prefix would block all traffic")

        limit = self.settings.max_block_prefix_hosts
        if network.num_addresses > limit:
            self._refuse(
                record,
                target,
                "prefix_too_wide",
                f"{describe_network(network)} exceeds the maximum of {limit} addresses "
                f"(response.max_block_prefix_hosts)",
            )

        self._check_protected(record, target, network, via="")
        for embedded, kind in _embedded_ipv4(network):
            self._check_protected(
                record, target, embedded, via=f" (embedded {kind} IPv4 {embedded})"
            )

        if self._active_block_count() >= self.settings.max_blocked_addresses:
            self._refuse(
                record,
                target,
                "block_limit_reached",
                f"{self.settings.max_blocked_addresses} blocks already active (response.max_blocked_addresses)",
            )
        return network

    def _check_protected(self, record: bool, target: str, network: IPNetworkT, *, via: str) -> None:
        """Refuse ``network`` if it is, or overlaps, anything protected.

        ``via`` names the embedding when ``network`` was derived from an IPv6 target.
        """
        code_suffix = "_embedded" if via else ""
        for address in (network.network_address, network.broadcast_address):
            if is_special(address):
                self._refuse(
                    record,
                    target,
                    "special_address" + code_suffix,
                    f"{address} is loopback, link-local, multicast or reserved{via}",
                )

        for protected in self._allowlist:
            if network.version == protected.version and network.overlaps(protected):
                self._refuse(
                    record,
                    target,
                    "allowlisted" + code_suffix,
                    f"{network} overlaps allowlisted network {protected}{via}",
                )

        for protected in self._management:
            if network.version == protected.version and network.overlaps(protected):
                self._refuse(
                    record,
                    target,
                    "management_address" + code_suffix,
                    f"{network} overlaps management address {protected}{via}",
                )

        if not self.settings.protect_management_addresses:
            return
        try:
            own_addresses = self._local_addresses()
        except OSError as exc:
            # Fail closed: without this host's addresses we cannot promise not
            # to block ourselves.
            self._refuse(
                record,
                target,
                "local_addresses_unknown",
                f"could not list this host's addresses ({exc}); refusing to block",
            )
        for raw in own_addresses:
            try:
                local = parse_network(raw)
            except ValueError:
                continue
            if local.version == network.version and network.overlaps(local):
                self._refuse(
                    record,
                    target,
                    "local_address" + code_suffix,
                    f"{network} contains {local.network_address}, an address of this host{via}",
                )

        for raw in self._operator_addresses():
            try:
                operator = parse_network(raw)
            except ValueError:
                continue
            if operator.version == network.version and network.overlaps(operator):
                self._refuse(
                    record,
                    target,
                    "operator_address" + code_suffix,
                    f"{network} contains {operator.network_address}, the address of an "
                    f"operator signed in within the last hour{via}",
                )

    def evaluate(self, target: str) -> SafetyReport:
        """Non-raising form of :meth:`check`, for previews. Records no refusal, log or metric."""
        try:
            network = self._check(target, record=False)
        except SafetyViolationError as exc:
            return SafetyReport(target=target, allowed=False, network=None, reason=exc.reason)
        return SafetyReport(target=target, allowed=True, network=str(network), reason="permitted")

    def _refuse(self, record: bool, target: str, code: str, reason: str) -> None:
        if record:
            self.refusals += 1
            metrics.safety_refusals.labels(reason=code).inc()
            log.warning("safety_refusal", target=target, rule=code, reason=reason)
        raise SafetyViolationError(target, reason)


_SIXTOFOUR = ipaddress.IPv6Network("2002::/16")
_TEREDO = ipaddress.IPv6Network("2001::/32")
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


def _embedded_ipv4(network: IPNetworkT) -> Iterator[tuple[ipaddress.IPv4Network, str]]:
    """IPv4 networks an IPv6 prefix carries inside it, by transition mechanism.

    Only prefixes narrow enough to pin the embedded bits are expanded; anything wider
    is already refused by ``max_block_prefix_hosts`` (at most 65,536 addresses).
    """
    if not isinstance(network, ipaddress.IPv6Network):
        return
    high = int(network.broadcast_address)
    for container, kind in ((_MAPPED, "IPv4-mapped"), (_NAT64, "NAT64")):
        if network.subnet_of(container):
            base = ipaddress.IPv4Address(int(network.network_address) & 0xFFFFFFFF)
            yield ipaddress.IPv4Network((base, network.prefixlen - 96)), kind
    if network.subnet_of(_SIXTOFOUR) and network.prefixlen >= 48:
        yield ipaddress.IPv4Network((int(network.network_address) >> 80) & 0xFFFFFFFF), "6to4"
    if network.subnet_of(_TEREDO) and network.prefixlen >= 64:
        server = (int(network.network_address) >> 64) & 0xFFFFFFFF
        yield ipaddress.IPv4Network(server), "Teredo server"
        if network.prefixlen >= 96:
            # The client address is stored bit-inverted: the prefix's highest address
            # holds the lowest client address of the covered range.
            client = ipaddress.IPv4Address(~high & 0xFFFFFFFF)
            yield ipaddress.IPv4Network((client, network.prefixlen - 96)), "Teredo client"
