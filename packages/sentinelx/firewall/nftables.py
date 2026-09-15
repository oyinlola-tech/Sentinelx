"""nftables adapter (the preferred Linux backend).

SentinelX owns one dedicated table and never touches any other.  The layout is::

    table inet sentinelx {
        set blocklist_v4  { type ipv4_addr; flags interval,timeout; }
        set blocklist_v6  { type ipv6_addr; flags interval,timeout; }
        set ratelimit_v4  { type ipv4_addr; flags interval,timeout; }
        set ratelimit_v6  { type ipv6_addr; flags interval,timeout; }
        chain input   { type filter hook input   priority -10; policy accept; ... }
        chain forward { type filter hook forward priority -10; policy accept; ... }
    }

Design decisions:

* **policy accept** on both chains.  The table can only ever *subtract* traffic
  that matches a set; a bug here cannot turn the host into default-deny.
* **Blocks are set elements, not rules.**  Adding or removing a block is an O(1)
  set update rather than a ruleset rewrite, and a set of 10,000 addresses costs
  the same per packet as a set of ten.
* **Temporary blocks use kernel timeouts.**  The kernel expires the element itself,
  so a temporary block lapses on time even if SentinelX has crashed.
* ``teardown()`` deletes the table, removing every trace of SentinelX in one
  atomic operation.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT
from sentinelx.firewall.base import BlockEntry, CommandRunner, FirewallAdapter, firewall_address
from sentinelx.telemetry.logging import get_logger

__all__ = ["NftablesAdapter"]

log = get_logger(__name__)


def _element(network: IPNetworkT) -> str:
    """Serialise a validated network for nft. Host routes use the bare address."""
    text = firewall_address(network)
    if network.num_addresses == 1:
        return str(network.network_address)
    return text


def _is_missing(stderr: str) -> bool:
    """nft's wording for "that table, set or element does not exist"."""
    text = stderr.lower()
    return "no such file or directory" in text or "does not exist" in text


class NftablesAdapter(FirewallAdapter):
    """Manages blocks through a dedicated nftables table.

    Args:
        table: table name (validated ``[A-Za-z0-9_]`` by settings).
        family: ``inet`` covers IPv4 and IPv6 in one table.
        rate_limit_pps: packets/second allowed from rate-limited sources.
        runner: injectable for tests; defaults to running ``nft``.
    """

    backend = "nftables"

    def __init__(
        self,
        *,
        table: str = "sentinelx",
        set_prefix: str = "blocklist",
        family: str = "inet",
        rate_limit_pps: int = 100,
        runner: CommandRunner | None = None,
        use_sudo: bool = False,
    ) -> None:
        for label, value in (("table", table), ("set_prefix", set_prefix)):
            if not value.replace("_", "").isalnum() or len(value) > 32:
                raise FirewallError(f"invalid nftables {label} name {value!r}")
        if family not in {"inet", "ip", "ip6"}:
            raise FirewallError(f"unsupported nftables family {family!r}")
        if not 1 <= int(rate_limit_pps) <= 10_000_000:
            raise FirewallError(f"rate_limit_pps out of range: {rate_limit_pps}")
        self.table = table
        self.family = family
        self.block_v4 = f"{set_prefix}_v4"
        self.block_v6 = f"{set_prefix}_v6"
        self.limit_v4 = "ratelimit_v4"
        self.limit_v6 = "ratelimit_v6"
        self.rate_limit_pps = int(rate_limit_pps)
        self._runner = runner or CommandRunner("nft", use_sudo=use_sudo)
        self._comments: dict[str, str] = {}

    # --------------------------------------------------------------- setup

    async def setup(self) -> None:
        """Create the table, sets and chains. Safe to run repeatedly."""
        nft = self._runner.run
        fam, table = self.family, self.table
        await nft("add", "table", fam, table)
        for name, kind in (
            (self.block_v4, "ipv4_addr"),
            (self.block_v6, "ipv6_addr"),
            (self.limit_v4, "ipv4_addr"),
            (self.limit_v6, "ipv6_addr"),
        ):
            await nft(
                "add",
                "set",
                fam,
                table,
                name,
                "{",
                "type",
                kind,
                ";",
                "flags",
                "interval,timeout",
                ";",
                "}",
            )
        for chain, hook in (("input", "input"), ("forward", "forward")):
            await nft(
                "add",
                "chain",
                fam,
                table,
                chain,
                "{",
                "type",
                "filter",
                "hook",
                hook,
                "priority",
                "-10",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            )
            # Flush then re-add so repeated setup never duplicates rules.
            await nft("flush", "chain", fam, table, chain)
            await nft(
                "add",
                "rule",
                fam,
                table,
                chain,
                "ip",
                "saddr",
                f"@{self.block_v4}",
                "counter",
                "drop",
            )
            await nft(
                "add",
                "rule",
                fam,
                table,
                chain,
                "ip6",
                "saddr",
                f"@{self.block_v6}",
                "counter",
                "drop",
            )
            rate = f"{self.rate_limit_pps}/second"
            await nft(
                "add",
                "rule",
                fam,
                table,
                chain,
                "ip",
                "saddr",
                f"@{self.limit_v4}",
                "limit",
                "rate",
                "over",
                rate,
                "counter",
                "drop",
            )
            await nft(
                "add",
                "rule",
                fam,
                table,
                chain,
                "ip6",
                "saddr",
                f"@{self.limit_v6}",
                "limit",
                "rate",
                "over",
                rate,
                "counter",
                "drop",
            )
        log.info("nftables_ready", table=table, family=fam)

    # ----------------------------------------------------------- operations

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        target_set = self.block_v4 if network.version == 4 else self.block_v6
        await self._add_element(target_set, network, duration, "block")
        self._comments[str(network)] = comment
        return BlockEntry(
            network=str(network),
            expires_at=datetime.now(UTC) + timedelta(seconds=duration) if duration else None,
            comment=comment,
        )

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        if packets_per_second != self.rate_limit_pps:
            # The rate lives in the rule, not per element; changing it per source
            # would need one rule per source, which defeats the set design.
            log.warning(
                "rate_limit_uses_configured_rate",
                requested=packets_per_second,
                applied=self.rate_limit_pps,
            )
        target_set = self.limit_v4 if network.version == 4 else self.limit_v6
        await self._add_element(target_set, network, duration, "rate_limit")
        return BlockEntry(
            network=str(network),
            expires_at=datetime.now(UTC) + timedelta(seconds=duration) if duration else None,
            comment=f"rate limit {self.rate_limit_pps}/s",
            rate_limited=True,
        )

    async def _add_element(
        self, set_name: str, network: IPNetworkT, duration: int | None, operation: str
    ) -> None:
        """Insert or replace a set element in one atomic nft transaction.

        ``add element`` leaves an existing element (and its timeout) untouched, so a
        re-block with a new duration, or a permanent block over a temporary one, would
        silently keep the old expiry. Add-delete-add in a single batch always leaves
        exactly the requested element, with no moment where the address is unblocked.
        """
        target = ("element", self.family, self.table, set_name)
        element = ["{", _element(network), "}"]
        final = ["{", _element(network)]
        if duration:
            final += ["timeout", f"{int(duration)}s"]
        final.append("}")
        try:
            await self._runner.run(
                "add",
                *target,
                *element,
                ";",
                "delete",
                *target,
                *element,
                ";",
                "add",
                *target,
                *final,
            )
        except FirewallError:
            self._record(operation, self.backend, False)
            raise
        self._record(operation, self.backend, True)

    async def unblock(self, network: IPNetworkT) -> bool:
        """Remove ``network`` from every set. False only when it was in none of them.

        Raises:
            FirewallError: when nft fails for any reason other than the element (or the
                table) not existing, e.g. permission denied. A failure is never
                reported as "was not blocked".
        """
        removed = False
        sets = (
            (self.block_v4, self.limit_v4)
            if network.version == 4
            else (self.block_v6, self.limit_v6)
        )
        for set_name in sets:
            result = await self._runner.run(
                "delete",
                "element",
                self.family,
                self.table,
                set_name,
                "{",
                _element(network),
                "}",
                check=False,
            )
            if result.ok:
                removed = True
            elif not _is_missing(result.stderr):
                self._record("unblock", self.backend, False)
                raise FirewallError(
                    f"nft could not remove {network}: {result.stderr.strip()[:300]}",
                    command=result.display,
                    stderr=result.stderr,
                )
        self._comments.pop(str(network), None)
        self._record("unblock", self.backend, True)
        return removed

    async def list_blocked(self) -> list[BlockEntry]:
        entries: list[BlockEntry] = []
        for set_name, limited in (
            (self.block_v4, False),
            (self.block_v6, False),
            (self.limit_v4, True),
            (self.limit_v6, True),
        ):
            result = await self._runner.run(
                "-j", "list", "set", self.family, self.table, set_name, check=False
            )
            if not result.ok:
                if _is_missing(result.stderr):
                    continue  # not set up yet: genuinely nothing blocked
                raise FirewallError(
                    f"nft could not list {set_name}: {result.stderr.strip()[:300]}",
                    command=result.display,
                    stderr=result.stderr,
                )
            for network, expires in self._parse_elements(result.stdout):
                entries.append(
                    BlockEntry(
                        network=network,
                        expires_at=datetime.now(UTC) + timedelta(seconds=expires)
                        if expires
                        else None,
                        comment=self._comments.get(network, "rate limit" if limited else ""),
                        rate_limited=limited,
                    )
                )
        return entries

    @staticmethod
    def _parse_elements(payload: str) -> list[tuple[str, float | None]]:
        """Parse ``nft -j list set`` output into (network, seconds remaining)."""
        try:
            document = json.loads(payload)
        except json.JSONDecodeError:
            return []
        found: list[tuple[str, float | None]] = []
        for item in document.get("nftables", []):
            set_obj = item.get("set") if isinstance(item, dict) else None
            if not isinstance(set_obj, dict):
                continue
            for element in set_obj.get("elem", []):
                expires: float | None = None
                value: Any = element
                if isinstance(element, dict) and "elem" in element:
                    expires = element["elem"].get("expires")
                    value = element["elem"].get("val")
                network = NftablesAdapter._value_to_network(value)
                if network is not None:
                    found.append((network, float(expires) if expires else None))
        return found

    @staticmethod
    def _value_to_network(value: Any) -> str | None:
        try:
            if isinstance(value, str):
                return str(ipaddress.ip_network(value, strict=False))
            if isinstance(value, dict) and "prefix" in value:
                prefix = value["prefix"]
                return str(ipaddress.ip_network(f"{prefix['addr']}/{prefix['len']}", strict=False))
            if isinstance(value, dict) and "range" in value:
                low, _high = value["range"]
                return str(ipaddress.ip_network(low, strict=False))
        except (ValueError, KeyError, TypeError):
            return None
        return None

    async def teardown(self) -> None:
        await self._runner.run("delete", "table", self.family, self.table, check=False)
        self._comments.clear()
        log.info("nftables_table_removed", table=self.table)

    async def health(self) -> dict[str, object]:
        result = await self._runner.run("list", "table", self.family, self.table, check=False)
        not_set_up = not result.ok and _is_missing(result.stderr)
        return {
            "backend": self.backend,
            # The table is created on first use; not existing yet is not a failure.
            "ok": result.ok or not_set_up,
            "enforcing": result.ok,
            "table": f"{self.family} {self.table}",
            "state": "ready" if result.ok else "not set up yet" if not_set_up else "error",
            "error": None if result.ok or not_set_up else result.stderr.strip()[:300],
        }
