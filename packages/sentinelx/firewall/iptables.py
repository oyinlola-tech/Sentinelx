"""iptables adapter, for hosts without nftables.

SentinelX owns one chain, ``SENTINELX``, jumped to from ``INPUT`` and ``FORWARD``.
Each block is a ``-s <net> -j DROP`` rule inside it.  iptables has no per-rule
expiry, so temporary blocks are expired by the response engine's reaper; the
adapter records the deadline so :meth:`list_blocked` can report it.

Prefer nftables where available: set-based matching scales far better, and kernel
timeouts survive a SentinelX crash.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT
from sentinelx.firewall.base import BlockEntry, CommandRunner, FirewallAdapter
from sentinelx.telemetry.logging import get_logger

__all__ = ["IptablesAdapter"]

log = get_logger(__name__)

CHAIN = "SENTINELX"
_COMMENT = "sentinelx"


class IptablesAdapter(FirewallAdapter):
    backend = "iptables"

    def __init__(
        self,
        *,
        rate_limit_pps: int = 100,
        runner_v4: CommandRunner | None = None,
        runner_v6: CommandRunner | None = None,
        use_sudo: bool = False,
    ) -> None:
        self.rate_limit_pps = int(rate_limit_pps)
        self._v4 = runner_v4 or CommandRunner("iptables", use_sudo=use_sudo)
        try:
            self._v6: CommandRunner | None = runner_v6 or CommandRunner(
                "ip6tables", use_sudo=use_sudo
            )
        except FirewallError:
            self._v6 = None
            log.warning("ip6tables_unavailable", effect="IPv6 blocks will be refused")
        self._meta: dict[str, BlockEntry] = {}

    def _runner(self, network: IPNetworkT) -> CommandRunner:
        if network.version == 6:
            if self._v6 is None:
                raise FirewallError("ip6tables is not installed; cannot block IPv6 addresses")
            return self._v6
        return self._v4

    async def setup(self) -> None:
        for runner in (r for r in (self._v4, self._v6) if r is not None):
            await runner.run("-w", "-N", CHAIN, check=False)  # exists -> non-zero, fine
            for parent in ("INPUT", "FORWARD"):
                exists = await runner.run("-w", "-C", parent, "-j", CHAIN, check=False)
                if not exists.ok:
                    await runner.run("-w", "-I", parent, "1", "-j", CHAIN)
        log.info("iptables_ready", chain=CHAIN)

    @staticmethod
    def _drop_rule(network: IPNetworkT) -> tuple[str, ...]:
        return ("-s", str(network), "-m", "comment", "--comment", _COMMENT, "-j", "DROP")

    def _limit_rule(self, network: IPNetworkT) -> tuple[str, ...]:
        # hashlimit names are limited to 15 chars; derive a stable one per network.
        name = "sx" + hashlib.sha1(str(network).encode(), usedforsecurity=False).hexdigest()[:12]
        return (
            "-s",
            str(network),
            "-m",
            "hashlimit",
            "--hashlimit-above",
            f"{self.rate_limit_pps}/sec",
            "--hashlimit-mode",
            "srcip",
            "--hashlimit-name",
            name,
            "-m",
            "comment",
            "--comment",
            _COMMENT,
            "-j",
            "DROP",
        )

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        runner = self._runner(network)
        rule = self._drop_rule(network)
        exists = await runner.run("-w", "-C", CHAIN, *rule, check=False)
        if not exists.ok:
            try:
                await runner.run("-w", "-I", CHAIN, "1", *rule)
            except FirewallError:
                self._record("block", self.backend, False)
                raise
        self._record("block", self.backend, True)
        entry = BlockEntry(
            network=str(network),
            expires_at=datetime.now(UTC) + timedelta(seconds=duration) if duration else None,
            comment=comment,
        )
        self._meta[str(network)] = entry
        return entry

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        runner = self._runner(network)
        rule = self._limit_rule(network)
        exists = await runner.run("-w", "-C", CHAIN, *rule, check=False)
        if not exists.ok:
            await runner.run("-w", "-A", CHAIN, *rule)
        self._record("rate_limit", self.backend, True)
        entry = BlockEntry(
            network=str(network),
            expires_at=datetime.now(UTC) + timedelta(seconds=duration) if duration else None,
            comment=f"rate limit {self.rate_limit_pps}/s",
            rate_limited=True,
        )
        self._meta[str(network)] = entry
        return entry

    async def unblock(self, network: IPNetworkT) -> bool:
        runner = self._runner(network)
        removed = False
        for rule in (self._drop_rule(network), self._limit_rule(network)):
            # Delete every copy; -D removes one at a time.
            for _ in range(16):
                result = await runner.run("-w", "-D", CHAIN, *rule, check=False)
                if not result.ok:
                    break
                removed = True
        self._meta.pop(str(network), None)
        self._record("unblock", self.backend, removed)
        return removed

    async def list_blocked(self) -> list[BlockEntry]:
        entries: dict[str, BlockEntry] = {}
        for runner in (r for r in (self._v4, self._v6) if r is not None):
            result = await runner.run("-w", "-S", CHAIN, check=False)
            if not result.ok:
                continue
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[0] != "-A" or "-s" not in parts:
                    continue
                network = parts[parts.index("-s") + 1]
                limited = "hashlimit" in parts
                entries[network] = self._meta.get(network) or BlockEntry(
                    network=network, rate_limited=limited
                )
        return list(entries.values())

    async def teardown(self) -> None:
        for runner in (r for r in (self._v4, self._v6) if r is not None):
            for parent in ("INPUT", "FORWARD"):
                await runner.run("-w", "-D", parent, "-j", CHAIN, check=False)
            await runner.run("-w", "-F", CHAIN, check=False)
            await runner.run("-w", "-X", CHAIN, check=False)
        self._meta.clear()

    async def health(self) -> dict[str, object]:
        result = await self._v4.run("-w", "-S", CHAIN, check=False)
        return {
            "backend": self.backend,
            "ok": result.ok,
            "enforcing": result.ok,
            "chain": CHAIN,
            "ipv6": self._v6 is not None,
            "error": None if result.ok else result.stderr.strip()[:300],
        }
