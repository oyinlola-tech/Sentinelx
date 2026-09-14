"""iptables adapter, for hosts without nftables.

SentinelX owns one chain, ``SENTINELX``, jumped to from ``INPUT`` and ``FORWARD``.
Each block is a ``-s <net> -j DROP`` rule inside it.  iptables has no per-rule
expiry, so a temporary block's deadline is written into the rule's comment
(``sentinelx:exp=<unix seconds>``). :meth:`list_blocked` reads it back, so the
response engine's reaper still removes the rule after a SentinelX restart. Expiry
only happens while a SentinelX server is running; nftables expires in the kernel.

Prefer nftables where available: set-based matching scales far better, and kernel
timeouts survive a SentinelX crash.
"""

from __future__ import annotations

import hashlib
import shlex
from datetime import UTC, datetime, timedelta

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT
from sentinelx.firewall.base import BlockEntry, CommandRunner, FirewallAdapter
from sentinelx.telemetry.logging import get_logger

__all__ = ["IptablesAdapter"]

log = get_logger(__name__)

CHAIN = "SENTINELX"
_COMMENT = "sentinelx"
_EXPIRY_PREFIX = "sentinelx:exp="


def _comment_for(duration: int | None) -> tuple[str, datetime | None]:
    if not duration:
        return _COMMENT, None
    expires = datetime.now(UTC) + timedelta(seconds=duration)
    return f"{_EXPIRY_PREFIX}{int(expires.timestamp())}", expires


def _expiry_from(comment: str) -> datetime | None:
    if not comment.startswith(_EXPIRY_PREFIX):
        return None
    try:
        return datetime.fromtimestamp(int(comment[len(_EXPIRY_PREFIX) :]), UTC)
    except ValueError:
        return None


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
    def _drop_rule(network: IPNetworkT, comment: str = _COMMENT) -> tuple[str, ...]:
        return ("-s", str(network), "-m", "comment", "--comment", comment, "-j", "DROP")

    def _limit_rule(self, network: IPNetworkT, comment: str = _COMMENT) -> tuple[str, ...]:
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
            comment,
            "-j",
            "DROP",
        )

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        runner = self._runner(network)
        tag, expires = _comment_for(duration)
        # Replace any existing rule for this network so a new duration takes effect.
        await self._delete_rules(runner, network)
        try:
            await runner.run("-w", "-I", CHAIN, "1", *self._drop_rule(network, tag))
        except FirewallError:
            self._record("block", self.backend, False)
            raise
        self._record("block", self.backend, True)
        entry = BlockEntry(network=str(network), expires_at=expires, comment=comment)
        self._meta[str(network)] = entry
        return entry

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        runner = self._runner(network)
        tag, expires = _comment_for(duration)
        await self._delete_rules(runner, network)
        try:
            await runner.run("-w", "-A", CHAIN, *self._limit_rule(network, tag))
        except FirewallError:
            self._record("rate_limit", self.backend, False)
            raise
        self._record("rate_limit", self.backend, True)
        entry = BlockEntry(
            network=str(network),
            expires_at=expires,
            comment=f"rate limit {self.rate_limit_pps}/s",
            rate_limited=True,
        )
        self._meta[str(network)] = entry
        return entry

    async def unblock(self, network: IPNetworkT) -> bool:
        removed = await self._delete_rules(self._runner(network), network)
        self._meta.pop(str(network), None)
        self._record("unblock", self.backend, removed)
        return removed

    async def _rules(self, runner: CommandRunner) -> list[list[str]]:
        """Rules in our chain as argv token lists (``-A SENTINELX -s ...``)."""
        result = await runner.run("-w", "-S", CHAIN, check=False)
        if not result.ok:
            return []
        rules = []
        for line in result.stdout.splitlines():
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if len(parts) >= 4 and parts[0] == "-A" and parts[1] == CHAIN and "-s" in parts:
                rules.append(parts)
        return rules

    async def _delete_rules(self, runner: CommandRunner, network: IPNetworkT) -> bool:
        """Delete every rule in our chain for ``network``, whatever its comment."""
        removed = False
        for parts in await self._rules(runner):
            if parts[parts.index("-s") + 1] != str(network):
                continue
            result = await runner.run("-w", "-D", *parts[1:], check=False)
            removed = removed or result.ok
        return removed

    async def list_blocked(self) -> list[BlockEntry]:
        entries: dict[str, BlockEntry] = {}
        for runner in (r for r in (self._v4, self._v6) if r is not None):
            for parts in await self._rules(runner):
                network = parts[parts.index("-s") + 1]
                comment = parts[parts.index("--comment") + 1] if "--comment" in parts else ""
                known = self._meta.get(network)
                entries[network] = BlockEntry(
                    network=network,
                    expires_at=_expiry_from(comment),
                    comment=known.comment if known else "",
                    rate_limited="hashlimit" in parts,
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
