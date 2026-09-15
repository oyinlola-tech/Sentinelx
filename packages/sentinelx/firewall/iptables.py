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
        previous = await self._rules_for(runner, network)
        try:
            await runner.run("-w", "-I", CHAIN, "1", *self._drop_rule(network, tag))
        except FirewallError:
            self._record("block", self.backend, False)
            raise
        # Only now remove the rules it replaces, so the address is never unblocked in
        # between and a failed insert leaves the old block in force.
        await self._delete(runner, previous)
        self._record("block", self.backend, True)
        entry = BlockEntry(network=str(network), expires_at=expires, comment=comment)
        self._meta[str(network)] = entry
        return entry

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        runner = self._runner(network)
        tag, expires = _comment_for(duration)
        previous = await self._rules_for(runner, network)
        try:
            await runner.run("-w", "-A", CHAIN, *self._limit_rule(network, tag))
        except FirewallError:
            self._record("rate_limit", self.backend, False)
            raise
        await self._delete(runner, previous)
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
            if "no chain" in result.stderr.lower() or "does not exist" in result.stderr.lower():
                return []  # not set up yet: genuinely nothing blocked
            raise FirewallError(
                f"iptables could not list {CHAIN}: {result.stderr.strip()[:300]}",
                command=result.display,
                stderr=result.stderr,
            )
        rules = []
        for line in result.stdout.splitlines():
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if len(parts) >= 4 and parts[0] == "-A" and parts[1] == CHAIN and "-s" in parts:
                rules.append(parts)
        return rules

    async def _rules_for(self, runner: CommandRunner, network: IPNetworkT) -> list[list[str]]:
        return [
            parts
            for parts in await self._rules(runner)
            if parts[parts.index("-s") + 1] == str(network)
        ]

    @staticmethod
    async def _delete(runner: CommandRunner, rules: list[list[str]]) -> None:
        # Delete by rule specification, as printed by ``iptables -S``. Raises on
        # permission errors rather than reporting a rule as gone.
        for parts in rules:
            await runner.run("-w", "-D", *parts[1:])

    async def _delete_rules(self, runner: CommandRunner, network: IPNetworkT) -> bool:
        """Delete every rule in our chain for ``network``, whatever its comment."""
        rules = await self._rules_for(runner, network)
        await self._delete(runner, rules)
        return bool(rules)

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
        text = result.stderr.lower()
        not_set_up = not result.ok and ("no chain" in text or "does not exist" in text)
        return {
            "backend": self.backend,
            # The chain is created on first use; not existing yet is not a failure.
            "ok": result.ok or not_set_up,
            "enforcing": result.ok,
            "chain": CHAIN,
            "ipv6": self._v6 is not None,
            "state": "ready" if result.ok else "not set up yet" if not_set_up else "error",
            "error": None if result.ok or not_set_up else result.stderr.strip()[:300],
        }
