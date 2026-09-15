"""macOS (and BSD) packet filter adapter.

SentinelX loads a small ruleset into its own pf anchor and keeps blocked addresses
in a table inside that anchor::

    table <sentinelx_block> persist
    block drop in quick from <sentinelx_block> to any
    block drop out quick from any to <sentinelx_block>

The default anchor, ``com.apple/sentinelx``, is evaluated by the stock macOS
``/etc/pf.conf`` (which contains ``anchor "com.apple/*"``), so no system file is
edited. On other systems add ``anchor "sentinelx"`` to ``pf.conf`` and set
``RESPONSE__PF_ANCHOR=sentinelx``.

pf tables have no per-entry expiry, so temporary blocks are expired by the response
engine's reaper, which restores deadlines from the database after a restart. Rate
limiting is not available. Requires root. Existing connections from a newly blocked
address are killed so a block takes effect immediately.
"""

from __future__ import annotations

import re
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT, parse_network
from sentinelx.firewall.base import BlockEntry, CommandRunner, FirewallAdapter, firewall_address
from sentinelx.telemetry.logging import get_logger

__all__ = ["PfAdapter"]

log = get_logger(__name__)

PLATFORM: str = sys.platform
TABLE = "sentinelx_block"
_ANCHOR_RE = re.compile(r"^[A-Za-z0-9_.]{1,32}(/[A-Za-z0-9_.]{1,32})?$")
_DELETED_RE = re.compile(r"(\d+)/(\d+) addresses? deleted")


class PfAdapter(FirewallAdapter):
    backend = "pf"

    def __init__(
        self, *, anchor: str = "com.apple/sentinelx", runner: CommandRunner | None = None
    ) -> None:
        if not _ANCHOR_RE.fullmatch(anchor):
            raise FirewallError(f"invalid pf anchor name {anchor!r}")
        self.anchor = anchor
        self._runner = runner or CommandRunner(
            "/sbin/pfctl" if Path("/sbin/pfctl").exists() else "pfctl"
        )
        self._token: str | None = None
        self._expiries: dict[str, datetime | None] = {}
        self._comments: dict[str, str] = {}

    def _table(self, *args: str) -> tuple[str, ...]:
        return ("-a", self.anchor, "-t", TABLE, "-T", *args)

    @staticmethod
    def _raise(result_stderr: str, action: str) -> NoReturn:
        text = result_stderr.strip()
        if "permission denied" in text.lower() or "operation not permitted" in text.lower():
            raise FirewallError(f"pf refused to {action}: run the sensor as root")
        raise FirewallError(f"pf could not {action}: {text[:300]}")

    async def setup(self) -> None:
        """Load the anchor ruleset and enable pf (reference-counted, reversible)."""
        rules = (
            f"table <{TABLE}> persist\n"
            f"block drop in quick from <{TABLE}> to any\n"
            f"block drop out quick from any to <{TABLE}>\n"
        )
        with tempfile.TemporaryDirectory(prefix="sentinelx-pf-") as directory:
            path = Path(directory) / "anchor.conf"
            path.write_text(rules, encoding="ascii")
            path.chmod(0o600)
            result = await self._runner.run("-a", self.anchor, "-f", str(path), check=False)
        if not result.ok:
            self._raise(result.stderr, "load the SentinelX anchor")
        # -E enables pf and returns a token; -X <token> releases only our reference,
        # so SentinelX never switches off a pf that something else enabled.
        enabled = await self._runner.run("-E", check=False)
        match = re.search(r"Token\s*:\s*(\d+)", enabled.stdout + enabled.stderr)
        if not enabled.ok and match is None:
            self._raise(enabled.stderr, "enable pf")
        self._token = match.group(1) if match else None
        log.info("pf_ready", anchor=self.anchor, table=TABLE)

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        address = str(parse_network(firewall_address(network)))
        result = await self._runner.run(*self._table("add", address), check=False)
        if not result.ok:
            self._record("block", self.backend, False)
            self._raise(result.stderr, f"block {address}")
        # Established states keep flowing past a new block; kill them (best effort).
        await self._runner.run("-k", str(parse_network(address).network_address), check=False)
        self._record("block", self.backend, True)
        expires = datetime.now(UTC) + timedelta(seconds=duration) if duration else None
        self._expiries[address] = expires
        self._comments[address] = comment
        return BlockEntry(network=address, expires_at=expires, comment=comment)

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        self._record("rate_limit", self.backend, False)
        raise FirewallError(
            "the pf backend cannot rate-limit traffic; use a block or a temporary block"
        )

    async def unblock(self, network: IPNetworkT) -> bool:
        address = str(parse_network(firewall_address(network)))
        result = await self._runner.run(*self._table("delete", address), check=False)
        if not result.ok:
            self._record("unblock", self.backend, False)
            self._raise(result.stderr, f"unblock {address}")
        match = _DELETED_RE.search(result.stderr + result.stdout)
        removed = bool(match and int(match.group(1)) > 0)
        self._expiries.pop(address, None)
        self._comments.pop(address, None)
        self._record("unblock", self.backend, True)
        return removed

    async def list_blocked(self) -> list[BlockEntry]:
        result = await self._runner.run(*self._table("show"), check=False)
        if not result.ok:
            if "does not exist" in result.stderr.lower():
                return []
            self._raise(result.stderr, "list blocked addresses")
        entries = []
        for line in result.stdout.splitlines():
            try:
                network = str(parse_network(line.strip()))
            except ValueError:
                continue
            entries.append(
                BlockEntry(
                    network=network,
                    expires_at=self._expiries.get(network),
                    comment=self._comments.get(network, ""),
                )
            )
        return entries

    async def teardown(self) -> None:
        await self._runner.run("-a", self.anchor, "-F", "all", check=False)
        if self._token is not None:
            await self._runner.run("-X", self._token, check=False)
            self._token = None
        self._expiries.clear()
        self._comments.clear()

    async def health(self) -> dict[str, object]:
        info = await self._runner.run("-s", "info", check=False)
        enabled = "Status: Enabled" in info.stdout
        rules = await self._runner.run("-a", self.anchor, "-s", "rules", check=False)
        loaded = rules.ok and TABLE in rules.stdout
        error = None
        if not info.ok:
            error = info.stderr.strip()[:300]
        elif not enabled:
            error = "pf is disabled"
        elif not loaded:
            error = f"the {self.anchor} anchor is not loaded or not referenced by pf.conf"
        return {
            "backend": self.backend,
            "ok": error is None,
            "enforcing": error is None,
            "anchor": self.anchor,
            "error": error,
        }
