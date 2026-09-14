"""In-memory firewall.

Used for dry runs, for tests, and as the ``null`` backend.  It enforces nothing on
the host; it records what a real firewall would hold, including expiry, so the
dashboard and API behave identically whichever backend is configured.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinelx.common.netutils import IPNetworkT
from sentinelx.firewall.base import BlockEntry, FirewallAdapter

__all__ = ["MemoryFirewall"]


class MemoryFirewall(FirewallAdapter):
    backend = "null"

    def __init__(self) -> None:
        self._entries: dict[str, BlockEntry] = {}
        self.operations: list[tuple[str, str]] = []
        """(operation, network) log - lets tests assert exactly what was attempted."""

    async def setup(self) -> None:
        return None

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        entry = BlockEntry(
            network=str(network),
            expires_at=datetime.now(UTC) + timedelta(seconds=duration) if duration else None,
            comment=comment,
        )
        self._entries[str(network)] = entry
        self.operations.append(("block", str(network)))
        self._record("block", self.backend, True)
        return entry

    async def unblock(self, network: IPNetworkT) -> bool:
        self.operations.append(("unblock", str(network)))
        removed = self._entries.pop(str(network), None) is not None
        self._record("unblock", self.backend, removed)
        return removed

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        entry = BlockEntry(
            network=str(network),
            expires_at=datetime.now(UTC) + timedelta(seconds=duration) if duration else None,
            comment=f"rate limit {packets_per_second}/s",
            rate_limited=True,
        )
        self._entries[str(network)] = entry
        self.operations.append(("rate_limit", str(network)))
        self._record("rate_limit", self.backend, True)
        return entry

    async def list_blocked(self) -> list[BlockEntry]:
        now = datetime.now(UTC)
        for key in [k for k, e in self._entries.items() if e.expires_at and e.expires_at <= now]:
            del self._entries[key]
        return list(self._entries.values())

    async def teardown(self) -> None:
        self._entries.clear()

    async def health(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "ok": True,
            "enforcing": False,
            "entries": len(self._entries),
        }
