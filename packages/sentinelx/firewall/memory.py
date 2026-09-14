"""Firewall adapters that never touch the host.

:class:`MemoryFirewall` is a simulator for tests, PCAP replays and benchmarks. It
records what a real firewall would hold, including expiry, and says so: its
backend name is ``memory`` and its health reports ``enforcing: False``.

:class:`NullFirewall` is what ``FIREWALL_BACKEND=null`` means in a real deployment:
there is no firewall. It refuses every change with :class:`FirewallError`, so a
block can never be reported as applied when nothing was enforced.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT
from sentinelx.firewall.base import BlockEntry, FirewallAdapter

__all__ = ["MemoryFirewall", "NullFirewall"]


class MemoryFirewall(FirewallAdapter):
    backend = "memory"

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


class NullFirewall(FirewallAdapter):
    """No firewall configured. Detection works; enforcement is refused, loudly."""

    backend = "null"
    _REFUSAL = (
        "no firewall backend is configured (FIREWALL_BACKEND=null), so nothing can be "
        "enforced; set FIREWALL_BACKEND to a backend this host supports"
    )

    async def setup(self) -> None:
        return None

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        self._record("block", self.backend, False)
        raise FirewallError(self._REFUSAL)

    async def unblock(self, network: IPNetworkT) -> bool:
        self._record("unblock", self.backend, False)
        raise FirewallError(self._REFUSAL)

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        self._record("rate_limit", self.backend, False)
        raise FirewallError(self._REFUSAL)

    async def list_blocked(self) -> list[BlockEntry]:
        return []

    async def teardown(self) -> None:
        return None

    async def health(self) -> dict[str, object]:
        return {"backend": self.backend, "ok": True, "enforcing": False, "entries": 0}
