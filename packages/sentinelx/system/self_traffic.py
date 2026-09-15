"""Recognise SentinelX's own connections to its database and Redis.

When storage runs on another host (or another container), every query the API makes
crosses the capture interface. Connection pools open and close connections in bursts
under load, which is exactly the shape the brute-force detectors look for: many short
sessions to PostgreSQL or Redis from one address. Those sessions are this process's
own work, and the configuration says precisely where they go.

A detection is treated as own traffic only when all of these hold:

* its destination address and port are a storage endpoint from this process's
  configuration (``STORAGE__DATABASE_URL``, ``STORAGE__REDIS_URL``), resolved to
  addresses;
* its source is an address of this host.

Traffic from any other address to the same database is still analysed, and so is
anything this host sends elsewhere.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from sentinelx.telemetry.logging import get_logger

__all__ = ["OwnServiceTraffic", "storage_endpoints"]

log = get_logger(__name__)

_DEFAULT_PORTS = {"postgresql": 5432, "postgres": 5432, "redis": 6379, "rediss": 6379}

Resolver = Callable[[str], Iterable[str]]


def storage_endpoints(urls: Iterable[str]) -> list[tuple[str, int]]:
    """``(host, port)`` for each network storage URL; file databases are skipped."""
    endpoints: list[tuple[str, int]] = []
    for url in urls:
        if not url:
            continue
        try:
            parts = urlsplit(url)
            scheme = parts.scheme.split("+", 1)[0].lower()
            port = parts.port or _DEFAULT_PORTS.get(scheme)
        except ValueError:
            continue
        if parts.hostname and port:
            endpoints.append((parts.hostname, port))
    return endpoints


def _resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


class OwnServiceTraffic:
    """Decides whether a flow is this process talking to its own storage.

    Host names are resolved lazily, only when a candidate flow comes from this host,
    and re-resolved at most every ``ttl`` seconds, so traffic from elsewhere (and PCAP
    replays of other networks) never waits on a lookup.
    """

    def __init__(
        self,
        urls: Iterable[str],
        *,
        local_addresses: Callable[[], frozenset[str]] | None = None,
        resolve: Resolver = _resolve,
        ttl: float = 60.0,
    ) -> None:
        if local_addresses is None:
            from sentinelx.system.interfaces import cached_local_addresses

            local_addresses = cached_local_addresses
        self._local_addresses = local_addresses
        self._configured = storage_endpoints(urls)
        self._resolve = resolve
        self._ttl = ttl
        self._resolved: tuple[float, frozenset[tuple[str, int]]] | None = None

    def endpoints(self) -> frozenset[tuple[str, int]]:
        """Resolved ``(address, port)`` pairs of the configured storage services."""
        now = time.monotonic()
        if self._resolved is not None and now - self._resolved[0] < self._ttl:
            return self._resolved[1]
        found: set[tuple[str, int]] = set()
        for host, port in self._configured:
            try:
                found.update((address, port) for address in self._resolve(host))
            except OSError as exc:
                log.warning("storage_endpoint_unresolved", host=host, error=str(exc))
        endpoints = frozenset(found)
        self._resolved = (now, endpoints)
        return endpoints

    def matches(
        self, source_ip: str | None, destination_ip: str | None, destination_port: int | None
    ) -> bool:
        if not (self._configured and source_ip and destination_ip and destination_port):
            return False
        if source_ip not in self._local_addresses():
            return False
        return (destination_ip, destination_port) in self.endpoints()
