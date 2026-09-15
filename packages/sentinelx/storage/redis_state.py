"""Redis-backed shared state, with an in-process fallback.

Redis carries the state that must be shared between processes: API rate-limit and
login-throttle counters (so limits hold across several API workers), cross-worker
event fan-out, and short-lived caches.

What deliberately does *not* live in Redis is the per-packet detection window
state.  A network round trip per packet would cap the sensor at a few thousand
packets per second; those windows are in-process (see
:mod:`sentinelx.common.windows`), and a sensor is one process.

When Redis is unreachable and ``REDIS_REQUIRED`` is false, every operation degrades
to an in-process equivalent.  The degradation is logged once, reported by the
system status endpoint, and Redis is retried periodically.  Limits then apply per
process rather than globally - documented, visible, and better than refusing to run.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from typing import Any

from sentinelx.common.errors import StorageError
from sentinelx.config.settings import StorageSettings
from sentinelx.telemetry.logging import get_logger

__all__ = ["SharedState"]

log = get_logger(__name__)

_RETRY_SECONDS = 30.0
_sequence = itertools.count()


class SharedState:
    """Rate limiting, caching and pub/sub over Redis, degrading to in-process."""

    def __init__(
        self, settings: StorageSettings, *, clock: Callable[[], float] = time.time
    ) -> None:
        self.settings = settings
        self.namespace = settings.redis_namespace
        self._clock = clock
        self._client: Any | None = None
        self._degraded_since: float | None = None
        self._last_attempt = 0.0
        self._memory_windows: dict[str, deque[float]] = {}
        self._memory_cache: dict[str, tuple[float, str]] = {}
        self._memory_channels: dict[str, list[asyncio.Queue[str]]] = {}

    # ------------------------------------------------------------ connection

    async def connect(self) -> None:
        """Connect to Redis, or enter degraded mode.

        Raises:
            StorageError: only when Redis is unreachable and ``redis_required`` is set.
        """
        self._last_attempt = self._clock()
        client: Any = None
        try:
            import importlib

            redis: Any = importlib.import_module("redis.asyncio")  # untyped third-party module
            client = redis.from_url(
                self.settings.redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
            await client.ping()
        except Exception as exc:
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.aclose()
            if self.settings.redis_required:
                raise StorageError(
                    f"Redis is required but unreachable: {type(exc).__name__}"
                ) from exc
            if self._degraded_since is None:
                self._degraded_since = self._clock()
                log.warning(
                    "redis_unavailable_degraded_mode",
                    error=type(exc).__name__,
                    effect="rate limits and fan-out are per-process until Redis returns",
                )
            return
        self._client = client
        if self._degraded_since is not None:
            written_back = await self._write_back(client)
            log.info(
                "redis_recovered",
                degraded_seconds=round(self._clock() - self._degraded_since, 1),
                cache_entries_written_back=written_back,
            )
        self._degraded_since = None
        log.info("redis_connected")

    async def _write_back(self, client: Any) -> int:
        """Copy cache entries written while degraded into Redis.

        Those entries include access-token revocations. Leaving them in process memory
        would make a token revoked during the outage valid again (on every worker) once
        Redis is back. A value already in Redis is kept, except that a larger number
        wins. (Session cut-offs for sign-out and password changes are stored in the
        database, not here.)
        """
        now = self._clock()
        written = 0
        for key, (expires, encoded) in list(self._memory_cache.items()):
            ttl = int(expires - now)
            if ttl < 1:
                self._memory_cache.pop(key, None)
                continue
            try:
                if not await client.set(key, encoded, ex=ttl, nx=True):
                    current = await client.get(key)
                    local, remote = json.loads(encoded), json.loads(current) if current else None
                    if (
                        isinstance(local, int | float)
                        and not isinstance(local, bool)
                        and isinstance(remote, int | float)
                        and local > remote
                    ):
                        await client.set(key, encoded, ex=ttl)
            except Exception as exc:
                log.warning("redis_write_back_failed", error=type(exc).__name__)
                return written
            self._memory_cache.pop(key, None)
            written += 1
        return written

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    @property
    def degraded(self) -> bool:
        return self._client is None

    async def _redis(self) -> Any | None:
        if self._client is None and self._clock() - self._last_attempt > _RETRY_SECONDS:
            await self.connect()
        return self._client

    async def _fail(self, exc: Exception) -> None:
        """Drop to degraded mode after a Redis error mid-operation."""
        if self.settings.redis_required:
            raise StorageError(f"Redis operation failed: {type(exc).__name__}") from exc
        log.warning("redis_operation_failed_degrading", error=type(exc).__name__)
        client, self._client = self._client, None
        self._degraded_since = self._clock()
        self._last_attempt = self._clock()
        if client is not None:
            try:
                await client.aclose()
            except Exception as close_exc:
                log.debug("redis_close_failed", error=type(close_exc).__name__)

    def _key(self, *parts: str) -> str:
        return ":".join((self.namespace, *parts))

    # --------------------------------------------------------------- limits

    async def hit(
        self, bucket: str, identity: str, *, limit: int, window_seconds: int
    ) -> tuple[bool, int, float]:
        """Record one request in a sliding window and decide whether it is allowed.

        Returns:
            ``(allowed, remaining, retry_after_seconds)``.
        """
        now = self._clock()
        key = self._key("rl", bucket, identity)
        client = await self._redis()
        if client is not None:
            try:
                member = f"{now:.6f}:{next(_sequence)}"
                async with client.pipeline(transaction=True) as pipe:
                    pipe.zremrangebyscore(key, 0, now - window_seconds)
                    pipe.zadd(key, {member: now})
                    pipe.zcard(key)
                    pipe.zrange(key, 0, 0, withscores=True)
                    pipe.expire(key, window_seconds + 1)
                    _, _, count, oldest, _ = await pipe.execute()
                oldest_ts = float(oldest[0][1]) if oldest else now
                return self._verdict(int(count), limit, oldest_ts, window_seconds, now)
            except Exception as exc:
                await self._fail(exc)

        window = self._memory_windows.setdefault(key, deque())
        while window and window[0] <= now - window_seconds:
            window.popleft()
        window.append(now)
        if len(self._memory_windows) > 100_000:
            self._evict_memory_windows(now, window_seconds)
        return self._verdict(len(window), limit, window[0], window_seconds, now)

    def _evict_memory_windows(self, now: float, window_seconds: int) -> None:
        """Bound the in-process limiter without resetting every client's throttle.

        Expired windows go first; if that is not enough, the least recently created
        half is dropped. (Clearing everything would let anyone who can present many
        source addresses reset login throttling for all clients.)
        """
        for key in [
            k for k, w in self._memory_windows.items() if not w or w[-1] <= now - window_seconds
        ]:
            del self._memory_windows[key]
        if len(self._memory_windows) > 100_000:
            for key in list(self._memory_windows)[:50_000]:
                del self._memory_windows[key]

    @staticmethod
    def _verdict(
        count: int, limit: int, oldest: float, window: int, now: float
    ) -> tuple[bool, int, float]:
        allowed = count <= limit
        retry_after = 0.0 if allowed else max(oldest + window - now, 0.0)
        return allowed, max(limit - count, 0), round(retry_after, 1)

    async def count(self, bucket: str, identity: str, *, window_seconds: int) -> tuple[int, float]:
        """Events recorded by :meth:`hit` in the window, without recording one.

        Returns:
            ``(count, seconds until the oldest event leaves the window)``.
        """
        now = self._clock()
        key = self._key("rl", bucket, identity)
        client = await self._redis()
        if client is not None:
            try:
                async with client.pipeline(transaction=True) as pipe:
                    pipe.zremrangebyscore(key, 0, now - window_seconds)
                    pipe.zcard(key)
                    pipe.zrange(key, 0, 0, withscores=True)
                    _, count, oldest = await pipe.execute()
                if not count:
                    return 0, 0.0
                oldest_ts = float(oldest[0][1]) if oldest else now
                return int(count), round(max(oldest_ts + window_seconds - now, 0.0), 1)
            except Exception as exc:
                await self._fail(exc)
        window = self._memory_windows.get(key)
        if not window:
            return 0, 0.0
        while window and window[0] <= now - window_seconds:
            window.popleft()
        if not window:
            return 0, 0.0
        return len(window), round(max(window[0] + window_seconds - now, 0.0), 1)

    async def reset(self, bucket: str, identity: str) -> None:
        key = self._key("rl", bucket, identity)
        client = await self._redis()
        if client is not None:
            try:
                await client.delete(key)
                return
            except Exception as exc:
                await self._fail(exc)
        self._memory_windows.pop(key, None)

    # ---------------------------------------------------------------- cache

    async def cache_set(self, name: str, value: Any, ttl_seconds: int) -> None:
        encoded = json.dumps(value, default=str)
        key = self._key("cache", name)
        client = await self._redis()
        if client is not None:
            try:
                await client.set(key, encoded, ex=ttl_seconds)
                return
            except Exception as exc:
                await self._fail(exc)
        now = self._clock()
        if len(self._memory_cache) > 50_000:
            for stale in [k for k, (expires, _) in self._memory_cache.items() if expires < now]:
                del self._memory_cache[stale]
        self._memory_cache[key] = (now + ttl_seconds, encoded)

    async def cache_get(self, name: str) -> Any | None:
        key = self._key("cache", name)
        client = await self._redis()
        if client is not None:
            try:
                raw = await client.get(key)
                return json.loads(raw) if raw is not None else None
            except Exception as exc:
                await self._fail(exc)
        entry = self._memory_cache.get(key)
        if entry is None or entry[0] < self._clock():
            self._memory_cache.pop(key, None)
            return None
        return json.loads(entry[1])

    async def cache_pop(self, name: str) -> Any | None:
        """Read and delete in one atomic step (Redis ``GETDEL``). For single-use values."""
        key = self._key("cache", name)
        client = await self._redis()
        if client is not None:
            try:
                raw = await client.getdel(key)
                return json.loads(raw) if raw is not None else None
            except Exception as exc:
                await self._fail(exc)
        entry = self._memory_cache.pop(key, None)
        if entry is None or entry[0] < self._clock():
            return None
        return json.loads(entry[1])

    # --------------------------------------------------------------- pub/sub

    async def publish(self, channel: str, message: dict[str, Any]) -> None:
        encoded = json.dumps(message, default=str)
        key = self._key("ch", channel)
        client = await self._redis()
        if client is not None:
            try:
                await client.publish(key, encoded)
                return
            except Exception as exc:
                await self._fail(exc)
        for queue in list(self._memory_channels.get(key, [])):
            if not queue.full():
                queue.put_nowait(encoded)

    async def subscribe(self, channel: str) -> AsyncIterator[dict[str, Any]]:
        key = self._key("ch", channel)
        client = await self._redis()
        if client is not None:
            pubsub = client.pubsub()
            await pubsub.subscribe(key)
            try:
                async for message in pubsub.listen():
                    if message.get("type") == "message":
                        yield json.loads(message["data"])
            finally:
                await pubsub.unsubscribe(key)
                await pubsub.aclose()
            return
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        self._memory_channels.setdefault(key, []).append(queue)
        try:
            while True:
                yield json.loads(await queue.get())
        finally:
            self._memory_channels[key].remove(queue)

    async def health(self) -> dict[str, Any]:
        # Retry a lost connection here too, so health recovers without other traffic.
        client = await self._redis()
        if client is None:
            since = self._degraded_since
            return {
                "ok": False,
                "degraded": True,
                "degraded_seconds": round(self._clock() - since, 1) if since else None,
            }
        try:
            await client.ping()
        except Exception as exc:
            await self._fail(exc)
            return {"ok": False, "degraded": True, "error": type(exc).__name__}
        return {"ok": True, "degraded": False}
