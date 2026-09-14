"""Sliding time windows and counters.

Detection is almost entirely "how many X in the last N seconds", so this module
provides that primitive once, correctly, instead of every detector reinventing it.

Everything here is in-process and synchronous.  Redis-backed equivalents live in
:mod:`sentinelx.storage.redis_counters` and are used when the pipeline runs across
processes; the in-process versions are what make the engine usable as a library
with no infrastructure at all.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Hashable, Iterator

__all__ = ["CounterWindow", "EwmaBaseline", "SlidingWindow", "UniqueWindow"]


class SlidingWindow[T]:
    """A time-ordered deque that forgets entries older than ``duration``.

    Timestamps are supplied by the caller (packet capture time), never read from
    the wall clock, so replaying a PCAP produces exactly the same windows as live
    traffic did.  This is what makes PCAP replay a faithful test.
    """

    __slots__ = ("_entries", "_max_entries", "duration")

    def __init__(self, duration: float, max_entries: int = 100_000) -> None:
        if duration <= 0:
            raise ValueError(f"window duration must be positive, got {duration}")
        self.duration = duration
        self._max_entries = max_entries
        self._entries: deque[tuple[float, T]] = deque()

    def add(self, timestamp: float, item: T) -> None:
        """Record ``item`` at ``timestamp`` and evict anything now expired."""
        self._entries.append((timestamp, item))
        self.expire(timestamp)
        # Hard cap protects against a flood pinning memory even inside one window.
        while len(self._entries) > self._max_entries:
            self._entries.popleft()

    def expire(self, now: float) -> None:
        """Drop entries older than ``now - duration``."""
        cutoff = now - self.duration
        entries = self._entries
        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def items(self) -> Iterator[T]:
        return (item for _, item in self._entries)

    def timestamps(self) -> Iterator[float]:
        return (ts for ts, _ in self._entries)

    def count_since(self, cutoff: float) -> int:
        """Entries with timestamp >= ``cutoff``. Lets a caller narrow the window."""
        return sum(1 for ts, _ in self._entries if ts >= cutoff)

    def items_since(self, cutoff: float) -> Iterator[T]:
        return (item for ts, item in self._entries if ts >= cutoff)

    def span(self) -> float:
        """Seconds between the oldest and newest retained entry."""
        if len(self._entries) < 2:
            return 0.0
        return self._entries[-1][0] - self._entries[0][0]

    def rate(self) -> float:
        """Entries per second over the observed span.

        Uses the observed span rather than the nominal window so a burst that
        arrived in 2s of a 60s window reports its real rate, not a diluted one.
        """
        span = self.span()
        if span <= 0:
            return float(len(self._entries))
        return len(self._entries) / span

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)


class CounterWindow[K: Hashable]:
    """Per-key event counts within a sliding window.

    Example: packets per source IP in the last 60 seconds.
    """

    __slots__ = ("_windows", "duration", "max_keys")

    def __init__(self, duration: float, max_keys: int = 50_000) -> None:
        self.duration = duration
        self.max_keys = max_keys
        self._windows: dict[K, SlidingWindow[None]] = {}

    def increment(self, key: K, timestamp: float, count: int = 1) -> int:
        """Record ``count`` events for ``key`` and return its current total."""
        window = self._windows.get(key)
        if window is None:
            self._evict_if_needed(timestamp)
            window = SlidingWindow(self.duration)
            self._windows[key] = window
        for _ in range(count):
            window.add(timestamp, None)
        return len(window)

    def count(self, key: K, now: float) -> int:
        """Current count for ``key``, after expiring stale entries."""
        window = self._windows.get(key)
        if window is None:
            return 0
        window.expire(now)
        return len(window)

    def rate(self, key: K, now: float) -> float:
        window = self._windows.get(key)
        if window is None:
            return 0.0
        window.expire(now)
        return window.rate()

    def top(self, now: float, limit: int = 10) -> list[tuple[K, int]]:
        """The ``limit`` busiest keys, highest first."""
        counts = [(key, self.count(key, now)) for key in list(self._windows)]
        counts = [pair for pair in counts if pair[1] > 0]
        counts.sort(key=lambda pair: pair[1], reverse=True)
        return counts[:limit]

    def keys(self) -> list[K]:
        return list(self._windows)

    def _evict_if_needed(self, now: float) -> None:
        """Drop empty windows once the key count gets large.

        Without this, a scan against many spoofed sources would grow the dict
        without bound even though every window inside it is empty.
        """
        if len(self._windows) < self.max_keys:
            return
        for key in list(self._windows):
            window = self._windows[key]
            window.expire(now)
            if not window:
                del self._windows[key]
        # Still full of live keys: drop the oldest-inserted half (dicts are ordered).
        if len(self._windows) >= self.max_keys:
            for key in list(self._windows)[: self.max_keys // 2]:
                del self._windows[key]


class UniqueWindow[K: Hashable]:
    """Counts *distinct* values seen per key inside a window.

    Example: how many distinct destination ports one source touched in 10s -
    the core signal for port-scan detection.
    """

    __slots__ = ("_windows", "duration", "max_keys")

    def __init__(self, duration: float, max_keys: int = 50_000) -> None:
        self.duration = duration
        self.max_keys = max_keys
        self._windows: dict[K, SlidingWindow[Hashable]] = {}

    def add(self, key: K, value: Hashable, timestamp: float) -> int:
        """Record that ``key`` touched ``value``; return the distinct count."""
        window = self._windows.get(key)
        if window is None:
            if len(self._windows) >= self.max_keys:
                self._evict(timestamp)
            window = SlidingWindow(self.duration)
            self._windows[key] = window
        window.add(timestamp, value)
        return len(set(window.items()))

    def unique_count(self, key: K, now: float) -> int:
        window = self._windows.get(key)
        if window is None:
            return 0
        window.expire(now)
        return len(set(window.items()))

    def unique_values(self, key: K, now: float) -> set[Hashable]:
        window = self._windows.get(key)
        if window is None:
            return set()
        window.expire(now)
        return set(window.items())

    def unique_since(self, key: K, cutoff: float) -> int:
        """Distinct values for ``key`` observed at or after ``cutoff``."""
        window = self._windows.get(key)
        return len(set(window.items_since(cutoff))) if window else 0

    def total_count(self, key: K, now: float) -> int:
        """Total observations (not distinct) for ``key``."""
        window = self._windows.get(key)
        if window is None:
            return 0
        window.expire(now)
        return len(window)

    def span(self, key: K) -> float:
        window = self._windows.get(key)
        return window.span() if window else 0.0

    def _evict(self, now: float) -> None:
        for key in list(self._windows):
            window = self._windows[key]
            window.expire(now)
            if not window:
                del self._windows[key]
        if len(self._windows) >= self.max_keys:
            for key in list(self._windows)[: self.max_keys // 2]:
                del self._windows[key]


class EwmaBaseline:
    """Exponentially weighted moving average and variance.

    Learns "normal" for a metric and reports how far the current value deviates,
    in standard deviations.  Chosen over a plain rolling mean because it adapts to
    genuine traffic growth without keeping history, and because a single update is
    O(1) - it can run per packet.

    The baseline refuses to report anomalies until ``min_samples`` observations
    have been folded in, so a cold start never produces a storm of alerts.
    """

    __slots__ = ("_initialised", "alpha", "mean", "min_samples", "samples", "variance")

    def __init__(self, alpha: float = 0.05, min_samples: int = 30) -> None:
        if not 0 < alpha <= 1:
            raise ValueError(f"alpha must be within (0, 1], got {alpha}")
        self.alpha = alpha
        self.min_samples = min_samples
        self.mean = 0.0
        self.variance = 0.0
        self.samples = 0
        self._initialised = False

    def update(self, value: float, *, alpha: float | None = None, update_variance: bool = True) -> None:
        """Fold a new observation into the baseline.

        Args:
            value: the observation.
            alpha: override the decay for this one update.
            update_variance: when False, only the mean moves. Used for observations
                already judged anomalous: letting them widen the variance shrinks
                every later deviation, and a sustained attack then stops scoring as
                anomalous and gets absorbed at full speed.
        """
        self.samples += 1
        if not self._initialised:
            self.mean = value
            self._initialised = True
            return
        rate = self.alpha if alpha is None else alpha
        delta = value - self.mean
        self.mean += rate * delta
        if update_variance:
            # West's incremental EWMVar: tracks variance with the same decay.
            self.variance = (1 - rate) * (self.variance + rate * delta * delta)

    @property
    def stddev(self) -> float:
        return math.sqrt(max(self.variance, 0.0))

    @property
    def ready(self) -> bool:
        """True once enough samples exist for deviations to mean anything."""
        return self.samples >= self.min_samples

    def deviation(self, value: float) -> float:
        """Signed deviation of ``value`` from the baseline, in sigma.

        Returns 0.0 while the baseline is still warming up, and falls back to a
        ratio-based estimate when the observed variance is ~0 (a perfectly steady
        metric that suddenly jumps would otherwise divide by zero).
        """
        if not self.ready:
            return 0.0
        sd = self.stddev
        if sd < 1e-9:
            if abs(value - self.mean) < 1e-9:
                return 0.0
            baseline = max(abs(self.mean), 1.0)
            return (value - self.mean) / baseline
        return (value - self.mean) / sd

    def anomaly_score(self, value: float, *, sigma_saturation: float = 6.0) -> float:
        """Map deviation onto 0.0-1.0.

        Only positive deviations score: for security metrics, "far less traffic
        than usual" is not itself an intrusion signal, and treating it as one
        produced noise in testing.
        """
        if not self.ready:
            return 0.0
        deviation = self.deviation(value)
        if deviation <= 0:
            return 0.0
        return min(1.0, deviation / sigma_saturation)

    def snapshot(self) -> dict[str, float]:
        return {
            "mean": self.mean,
            "stddev": self.stddev,
            "samples": float(self.samples),
        }
