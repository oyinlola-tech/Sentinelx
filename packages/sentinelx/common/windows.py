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
from collections import Counter, deque
from collections.abc import Hashable, Iterator

__all__ = [
    "CounterWindow",
    "DistinctWindow",
    "EwmaBaseline",
    "SizeWindow",
    "SlidingWindow",
    "TimeSeriesCounter",
    "UniqueWindow",
]


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


class TimeSeriesCounter:
    """Event timestamps with O(1) counts over several trailing windows at once.

    Detectors ask "how many events in the last N seconds" for different N about
    the same series (connection attempts over 10s for the rate detector, over 15s
    for the scan detector, over a rule's own ``within``).  Counting by scanning the
    deque is O(events) per question, and asked once per packet it is quadratic under
    exactly the load an IDS must survive.

    Timestamps live in a list with a moving head, and each registered duration keeps
    its own head pointer that only ever advances, so every registered count is
    amortised O(1).  Unregistered cutoffs use :func:`bisect.bisect_left`, O(log n).
    Out-of-order timestamps (common when merged captures are replayed) are clamped
    to the newest seen, which keeps the list sorted at the cost of a few
    milliseconds of timing precision.
    """

    __slots__ = ("_heads", "_max_entries", "_start", "_times", "durations", "retention")

    def __init__(
        self, durations: tuple[float, ...] | list[float], max_entries: int = 200_000
    ) -> None:
        cleaned = sorted({float(d) for d in durations if d > 0})
        if not cleaned:
            raise ValueError("at least one positive duration is required")
        self.durations = tuple(cleaned)
        self.retention = cleaned[-1]
        self._times: list[float] = []
        self._start = 0
        self._heads: dict[float, int] = dict.fromkeys(self.durations, 0)
        self._max_entries = max_entries

    def add(self, timestamp: float) -> None:
        times = self._times
        if times and timestamp < times[-1]:
            timestamp = times[-1]
        times.append(timestamp)
        self._advance(timestamp)
        if len(times) - self._start > self._max_entries:
            self._start = len(times) - self._max_entries
            for duration, head in self._heads.items():
                self._heads[duration] = max(head, self._start)
        if self._start > 4096 and self._start * 2 > len(times):
            self._compact()

    def _advance(self, now: float) -> None:
        times = self._times
        end = len(times)
        for duration, head in self._heads.items():
            cutoff = now - duration
            while head < end and times[head] < cutoff:
                head += 1
            self._heads[duration] = head
        self._start = min(self._heads.values())

    def _compact(self) -> None:
        offset = self._start
        del self._times[:offset]
        self._start = 0
        for duration in self._heads:
            self._heads[duration] -= offset

    def count(self, duration: float, now: float) -> int:
        """Events in the trailing ``duration`` ending at ``now``."""
        if duration in self._heads:
            if self._times and now > self._times[-1]:
                self._advance(now)
            return len(self._times) - self._heads[duration]
        return self.count_since(now - duration)

    def count_since(self, cutoff: float) -> int:
        from bisect import bisect_left

        return len(self._times) - bisect_left(self._times, cutoff, lo=self._start)

    def expire(self, now: float) -> None:
        if self._times and now > self._times[-1]:
            self._advance(now)

    def span(self, duration: float | None = None) -> float:
        """Seconds between the oldest event in the window and the newest event."""
        if not self._times:
            return 0.0
        head = self._heads.get(duration if duration is not None else self.retention, self._start)
        if head >= len(self._times):
            return 0.0
        return self._times[-1] - self._times[head]

    def __len__(self) -> int:
        """Events within the longest registered window."""
        return len(self._times) - self._heads[self.retention]

    def __bool__(self) -> bool:
        return len(self) > 0


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


class SizeWindow(SlidingWindow[int]):
    """A sliding window of sizes with O(1) running mean and standard deviation.

    Flood detectors look at size uniformity on every packet past their threshold;
    recomputing statistics over the window each time was quadratic under a flood.
    """

    __slots__ = ("_sum", "_sum_squares")

    def __init__(self, duration: float, max_entries: int = 100_000) -> None:
        super().__init__(duration, max_entries)
        self._sum = 0
        self._sum_squares = 0

    def add(self, timestamp: float, item: int) -> None:
        self._entries.append((timestamp, item))
        self._sum += item
        self._sum_squares += item * item
        self.expire(timestamp)
        while len(self._entries) > self._max_entries:
            self._drop(self._entries.popleft()[1])

    def expire(self, now: float) -> None:
        cutoff = now - self.duration
        entries = self._entries
        while entries and entries[0][0] < cutoff:
            self._drop(entries.popleft()[1])

    def _drop(self, item: int) -> None:
        self._sum -= item
        self._sum_squares -= item * item

    @property
    def mean(self) -> float:
        return self._sum / len(self._entries) if self._entries else 0.0

    @property
    def stddev(self) -> float:
        count = len(self._entries)
        if count == 0:
            return 0.0
        mean = self._sum / count
        # Integer sums keep this exact; max() guards float rounding below zero.
        return math.sqrt(max(self._sum_squares / count - mean * mean, 0.0))


class DistinctWindow[V: Hashable](SlidingWindow[V]):
    """A sliding window that also tracks how many *distinct* values it holds.

    A running :class:`~collections.Counter` is maintained alongside the deque, so
    adding, expiring and asking "how many distinct values?" are all amortised O(1).

    This matters for security, not just speed.  The previous implementation rebuilt
    a ``set`` of the whole window on every packet, which made per-packet cost grow
    with the window's size: a single source flooding 300 packets per second slowed
    processing roughly sixfold, i.e. an attacker could degrade the IDS simply by
    being noisy.  ``tests/unit/test_windows.py`` pins the linear behaviour.
    """

    __slots__ = ("_counts",)

    def __init__(self, duration: float, max_entries: int = 100_000) -> None:
        super().__init__(duration, max_entries)
        self._counts: Counter[V] = Counter()

    def add(self, timestamp: float, item: V) -> None:
        self._entries.append((timestamp, item))
        self._counts[item] += 1
        self.expire(timestamp)
        while len(self._entries) > self._max_entries:
            self._forget(self._entries.popleft()[1])

    def expire(self, now: float) -> None:
        cutoff = now - self.duration
        entries = self._entries
        while entries and entries[0][0] < cutoff:
            self._forget(entries.popleft()[1])

    def _forget(self, item: V) -> None:
        remaining = self._counts[item] - 1
        if remaining:
            self._counts[item] = remaining
        else:
            del self._counts[item]

    @property
    def distinct(self) -> int:
        return len(self._counts)

    def distinct_values(self) -> set[V]:
        return set(self._counts)

    def count_of(self, item: V) -> int:
        """Occurrences of ``item`` currently in the window. O(1)."""
        return self._counts.get(item, 0)

    def most_common(self, limit: int = 1) -> list[tuple[V, int]]:
        return self._counts.most_common(limit)

    def distinct_since(self, cutoff: float) -> int:
        """Distinct values at or after ``cutoff``. O(1) when the cutoff spans the window."""
        if not self._entries or self._entries[0][0] >= cutoff:
            return len(self._counts)
        return len(set(self.items_since(cutoff)))


class UniqueWindow[K: Hashable]:
    """Counts *distinct* values seen per key inside a window.

    Example: how many distinct destination ports one source touched in 10s -
    the core signal for port-scan detection.  Backed by :class:`DistinctWindow`,
    so every operation is amortised O(1) per observation.
    """

    __slots__ = ("_windows", "duration", "max_keys")

    def __init__(self, duration: float, max_keys: int = 50_000) -> None:
        self.duration = duration
        self.max_keys = max_keys
        self._windows: dict[K, DistinctWindow[Hashable]] = {}

    def add(self, key: K, value: Hashable, timestamp: float) -> int:
        """Record that ``key`` touched ``value``; return the distinct count."""
        window = self._windows.get(key)
        if window is None:
            if len(self._windows) >= self.max_keys:
                self._evict(timestamp)
            window = DistinctWindow(self.duration)
            self._windows[key] = window
        window.add(timestamp, value)
        return window.distinct

    def unique_count(self, key: K, now: float) -> int:
        window = self._windows.get(key)
        if window is None:
            return 0
        window.expire(now)
        return window.distinct

    def contains(self, key: K, value: Hashable) -> bool:
        """Whether ``key`` has touched ``value`` within the window. O(1)."""
        window = self._windows.get(key)
        return window is not None and window.count_of(value) > 0

    def unique_values(self, key: K, now: float) -> set[Hashable]:
        window = self._windows.get(key)
        if window is None:
            return set()
        window.expire(now)
        return window.distinct_values()

    def unique_since(self, key: K, cutoff: float) -> int:
        """Distinct values for ``key`` observed at or after ``cutoff``."""
        window = self._windows.get(key)
        return window.distinct_since(cutoff) if window else 0

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

    def update(
        self, value: float, *, alpha: float | None = None, update_variance: bool = True
    ) -> None:
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
