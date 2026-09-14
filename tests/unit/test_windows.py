from __future__ import annotations

import pytest

from sentinelx.common.windows import CounterWindow, EwmaBaseline, SlidingWindow, UniqueWindow


class TestSlidingWindow:
    def test_expires_entries_older_than_duration(self) -> None:
        window: SlidingWindow[int] = SlidingWindow(10.0)
        for offset in range(5):
            window.add(100.0 + offset, offset)
        window.expire(112.0)
        assert list(window.items()) == [2, 3, 4]

    def test_boundary_entry_exactly_at_cutoff_is_kept(self) -> None:
        window: SlidingWindow[int] = SlidingWindow(10.0)
        window.add(100.0, 1)
        window.expire(110.0)
        assert len(window) == 1

    def test_rate_uses_observed_span_not_nominal_window(self) -> None:
        window: SlidingWindow[None] = SlidingWindow(60.0)
        for offset in range(11):
            window.add(100.0 + offset * 0.1, None)  # 11 events in 1 second
        assert window.rate() == pytest.approx(11.0)

    def test_single_entry_rate_does_not_divide_by_zero(self) -> None:
        window: SlidingWindow[None] = SlidingWindow(5.0)
        window.add(1.0, None)
        assert window.rate() == 1.0

    def test_hard_cap_bounds_memory_under_flood(self) -> None:
        window: SlidingWindow[int] = SlidingWindow(1000.0, max_entries=100)
        for index in range(1000):
            window.add(1.0, index)
        assert len(window) == 100

    def test_rejects_non_positive_duration(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            SlidingWindow(0)


class TestUniqueWindow:
    def test_counts_distinct_values_per_key(self) -> None:
        window: UniqueWindow[str] = UniqueWindow(10.0)
        for port in (22, 23, 22, 80):
            window.add("a", port, 1.0)
        window.add("b", 22, 1.0)
        assert window.unique_count("a", 1.0) == 3
        assert window.total_count("a", 1.0) == 4
        assert window.unique_count("b", 1.0) == 1
        assert window.unique_count("missing", 1.0) == 0

    def test_evicts_idle_keys_when_full(self) -> None:
        window: UniqueWindow[int] = UniqueWindow(1.0, max_keys=10)
        for key in range(10):
            window.add(key, 1, 0.0)
        window.add(99, 1, 100.0)  # all earlier windows are expired by now
        assert window.unique_count(99, 100.0) == 1
        assert len(window._windows) <= 10


class TestCounterWindow:
    def test_top_orders_by_count(self) -> None:
        counter: CounterWindow[str] = CounterWindow(60.0)
        counter.increment("a", 1.0, 3)
        counter.increment("b", 1.0, 7)
        assert counter.top(1.0) == [("b", 7), ("a", 3)]


class TestEwmaBaseline:
    def test_no_anomaly_before_warmup(self) -> None:
        baseline = EwmaBaseline(alpha=0.2, min_samples=10)
        for _ in range(5):
            baseline.update(20.0)
        assert baseline.anomaly_score(10_000.0) == 0.0

    def test_spike_after_stable_baseline_scores_high(self) -> None:
        baseline = EwmaBaseline(alpha=0.1, min_samples=20)
        for value in [18, 22, 19, 21, 20] * 10:
            baseline.update(float(value))
        assert baseline.anomaly_score(21.0) < 0.3
        assert baseline.anomaly_score(300.0) == 1.0

    def test_drop_below_baseline_is_not_anomalous(self) -> None:
        baseline = EwmaBaseline(alpha=0.1, min_samples=5)
        for _ in range(20):
            baseline.update(100.0)
        assert baseline.anomaly_score(0.0) == 0.0

    def test_perfectly_flat_baseline_still_detects_jump(self) -> None:
        baseline = EwmaBaseline(alpha=0.1, min_samples=5)
        for _ in range(20):
            baseline.update(20.0)
        assert baseline.deviation(300.0) > 0
        assert baseline.anomaly_score(300.0) > 0.9

    @pytest.mark.parametrize("alpha", [0.0, -0.1, 1.5])
    def test_rejects_invalid_alpha(self, alpha: float) -> None:
        with pytest.raises(ValueError):
            EwmaBaseline(alpha=alpha)
