"""Statistical anomaly detection.

Learns what "normal" looks like for a set of network-wide metrics and reports when
the present departs from it.  This catches what thresholds cannot: a DNS rate of
300/s is unremarkable on a large resolver and alarming on a ten-person office, and
no single threshold is right for both.

Method: for each metric, an exponentially weighted mean and variance
(:class:`~sentinelx.common.windows.EwmaBaseline`), sampled once per
``sample_interval_seconds`` of *packet time*.  The anomaly score is the positive
deviation in standard deviations, mapped onto 0-1 and saturating at
``sigma_saturation``.

Two guards keep it honest:

* **Warm-up** - nothing is reported until ``min_samples`` intervals have been seen.
* **Poisoning resistance** - an interval that scores as anomalous moves the baseline
  mean at a tenth of the normal rate and does not widen its variance, so a
  sustained attack keeps scoring as anomalous instead of teaching the model that
  it is normal. A genuine lasting change in traffic is still absorbed, slowly.

Anomalies are always reported with ``recommended_action=alert``.  A statistical
deviation says "this is unusual", not "this is malicious", and the platform will
not block on that alone.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Final

from sentinelx.common.enums import ActionType, Protocol, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence, PacketEvent
from sentinelx.common.windows import EwmaBaseline
from sentinelx.config.settings import AnomalySettings, DetectionSettings
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext

__all__ = ["METRICS", "IntervalSample", "StatisticalAnomalyDetector"]

#: metric name -> (human label, unit, minimum absolute value worth reporting)
#: Ordered most specific first; ties in anomaly score go to the earlier metric.
METRICS: Final[dict[str, tuple[str, str, float]]] = {
    "syn_per_second": ("TCP connection attempts", "SYN/s", 10.0),
    "dns_per_second": ("DNS query rate", "queries/s", 10.0),
    "icmp_per_second": ("ICMP rate", "packets/s", 10.0),
    "unique_sources": ("Distinct active sources", "sources", 20.0),
    "packets_per_second": ("Total packet rate", "packets/s", 50.0),
    "bytes_per_second": ("Total byte rate", "bytes/s", 50_000.0),
}


@dataclass(slots=True)
class IntervalSample:
    """Counters accumulated over one sampling interval."""

    start: float
    packets: int = 0
    bytes_total: int = 0
    syns: int = 0
    dns_queries: int = 0
    icmp: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    syn_sources: Counter[str] = field(default_factory=Counter)
    dns_sources: Counter[str] = field(default_factory=Counter)
    icmp_sources: Counter[str] = field(default_factory=Counter)

    def observe(
        self, packet: PacketEvent, *, solicited_reply: bool = False, response: bool = False
    ) -> None:
        """Count one packet.

        Args:
            solicited_reply: an ICMP echo reply to a request.
            response: the packet comes from the side that did not open its flow. Rates
                count it; attribution does not, so the source blamed for a spike is
                whoever drove it rather than whoever answered.
        """
        self.packets += 1
        self.bytes_total += packet.length
        if not response:
            self.sources[packet.src_ip] += 1
        if packet.tcp_flags is not None and packet.tcp_flags.is_syn_only:
            self.syns += 1
            self.syn_sources[packet.src_ip] += 1
        elif packet.protocol in (Protocol.ICMP, Protocol.ICMPV6):
            self.icmp += 1
            # The rate counts every ICMP packet, but a host answering pings is not a
            # contributor to blame: attribution goes to whoever sent the requests.
            if not (solicited_reply or response):
                self.icmp_sources[packet.src_ip] += 1
        dns = packet.metadata.get("dns")
        if isinstance(dns, dict) and not dns.get("is_response"):
            self.dns_queries += 1
            self.dns_sources[packet.src_ip] += 1

    def values(self, seconds: float) -> dict[str, float]:
        return {
            "packets_per_second": self.packets / seconds,
            "bytes_per_second": self.bytes_total / seconds,
            "syn_per_second": self.syns / seconds,
            "dns_per_second": self.dns_queries / seconds,
            "icmp_per_second": self.icmp / seconds,
            "unique_sources": float(len(self.sources)),
        }

    def top_contributor(self, metric: str) -> tuple[str, int, int] | None:
        """(source, its count, interval total) for the source driving a metric."""
        counter = {
            "syn_per_second": self.syn_sources,
            "dns_per_second": self.dns_sources,
            "icmp_per_second": self.icmp_sources,
        }.get(metric, self.sources)
        if not counter:
            return None
        source, count = counter.most_common(1)[0]
        return source, count, sum(counter.values())


class StatisticalAnomalyDetector(Detector):
    """EWMA baseline deviation across network-wide metrics."""

    name = "statistical_anomaly"
    description = "Network-wide traffic metrics deviating from their learned baseline."
    category = ThreatCategory.ANOMALY
    default_severity = Severity.MEDIUM

    def __init__(
        self, anomaly: AnomalySettings | None = None, settings: DetectionSettings | None = None
    ) -> None:
        super().__init__(settings)
        self.anomaly = anomaly or AnomalySettings()
        self.interval = self.anomaly.sample_interval_seconds
        self.baselines: dict[str, EwmaBaseline] = {
            metric: EwmaBaseline(
                alpha=self.anomaly.baseline_alpha, min_samples=self.anomaly.min_samples
            )
            for metric in METRICS
        }
        self._current: IntervalSample | None = None
        self.intervals = 0
        self._pending: list[Detection] = []

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        now = packet.timestamp
        if self._current is None or now < self._current.start - self.interval:
            # First packet, or packet time stepped backwards by more than an
            # interval. Without resynchronising, every packet until time caught up
            # would pile into one "interval" and be scored as a huge rate spike.
            self._current = IntervalSample(start=now)

        # Close every interval that has fully elapsed. Empty intervals in a gap are
        # real observations of zero traffic and are folded in as such (capped, so a
        # long idle period does not take unbounded time to process).
        closed = 0
        while now - self._current.start >= self.interval and closed < 3600:
            finished = self._current
            self._current = IntervalSample(start=finished.start + self.interval)
            self._close(finished, context)
            closed += 1
        if now - self._current.start >= self.interval:  # very long gap: resynchronise
            self._current = IntervalSample(start=now)

        # SentinelX's own storage traffic is not part of the network being watched: the
        # dashboard loading a page would otherwise read as a traffic spike.
        if not context.own_traffic:
            self._current.observe(
                packet, solicited_reply=context.solicited_reply, response=context.is_response
            )
        self.evaluations += 1
        return self._pending.pop(0) if self._pending else None

    def _close(self, sample: IntervalSample, context: FeatureContext) -> None:
        self.intervals += 1
        values = sample.values(self.interval)

        # Score every metric against the baseline *as it stood before this interval*
        # and build any detection from that same state. Updating first would make
        # the evidence describe a baseline the value was never compared against.
        worst: tuple[float, str, float] | None = None
        anomalous: set[str] = set()
        for metric in METRICS:  # METRICS order, not values() order, decides ties
            value = values[metric]
            baseline = self.baselines[metric]
            score = baseline.anomaly_score(value, sigma_saturation=self.anomaly.sigma_saturation)
            if (
                baseline.ready
                and score >= self.anomaly.anomaly_threshold
                and value >= METRICS[metric][2]
            ):
                anomalous.add(metric)
                # Strictly greater: METRICS is ordered most specific first, so on a
                # tie the specific metric (DNS rate) is reported over the aggregate.
                if worst is None or score > worst[0]:
                    worst = (score, metric, value)

        if worst is not None:
            detection = self._detection(worst[0], worst[1], worst[2], sample, context)
            if detection is not None:
                self._pending.append(detection)

        for metric, value in values.items():
            baseline = self.baselines[metric]
            if metric in anomalous:
                # Poisoning resistance: anomalous intervals move the mean ten times
                # more slowly and never widen the variance.
                baseline.update(value, alpha=baseline.alpha / 10, update_variance=False)
            else:
                baseline.update(value)

    def _detection(
        self,
        score: float,
        metric: str,
        value: float,
        sample: IntervalSample,
        context: FeatureContext,
    ) -> Detection | None:
        baseline = self.baselines[metric]
        label, unit, _ = METRICS[metric]
        contributor = sample.top_contributor(metric)
        if contributor is None:
            return None
        source, count, total = contributor
        share = count / total if total else 0.0
        sigma = baseline.deviation(value)
        severity = Severity.HIGH if score >= 0.97 and share >= 0.5 else Severity.MEDIUM

        evidence = [
            Evidence(
                key="metric",
                value=metric,
                description=f"{label}: {value:,.1f} {unit} against a baseline of {baseline.mean:,.1f} {unit}",
                weight=1.0,
            ),
            Evidence(
                key="anomaly_score",
                value=round(score, 3),
                threshold=self.anomaly.anomaly_threshold,
                description=f"anomaly score {score:.2f} ({sigma:.1f} standard deviations above normal)",
                weight=1.0,
            ),
            Evidence(
                key="baseline",
                value=baseline.snapshot(),
                description=(
                    f"baseline learned from {baseline.samples} intervals of {self.interval:g}s "
                    f"(mean {baseline.mean:,.1f}, stddev {baseline.stddev:,.1f})"
                ),
                weight=0.4,
            ),
            Evidence(
                key="top_contributor",
                value={"source": source, "share": round(share, 3)},
                description=f"{source} produced {share:.0%} of this interval's {_lower_first(label)}",
                weight=0.7,
            ),
        ]
        self.hits += 1
        return Detection(
            detector=self.name,
            category=self.category,
            severity=severity,
            # Capped below the rule-based detectors: deviation is weaker evidence
            # of malice than a matched behavioural pattern.
            confidence=round(min(0.85, 0.4 + 0.45 * score * max(share, 0.3)), 3),
            title=f"Unusual {_lower_first(label)}",
            description=f"{label} reached {value:,.1f} {unit}, {sigma:.1f} standard deviations above the learned baseline.",
            source_ip=source,
            protocol=context.packet.protocol,
            evidence=evidence,
            recommended_action=ActionType.ALERT,
            observation_window_seconds=self.interval,
            packet_count=sample.packets,
            tags=("anomaly", metric),
        )

    def baseline_report(self) -> dict[str, dict[str, float | bool | str]]:
        """Current baselines, for the Analytics page and ``sentinelx anomaly status``."""
        return {
            metric: {
                "label": METRICS[metric][0],
                "unit": METRICS[metric][1],
                "ready": baseline.ready,
                **baseline.snapshot(),
            }
            for metric, baseline in self.baselines.items()
        }


def _lower_first(label: str) -> str:
    """``"Packet rate"`` -> ``"packet rate"``, but leave acronyms alone (``"DNS query rate"``)."""
    if len(label) > 1 and label[1].isupper():
        return label
    return label[:1].lower() + label[1:]
