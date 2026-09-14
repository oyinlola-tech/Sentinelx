"""The detection engine.

Runs every enabled detector against each :class:`FeatureContext` and applies the
cross-cutting policy that no individual detector should have to implement:

* **Allowlisting** - sources the operator has declared trusted are never reported.
* **Cooldown** - once a detector has reported a source, repeats are suppressed for
  ``detection_cooldown_seconds``.  A port scan is thousands of packets; it should
  be one detection, not thousands.  Suppressions are counted, and the engine
  re-reports once the cooldown lapses if the behaviour persists.
* **Evidence enforcement** - a detection with no evidence is discarded and
  counted as a detector error.  Explainability is a hard requirement, not a
  convention.
* **Fault isolation** - an exception in one detector is logged and counted and
  never prevents the others from running or crashes the pipeline.

The engine is synchronous and has no I/O.  That is deliberate: it can be driven by
live capture, by PCAP replay, by the benchmark harness, or directly from a test,
with identical results.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from sentinelx.common.enums import DetectionMode
from sentinelx.common.models import Detection
from sentinelx.common.netutils import IPNetworkT, parse_ip, parse_networks
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.base import Detector
from sentinelx.detection.behavioral import (
    BruteForceDetector,
    ConnectionRateDetector,
    HttpFloodDetector,
    IcmpFloodDetector,
    SynFloodDetector,
)
from sentinelx.detection.dns import DnsAnomalyDetector
from sentinelx.detection.policy import DenylistDetector, TcpFlagAnomalyDetector
from sentinelx.detection.scanning import (
    HorizontalScanDetector,
    TcpPortScanDetector,
    UdpScanDetector,
)
from sentinelx.features.extractor import FeatureContext
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["BUILTIN_DETECTORS", "DetectionEngine", "default_detectors"]

log = get_logger(__name__)

#: Built-in detectors, in evaluation order. Cheap, precise detectors run first.
BUILTIN_DETECTORS: tuple[type[Detector], ...] = (
    DenylistDetector,
    TcpFlagAnomalyDetector,
    TcpPortScanDetector,
    HorizontalScanDetector,
    UdpScanDetector,
    BruteForceDetector,
    SynFloodDetector,
    ConnectionRateDetector,
    IcmpFloodDetector,
    HttpFloodDetector,
    DnsAnomalyDetector,
)

#: Detectors that run in SIGNATURE_ONLY mode: those that match facts, not rates.
_SIGNATURE_DETECTORS = frozenset({"denylist", "tcp_flag_anomaly"})


def default_detectors(settings: DetectionSettings) -> list[Detector]:
    """Instantiate the built-in detectors appropriate for ``settings.mode``."""
    if settings.mode is DetectionMode.DISABLED:
        return []
    detectors = [cls(settings) for cls in BUILTIN_DETECTORS]
    if settings.mode is DetectionMode.SIGNATURE_ONLY:
        detectors = [d for d in detectors if d.name in _SIGNATURE_DETECTORS]
    if settings.enabled_detectors:
        allowed = set(settings.enabled_detectors)
        detectors = [d for d in detectors if d.name in allowed]
    if settings.disabled_detectors:
        blocked = set(settings.disabled_detectors)
        for detector in detectors:
            if detector.name in blocked:
                detector.enabled = False
    return detectors


class DetectionEngine:
    """Runs detectors and applies allowlist, cooldown and evidence policy.

    Example:
        >>> engine = DetectionEngine(settings)
        >>> for detection in engine.evaluate(context):
        ...     print(detection.explain())
    """

    def __init__(
        self,
        settings: DetectionSettings | None = None,
        detectors: Iterable[Detector] | None = None,
    ) -> None:
        self.settings = settings or DetectionSettings()
        self.detectors: list[Detector] = (
            list(detectors) if detectors is not None else default_detectors(self.settings)
        )
        self._allowlist: list[IPNetworkT] = parse_networks(self.settings.allowlist_networks)
        self._cooldown = self.settings.detection_cooldown_seconds
        #: (detector, source) -> (packet time, severity rank, confidence) last reported.
        self._last_reported: dict[tuple[str, str], tuple[float, int, float]] = {}
        self.escalations = 0
        self.detections_emitted = 0
        self.suppressed_cooldown = 0
        self.suppressed_allowlist = 0
        self.detector_errors = 0
        # Detectors are also looked up by name for enable/disable at runtime.
        self._by_name: dict[str, Detector] = {d.name: d for d in self.detectors}

    # ------------------------------------------------------------ evaluation

    def evaluate(self, context: FeatureContext) -> list[Detection]:
        """Run every enabled detector against one packet.

        Returns:
            Detections that passed allowlist, cooldown and evidence checks.
            Usually empty.
        """
        if not self.detectors:
            return []
        started = time.perf_counter()
        results: list[Detection] = []

        for detector in self.detectors:
            if not detector.enabled:
                continue
            try:
                detection = detector.inspect(context)
            except Exception:
                self.detector_errors += 1
                metrics.detector_errors.labels(detector=detector.name).inc()
                log.exception(
                    "detector_failed", detector=detector.name, packet=context.packet.summary()
                )
                continue
            if detection is None:
                continue
            accepted = self._admit(detection, context)
            if accepted is not None:
                results.append(accepted)

        metrics.detection_latency.observe(time.perf_counter() - started)
        return results

    def _admit(self, detection: Detection, context: FeatureContext) -> Detection | None:
        """Apply engine-wide policy to a candidate detection."""
        if not detection.evidence:
            self.detector_errors += 1
            metrics.detector_errors.labels(detector=detection.detector).inc()
            log.error(
                "detection_without_evidence_rejected",
                detector=detection.detector,
                source=detection.source_ip,
            )
            return None

        if self._is_allowlisted(detection.source_ip):
            self.suppressed_allowlist += 1
            metrics.detections_suppressed.labels(reason="allowlist").inc()
            return None

        key = (detection.detector, detection.source_ip)
        now = context.now
        last = self._last_reported.get(key)
        if last is not None and now - last[0] < self._cooldown:
            if not self._escalates(detection, last):
                self.suppressed_cooldown += 1
                metrics.detections_suppressed.labels(reason="cooldown").inc()
                return None
            self.escalations += 1
        self._last_reported[key] = (now, detection.severity.rank, detection.confidence)
        if len(self._last_reported) > 100_000:
            self._prune_cooldowns(now)

        profile = context.profile_of(detection.source_ip)
        if profile is not None:
            profile.detections_triggered += 1

        self.detections_emitted += 1
        metrics.detections.labels(
            detector=detection.detector,
            severity=detection.severity.value,
            category=detection.category.value,
        ).inc()
        log.info(
            "detection",
            detector=detection.detector,
            severity=detection.severity.value,
            confidence=detection.confidence,
            source=detection.source_ip,
            destination=detection.destination_ip,
            title=detection.title,
        )
        return detection

    @staticmethod
    def _escalates(detection: Detection, last: tuple[float, int, float]) -> bool:
        """True when a repeat inside the cooldown is materially worse than before.

        Detectors fire as soon as a threshold is crossed, which is when evidence is
        thinnest. Suppressing everything afterwards would freeze the record at
        "20 ports, confidence 0.6" while the scan grows to 2,000 ports. Allowing a
        re-report on a severity increase, or a confidence gain of at least 0.2,
        keeps the record honest without reintroducing alert floods: each detector
        can escalate at most a handful of times before it saturates.
        """
        _, last_rank, last_confidence = last
        return detection.severity.rank > last_rank or detection.confidence >= last_confidence + 0.2

    def _is_allowlisted(self, address: str) -> bool:
        if not self._allowlist:
            return False
        try:
            ip = parse_ip(address)
        except ValueError:
            return False
        return any(ip.version == net.version and ip in net for net in self._allowlist)

    def _prune_cooldowns(self, now: float) -> None:
        cutoff = now - self._cooldown
        self._last_reported = {k: v for k, v in self._last_reported.items() if v[0] >= cutoff}

    # ------------------------------------------------------------ management

    def add_detector(self, detector: Detector) -> None:
        """Register an additional detector (rule-based, anomaly, ML, plugin)."""
        if detector.name in self._by_name:
            self.detectors = [d for d in self.detectors if d.name != detector.name]
        self.detectors.append(detector)
        self._by_name[detector.name] = detector

    def remove_detector(self, name: str) -> bool:
        if name not in self._by_name:
            return False
        del self._by_name[name]
        self.detectors = [d for d in self.detectors if d.name != name]
        return True

    def get(self, name: str) -> Detector | None:
        return self._by_name.get(name)

    def set_enabled(self, name: str, enabled: bool) -> bool:
        detector = self._by_name.get(name)
        if detector is None:
            return False
        detector.enabled = enabled
        log.info("detector_toggled", detector=name, enabled=enabled)
        return True

    def update_allowlist(self, networks: list[str]) -> None:
        """Replace the allowlist. Validates every entry before applying any."""
        self._allowlist = parse_networks(networks)

    def reset(self) -> None:
        """Clear cooldown state and counters, keeping detectors and configuration."""
        self._last_reported.clear()
        self.detections_emitted = 0
        self.suppressed_cooldown = 0
        self.suppressed_allowlist = 0
        self.detector_errors = 0
        self.escalations = 0
        for detector in self.detectors:
            detector.evaluations = 0
            detector.hits = 0

    def stats(self) -> dict[str, object]:
        return {
            "detectors": len(self.detectors),
            "enabled": sum(1 for d in self.detectors if d.enabled),
            "detections_emitted": self.detections_emitted,
            "suppressed_cooldown": self.suppressed_cooldown,
            "escalations": self.escalations,
            "suppressed_allowlist": self.suppressed_allowlist,
            "detector_errors": self.detector_errors,
            "per_detector": [d.stats() for d in self.detectors],
        }
