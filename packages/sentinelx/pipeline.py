"""The detection pipeline.

The single place where every stage is wired together::

    capture -> decode -> features -> detect -> intel -> score -> correlate -> respond -> publish

Live capture, PCAP replay, the benchmark harness, the CLI and the API all drive
*this* class.  There is no second pipeline for replay or for tests, which is what
makes "a detection that fires on a replay would have fired on the wire" true.

The per-packet stages (decode, features, detect) are synchronous and allocation
-light.  Only when a detector fires does the pipeline switch to async work (intel
lookups, the firewall, the event bus), because that is rare and is I/O.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelx.capture.base import PacketCapture, RawFrame
from sentinelx.common.models import (
    Detection,
    Incident,
    PacketEvent,
    ResponseDecision,
    RiskAssessment,
)
from sentinelx.common.netutils import parse_networks
from sentinelx.config.settings import Settings
from sentinelx.correlation.engine import CorrelationEngine, CorrelationResult
from sentinelx.detection.base import Detector
from sentinelx.detection.engine import DetectionEngine
from sentinelx.events.bus import EventBus, EventType
from sentinelx.events.serialize import detection_to_dict, incident_to_dict
from sentinelx.features.extractor import FeatureExtractor
from sentinelx.firewall import FirewallAdapter, MemoryFirewall
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.response.engine import AuditSink, ResponseEngine
from sentinelx.scoring.engine import RiskContext, RiskEngine
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import ProcessSampler, metrics
from sentinelx.threat_intel.providers import ThreatIntelService

__all__ = ["DetectionRecord", "Pipeline", "RunReport"]

log = get_logger(__name__)

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


@dataclass(slots=True)
class DetectionRecord:
    """A detection together with everything decided about it."""

    detection: Detection
    risk: RiskAssessment
    incident: Incident | None
    decisions: list[ResponseDecision]
    latency_seconds: float
    """Wall time from receiving the triggering frame to finishing the response."""


@dataclass(slots=True)
class RunReport:
    """Measured results of one run over a capture source.

    Every figure here is measured during the run. Nothing is estimated.
    """

    source: str
    started_at: datetime
    finished_at: datetime | None = None
    frames: int = 0
    packets_decoded: int = 0
    decode_failures: int = 0
    bytes_total: int = 0
    wall_seconds: float = 0.0
    capture_span_seconds: float = 0.0
    detections: list[DetectionRecord] = field(default_factory=list)
    incidents: dict[str, Incident] = field(default_factory=dict)
    processing_latencies: list[float] = field(default_factory=list)
    cpu_percent_samples: list[float] = field(default_factory=list)
    memory_peak_bytes: float = 0.0
    stopped_early: bool = False
    detections_seen: int = 0
    """All detections in the run; ``detections`` may hold only the most recent."""
    incidents_seen: int = 0
    metrics_received: int = 0
    metrics_dropped: int = 0
    """Capture counts already published to Prometheus, so updates can be incremental."""

    @property
    def packets_per_second(self) -> float:
        return self.frames / self.wall_seconds if self.wall_seconds > 0 else 0.0

    def _percentile(self, values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
        return ordered[index]

    def as_dict(self) -> dict[str, Any]:
        detection_latency = [r.latency_seconds for r in self.detections]
        decisions = [d for r in self.detections for d in r.decisions if d.action.is_preventive]
        cpu = self.cpu_percent_samples
        return {
            "source": self.source,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "frames": self.frames,
            "packets_decoded": self.packets_decoded,
            "decode_failures": self.decode_failures,
            "bytes_total": self.bytes_total,
            "wall_seconds": round(self.wall_seconds, 4),
            "capture_span_seconds": round(self.capture_span_seconds, 4),
            "packets_per_second": round(self.packets_per_second, 1),
            "detection_count": max(self.detections_seen, len(self.detections)),
            "incident_count": max(self.incidents_seen, len(self.incidents)),
            "detections_by_detector": _count(r.detection.detector for r in self.detections),
            "detections_by_severity": _count(r.detection.severity.value for r in self.detections),
            "response_decisions": _count(f"{d.action.value}:{d.outcome}" for d in decisions),
            "latency": {
                "per_packet_mean_ms": round(
                    1000 * sum(self.processing_latencies) / len(self.processing_latencies), 4
                )
                if self.processing_latencies
                else 0.0,
                "per_packet_p50_ms": round(
                    1000 * self._percentile(self.processing_latencies, 50), 4
                ),
                "per_packet_p99_ms": round(
                    1000 * self._percentile(self.processing_latencies, 99), 4
                ),
                "detection_mean_ms": round(
                    1000 * sum(detection_latency) / len(detection_latency), 3
                )
                if detection_latency
                else 0.0,
                "detection_max_ms": round(1000 * max(detection_latency), 3)
                if detection_latency
                else 0.0,
            },
            "resources": {
                "cpu_percent_mean": round(sum(cpu) / len(cpu), 1) if cpu else 0.0,
                "cpu_percent_max": round(max(cpu), 1) if cpu else 0.0,
                "memory_peak_mb": round(self.memory_peak_bytes / 1_048_576, 1),
            },
            "stopped_early": self.stopped_early,
        }


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


class Pipeline:
    """Owns and connects every processing stage.

    Args:
        settings: full platform settings.
        bus: event bus; a private one is created if omitted (library use).
        firewall: enforcement adapter; defaults to the in-memory firewall.
        audit: audit sink for response decisions.
        intel: threat intelligence service.
        extra_detectors: rule-based, anomaly or plugin detectors to add.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        bus: EventBus | None = None,
        firewall: FirewallAdapter | None = None,
        audit: AuditSink | None = None,
        intel: ThreatIntelService | None = None,
        extra_detectors: list[Detector] | None = None,
    ) -> None:
        self.settings = settings
        self.bus = bus or EventBus()
        self.decoder = PacketDecoder(parse_networks(settings.capture.home_networks))
        self.extractor = FeatureExtractor(settings.detection)
        self.detection = DetectionEngine(settings.detection)
        for detector in extra_detectors or []:
            self.detection.add_detector(detector)
        self.risk = RiskEngine(settings.scoring)
        self.correlation = CorrelationEngine(settings.correlation)
        self.intel = intel or ThreatIntelService()
        self.response = ResponseEngine(
            settings.response,
            firewall or MemoryFirewall(),
            scoring=settings.scoring,
            bus=self.bus,
            audit=audit,
            on_response=self.risk.record_response,
        )
        self._sampler = ProcessSampler()
        self.capture: PacketCapture | None = None
        self.started_at: float | None = None
        self.last_report: RunReport | None = None
        self._packet_hooks: list[Callable[[PacketEvent], None]] = []
        self._replay_id: str | None = None
        #: TELEMETRY__PROFILE_PIPELINE: time each stage into sentinelx_stage_latency_seconds.
        self.profile = settings.telemetry.profile_pipeline

    @property
    def replay_id(self) -> str | None:
        """Tags published detections, incidents and decisions while a replay runs."""
        return self._replay_id

    @replay_id.setter
    def replay_id(self, value: str | None) -> None:
        self._replay_id = value
        self.response.replay_id = value

    # ------------------------------------------------------------- lifecycle

    async def start(self, known_expiries: dict[str, datetime] | None = None) -> None:
        await self.bus.start()
        await self.response.start(known_expiries)
        self.started_at = time.monotonic()
        log.info(
            "pipeline_started",
            sensor=self.settings.sensor_name,
            banner=self.settings.safety_banner(),
        )

    async def stop(self) -> None:
        if self.capture is not None:
            self.capture.stop()
        await self.response.stop()
        await self.bus.stop()

    def add_packet_hook(self, hook: Callable[[PacketEvent], None]) -> None:
        """Observe every decoded packet (CLI live monitor). Keep hooks cheap."""
        self._packet_hooks.append(hook)

    def reset_state(self) -> None:
        """Forget traffic state so a replay starts clean. Configuration is kept."""
        self.extractor.reset()
        self.detection.reset()
        self.risk.reset()
        self.correlation.reset()

    # ------------------------------------------------------------ processing

    async def process_frame(self, frame: RawFrame) -> list[DetectionRecord]:
        """Push one frame through every stage."""
        started = time.perf_counter()
        packet = self.decoder.decode(
            frame.data, frame.timestamp, frame.link_type, frame.interface, frame.wire_length
        )
        if self.profile:
            decoded = time.perf_counter()
            metrics.stage_latency.labels(stage="decode").observe(decoded - started)
        if packet is None:
            return []
        for hook in self._packet_hooks:
            hook(packet)

        context = self.extractor.process(packet)
        if self.profile:
            extracted = time.perf_counter()
            metrics.stage_latency.labels(stage="features").observe(extracted - decoded)
        detections = self.detection.evaluate(context)
        if self.profile:
            evaluated = time.perf_counter()
            metrics.stage_latency.labels(stage="detection").observe(evaluated - extracted)
        metrics.packets_processed.labels(protocol=packet.protocol.value).inc()
        if not detections:
            metrics.pipeline_latency.observe(time.perf_counter() - started)
            return []

        records = [await self._handle_detection(detection, started) for detection in detections]
        finished = time.perf_counter()
        if self.profile:
            # Threat intel, risk, correlation, response and publishing, for every detection.
            metrics.stage_latency.labels(stage="response").observe(finished - evaluated)
        metrics.pipeline_latency.observe(finished - started)
        return records

    async def _handle_detection(self, detection: Detection, started: float) -> DetectionRecord:
        intel_score, intel_sources, trusted, _ = await self.intel.evaluate(detection.source_ip)
        context = RiskContext(
            intel_score=intel_score,
            intel_sources=intel_sources,
            allowlisted=trusted,
            correlated_detectors=self.correlation.correlated_detector_count(detection),
        )
        risk = self.risk.assess(detection, context)
        await self.bus.publish(
            EventType.DETECTION_CREATED,
            {**detection_to_dict(detection, risk), "replay_id": self.replay_id},
        )

        incident: Incident | None = None
        result = self.correlation.correlate(detection, risk)
        if result is not None:
            incident = result.incident
            payload = {
                **incident_to_dict(incident),
                "replay_id": self.replay_id,
                # Which detections to link to this incident in storage: all of them when
                # it opens, only the new one on each update.
                "linked_detection_ids": list(incident.detection_ids)
                if result.created
                else [detection.detection_id],
            }
            if result.created:
                await self.bus.publish(EventType.INCIDENT_OPENED, payload)
            else:
                await self.bus.publish(EventType.INCIDENT_UPDATED, payload)
            if result.severity_changed:
                await self.bus.publish(
                    EventType.SEVERITY_CHANGED,
                    {
                        "incident_id": incident.incident_id,
                        "previous": result.previous_severity.value
                        if result.previous_severity
                        else None,
                        "current": incident.severity.value,
                        "risk": incident.risk.score,
                    },
                )

        decisions = await self.response.handle_detection(detection, risk)
        if incident is not None and result is not None and self._incident_needs_response(result):
            decisions.extend(await self.response.handle_incident(incident))

        return DetectionRecord(
            detection=detection,
            risk=risk,
            incident=incident,
            decisions=decisions,
            latency_seconds=time.perf_counter() - started,
        )

    def _incident_needs_response(self, result: CorrelationResult) -> bool:
        """Re-evaluate the incident response when it could have changed.

        That is on creation, on escalation, and when a new member pushes incident risk
        across the automatic response threshold (which can happen without a change in
        severity).
        """
        if result.created or result.severity_changed:
            return True
        threshold = self.settings.scoring.auto_block_threshold
        previous = result.previous_risk
        return previous is not None and previous < threshold <= result.incident.risk.score

    # ------------------------------------------------------------------ run

    async def run(
        self,
        capture: PacketCapture,
        *,
        progress: ProgressCallback | None = None,
        progress_interval: float = 1.0,
        max_packets: int | None = None,
        record_latency: bool = True,
        max_results: int | None = None,
    ) -> RunReport:
        """Drive a capture source to exhaustion (or until stopped).

        Publishes ``packet.stats`` roughly every ``progress_interval`` seconds, and
        calls ``progress`` with the same payload.

        ``max_results`` bounds the detections and incidents kept in the report (the
        counts stay complete); live capture sets it, because a sensor never stops.
        """
        self.capture = capture
        report = RunReport(source=capture.interface, started_at=datetime.now(UTC))
        wall_start = time.perf_counter()
        last_progress = wall_start
        first_ts: float | None = None
        last_ts: float | None = None
        latencies = report.processing_latencies
        self._sampler.sample()

        try:
            async with capture:
                async for frame in capture.frames():
                    frame_start = time.perf_counter()
                    report.frames += 1
                    report.bytes_total += frame.wire_length
                    first_ts = frame.timestamp if first_ts is None else first_ts
                    last_ts = frame.timestamp
                    records = await self.process_frame(frame)
                    if record_latency and len(latencies) < 2_000_000:
                        latencies.append(time.perf_counter() - frame_start)
                    for record in records:
                        report.detections_seen += 1
                        report.detections.append(record)
                        incident = record.incident
                        if incident is not None:
                            if incident.incident_id not in report.incidents:
                                report.incidents_seen += 1
                            report.incidents[incident.incident_id] = incident
                    if max_results is not None:
                        # A live sensor runs indefinitely: keep only the most recent results.
                        if len(report.detections) > 2 * max_results:
                            del report.detections[: len(report.detections) - max_results]
                        while len(report.incidents) > max_results:
                            report.incidents.pop(next(iter(report.incidents)))

                    now = time.perf_counter()
                    if now - last_progress >= progress_interval:
                        last_progress = now
                        await self._emit_progress(report, now - wall_start, capture, progress)
                    if max_packets is not None and report.frames >= max_packets:
                        report.stopped_early = True
                        break
                self._publish_capture_metrics(report, capture)
        finally:
            report.wall_seconds = time.perf_counter() - wall_start
            report.finished_at = datetime.now(UTC)
            report.packets_decoded = self.decoder.decoded
            report.decode_failures = self.decoder.failed
            report.capture_span_seconds = (
                (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0
            )
            sample = self._sampler.sample()
            report.cpu_percent_samples.append(sample["cpu_percent"])
            report.memory_peak_bytes = max(report.memory_peak_bytes, sample["memory_bytes"])
            self.capture = None
            self.last_report = report
        await self._emit_progress(report, report.wall_seconds, capture, progress, final=True)
        return report

    @staticmethod
    def _publish_capture_metrics(report: RunReport, capture: PacketCapture) -> None:
        """Add capture counts to Prometheus as they happen, not only when a run ends."""
        received = capture.stats.received
        dropped = capture.stats.total_dropped
        if received > report.metrics_received:
            metrics.packets_captured.labels(
                source=capture.source_kind, interface=capture.interface
            ).inc(received - report.metrics_received)
            report.metrics_received = received
        if dropped > report.metrics_dropped:
            metrics.packets_dropped.labels(reason="capture").inc(dropped - report.metrics_dropped)
            report.metrics_dropped = dropped

    async def _emit_progress(
        self,
        report: RunReport,
        elapsed: float,
        capture: PacketCapture,
        callback: ProgressCallback | None,
        *,
        final: bool = False,
    ) -> None:
        sample = self._sampler.sample()
        self._publish_capture_metrics(report, capture)
        report.cpu_percent_samples.append(sample["cpu_percent"])
        if len(report.cpu_percent_samples) > 3600:
            del report.cpu_percent_samples[:1800]
        report.memory_peak_bytes = max(report.memory_peak_bytes, sample["memory_bytes"])
        payload = {
            "source": capture.interface,
            "kind": capture.source_kind,
            "final": final,
            "frames": report.frames,
            "bytes": report.bytes_total,
            "elapsed_seconds": round(elapsed, 3),
            "packets_per_second": round(report.frames / elapsed, 1) if elapsed > 0 else 0.0,
            "detections": max(report.detections_seen, len(report.detections)),
            "incidents": max(report.incidents_seen, len(report.incidents)),
            "active_flows": len(self.extractor.flows),
            "tracked_sources": len(self.extractor.profiles),
            "dropped": capture.stats.total_dropped,
            "protocols": self.extractor.stats.protocol_distribution(),
            "cpu_percent": sample["cpu_percent"],
            "memory_bytes": sample["memory_bytes"],
        }
        metrics.active_flows.set(len(self.extractor.flows))
        metrics.tracked_sources.set(len(self.extractor.profiles))
        await self.bus.publish(EventType.PACKET_STATS, payload)
        if callback is not None:
            outcome = callback(payload)
            if outcome is not None:
                await outcome

    # --------------------------------------------------------------- status

    def status(self) -> dict[str, Any]:
        return {
            "sensor": self.settings.sensor_name,
            "running": self.capture is not None,
            "capture": self.capture.describe() if self.capture else None,
            "uptime_seconds": round(time.monotonic() - self.started_at, 1)
            if self.started_at
            else 0.0,
            "safety": self.settings.safety_banner(),
            "decoder": self.decoder.stats(),
            "features": self.extractor.state(),
            "detection": self.detection.stats(),
            "response": self.response.status(),
            "open_incidents": len(self.correlation.open_incidents()),
            "event_bus": self.bus.stats(),
            "process": self._sampler.sample(),
        }
