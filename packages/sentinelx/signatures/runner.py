"""Rule test runner.

Runs a rule, in isolation, through the real pipeline stages (decode, features,
detection) against synthetic scenarios or a PCAP, and reports what it matched.
Used by ``sentinelx rules test``, the dashboard's "Test rule" button, and CI.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.capture.base import RawFrame
from sentinelx.capture.pcap import PcapFileCapture
from sentinelx.common.models import Detection
from sentinelx.config.settings import DetectionSettings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.features.extractor import FeatureExtractor
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.signatures.detector import RuleDetector
from sentinelx.signatures.rules import Rule
from sentinelx.testing.scenarios import get_scenario

__all__ = ["RuleRunResult", "RuleTestOutcome", "run_rule_on_frames", "run_rule_on_pcap", "run_rule_tests"]


@dataclass(slots=True)
class RuleRunResult:
    rule_id: str
    packets: int
    detections: list[Detection]
    elapsed_seconds: float
    sources: dict[str, int] = field(default_factory=dict)

    @property
    def matched(self) -> bool:
        return bool(self.detections)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "packets": self.packets,
            "matched": self.matched,
            "detection_count": len(self.detections),
            "sources": self.sources,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "first_detection": self.detections[0].explain() if self.detections else None,
            "evidence": [e.as_dict() for e in self.detections[0].evidence] if self.detections else [],
        }


@dataclass(frozen=True, slots=True)
class RuleTestOutcome:
    rule_id: str
    scenario: str
    expected: str
    actual: str
    detections: int

    @property
    def passed(self) -> bool:
        return self.expected == self.actual

    def as_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "scenario": self.scenario, "expected": self.expected,
                "actual": self.actual, "detections": self.detections, "passed": self.passed}


def run_rule_on_frames(rule: Rule, frames: Iterable[RawFrame], settings: DetectionSettings | None = None) -> RuleRunResult:
    """Evaluate one rule, and nothing else, over frames. Cooldown is disabled so every match counts."""
    detection_settings = (settings or DetectionSettings()).model_copy(update={"detection_cooldown_seconds": 0})
    decoder = PacketDecoder()
    extractor = FeatureExtractor(detection_settings)
    detector = RuleDetector(rule.model_copy(update={"enabled": True}), detection_settings)
    engine = DetectionEngine(detection_settings, detectors=[detector])
    detections: list[Detection] = []
    packets = 0
    started = time.perf_counter()
    for frame in frames:
        packet = decoder.decode(frame.data, frame.timestamp, frame.link_type, frame.interface, frame.wire_length)
        if packet is None:
            continue
        packets += 1
        detections.extend(engine.evaluate(extractor.process(packet)))
    sources: dict[str, int] = {}
    for detection in detections:
        sources[detection.source_ip] = sources.get(detection.source_ip, 0) + 1
    return RuleRunResult(rule.id, packets, detections, time.perf_counter() - started, sources)


async def run_rule_on_pcap(rule: Rule, path: Path, settings: DetectionSettings | None = None) -> RuleRunResult:
    frames: list[RawFrame] = []
    async with PcapFileCapture(path) as capture:
        async for frame in capture.frames():
            frames.append(frame)
    return await asyncio.to_thread(run_rule_on_frames, rule, frames, settings)


def run_rule_tests(rule: Rule, settings: DetectionSettings | None = None) -> list[RuleTestOutcome]:
    """Run a rule's embedded ``tests:`` expectations."""
    outcomes = []
    for test in rule.tests:
        scenario = get_scenario(test.scenario, **test.params)
        result = run_rule_on_frames(rule, scenario.frames, settings)
        outcomes.append(
            RuleTestOutcome(rule.id, test.scenario, test.expect, "match" if result.matched else "no_match", len(result.detections))
        )
    return outcomes
