"""Controlled detection experiments.

Every number this module reports is measured by running synthetic traffic with a
known ground truth through the production :class:`~sentinelx.pipeline.Pipeline`.
Nothing is estimated and nothing is hard-coded.  Results depend on the machine,
the Python version and the settings in force; the report records all three so a
figure is never quoted without its context.

Definitions (also in docs/benchmarking.md):

detection rate
    Fraction of runs in which at least one *expected* detector fired against the
    *expected* source.
detector recall
    Fraction of expected (detector, run) pairs that fired.
false positive
    Any detection against a source other than the scenario's attacker, including
    every detection in benign-only traffic.
time to detect
    Seconds of *attack traffic* (capture time) from the attacker's first packet
    to the packet that triggered the first correct detection. This is the latency
    an operator experiences, independent of machine speed.
packets to detect
    Attacker packets seen before that detection.
processing latency
    Wall time to push the triggering packet through the whole pipeline, including
    scoring, correlation and the response decision.
throughput
    Frames per wall-clock second for the full pipeline over in-memory frames, so
    disk and capture I/O are excluded and the figure isolates SentinelX itself.
"""

from __future__ import annotations

import asyncio
import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelx import __version__
from sentinelx.capture.base import RawFrame
from sentinelx.config.settings import Settings
from sentinelx.firewall import MemoryFirewall
from sentinelx.parser.decoder import PacketDecoder
from sentinelx.pipeline import Pipeline
from sentinelx.telemetry.metrics import ProcessSampler
from sentinelx.testing.scenarios import Scenario, get_scenario

__all__ = [
    "EXPERIMENTS",
    "Experiment",
    "ExperimentResult",
    "decoder_microbenchmark",
    "run_experiments",
]


@dataclass(frozen=True, slots=True)
class Experiment:
    name: str
    group: str
    """Which of the five research questions this answers."""
    scenario: str
    params: dict[str, Any] = field(default_factory=dict)
    background_packets: int = 0
    """Benign packets interleaved with the attack, to measure detection under noise."""


EXPERIMENTS: tuple[Experiment, ...] = (
    Experiment("normal traffic", "1. normal traffic", "normal_traffic", {"packet_count": 6000}),
    Experiment("vertical SYN scan", "2. port scanning", "tcp_port_scan"),
    Experiment(
        "vertical scan in background traffic",
        "2. port scanning",
        "tcp_port_scan",
        background_packets=4000,
    ),
    Experiment("horizontal sweep (445)", "2. port scanning", "horizontal_scan", {"port": 445}),
    Experiment("UDP scan", "2. port scanning", "udp_scan"),
    Experiment("SSH brute force", "3. brute force", "ssh_brute_force"),
    Experiment("RDP brute force", "3. brute force", "ssh_brute_force", {"port": 3389}),
    Experiment(
        "SSH brute force in background traffic",
        "3. brute force",
        "ssh_brute_force",
        background_packets=4000,
    ),
    Experiment("SYN flood", "4. flooding", "syn_flood"),
    Experiment("ICMP flood", "4. flooding", "icmp_flood"),
    Experiment("HTTP flood", "4. flooding", "http_flood"),
    Experiment("DNS tunnelling", "5. DNS anomalies", "dns_tunneling"),
    Experiment("DNS query flood (DGA-like)", "5. DNS anomalies", "dns_flood"),
    Experiment("DNS rate spike vs learned baseline", "5. DNS anomalies", "dns_rate_spike"),
    # Known limitations: these are expected to be missed with default thresholds.
    Experiment("slow port scan (evasion)", "6. evasion: expected misses", "slow_port_scan"),
    Experiment(
        "low-rate brute force (evasion)", "6. evasion: expected misses", "low_rate_brute_force"
    ),
)


@dataclass(slots=True)
class RunMeasurement:
    frames: int
    wall_seconds: float
    detections: int
    true_positive_detections: int
    false_positive_detections: int
    detected: bool
    expected_fired: set[str]
    time_to_detect: float | None
    packets_to_detect: int | None
    processing_latencies: list[float]
    cpu_percent: float
    rss_bytes: float


@dataclass(slots=True)
class ExperimentResult:
    experiment: Experiment
    runs: list[RunMeasurement]
    expected_detectors: set[str]
    benign: bool

    def summary(self) -> dict[str, Any]:
        runs = self.runs
        total_detections = sum(r.detections for r in runs)
        fps = sum(r.false_positive_detections for r in runs)
        frames = sum(r.frames for r in runs)
        wall = sum(r.wall_seconds for r in runs)
        latencies = [value for r in runs for value in r.processing_latencies]
        ttd = [r.time_to_detect for r in runs if r.time_to_detect is not None]
        ptd = [r.packets_to_detect for r in runs if r.packets_to_detect is not None]
        recall_hits = sum(len(r.expected_fired) for r in runs)
        recall_total = len(self.expected_detectors) * len(runs)

        def stat(values: list[float]) -> dict[str, float] | None:
            if not values:
                return None
            return {
                "mean": round(statistics.fmean(values), 6),
                "stdev": round(statistics.stdev(values), 6) if len(values) > 1 else 0.0,
                "min": round(min(values), 6),
                "max": round(max(values), 6),
            }

        return {
            "name": self.experiment.name,
            "group": self.experiment.group,
            "scenario": self.experiment.scenario,
            "params": self.experiment.params,
            "background_packets": self.experiment.background_packets,
            "runs": len(runs),
            "benign": self.benign,
            "expected_detectors": sorted(self.expected_detectors),
            "detection_rate": None
            if self.benign
            else round(sum(r.detected for r in runs) / len(runs), 4),
            "detector_recall": None
            if self.benign or not recall_total
            else round(recall_hits / recall_total, 4),
            "detections": total_detections,
            "false_positive_detections": fps,
            "false_positive_rate": round(fps / total_detections, 4) if total_detections else 0.0,
            "false_positives_per_10k_packets": round(10_000 * fps / frames, 3) if frames else 0.0,
            "time_to_detect_seconds": stat(ttd),
            "packets_to_detect": stat([float(value) for value in ptd]),
            "processing_latency_ms": stat([1000 * value for value in latencies]),
            "throughput_pps": round(frames / wall, 1) if wall else 0.0,
            "cpu_percent_mean": round(statistics.fmean([r.cpu_percent for r in runs]), 1),
            "rss_peak_mb": round(max(r.rss_bytes for r in runs) / 1_048_576, 1),
        }


def _interleave(attack: Scenario, background: Scenario) -> list[RawFrame]:
    """Place the attack in the middle of the background capture, merged by time."""
    if not background.frames:
        return list(attack.frames)
    middle = background.frames[len(background.frames) // 2].timestamp
    shift = middle - attack.frames[0].timestamp
    shifted = [
        RawFrame(f.data, f.timestamp + shift, f.link_type, f.interface, f.wire_length)
        for f in attack.frames
    ]
    return sorted([*background.frames, *shifted], key=lambda frame: frame.timestamp)


def _settings() -> Settings:
    settings = Settings()
    settings.response.dry_run = True
    settings.telemetry.log_level = "CRITICAL"
    return settings


async def _run_once(
    experiment: Experiment, seed_offset: int, include_rules: bool
) -> tuple[RunMeasurement, Scenario]:
    params = dict(experiment.params)
    if "seed" not in params:
        params["seed"] = 1000 + seed_offset  # every run sees different, reproducible traffic
    scenario = get_scenario(experiment.scenario, **params)
    frames = list(scenario.frames)
    if experiment.background_packets:
        background = get_scenario(
            "normal_traffic", seed=2000 + seed_offset, packet_count=experiment.background_packets
        )
        frames = _interleave(scenario, background)

    settings = _settings()
    pipeline = Pipeline(settings, firewall=MemoryFirewall())
    if include_rules:
        from pathlib import Path

        from sentinelx.services.rules import max_rule_window
        from sentinelx.signatures import RuleDetector, load_rules

        for rule in load_rules(
            Path(settings.rules_directory), max_window_seconds=max_rule_window(settings)
        ).rules:
            pipeline.detection.add_detector(RuleDetector(rule, settings.detection))
    from sentinelx.anomaly import StatisticalAnomalyDetector

    pipeline.detection.add_detector(
        StatisticalAnomalyDetector(settings.anomaly, settings.detection)
    )
    await pipeline.start()

    decoder = PacketDecoder()
    attacker = scenario.expected_source
    expected = scenario.expected_detectors
    first_attack_ts: float | None = None
    attacker_packets = 0
    detections = tp = fp = 0
    fired: set[str] = set()
    time_to_detect: float | None = None
    packets_to_detect: int | None = None
    latencies: list[float] = []
    # Ground truth is computed before the clock starts, so identifying attacker
    # packets never counts against SentinelX's measured throughput.
    is_attacker = [False] * len(frames)
    if attacker is not None:
        for index, frame in enumerate(frames):
            packet = decoder.decode(frame.data, frame.timestamp, frame.link_type)
            is_attacker[index] = packet is not None and packet.src_ip == attacker
    sampler = ProcessSampler()
    sampler.sample()

    started = time.perf_counter()
    for index, frame in enumerate(frames):
        if is_attacker[index]:
            attacker_packets += 1
            if first_attack_ts is None:
                first_attack_ts = frame.timestamp
        records = await pipeline.process_frame(frame)
        for record in records:
            detections += 1
            latencies.append(record.latency_seconds)
            correct = (not scenario.benign) and record.detection.source_ip == attacker
            if correct:
                tp += 1
                if record.detection.detector in expected:
                    fired.add(record.detection.detector)
                    if time_to_detect is None and first_attack_ts is not None:
                        time_to_detect = frame.timestamp - first_attack_ts
                        packets_to_detect = attacker_packets
            else:
                fp += 1
    wall = time.perf_counter() - started
    sample = sampler.sample()
    await pipeline.stop()

    measurement = RunMeasurement(
        frames=len(frames),
        wall_seconds=wall,
        detections=detections,
        true_positive_detections=tp,
        false_positive_detections=fp,
        detected=bool(fired),
        expected_fired=fired,
        time_to_detect=time_to_detect,
        packets_to_detect=packets_to_detect,
        processing_latencies=latencies,
        cpu_percent=sample["cpu_percent"],
        rss_bytes=sample["memory_bytes"],
    )
    return measurement, scenario


async def run_experiments(
    runs: int = 5,
    *,
    include_rules: bool = True,
    only: list[str] | None = None,
    progress: Any = None,
) -> list[ExperimentResult]:
    results = []
    for experiment in EXPERIMENTS:
        if only and experiment.scenario not in only and experiment.name not in only:
            continue
        measurements = []
        scenario: Scenario | None = None
        for index in range(runs):
            measurement, scenario = await _run_once(experiment, index, include_rules)
            measurements.append(measurement)
            if progress:
                progress(experiment, index + 1, runs)
        if scenario is None:
            continue
        results.append(
            ExperimentResult(
                experiment, measurements, set(scenario.expected_detectors), scenario.benign
            )
        )
    return results


def decoder_microbenchmark(packets: int = 50_000, repeats: int = 3) -> dict[str, Any]:
    """Frames per second to decode the same bytes with SentinelX's parser and with Scapy.

    Both produce the fields detection needs (addresses, ports, flags); the Scapy
    figure is what building a full packet object per frame costs. Best of
    ``repeats`` runs, to reduce scheduler noise.
    """
    frames = get_scenario("normal_traffic", packet_count=min(packets, 20_000)).frames
    frames = (frames * (packets // len(frames) + 1))[:packets]
    decoder = PacketDecoder()

    def ours() -> float:
        started = time.perf_counter()
        for frame in frames:
            decoder.decode(frame.data, frame.timestamp)
        return len(frames) / (time.perf_counter() - started)

    result: dict[str, Any] = {
        "packets": len(frames),
        "sentinelx_pps": round(max(ours() for _ in range(repeats)), 0),
    }
    try:
        from scapy.layers.l2 import Ether
    except ImportError:  # pragma: no cover
        result["scapy_pps"] = None
        return result
    subset = frames[: min(len(frames), 20_000)]

    def scapy() -> float:
        started = time.perf_counter()
        for frame in subset:
            packet = Ether(frame.data)
            packet.getlayer("IP")
        return len(subset) / (time.perf_counter() - started)

    result["scapy_pps"] = round(max(scapy() for _ in range(repeats)), 0)
    result["speedup"] = (
        round(result["sentinelx_pps"] / result["scapy_pps"], 1) if result["scapy_pps"] else None
    )
    return result


def environment() -> dict[str, Any]:
    cpu = platform.processor() or platform.machine()
    try:
        with open("/proc/cpuinfo", encoding="ascii", errors="replace") as handle:  # noqa: PTH123
            for line in handle:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {
        "sentinelx": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu": cpu,
        "cpu_count": os.cpu_count(),
        "timestamp": datetime.now(UTC).isoformat(),
    }


def run_sync(
    runs: int, include_rules: bool, only: list[str] | None, progress: Any = None
) -> list[ExperimentResult]:
    return asyncio.run(
        run_experiments(runs, include_rules=include_rules, only=only, progress=progress)
    )
