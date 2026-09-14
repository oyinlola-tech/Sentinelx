#!/usr/bin/env python3
"""Run SentinelX's controlled detection experiments and write a report.

    python scripts/benchmark.py                 # 5 runs per experiment
    python scripts/benchmark.py --runs 10
    python scripts/benchmark.py --only tcp_port_scan dns_tunneling
    python scripts/benchmark.py --no-rules      # built-in detectors only

Writes benchmarks/results/<timestamp>.json (every measured value) and a
Markdown summary beside it. Numbers are only meaningful together with the
environment block recorded in the same file: quote them with it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog

from sentinelx.bench.experiments import decoder_microbenchmark, environment, run_sync

ROOT = Path(__file__).resolve().parents[1]


def fmt(stat: dict[str, float] | None, unit: str = "", digits: int = 2) -> str:
    if not stat:
        return "—"
    return f"{stat['mean']:.{digits}f}{unit} ± {stat['stdev']:.{digits}f}"


def markdown(
    env: dict[str, object],
    micro: dict[str, object],
    results: list[dict[str, object]],
    runs: int,
    rules: bool,
) -> str:
    lines = [
        "# SentinelX detection benchmark",
        "",
        f"Measured {env['timestamp']} on `{env['cpu']}` ({env['cpu_count']} logical CPUs), "
        f"Python {env['python']}, SentinelX {env['sentinelx']}, {env['platform']}.",
        f"{runs} runs per experiment with different traffic seeds; custom rules {'enabled' if rules else 'disabled'}; default thresholds.",
        "",
        "Synthetic traffic with known ground truth, processed by the production pipeline. These figures "
        "describe these scenarios on this machine, not real-world detection performance; see docs/benchmarking.md.",
        "",
        "## Detection quality",
        "",
        "| Group | Experiment | Detection rate | Detector recall | False positives (per 10k pkts) | Time to detect (attack s) | Packets to detect |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        rate = "n/a (benign)" if r["benign"] else f"{r['detection_rate']:.0%}"
        recall = "n/a" if r["detector_recall"] is None else f"{r['detector_recall']:.0%}"
        lines.append(
            f"| {r['group']} | {r['name']} | {rate} | {recall} | {r['false_positive_detections']} ({r['false_positives_per_10k_packets']}) "
            f"| {fmt(r['time_to_detect_seconds'], 's')} | {fmt(r['packets_to_detect'], '', 0)} |"  # type: ignore[arg-type]
        )
    lines += [
        "",
        "## Performance",
        "",
        "| Experiment | Throughput (pkts/s) | Processing latency per detection (ms) | CPU mean | Peak RSS |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['name']} | {r['throughput_pps']:,.0f} | {fmt(r['processing_latency_ms'], '', 3)} | {r['cpu_percent_mean']}% | {r['rss_peak_mb']} MB |"  # type: ignore[arg-type]
        )
    lines += [
        "",
        "## Decoder",
        "",
        f"Decoding {micro['packets']:,} frames: SentinelX parser {micro['sentinelx_pps']:,.0f} frames/s; "  # type: ignore[str-format]
        f"Scapy `Ether(bytes)` {micro['scapy_pps']:,.0f} frames/s ({micro['speedup']}x).",  # type: ignore[str-format]
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SentinelX detection experiments.")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--only", nargs="*", help="Scenario or experiment names to run.")
    parser.add_argument("--no-rules", action="store_true", help="Measure built-in detectors only.")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results")
    args = parser.parse_args()
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

    def progress(experiment: object, done: int, total: int) -> None:
        print(
            f"\r  {experiment.name:45} {done}/{total}",
            end="" if done < total else "\n",
            file=sys.stderr,
            flush=True,
        )

    env = environment()
    print("decoder microbenchmark...", file=sys.stderr)
    micro = decoder_microbenchmark()
    print("experiments...", file=sys.stderr)
    results = [
        result.summary() for result in run_sync(args.runs, not args.no_rules, args.only, progress)
    ]

    args.output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    document = {
        "environment": env,
        "runs": args.runs,
        "rules": not args.no_rules,
        "decoder": micro,
        "experiments": results,
    }
    json_path = args.output / f"{stamp}.json"
    md_path = args.output / f"{stamp}.md"
    json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(
        markdown(env, micro, results, args.runs, not args.no_rules), encoding="utf-8"
    )
    print(md_path.read_text(encoding="utf-8"))
    print(f"wrote {json_path.relative_to(ROOT)} and {md_path.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
