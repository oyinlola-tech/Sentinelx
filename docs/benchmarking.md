# Benchmarking

This document explains how SentinelX detection quality and performance are measured, reports the most recent measured results, and lists what those results do not show.

Only numbers produced by `scripts/benchmark.py` belong in this project's documentation. If you change a detector, a threshold or the hot path, re-run the benchmark and update this page from the generated report. Don't edit the figures by hand.

## Running the benchmark

```bash
make benchmark                                   # 5 runs per experiment
.venv/bin/python scripts/benchmark.py --runs 5
.venv/bin/python scripts/benchmark.py --only tcp_port_scan ssh_brute_force
.venv/bin/python scripts/benchmark.py --no-rules  # built-in detectors only
```

| Option | Meaning |
|---|---|
| `--runs N` | Repetitions per experiment. Each run uses a different traffic seed. |
| `--only NAME ...` | Restrict to scenario or experiment names. |
| `--no-rules` | Disable the custom YAML rules and measure built-in detectors only. |
| `--output DIR` | Where to write results (default `benchmarks/results/`). |

Each invocation writes two files named by UTC timestamp: `<stamp>.json` (every per-run measurement) and `<stamp>.md` (the summary tables). The environment block records the SentinelX version, Python version, platform, CPU model, logical CPU count and timestamp, so a figure is never quoted without its context.

## Method

The harness is `packages/sentinelx/bench/experiments.py`.

1. A scenario from `packages/sentinelx/testing/scenarios.py` generates synthetic frames with a known attacker address and known expected detectors. Some experiments interleave 4,000 benign background packets with the attack.
2. Ground truth (which frames belong to the attacker) is computed **before** timing starts, so bookkeeping does not inflate processing cost.
3. Frames are pushed from memory through the production `Pipeline`: decoder, feature extractor, detection engine, custom rules, risk scoring, correlation and the response decision. The response engine uses an in-memory firewall, so nothing on the host changes.
4. Disk and capture I/O are excluded on purpose; throughput isolates SentinelX's own processing cost.
5. CPU and resident memory are sampled from the process during each run.

### Metric definitions

| Metric | Definition |
|---|---|
| Detection rate | Fraction of runs in which at least one expected detector fired against the expected source. |
| Detector recall | Fraction of expected (detector, run) pairs that fired. |
| False positive | Any detection against a source other than the scenario's attacker, including every detection in benign-only traffic. Also shown per 10,000 packets. |
| Time to detect | Seconds of attack traffic (capture timestamps) from the attacker's first packet to the packet that triggered the first correct detection. It depends on the scenario's attack rate and the detector thresholds, not on machine speed. |
| Packets to detect | Attacker packets seen before that detection. |
| Processing latency | Wall time to push the triggering packet through the whole pipeline, including scoring, correlation and the response decision. |
| Throughput | Frames per wall-clock second through the full pipeline over in-memory frames. |
| Decoder microbenchmark | 50,000 frames decoded by the SentinelX `struct` decoder versus Scapy `Ether(bytes)`. |

## Latest results

Measured 2026-09-14 on an Intel Core i5-8350U (8 logical CPUs, laptop), Python 3.14.6, SentinelX 0.1.0, Linux 7.1.5 (Kali). 5 runs per experiment, custom rules enabled, default thresholds. Source: `benchmarks/results/20260914T213750Z.md`.

### Detection quality

| Group | Experiment | Detection rate | Detector recall | False positives | Time to detect (attack s) | Packets to detect |
|---|---|---|---|---|---|---|
| 1. Normal traffic | Normal traffic (6,000 packets) | n/a (benign) | n/a | 0 | — | — |
| 2. Port scanning | Vertical SYN scan | 100% | 100% | 0 | 0.22 ± 0.03 | 20 |
| 2. Port scanning | Vertical scan in background traffic | 100% | 100% | 0 | 0.22 ± 0.03 | 20 |
| 2. Port scanning | Horizontal sweep (445) | 100% | 100% | 0 | 0.41 ± 0.04 | 25 |
| 2. Port scanning | UDP scan | 100% | 100% | 0 | 0.29 ± 0.02 | 25 |
| 3. Brute force | SSH brute force | 100% | 100% | 0 | 7.54 ± 0.61 | 45 |
| 3. Brute force | RDP brute force | 100% | 100% | 0 | 7.54 ± 0.61 | 45 |
| 3. Brute force | SSH brute force in background traffic | 100% | 100% | 0 | 7.54 ± 0.61 | 45 |
| 4. Flooding | SYN flood | 100% | 100% | 0 | 0.25 ± 0.00 | 200 |
| 4. Flooding | ICMP flood | 100% | 100% | 0 | 0.50 ± 0.01 | 200 |
| 4. Flooding | HTTP flood | 100% | 100% | 0 | 1.37 ± 0.02 | 300 |
| 5. DNS anomalies | DNS tunnelling | 100% | 100% | 0 | 0.58 ± 0.03 | 20 |
| 5. DNS anomalies | DNS query flood (DGA-like) | 100% | 100% | 0 | 0.61 ± 0.03 | 100 |
| 5. DNS anomalies | DNS rate spike versus learned baseline | 100% | 100% | 0 | 1.03 ± 0.02 | 309 ± 8 |
| 6. Evasion | Slow port scan | **0%** | 0% | 0 | — | — |
| 6. Evasion | Low-rate brute force | **0%** | 0% | 0 | — | — |

### Performance

| Experiment | Throughput (packets/s) | Processing latency per detection (ms) | CPU mean | Peak RSS |
|---|---|---|---|---|
| Normal traffic | 4,556 | — | 99.7% | 119.4 MB |
| Vertical SYN scan | 3,306 | 0.655 ± 0.158 | 97.8% | 119.4 MB |
| Vertical scan in background traffic | 4,096 | 0.814 ± 0.589 | 99.8% | 119.4 MB |
| Horizontal sweep (445) | 3,072 | 0.592 ± 0.146 | 102.2% | 119.4 MB |
| UDP scan | 3,989 | 0.498 ± 0.167 | 112.8% | 119.4 MB |
| SSH brute force | 3,325 | 0.628 ± 0.183 | 97.8% | 119.4 MB |
| RDP brute force | 3,322 | 0.644 ± 0.176 | 101.6% | 119.4 MB |
| SSH brute force in background traffic | 4,090 | 0.579 ± 0.155 | 99.8% | 119.4 MB |
| SYN flood | 3,627 | 0.497 ± 0.081 | 100.4% | 119.4 MB |
| ICMP flood | 4,551 | 0.394 ± 0.033 | 99.3% | 119.4 MB |
| HTTP flood | 3,347 | 0.583 ± 0.122 | 100.4% | 119.4 MB |
| DNS tunnelling | 2,890 | 0.578 ± 0.099 | 102.5% | 119.4 MB |
| DNS query flood (DGA-like) | 3,959 | 0.432 ± 0.084 | 99.4% | 119.4 MB |
| DNS rate spike versus learned baseline | 3,947 | 0.503 ± 0.100 | 99.8% | 124.0 MB |
| Slow port scan (evasion) | 4,634 | — | 91.9% | 124.0 MB |
| Low-rate brute force (evasion) | 4,471 | — | 103.8% | 124.0 MB |

CPU is the process CPU percentage sampled by psutil, where 100% is one full core. The pipeline is single-threaded, so values slightly above 100% come from sampling granularity and background threads in the interpreter and libraries, not from parallel packet processing.

### Decoder

Decoding 50,000 frames: the SentinelX decoder ran at 41,433 frames/s, Scapy `Ether(bytes)` at 19,458 frames/s, a 2.1× difference. An earlier run on the same machine measured 43,785 versus 17,298 frames/s (2.5×). Treat the gap as "roughly two times", and measure on your own hardware.

## How to read these results

**The attack scenarios are easy by construction.** Each is a clean, synthetic attack generated to exceed the default thresholds, and the default thresholds were chosen with these scenarios in view. A 100% detection rate with zero false positives here shows that each detector works end to end and that benign traffic in these scenarios does not trip it. It is not an estimate of detection rate or false positive rate on a real network, where traffic is messier, attackers adapt, and legitimate services (vulnerability scanners, monitoring systems, busy resolvers, NAT gateways) resemble attacks.

**Time to detect is a property of the scenario, not the machine.** The SSH brute-force scenario spaces attempts so that the 15th short-lived session (the default `brute_force_attempts`) arrives about 7.5 seconds into the attack. A faster attacker is detected sooner; a slower one may not be detected at all.

**The evasion experiments are expected misses, and they are included on purpose.** Threshold detectors see only what falls inside their window:

- *Slow port scan:* 60 ports probed once every 1.2 seconds. At most about 12 distinct ports fall inside the default 15-second `port_scan_window_seconds`, below the default `port_scan_unique_ports` of 20.
- *Low-rate brute force:* one SSH attempt every 8 seconds. At most about 7 attempts fall inside the default 60-second `brute_force_window_seconds`, below the default `brute_force_attempts` of 15.

Longer windows or lower thresholds catch these, at the cost of more state per source and more false positives. The regression tests in `tests/detection/test_detectors.py` (`TestDocumentedEvasions`) pin this behaviour so that a change in coverage is noticed.

**Throughput limits deployment.** The full pipeline processed roughly 2,900 to 4,600 packets per second on one core of a laptop CPU. That is adequate for a home network, a lab, a small office uplink, or offline PCAP analysis. It is not adequate for a sustained multi-hundred-megabit link, where packet rates are one or two orders of magnitude higher. Live capture on such a link will drop packets; the capture statistics report kernel drops (`dropped_kernel`) and pipeline queue drops (`dropped_queue`) separately, so the loss is visible. Options are a BPF filter that narrows capture to the traffic of interest, a SPAN port carrying a subset of traffic, or a dedicated high-throughput IDS such as Suricata or Zeek in front of SentinelX.

**Things not measured here:**

- Real-world detection accuracy (no labelled production dataset is used).
- Capture drop rate on a live interface under load.
- API and database throughput under concurrent dashboard use.
- The optional machine-learning anomaly model, whose results depend on the training traffic you provide.
- Memory growth over days of operation. State is bounded by `max_tracked_sources` and window eviction, and the scaling tests in `tests/unit/test_windows.py` check that per-packet cost does not grow with window contents, but no long-duration soak test is part of this benchmark.

## Reporting results

When you publish or quote SentinelX numbers:

- Include the environment block (CPU, Python version, SentinelX version, run count).
- Say whether custom rules were enabled.
- Quote the evasion results next to the detection results.
- Link to the generated `.md` report rather than retyping figures.
