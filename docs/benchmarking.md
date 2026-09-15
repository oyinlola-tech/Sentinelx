# Benchmarking

This document explains how SentinelX detection quality and performance are measured, reports the most recent measured results, and lists what those results do not show.

There are two benchmarks:

| Script | Measures | Report files |
|---|---|---|
| `scripts/benchmark.py` | Detection quality, packet throughput and decoder speed on synthetic traffic, in memory | `benchmarks/results/<UTC timestamp>.json` and `.md` |
| `scripts/benchmark_platform.py` | API latency, WebSocket delivery, storage throughput and pipeline behaviour under growing volume, against a real server | `benchmarks/results/platform-<UTC timestamp>.json` and `.md` |

Only numbers produced by these scripts belong in this project's documentation. If you change a detector, a threshold, the hot path, the API or storage, re-run the relevant benchmark and update this page from the generated report. Don't edit the figures by hand.

The reports quoted here are committed in `benchmarks/results/`, so every figure on this page can be checked against its source file.

## Contents

- [Detection benchmark](#detection-benchmark)
- [Platform benchmark](#platform-benchmark)
- [How to read these results](#how-to-read-these-results)
- [Reporting results](#reporting-results)

## Detection benchmark

### Running the benchmark

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

Each invocation writes two files named by UTC timestamp: `<stamp>.json` (every per-run measurement) and `<stamp>.md` (the summary tables). The environment line records the SentinelX version, Python version, platform, CPU model, logical CPU count and timestamp, so a figure is never quoted without its context.

### Method

The harness is `packages/sentinelx/bench/experiments.py`.

1. A scenario from `packages/sentinelx/testing/scenarios.py` generates synthetic frames with a known attacker address and known expected detectors. Some experiments interleave 4,000 benign background packets with the attack.
2. Ground truth (which frames belong to the attacker) is computed **before** timing starts, so bookkeeping does not inflate processing cost.
3. Frames are pushed from memory through the production `Pipeline`: decoder, feature extractor, detection engine, custom rules, risk scoring, correlation and the response decision. The response engine uses an in-memory firewall with dry run forced, so nothing on the host changes.
4. The pipeline is assembled through `packages/sentinelx/assembly.py`, the same code the live sensor and every replay use: built-in detectors, the local threat-intelligence allowlist and denylist, the shipped rules (unless `--no-rules`), the statistical anomaly detector when `anomaly.enabled` is true (the default), and the machine-learning anomaly detector when `anomaly.ml_enabled` is true and a model loads. Settings come from the environment and `.env` of the shell that runs the script.
5. Disk and capture I/O are excluded on purpose; throughput isolates SentinelX's own processing cost.
6. CPU and resident memory are sampled from the process during each run.

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

### Latest detection results

Measured 2026-09-14 on an Intel Core i5-8350U (8 logical CPUs, laptop), Python 3.14.6, SentinelX 0.1.0, Linux 7.1.5 (Kali). 5 runs per experiment, custom rules enabled, default thresholds. Source: `benchmarks/results/20260914T213750Z.md`.

**This run predates the change that made the harness assemble pipelines through `assembly.py`.** At the time the harness attached the built-in detectors, the shipped rules and the statistical anomaly detector, but not the threat-intelligence providers, and it never attached the machine-learning detector. With default settings the statistical detector is attached as before, and the shipped intelligence lists in `rules/intel/` contain no entries, so a re-run is expected to detect the same things. The figures below have not been re-measured with the current harness, however, and throughput and latency may differ slightly: each detection is now checked against the two local intelligence providers, and other code on the per-packet path has changed since.

#### Detection quality

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

#### Performance

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

#### Decoder

Decoding 50,000 frames: the SentinelX decoder ran at 41,433 frames/s, Scapy `Ether(bytes)` at 19,458 frames/s, a 2.1× difference. An earlier run on the same machine measured 43,785 versus 17,298 frames/s (2.5×). Treat the gap as "roughly two times", and measure on your own hardware.

## Platform benchmark

`scripts/benchmark_platform.py` measures what the detection benchmark leaves out: how fast the API answers, how quickly events reach a WebSocket client, how fast detections are stored, and whether per-packet cost and memory stay flat as traffic volume grows.

### Running it

```bash
.venv/bin/python scripts/benchmark_platform.py
.venv/bin/python scripts/benchmark_platform.py --postgres postgresql://user:password@127.0.0.1:5432/scratch
```

| Option | Meaning |
|---|---|
| `--postgres URL` | Also run the storage measurement against this PostgreSQL database. The script applies the migrations and writes data, so use a disposable database. |
| `--output DIR` | Where to write results (default `benchmarks/results/`). |

The script needs no Redis and no Docker. It starts a real server on an ephemeral port on `127.0.0.1` and removes its temporary SQLite databases and capture directory when it finishes.

### Method

1. **Server.** The SentinelX application is started in-process under uvicorn with a single worker, listening on an ephemeral loopback port, with a SQLite database file and a Redis URL that cannot be reached (so the in-process degraded mode is used). Rate limits, the login throttle and lockout are raised so they do not interfere.
2. **Seeding.** The `mixed_intrusion` scenario, shifted so that it ends at the current time, is run four times through the server's live pipeline with the detection cooldown temporarily set to 0, so the database holds many rows to query. The committed run seeded 836 detections. The cooldown is restored to its default afterwards.
3. **API latency.** An `httpx` client on the same host sends 20 warm-up requests per endpoint, then 300 sequential requests and 600 requests with 10 concurrent workers, recording each request's round-trip time. Login is measured with 40 sequential and 80 concurrent requests. Percentiles are nearest-rank over those samples; `req/s` is requests divided by the wall time of the phase.
4. **WebSocket delivery.** A client obtains a ticket, subscribes to `detection.created`, `incident.opened` and `incident.updated`, then asks the API to generate the `syn_flood` fixture and replay it (with the default detection cooldown). For each event it records the time from the envelope `timestamp` (when the server published the event) to receipt.
5. **Storage.** A separate `Platform` (not the HTTP server) with a new SQLite file, and with the PostgreSQL database when `--postgres` is given, runs `mixed_intrusion` three times through its pipeline with the detection cooldown set to 0 for the whole measurement. The clock runs from the start of the pipeline run until the event bus has drained and the persister has flushed, so "Seconds (produce and store)" includes pipeline processing, not only database writes. "Stored per second" is stored rows divided by that time.
6. **Pipeline load.** For 1,000, 10,000 and 50,000 packets of `normal_traffic`, a fresh pipeline assembled through `assembly.py` (shipped rules, anomaly detectors, threat intelligence, in-memory firewall) processes the frames from memory. The script records throughput, per-packet processing latency, the process's resident memory growth, and the number of tracked sources.

### Latest platform results

Measured 2026-09-15T00:34:46.781411+00:00 on `Intel(R) Core(TM) i5-8350U CPU @ 1.70GHz` (8 logical CPUs), Python 3.14.6, SentinelX 0.1.0, Linux-7.1.5+kali-amd64-x86_64-with-glibc2.43. Single uvicorn worker on loopback; SQLite unless stated; Redis not used (degraded in-process mode). Source: `benchmarks/results/platform-20260915T003639Z.md` (per-request detail in the `.json` file).

#### API latency

| Endpoint | Mode | p50 ms | p95 ms | p99 ms | req/s | failures |
|---|---|---|---|---|---|---|
| GET /system/health (unauthenticated) | sequential | 1.846 | 2.686 | 3.503 | 493.2 | 0 |
| GET /system/health (unauthenticated) | concurrency 10 | 22.444 | 35.396 | 55.86 | 415.7 | 0 |
| GET /detections?limit=50 | sequential | 14.791 | 19.404 | 20.786 | 65.1 | 0 |
| GET /detections?limit=50 | concurrency 10 | 233.856 | 292.615 | 326.854 | 43.0 | 0 |
| GET /stats/overview | sequential | 35.082 | 49.63 | 54.549 | 27.2 | 0 |
| GET /stats/overview | concurrency 10 | 286.979 | 331.97 | 389.276 | 34.5 | 0 |
| GET /incidents?limit=50 | sequential | 8.921 | 10.883 | 13.593 | 108.1 | 0 |
| GET /incidents?limit=50 | concurrency 10 | 92.167 | 110.55 | 122.329 | 108.0 | 0 |
| POST /auth/login (Argon2id) | sequential | 65.093 | 72.731 | 105.045 | 15.2 | 0 |
| POST /auth/login (Argon2id) | concurrency 10 | 658.121 | 749.815 | 767.157 | 15.2 | 0 |

#### WebSocket event delivery

10 events during a SYN flood replay; publish to client p50 28.866 ms, p95 46.884 ms, p99 46.884 ms, max 46.884 ms.

#### Storage

| Database | Detections produced | Stored | Seconds (produce and store) | Stored per second |
|---|---|---|---|---|
| SQLite | 832 | 832 | 6.727 | 123.7 |
| PostgreSQL | 832 | 832 | 9.015 | 92.3 |

The `.json` report also records the pipeline part of that time on its own (`pipeline_seconds`): 5.701 s for the SQLite run and 2.923 s for the PostgreSQL run. The report does not record the PostgreSQL server's version or location.

#### Pipeline under growing traffic volume

| Packets | Packets/s | p50 ms | p99 ms | RSS growth MB | Sources tracked |
|---|---|---|---|---|---|
| 1,000 | 4,926.9 | 0.177 | 0.348 | 0.0 | 24 |
| 10,000 | 5,311.9 | 0.165 | 0.465 | 0.5 | 24 |
| 50,000 | 4,922.4 | 0.173 | 0.609 | 0.0 | 24 |

### Caveats for the platform results

- **One worker, one machine, loopback.** The client and the server ran on the same laptop and shared its CPU, over loopback, with a single uvicorn worker. There is no network latency in these figures, and the client's own work competes with the server. The concurrency-10 rows show queueing in one event loop, not the capacity of a multi-worker deployment: requests per second at concurrency 10 were lower than sequential for `/detections`, the same for `/incidents` and only modestly higher for `/stats/overview`, while median latency rose by a factor of about 8 to 16.
- **SQLite for the API measurements.** The API latency and WebSocket figures were measured with SQLite, not PostgreSQL, against a database holding 836 seeded detections. Query times on a production PostgreSQL database with months of data will differ.
- **Redis was not used.** Rate limiting, tickets and the revocation list ran in process memory. A deployment with Redis adds a network round trip to every request's rate-limit check.
- **Login is deliberately slow.** Each login verifies an Argon2id hash in a worker thread, with at most 4 verifications at a time per process. About 15 logins per second, and a median of 658 ms with 10 concurrent attempts, is that cost working as intended.
- **The storage figure is not a pure database-write rate.** It includes pipeline processing, and the pipeline ran with the detection cooldown at 0 so that every repeated detection was stored. With the default cooldown far fewer detections are produced for the same traffic.
- **The WebSocket figure rests on 10 events.** It comes from a replay run with the default detection cooldown, which produced only 10 matching events, so p95, p99 and max are the same sample. Treat it as an order of magnitude, not a distribution.
- **The pipeline load test uses benign traffic from 24 sources.** Flat latency and memory across 1,000 to 50,000 packets show that per-packet cost does not grow with volume for a fixed set of sources. It does not measure behaviour with many thousands of distinct sources, where the `max_tracked_sources` bound and eviction come into play.

## How to read these results

**The attack scenarios are easy by construction.** Each is a clean, synthetic attack generated to exceed the default thresholds, and the default thresholds were chosen with these scenarios in view. A 100% detection rate with zero false positives here shows that each detector works end to end and that benign traffic in these scenarios does not trip it. It is not an estimate of detection rate or false positive rate on a real network, where traffic is messier, attackers adapt, and legitimate services (vulnerability scanners, monitoring systems, busy resolvers, NAT gateways) resemble attacks.

**Time to detect is a property of the scenario, not the machine.** The SSH brute-force scenario spaces attempts so that the 15th short-lived session (the default `brute_force_attempts`) arrives about 7.5 seconds into the attack. A faster attacker is detected sooner; a slower one may not be detected at all.

**The evasion experiments are expected misses, and they are included on purpose.** Threshold detectors see only what falls inside their window:

- *Slow port scan:* 60 ports probed once every 1.2 seconds. At most about 12 distinct ports fall inside the default 15-second `port_scan_window_seconds`, below the default `port_scan_unique_ports` of 20.
- *Low-rate brute force:* one SSH attempt every 8 seconds. At most about 7 attempts fall inside the default 60-second `brute_force_window_seconds`, below the default `brute_force_attempts` of 15.

Longer windows or lower thresholds catch these, at the cost of more state per source and more false positives. The regression tests in `tests/detection/test_detectors.py` (`TestDocumentedEvasions`) pin this behaviour so that a change in coverage is noticed.

**Throughput limits deployment.** The full pipeline processed roughly 2,900 to 4,600 packets per second on one core of a laptop CPU in the detection benchmark, and about 4,900 to 5,300 packets per second on benign traffic in the platform benchmark's load test. That is adequate for a home network, a lab, a small office uplink, or offline PCAP analysis. It is not adequate for a sustained multi-hundred-megabit link, where packet rates are one or two orders of magnitude higher. Live capture on such a link will drop packets; the capture statistics report kernel drops (`dropped_kernel`) and pipeline queue drops (`dropped_queue`) separately, so the loss is visible. Options are a BPF filter that narrows capture to the traffic of interest, a SPAN port carrying a subset of traffic, or a dedicated high-throughput IDS such as Suricata or Zeek in front of SentinelX.

**Things not measured here:**

- Real-world detection accuracy (no labelled production dataset is used).
- Capture drop rate on a live interface under load.
- API throughput with multiple workers, PostgreSQL behind the API, Redis, a network between client and server, or large amounts of stored data.
- The optional machine-learning anomaly model, whose results depend on the training traffic you provide.
- Memory growth over days of operation. State is bounded by `max_tracked_sources` and window eviction, and the scaling tests in `tests/unit/test_windows.py` check that per-packet cost does not grow with window contents, but no long-duration soak test is part of either benchmark.

## Reporting results

When you publish or quote SentinelX numbers:

- Include the environment line (CPU, Python version, SentinelX version, run count).
- Say whether custom rules were enabled, and for platform figures which database was used and whether Redis was available.
- Quote the evasion results next to the detection results.
- Link to the generated `.md` report rather than retyping figures, and commit the report if the figures appear in this repository.
