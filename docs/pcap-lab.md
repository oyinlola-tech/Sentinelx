# PCAP Lab

The PCAP Lab is SentinelX's offline analysis workflow. It runs a capture file through the detection pipeline so you can see what the engine reports, test rules against known traffic, and reproduce a detection without live capture privileges.

The Lab has three front ends that share the same capture reader (`packages/sentinelx/capture/pcapfile.py`, driven by `PcapFileCapture` in `packages/sentinelx/capture/pcap.py`) and the same pipeline assembly (`packages/sentinelx/assembly.py`):

| Front end | Entry point | Stores results |
|---|---|---|
| CLI | `sentinelx replay`, `sentinelx monitor`, `sentinelx fixtures`, `sentinelx rules test` | Only with `sentinelx replay --persist` |
| API | `/api/v1/replay*` (`packages/sentinelx/api/routes/replay.py`, `packages/sentinelx/services/replay.py`) | Always |
| Dashboard | **PCAP Lab** page (`apps/dashboard/src/app/(console)/lab/page.tsx`) | Always, through the API |

No replay ever changes the firewall. See [Replay isolation](#replay-isolation).

## Contents

- [Synthetic fixtures](#synthetic-fixtures)
- [Replaying from the CLI](#replaying-from-the-cli)
- [Reproducible results](#reproducible-results)
- [Watching traffic with sentinelx monitor](#watching-traffic-with-sentinelx-monitor)
- [Dashboard PCAP Lab](#dashboard-pcap-lab)
- [Replay API](#replay-api)
- [Replay isolation](#replay-isolation)
- [Testing a rule against a capture](#testing-a-rule-against-a-capture)
- [Using your own captures](#using-your-own-captures)
- [Privacy when sharing captures](#privacy-when-sharing-captures)

## Synthetic fixtures

`packages/sentinelx/testing/scenarios.py` builds packets in memory for a set of named traffic scenarios. Nothing is transmitted: the CLI and API only write the frames to a classic pcap file (Ethernet link type, microsecond timestamps) with `packages/sentinelx/testing/pcap.py`. Each scenario records the detectors a correct engine should report (`expected_detectors`) and, for attacks, the attacker address. The same scenarios drive the test suite and `scripts/benchmark.py`.

### Listing and generating

```bash
sentinelx fixtures list                                   # table of scenarios
sentinelx fixtures list --json                            # name, packets, benign, expected_detectors, description
sentinelx fixtures generate                               # every scenario into pcaps/fixtures/
sentinelx fixtures generate tcp_port_scan dns_tunneling   # selected scenarios
sentinelx fixtures generate -o /tmp/fixtures              # another directory
make fixtures                                             # same as the first generate command
```

| Command | Argument or option | Meaning |
|---|---|---|
| `fixtures list` | `--json` | Machine-readable output on stdout |
| `fixtures generate` | `NAMES...` | Scenario names. Default: all |
| | `--output`, `-o PATH` | Output directory (default `pcaps/fixtures`). Created if missing. Files are named `<scenario>.pcap` and overwrite existing files of the same name |

An unknown scenario name prints `unknown scenario(s): <names>` and exits with code 2; `sentinelx fixtures list` shows the valid names.

Every scenario is fully determined by its parameters, including its `seed`. Packet counts, addresses, ports, timing, IP identification fields, TCP sequence numbers and DNS transaction IDs all come from a seeded generator, and every scenario starts at the same base timestamp (UNIX time 1,700,000,000). Generating the same scenario twice writes byte-identical files (`tests/capture/test_pcapfile.py` checks this); a different `seed` gives different traffic. The header fields (IP identification, TCP sequence numbers, DNS transaction IDs) come from a generator that `get_scenario` reseeds from the scenario name and parameters, so `sentinelx fixtures generate` writes the same bytes on every run and on every architecture (all 14 default fixtures were compared between x86_64 and ARM64).

A small set of these scenarios, plus hand-built malformed files, is committed as a regression suite in `tests/pcaps/` (see `tests/pcaps/README.md`). `scripts/generate_test_pcaps.py` regenerates the files and `tests/pcaps/MANIFEST.json`, which records each file's SHA-256 and the exact detections and incident count a replay produces. `tests/capture/test_pcap_suite.py` replays each file through the full detection pipeline and compares the result with the manifest:

| Directory | Files | Expected result |
|---|---|---|
| `benign/` | `normal_traffic.pcap` | No detections |
| `attacks/` | `tcp_port_scan`, `horizontal_scan`, `udp_scan`, `ssh_brute_force`, `dns_tunneling`, `mixed_intrusion` | The intended detectors fire, only against the attacking address |
| `evasion/` | `slow_port_scan`, `low_rate_brute_force` | Not detected at the default thresholds. The test asserts this as a known limitation |
| `malformed/` | `truncated_record.pcap`, `oversized_record.pcap`, `empty.pcap`, `not_a_capture.pcap`, `bad_block_length.pcapng` | Rejected by the reader with `PcapError` |

`pcaps/` is ignored by git apart from `pcaps/.gitkeep`. Regenerate fixtures rather than committing them.

### Scenarios

The "Expected detectors" column is the scenario's `expected_detectors` set. The "Observed with default settings" column is what `sentinelx replay <file> --json` reported for each generated file on 2026-09-15, with no `.env`, the default detection settings (anomaly detection enabled, no machine-learning model), the local threat-intelligence lists and the rule files in `rules/` loaded. Replays started through the API gave the same detections for `tcp_port_scan`, `mixed_intrusion` and `dns_rate_spike`, which were checked; they apply the platform's active rules from the database instead of the rule files, which is the same set unless rules were changed or disabled. Detectors named `rule:<id>` are custom rules from `rules/`. Counts above 1 come from the engine's cooldown and escalation policy, which re-reports a source when its behaviour grows (see [detection-engine.md](detection-engine.md)).

| Scenario | Packets | Traffic produced | Expected detectors | Observed with default settings |
|---|---|---|---|---|
| `normal_traffic` | 600 | 20 clients in 192.168.10.20-39: DNS queries and responses via 192.168.10.1, TCP 80 and 443 sessions to three external servers with complete handshakes, HTTP requests or TLS-like payloads and orderly FIN close, occasional ICMP echo request and reply | none (benign; any detection is a false positive) | none |
| `tcp_port_scan` | 440 | 203.0.113.45 sends bare SYNs to 220 random ports on 192.168.10.50; the target answers RST/ACK, with SYN/ACK on every 80th port | `tcp_port_scan` | `tcp_port_scan` (3), `rule:rapid_syn_scan` (1), `connection_rate` (1); 1 incident, "Reconnaissance with service disruption" |
| `horizontal_scan` | 120 | 203.0.113.77 sends a SYN to port 445 on 120 hosts in 192.168.20.0/24 | `horizontal_scan` | `horizontal_scan` (2), `rule:smb_sweep` (1); 1 incident, "Sustained reconnaissance" |
| `udp_scan` | 200 | 203.0.113.90 sends UDP datagrams to 150 ports on 192.168.10.60; every third probe gets ICMP port unreachable | `udp_scan` | `udp_scan` (2); no incident |
| `ssh_brute_force` | 360 | 60 sessions from 198.51.100.23 to 192.168.10.10:22, each a full handshake, SSH banner exchange and server RST, 0.25 to 0.8 s apart | `ssh_brute_force` | `ssh_brute_force` (3), `rule:ssh_brute_force` (1); 1 incident, "Sustained credential attack" |
| `syn_flood` | 3,000 | 3,000 SYNs from 198.51.100.200 to 192.168.10.80:80, 0.5 to 2 ms apart, no handshakes | `syn_flood`, `connection_rate` | `syn_flood` (3), `connection_rate` (3); 1 incident, "Denial-of-service activity" |
| `icmp_flood` | 1,200 | ICMP echo requests from 198.51.100.66 to 192.168.10.90, 1 to 4 ms apart | `icmp_flood` | `icmp_flood` (3); no incident |
| `http_flood` | 900 | HTTP `GET /search?q=N` requests from 198.51.100.77 to 192.168.10.100:80, 1 to 8 ms apart | `http_flood` | `http_flood` (3), `rule:http_request_flood` (1); 1 incident, "Denial-of-service activity" |
| `dns_tunneling` | 400 | TXT queries from 192.168.10.66 with random 48 to 60 character labels under `tunnel.example.test` | `dns_anomaly` | `dns_anomaly` (2, "Possible DNS tunnelling"), `rule:dns_txt_tunnel` (1); 1 incident, "Possible data exfiltration" |
| `dns_flood` | 1,800 | 900 A queries from 192.168.10.67 for random 10 to 16 letter `.test` names, each answered with NXDOMAIN | `dns_anomaly` | `dns_anomaly` (2, "Abnormal DNS query volume"); no incident |
| `mixed_intrusion` | 1,080 | 203.0.113.200 against 192.168.10.10: a 120-port SYN scan, then 40 SSH sessions, then 600 ICMP echo requests, with 2 s gaps | `tcp_port_scan`, `ssh_brute_force`, `icmp_flood` | `tcp_port_scan` (3), `rule:rapid_syn_scan` (1), `ssh_brute_force` (1), `rule:ssh_brute_force` (1), `icmp_flood` (3); all 9 in 1 incident, "Potential host compromise attempt" |
| `dns_rate_spike` | 10,033 | 180 s of about 20 DNS queries per second from 20 clients in 192.168.30.10-29, then 20 s in which 192.168.30.99 adds 300 queries per second for ordinary names | `statistical_anomaly` | `statistical_anomaly` (1), `dns_anomaly` (2); 1 incident, "Possible data exfiltration". The same in CLI, persisted, API and dashboard replays |
| `slow_port_scan` | 120 | 203.0.113.61 probes 60 ports on 192.168.10.51, one every 1.2 s, with RST replies. Evasion case | `tcp_port_scan` (expected to be missed) | none |
| `low_rate_brute_force` | 180 | 30 SSH sessions from 198.51.100.44 to 192.168.10.10:22, one every 8 s. Evasion case | `ssh_brute_force` (expected to be missed) | none |

The two evasion scenarios stay below the default scan and brute-force thresholds inside their windows, so a miss is the correct result with default settings. [benchmarking.md](benchmarking.md) explains why and reports the measured detection rates.

In the default `detect_only` response mode, preventive decisions in these replays are recorded with the outcome `skipped` (for example `temporary_block:skipped`).

## Replaying from the CLI

```bash
sentinelx replay pcaps/fixtures/mixed_intrusion.pcap
sentinelx replay capture.pcap --speed 1                   # original timing
sentinelx replay capture.pcap --limit 10000 --report report.json
sentinelx replay capture.pcap --json > report.json
sentinelx replay capture.pcap --persist                   # store under a replay id
make replay PCAP=capture.pcap                             # generates fixtures first if the file is missing
```

With no `PCAP` argument, `make replay` uses `pcaps/fixtures/mixed_intrusion.pcap`.

| Argument or option | Default | Meaning |
|---|---|---|
| `PCAP` | required | A pcap or pcapng file. Must exist and be a readable file |
| `--speed FLOAT` | `0.0` | `0` replays as fast as possible. `1` reproduces the original inter-packet timing; larger values run faster. Must be `>= 0`. A single pacing sleep is capped at 1 second, so long idle gaps are shortened |
| `--limit INTEGER` | none | Stop after N packets (`>= 1`) |
| `--persist` | off | Run through the platform's replay service and store the run, its detections and its incidents in the database under a replay ID |
| `--report PATH` | none | Write the full JSON report to this file |
| `--json` | off | Print the JSON report on stdout instead of the summary panel and tables |

Detectors window on packet timestamps, not on wall-clock time. Replay speed changes how long a replay takes, not which detections it produces.

### Without --persist

The command reads settings from the environment and `.env`, forces `response.dry_run` to true, and builds a pipeline with an in-memory firewall. It assembles the pipeline through `packages/sentinelx/assembly.py`, like the live sensor: the built-in detectors, the local threat-intelligence allowlist and denylist (`RULES_DIRECTORY/intel/`), the rule files from `RULES_DIRECTORY` (default `rules/`), the statistical anomaly detector when `anomaly.enabled` is true, and the machine-learning anomaly detector when `anomaly.ml_enabled` is true and the model file loads. No database is needed. Invalid rule files are skipped with a `rule skipped:` warning on stderr.

The human-readable output shows the file (packet count and capture span), frames processed, measured throughput, per-packet latency (p50 and p99), mean time to a response decision, CPU and peak RSS, detection and incident counts, and decode failures, followed by a detection table and one panel per incident.

The JSON report contains:

| Key | Content |
|---|---|
| `source`, `started_at`, `finished_at` | Capture source label (`pcap:<filename>`) and wall-clock times |
| `frames`, `packets_decoded`, `decode_failures`, `bytes_total` | Frame counts. A high `decode_failures` usually means an unsupported link type (see [Supported formats](#supported-formats)) |
| `wall_seconds`, `capture_span_seconds`, `packets_per_second` | Replay duration, time covered by the capture, measured throughput |
| `detection_count`, `incident_count`, `detections_by_detector`, `detections_by_severity`, `response_decisions` | Summaries. `response_decisions` keys are `<action>:<outcome>` |
| `latency` | `per_packet_mean_ms`, `per_packet_p50_ms`, `per_packet_p99_ms`, `detection_mean_ms`, `detection_max_ms` |
| `resources` | `cpu_percent_mean`, `cpu_percent_max`, `memory_peak_mb` |
| `stopped_early` | Whether the run stopped before the end of the file |
| `file` | `path` (as given on the command line), `filename`, `size_bytes`, `packet_count`, `total_bytes`, `link_type` (the lowest link type in the file), `link_types` (every link type in the file), `first_timestamp`, `last_timestamp`, `duration_seconds`, `average_packet_size` |
| `detections` | Every detection with its evidence and risk assessment |
| `incidents` | Every correlated incident |
| `safety_note` | "Replay responses are always simulated; no firewall changes were made." |

Throughput, latency and resource figures are measured on the machine running the replay. Do not quote them as benchmark results; use `scripts/benchmark.py` for that (see [benchmarking.md](benchmarking.md)).

### With --persist

`--persist` starts the same replay service the API uses, so the run appears in the dashboard's PCAP Lab. The service only reads files inside `PCAP_DIRECTORY` (default `./pcaps`); a file elsewhere is first copied to `PCAP_DIRECTORY/cli/<filename>`, replacing any earlier copy with the same name. The command waits for the replay to finish (a replay is reported `completed` only after its results are written), then waits one further storage flush interval, prints `stored as replay <id>; view it in the PCAP Lab` on stderr, and exits with code 1 if the replay did not complete.

A persisted run requires a working database (`DATABASE_URL`). Redis is optional; without it the platform logs a degraded-mode warning and continues.

The stored table shows `replay_id`, `frames`, `packets_per_second`, `wall_seconds`, `detection_count`, `incident_count` and `response_decisions`. `--json` and `--report` output the stored report with `replay_id` added. The stored report differs from the non-persisted one in three ways:

- It has no `file` block.
- `detections` and a `decisions` list (preventive response decisions) are each truncated to 500 entries.
- The pipeline is the replay service's isolated pipeline. It applies the platform's active rules from the database (file rules and rules created through the API, with their enabled or disabled state) instead of reading the rule files directly. Anomaly detectors and threat intelligence are attached exactly as for the live sensor.

## Reproducible results

Every detection is stamped with the capture time of the packet that triggered it, not the time the replay processed it. Correlation windows and incident `first_seen` and `last_seen` use the same times. As a result:

- Replaying the same file twice gives identical detections, timestamps, risk scores and incidents, whatever the replay speed. This was checked for the CLI (`mixed_intrusion`) and for API replays (`tcp_port_scan`, `mixed_intrusion`, `dns_rate_spike`). Detection ids, incident ids and response decision times (`decided_at`, which is wall-clock time) differ between runs.
- A replay of an old capture produces detections dated when the traffic was captured. The generated fixtures, for example, are dated 2023-11-14. The dashboard's live views and time filters therefore do not show replay detections as recent; open them from the replay's report or filter by `replay_id`.

Two conditions apply. The run must use the same settings, rules, threat-intelligence lists and (if enabled) model. And risk scores include a "source history" contribution from the pipeline's own state, which is fresh for every replay, so a replay's scores are reproducible but can differ from the scores the same traffic got on a live sensor that had already seen the source.

## Watching traffic with sentinelx monitor

`sentinelx monitor` is a live terminal view of packets, detections and incidents. It does not store anything.

```bash
sentinelx monitor --scenario mixed_intrusion           # synthetic traffic, no privileges needed
sentinelx monitor --pcap capture.pcap                  # a capture at its original speed
sentinelx monitor --interface eth0 --bpf 'tcp or udp'  # live capture, needs CAP_NET_RAW
sentinelx monitor --pcap capture.pcap --duration 60
```

| Option | Meaning |
|---|---|
| `--scenario TEXT` | Feed a synthetic scenario from memory. Unknown names exit with code 2 |
| `--pcap PATH` | Replay a capture at speed 1 (original timing) |
| `--interface`, `-i TEXT` | Capture from an interface. Default: `CAPTURE_INTERFACE` |
| `--bpf TEXT` | Kernel BPF filter for live capture. Default: `BPF_FILTER`. Live capture also uses the configured capture backend, promiscuous mode, buffer size and queue size |
| `--duration FLOAT` | Stop after N seconds |
| `--enforce` | Use the configured firewall backend and response settings. Still subject to `DRY_RUN` |

The source is chosen in the order `--scenario`, `--pcap`, then live capture. Without `--enforce`, the monitor uses an in-memory firewall and forces dry run. The pipeline is assembled like `sentinelx replay` (rule files, anomaly detectors, threat intelligence). The view shows the safety posture, packet, flow, detection and incident counters, the 12 most recent detections with their first evidence line, and a sample of one packet in 50. A scenario or capture source ends when its last packet has been processed.

Live capture privileges and interface selection are covered in [packet-capture.md](packet-capture.md).

## Dashboard PCAP Lab

The **PCAP Lab** page (`/lab`, in the Respond group of the navigation) is a front end to the [Replay API](#replay-api). Viewers can browse files and reports; uploading, generating fixtures, starting and cancelling replays require the analyst role.

**Choose a capture.** Select a file from `PCAP_DIRECTORY` (listed recursively; `.pcap`, `.pcapng` and `.cap` files) and a replay speed: Unpaced (`0`), Original timing (`1`) or 5× original (`5`). **Replay capture** starts a run and opens its report.

**Add a capture.**

- **Upload pcap or pcapng** accepts `.pcap`, `.pcapng` and `.cap` files. The browser sends the file as the raw request body (`Content-Type: application/octet-stream`, original name in the `filename` query parameter). The server checks the size, quota and file format, stores it under a generated name in `uploads/`, and a notification shows the packet count. The uploaded file is selected for replay.
- **Generate a synthetic test fixture** writes the selected scenario with default parameters to `PCAP_DIRECTORY/fixtures/<scenario>.pcap`. The confirmation lists the detectors a correct engine should report.

**Recent replays** lists the last 20 runs with file, age, user, detection count and status (`queued`, `running`, `completed`, `failed`, `cancelled`). Progress for a running replay arrives over the WebSocket (`replay.progress` and `replay.completed` events).

**Replay report.** Selecting a run (`/lab?replay=<id>`) shows packets processed, throughput, wall time, capture span, decode failures, detection and incident counts, per-packet and detection latency, and CPU and memory, followed by the incidents (linked to their incident pages), the simulated response decisions, and the detection table. A running replay can be cancelled from its report; detections and incidents it already raised are kept. A failed replay shows its error message.

Detections, incidents and response decisions from a replay are tagged with its replay ID. They are excluded from the live detection and incident lists, the dashboards and the firewall action history, and are returned by the API only when you filter by that replay ID (or pass `include_replays=true` to `GET /firewall/actions`). The **Monitor** page's live feed labels replay events and has a checkbox to include or hide them.

## Replay API

All paths are under `/api/v1`. Scripts authenticate with a bearer token from `POST /api/v1/auth/login`; see [api.md](api.md).

| Method and path | Role | Purpose |
|---|---|---|
| `GET /replay/files` | viewer | List `.pcap`, `.pcapng` and `.cap` files under `PCAP_DIRECTORY` with `path`, `filename`, `size_bytes`, `modified_at` |
| `GET /replay/files/inspect?path=` | viewer | Capture metadata (packet count, link types, time span) without replaying; `path` is echoed as given |
| `POST /replay/upload?filename=` | analyst | Upload a capture as the raw request body. Returns `201` with the file metadata (see [Uploads](#uploads)) |
| `GET /replay/scenarios` | viewer | Scenario names with a one-line description |
| `POST /replay/scenarios/{name}` | analyst | Write a scenario to `fixtures/<name>.pcap`. Body `{"params": {...}}`. Returns `201` with `path`, `packets`, `expected_detectors`, `expected_source` and `benign` |
| `POST /replay` | analyst | Start a replay. Body `{"path": "...", "speed": 0, "limit": null}`. Returns `202` with `replay_id` and status `queued` |
| `GET /replay?limit=` | viewer | Recent runs (1 to 200, default 50) with a summary |
| `GET /replay/{replay_id}` | viewer | One run with its full stored report |
| `POST /replay/{replay_id}/cancel` | analyst | Cancel a running replay. `409` if it is not running |
| `GET /detections?replay_id=`, `GET /incidents?replay_id=` | viewer | Stored detections and incidents of one replay |
| `GET /firewall/actions?include_replays=true` | viewer | Response decisions including those made during replays |

```bash
curl -s -X POST 'http://127.0.0.1:8000/api/v1/replay/upload?filename=capture.pcap' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @capture.pcap
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"path": "uploads/<stored-name>.pcap", "speed": 0}' \
  http://127.0.0.1:8000/api/v1/replay
```

Capture errors (a path outside the directory, a missing file, an upload that is not a capture, invalid scenario parameters, too many concurrent replays, an unreadable capture) are returned as `422` with a `detail` message. Upload-specific status codes (`413`, `415`, `507`) are described below.

### Uploads

`POST /replay/upload` takes the capture file as the request body, not as a multipart form. The route (`api/routes/replay.py`) and `ReplayService.store_upload` apply these checks, in this order:

1. **Authentication and role.** Checked before any of the body is read: an anonymous request gets `401`, a viewer `403`, and nothing is written.
2. **Content type.** `Content-Type` must be `application/octet-stream`, `application/vnd.tcpdump.pcap` or `application/x-pcapng`. Anything else, including `multipart/form-data`, gets `415`.
3. **Declared size.** The limit is the smaller of `api.max_upload_mb` (default 200, env `API__MAX_UPLOAD_MB`) and `capture.max_pcap_size_mb` (default 512, env `CAPTURE__MAX_PCAP_SIZE_MB`). A `Content-Length` above it gets `413` before the body is read; a non-numeric one gets `400`.
4. **Quota.** If the files in `PCAP_DIRECTORY/uploads` already total `capture.upload_quota_mb` (default 2048, env `CAPTURE__UPLOAD_QUOTA_MB`) or more, the upload is refused with `507` (`the upload area is full (...); delete old uploads or raise CAPTURE__UPLOAD_QUOTA_MB`). Otherwise the effective limit is also capped at the remaining quota.
5. **Streamed size.** The body is written to disk as it arrives. As soon as the bytes written exceed the effective limit, writing stops, the partial file is deleted and the upload fails with `413` (`upload exceeds the <N> MB that can be accepted`). This also bounds uploads sent without `Content-Length`.
6. **Format.** The first four bytes must be a pcap header in either byte order, with microsecond or nanosecond timestamps (`d4c3b2a1`, `a1b2c3d4`, `4d3cb2a1`, `a1b23c4d`), or a pcapng section header block (`0a0d0d0a`). The whole file must then parse with the validating reader. Otherwise it is deleted and the upload fails with `422` (`file is not a pcap or pcapng capture`, or the reader's corruption message).

What is stored and returned:

- **Stored name.** Files are saved as `<UTC timestamp>-<8 random hex characters>-<sanitised stem>.pcapng` when the `filename` query parameter ends in `.pcapng`, and `.pcap` otherwise. The stem keeps only letters, digits, `.`, `_` and `-`, up to 60 characters. The original name is recorded only in the audit log.
- **Permissions and audit.** Stored files are set to mode `0640`. Each upload is recorded as an `UPLOAD_PCAP` audit event with the original name and size.
- **Response.** `201` with `path` relative to `PCAP_DIRECTORY` (`uploads/<stored name>`), `filename` (the stored name), `size_bytes`, `packet_count`, `total_bytes`, `link_type`, `link_types`, `first_timestamp`, `last_timestamp`, `duration_seconds` and `average_packet_size`. The absolute server path is never returned. Pass `path` unchanged to `POST /replay`.
- **Retention.** The platform's retention job (first run a minute after start, then every 6 hours, or `sentinelx db purge`) deletes regular files in `PCAP_DIRECTORY/uploads` whose modification time is older than `RETENTION_DAYS` (`storage.retention_days`, default 30). It does not touch generated fixtures or files placed elsewhere in `PCAP_DIRECTORY`.

There is no API endpoint for deleting a single capture. Remove files from `PCAP_DIRECTORY` on the server to free quota before the retention period ends.

### Scenario parameters

`params` (at most 10 entries, integer, float or string values) are passed as keyword arguments to the scenario function in `scenarios.py`, for example `{"params": {"ports": 30}}` for `tcp_port_scan` or `{"params": {"port": 80}}` for `horizontal_scan`. `validate_scenario_params` checks them before anything is generated. The same checks apply to the `params` of rules' embedded tests when a rule is validated.

| Parameter | Accepted values |
|---|---|
| any unknown name | refused, listing the accepted names |
| any boolean | refused |
| `seed` | integer, 0 to 2^32 |
| `port` | integer, 1 to 65,535 |
| `packet_count`, `count`, `hosts`, `attempts`, `ports`, `sources` | integer, 1 to 50,000 |
| `normal_qps`, `spike_qps` | integer, 0 to 50,000 |
| `baseline_seconds`, `spike_seconds` | integer, 0 to 3,600 |
| `interval` | number, 0.001 to 600 |
| `attacker`, `target`, `client`, `resolver` | an IPv4 or IPv6 address |
| `dns_rate_spike` as a whole | refused when the parameters would generate more than 2,000,000 packets |

An unknown scenario returns `404`. Any other problem returns `422` with a message that names the parameter, for example `invalid parameters for tcp_port_scan: ports: must be between 1 and 50000`. Generating a fixture is recorded as a `GENERATE_FIXTURE` audit event. The CLI `fixtures generate` command and the dashboard always use the defaults.

### Path resolution

Every client-supplied path (`inspect`, `POST /replay`, and `pcap_path` in `POST /rules/test`) goes through `ReplayService.resolve`. The path is joined to `PCAP_DIRECTORY`, fully resolved (which also follows symbolic links), and rejected with `path is outside the PCAP directory` unless the result is inside that directory. An absolute path or a `..` sequence that leads outside the directory is refused this way, as is a path containing control characters. The resolved path must also be an existing regular file. The extension is not checked here; only the file listing filters on `.pcap`, `.pcapng` and `.cap`.

### Running and cancelling

- At most 2 replays run at once per API process. A third start is refused.
- `speed` must be between 0 and 100. `limit`, when given, is between 1 and 100,000,000.
- Starting, cancelling and uploading are recorded as `START_REPLAY`, `CANCEL_REPLAY` and `UPLOAD_PCAP` audit events.
- Progress is published every 0.5 seconds as `replay.progress` and stored on the run record. The end of a run publishes `replay.completed` with status `completed`, `cancelled` or `failed`.
- A run is marked `completed` only after its detections and incidents have been written: the service first waits for the event bus to drain (up to 10 seconds) and for the persister to flush (`Platform._settle_storage`). Detections and incidents read for a replay right after it reports `completed` are therefore final.
- A failed run stores the capture error message, or `<ExceptionType>: replay failed` for other errors.
- Replay is CPU-bound and shares the event loop with the API. The reader yields to the loop at least every 5 ms of processing, so the API and WebSocket stay responsive during an unpaced replay, but they slow down.

## Replay isolation

`ReplayService._isolated_pipeline` builds a separate `Pipeline` for each replay:

- **Separate state.** Its feature windows, source profiles, scoring history and correlation state are its own, so replayed traffic cannot mix with live detection state.
- **Forced dry run.** A deep copy of the settings is taken (`simulation_settings` in `packages/sentinelx/assembly.py`) and `response.dry_run` is set to true and `response.firewall_backend` to `null`, whatever the live configuration is.
- **In-memory firewall.** The pipeline is given a `MemoryFirewall`, so even the simulated decisions have no path to a real firewall.
- **Decisions stay visible.** If the live response mode is `manual_approval`, the replay switches to `automatic` so the report shows what would have been decided instead of queueing approval requests. With dry run forced, those decisions are not applied.
- **Tagged output.** `pipeline.replay_id` is set, and every detection, incident and response decision it publishes carries that ID. The persister stores the ID with each record. Live detection and incident queries exclude records that have one, and the firewall action history (`GET /firewall`, `GET /firewall/actions`) excludes replay decisions unless `include_replays=true`.

The CLI replay without `--persist` uses the same `simulation_settings` (dry run forced, `null` backend, `manual_approval` shown as `automatic`) and a `MemoryFirewall`, so its decisions appear as simulated exactly as in an API or dashboard replay. `sentinelx monitor` forces dry run and uses a `MemoryFirewall` unless `--enforce` is given; it does not change the response mode.

Every front end assembles its detectors through `packages/sentinelx/assembly.py`, so a replay runs exactly the detection a live sensor runs. `tests/api/test_security_hardening.py` checks that an API replay pipeline has the same detector names as the live pipeline and shares its threat-intelligence service.

| Component | Live platform | `sentinelx replay` and `monitor` | `--persist`, API and dashboard replays |
|---|---|---|---|
| Built-in detectors (per `DETECTION_MODE` and `detection.disabled_detectors`) | yes | yes | yes |
| Rules | active rules from the database | rule files from `RULES_DIRECTORY` | active rules from the database |
| Statistical anomaly detector | when `anomaly.enabled` | when `anomaly.enabled` | when `anomaly.enabled` |
| Machine-learning anomaly detector | when `anomaly.ml_enabled` and the model loads | same | same |
| Threat intelligence allowlist and denylist (`RULES_DIRECTORY/intel/`) | yes | yes | yes (the live platform's instance) |

The anomaly detectors are not attached in `DETECTION_MODE=disabled` or `signature_only`.

## Testing a rule against a capture

`sentinelx rules test` runs rules in isolation: decode, feature extraction and one `RuleDetector`, with no built-in detectors, scoring, correlation or response (`packages/sentinelx/signatures/runner.py`). The detection cooldown is set to 0, so every matching packet counts as a detection. Expect much higher counts than a replay reports for the same file.

```bash
sentinelx rules test rules/network-recon.yml                                   # embedded tests
sentinelx rules test rules/network-recon.yml --scenario tcp_port_scan          # one scenario
sentinelx rules test rules/network-recon.yml --pcap pcaps/fixtures/tcp_port_scan.pcap
sentinelx rules test rules/network-recon.yml --pcap capture.pcap --json
sentinelx rules test rules                                                     # every rule file in a directory
```

| Argument or option | Meaning |
|---|---|
| `PATH` | A rule file, or a directory of `*.yml` and `*.yaml` files. Every rule in it is tested |
| `--pcap FILE` | Run each rule over a capture (`run_rule_on_pcap`, which reads the file with the same reader as replays) |
| `--scenario TEXT` | Run each rule over one synthetic scenario with default parameters |
| `--json` | Machine-readable output |

If both `--pcap` and `--scenario` are given, `--pcap` is used. Without either, the rules' embedded `tests:` are run and the command exits with code 1 if any test fails. Against a capture or scenario there is no expected outcome, so the exit code is 1 only when a rule file is invalid. An unknown `--scenario` name exits with code 2 and prints the available scenarios.

For each rule, `--json` returns `rule`, `target`, `packets` (decoded packets), `matched`, `detection_count`, `sources` (detections per source address), `elapsed_seconds`, `first_detection` (the explanation of the first match) and `evidence`. For example, `rules/network-recon.yml` against the generated `tcp_port_scan.pcap` gave `rapid_syn_scan` 171 detections from 203.0.113.45 over 440 packets, and `smb_sweep` none. Against `normal_traffic.pcap` neither rule matched.

The dashboard's rule editor (**Rules** page, analyst role) has the same choice of target: embedded tests, a scenario, or any capture in `PCAP_DIRECTORY`. It calls `POST /api/v1/rules/test` with `definition` and either `scenario` or `pcap_path`, and `pcap_path` is resolved with the same directory check as replays. Rules can be tested there without being saved.

The rule format and condition fields are documented in [rule-engine.md](rule-engine.md).

## Using your own captures

### Capturing

With tcpdump, which writes classic pcap with microsecond timestamps by default:

```bash
sudo tcpdump -i eth0 -w capture.pcap                        # until Ctrl-C
sudo tcpdump -i eth0 -c 50000 -w capture.pcap               # stop after 50,000 packets
sudo tcpdump -i eth0 -w capture.pcap 'host 192.168.1.50'    # only one host's traffic
```

With Wireshark's `dumpcap`, which writes pcapng unless told otherwise:

```bash
dumpcap -i eth0 -a duration:60 -w capture.pcapng            # pcapng, 60 seconds
dumpcap -i eth0 -a duration:60 -P -w capture.pcap           # classic pcap
```

Guidelines:

- Do not truncate packets with a small snapshot length. SentinelX's own live capture keeps 2,048 bytes per frame so that DNS, HTTP request lines and TLS ClientHello metadata are available to detectors and rules; tcpdump's default keeps whole packets.
- Detectors work on per-source rates inside windows of seconds. Capture long enough to cover the behaviour you want to test, and keep the original timestamps: do not merge or retime files with tools that rewrite timestamps.
- Put files you want to replay from the dashboard or API into `PCAP_DIRECTORY`, or upload them.

### Supported formats

Files are read by `packages/sentinelx/capture/pcapfile.py`, a streaming reader written against the pcap and pcapng formats directly; packet decoding is SentinelX's own. The decoder handles these link types: Ethernet (1, including stacked 802.1Q and 802.1ad VLAN tags), Linux cooked capture v1 (113) and v2 (276), raw IP (101, 228, 229) and BSD loopback (0). A frame with any other link type counts as a decode failure.

| File | Status |
|---|---|
| Classic pcap, microsecond or nanosecond timestamps, either byte order | Supported. Nanosecond files (`tcpdump --time-stamp-precision=nano`, magic `a1b23c4d`) are read at nanosecond resolution. The FCS bits in the link-type field are ignored |
| pcapng | Supported. Each interface's link type and timestamp resolution (`if_tsresol`, decimal or binary) are honoured per packet, so a file that mixes interfaces, for example Ethernet and Linux cooked capture from `tcpdump -i any`, decodes correctly. Enhanced Packet Blocks and Simple Packet Blocks are read; Simple Packet Blocks carry no timestamp and take the previous packet's. Multiple sections and either byte order are supported. Other block types are skipped |
| Anything else | Refused with `not a pcap or pcapng capture file` |

The reader streams one record at a time, so memory use does not grow with file size. It validates every length field before reading: a pcap record larger than the file's snapshot length (treated as at least 65,535 bytes) or 262,144 bytes, a pcapng block over about 1 MiB, a block whose length is not a multiple of 4 or does not match its trailer, a packet for an undeclared interface, and a truncated record all raise a capture error. Packets before the corruption have already been processed when a replay stops on such an error. `tests/capture/test_pcapfile.py` covers these cases and, when Wireshark's `editcap` is installed, checks that pcapng and nanosecond conversions of a fixture read back with identical packets and timestamps.

Check a file before relying on it: `sentinelx replay capture.pcap --json` reports `decode_failures`, and `file.link_types` lists the link types in the file. `GET /api/v1/replay/files/inspect` reports the same metadata for a file in `PCAP_DIRECTORY`.

## Privacy when sharing captures

A packet capture can contain far more than the traffic you meant to share: internal addresses and host names, MAC addresses, DNS queries that reveal browsing, HTTP URLs, cookies and `Authorization` headers on unencrypted connections, TLS server names, and credentials of any cleartext protocol.

Before sharing a capture in an issue, a pull request or a vulnerability report:

- **Prefer a synthetic reproducer.** If the behaviour can be shown with a scenario from `scenarios.py`, possibly with changed parameters, share the scenario name and parameters instead of a capture. Scenarios are deterministic, so the name and parameters reproduce the exact file. A rule that misbehaves can usually be shown with `sentinelx rules test --scenario`.
- **Capture only what is needed.** Use a BPF filter at capture time, or cut an existing file down to the relevant hosts, for example `tcpdump -r capture.pcap -w reduced.pcap 'host 203.0.113.45'`.
- **Keep it short.** Cut the file to the time range that triggers the behaviour, and confirm that the reduced file still reproduces it with `sentinelx replay reduced.pcap`.
- **Anonymise addresses consistently if you must.** Tools that rewrite IP addresses change what SentinelX sees: home network direction labels, allowlist and denylist matches, and per-source counting all depend on addresses. Rewrite every address with a consistent mapping and re-run the replay afterwards to check that the result is unchanged.
- **Remove payloads that are not needed.** Scan, flood and brute-force detections depend on headers and timing. DNS, HTTP and TLS rules need their protocol headers. Do not share cleartext credentials or session tokens at all.
- **Treat uploaded captures as sensitive data.** Files uploaded to the PCAP Lab stay in `PCAP_DIRECTORY/uploads` with mode `0640` until the retention job deletes them (`RETENTION_DAYS`, default 30) or someone removes them on the server, and every analyst can replay them.

For security vulnerabilities, follow [SECURITY.md](../SECURITY.md) and share captures only through a private channel. The platform's threat model, including upload handling, is in [security.md](security.md).
