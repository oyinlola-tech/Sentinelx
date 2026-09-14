# PCAP Lab

The PCAP Lab is SentinelX's offline analysis workflow. It runs a capture file through the detection pipeline so you can see what the engine reports, test rules against known traffic, and reproduce a detection without live capture privileges.

The Lab has three front ends that share the same capture reader (`packages/sentinelx/capture/pcap.py`):

| Front end | Entry point | Stores results |
|---|---|---|
| CLI | `sentinelx replay`, `sentinelx monitor`, `sentinelx fixtures`, `sentinelx rules test` | Only with `sentinelx replay --persist` |
| API | `/api/v1/replay*` (`packages/sentinelx/api/routes/replay.py`, `packages/sentinelx/services/replay.py`) | Always |
| Dashboard | **PCAP Lab** page (`apps/dashboard/src/app/(console)/lab/page.tsx`) | Always, through the API |

No replay ever changes the firewall. See [Replay isolation](#replay-isolation).

## Contents

- [Synthetic fixtures](#synthetic-fixtures)
- [Replaying from the CLI](#replaying-from-the-cli)
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

An unknown scenario name exits with code 2 and lists the valid names.

Each scenario uses a fixed seed for its traffic pattern and starts at the same base timestamp (UNIX time 1,700,000,000), so packet counts, addresses, ports and timing are reproducible. IP identification fields, TCP sequence numbers and DNS transaction IDs are drawn from an unseeded generator, so two generated files are not byte-identical.

`pcaps/` is ignored by git apart from `pcaps/.gitkeep`. Regenerate fixtures rather than committing them.

### Scenarios

The "Expected detectors" column is the scenario's `expected_detectors` set. The "Observed with default settings" column is what `sentinelx replay <file> --json` reported for each generated file, with no `.env`, the default detection settings, and the rule files in `rules/` loaded. Detectors named `rule:<id>` are custom rules from `rules/`. Counts above 1 come from the engine's cooldown and escalation policy, which re-reports a source when its behaviour grows (see [detection-engine.md](detection-engine.md)).

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
| `dns_rate_spike` | 10,033 | 180 s of about 20 DNS queries per second from 20 clients in 192.168.30.10-29, then 20 s in which 192.168.30.99 adds 300 queries per second for ordinary names | `statistical_anomaly` | CLI replay: `statistical_anomaly` (1), `dns_anomaly` (2); 1 incident, "Possible data exfiltration". Stored replay (`--persist`, API, dashboard): `dns_anomaly` (2) only, because those replays do not attach the statistical detector |
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

The command reads settings from the environment and `.env`, forces `response.dry_run` to true, builds a pipeline with an in-memory firewall, loads the rule files from `RULES_DIRECTORY` (default `rules/`), and attaches the statistical anomaly detector when anomaly detection is enabled. No database is needed. Invalid rule files are skipped with a `rule skipped:` warning on stderr.

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
| `file` | `path`, `filename`, `size_bytes`, `packet_count`, `total_bytes`, `link_type`, `first_timestamp`, `last_timestamp`, `duration_seconds`, `average_packet_size` |
| `detections` | Every detection with its evidence and risk assessment |
| `incidents` | Every correlated incident |
| `safety_note` | "Replay responses are always simulated; no firewall changes were made." |

Throughput, latency and resource figures are measured on the machine running the replay. Do not quote them as benchmark results; use `scripts/benchmark.py` for that (see [benchmarking.md](benchmarking.md)).

### With --persist

`--persist` starts the same replay service the API uses, so the run appears in the dashboard's PCAP Lab. The service only reads files inside `PCAP_DIRECTORY` (default `./pcaps`); a file elsewhere is first copied to `PCAP_DIRECTORY/cli/<filename>`, replacing any earlier copy with the same name. The command waits for the replay to finish, waits one storage flush interval so the detections are queryable, prints `stored as replay <id>; view it in the PCAP Lab` on stderr, and exits with code 1 if the replay did not complete.

A persisted run requires a working database (`DATABASE_URL`). Redis is optional; without it the platform logs a degraded-mode warning and continues.

The stored table shows `replay_id`, `frames`, `packets_per_second`, `wall_seconds`, `detection_count`, `incident_count` and `response_decisions`. `--json` and `--report` output the stored report with `replay_id` added. The stored report differs from the non-persisted one in three ways:

- It has no `file` block.
- `detections` and a `decisions` list (preventive response decisions) are each truncated to 500 entries.
- The pipeline is the replay service's isolated pipeline. It applies the platform's active rules from the database (file rules and rules created through the API, with their enabled or disabled state) but does not attach the statistical or machine-learning anomaly detectors.

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
| `--bpf TEXT` | Kernel BPF filter for live capture |
| `--duration FLOAT` | Stop after N seconds |
| `--enforce` | Use the configured firewall backend and response settings. Still subject to `DRY_RUN` |

The source is chosen in the order `--scenario`, `--pcap`, then live capture. Without `--enforce`, the monitor uses an in-memory firewall and forces dry run. The view shows the safety posture, packet, flow, detection and incident counters, the 12 most recent detections with their first evidence line, and a sample of one packet in 50. A scenario or capture source ends when its last packet has been processed.

Live capture privileges and interface selection are covered in [packet-capture.md](packet-capture.md).

## Dashboard PCAP Lab

The **PCAP Lab** page (`/lab`, in the Respond group of the navigation) is a front end to the [Replay API](#replay-api). Viewers can browse files and reports; uploading, generating fixtures, starting and cancelling replays require the analyst role.

**Choose a capture.** Select a file from `PCAP_DIRECTORY` (listed recursively; `.pcap`, `.pcapng` and `.cap` files) and a replay speed: Unpaced (`0`), Original timing (`1`) or 5× original (`5`). **Replay capture** starts a run and opens its report.

**Add a capture.**

- **Upload pcap or pcapng** accepts `.pcap`, `.pcapng` and `.cap` files. The server checks the file signature and size and stores it under a generated name. The uploaded file is selected when the upload succeeds.
- **Generate a synthetic test fixture** writes the selected scenario to `PCAP_DIRECTORY/fixtures/<scenario>.pcap`. The confirmation lists the detectors a correct engine should report.

**Recent replays** lists the last 20 runs with file, age, user, detection count and status (`queued`, `running`, `completed`, `failed`, `cancelled`). Progress for a running replay arrives over the WebSocket (`replay.progress` and `replay.completed` events).

**Replay report.** Selecting a run (`/lab?replay=<id>`) shows packets processed, throughput, wall time, capture span, decode failures, detection and incident counts, per-packet and detection latency, and CPU and memory, followed by the incidents (linked to their incident pages), the simulated response decisions, and the detection table. A running replay can be cancelled from its report. A failed replay shows its error message.

Detections and incidents from a replay are tagged with its replay ID. They are excluded from the live detection and incident lists and dashboards, and are returned by the API only when you filter by that replay ID. The **Monitor** page's live feed labels replay events and has a checkbox to include or hide them.

## Replay API

All paths are under `/api/v1`. Scripts authenticate with a bearer token from `POST /api/v1/auth/login`; see [api.md](api.md).

| Method and path | Role | Purpose |
|---|---|---|
| `GET /replay/files` | viewer | List `.pcap`, `.pcapng` and `.cap` files under `PCAP_DIRECTORY` with `path`, `filename`, `size_bytes`, `modified_at` |
| `GET /replay/files/inspect?path=` | viewer | Capture metadata (packet count, link type, time span) without replaying |
| `POST /replay/upload` | analyst | Multipart upload in the `file` field. Returns `201` with the stored `path` and the file metadata |
| `GET /replay/scenarios` | viewer | Scenario names with a one-line description |
| `POST /replay/scenarios/{name}` | analyst | Write a scenario to `fixtures/<name>.pcap`. Body `{"params": {...}}` |
| `POST /replay` | analyst | Start a replay. Body `{"path": "...", "speed": 0, "limit": null}`. Returns `202` with `replay_id` and status `queued` |
| `GET /replay?limit=` | viewer | Recent runs (1 to 200, default 50) with a summary |
| `GET /replay/{replay_id}` | viewer | One run with its full stored report |
| `POST /replay/{replay_id}/cancel` | analyst | Cancel a running replay. `409` if it is not running |
| `GET /detections?replay_id=`, `GET /incidents?replay_id=` | viewer | Stored detections and incidents of one replay |

```bash
curl -s -H "Authorization: Bearer $TOKEN" -F file=@capture.pcap \
  http://127.0.0.1:8000/api/v1/replay/upload
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"path": "uploads/<stored-name>.pcap", "speed": 0}' \
  http://127.0.0.1:8000/api/v1/replay
```

Capture errors (a path outside the directory, a missing file, a rejected upload, too many concurrent replays, an unreadable capture) are returned as `422` with a `detail` message.

### Uploads

`ReplayService.store_upload` streams the upload to `PCAP_DIRECTORY/uploads/` in 1 MB chunks.

- **Size limit.** The limit is the smaller of `api.max_upload_mb` (default 200, env `API__MAX_UPLOAD_MB`) and `capture.max_pcap_size_mb` (default 512, env `CAPTURE__MAX_PCAP_SIZE_MB`). Writing stops and the partial file is deleted as soon as the limit is exceeded.
- **Magic number.** The first four bytes must be a pcap header in either byte order, with microsecond or nanosecond timestamps (`d4c3b2a1`, `a1b2c3d4`, `4d3cb2a1`, `a1b23c4d`), or a pcapng section header block (`0a0d0d0a`). The file must then parse as a capture. Otherwise it is deleted and the upload is rejected.
- **Stored name.** Files are saved as `<UTC timestamp>-<8 random hex characters>-<sanitised stem>.pcapng` when the original name ends in `.pcapng`, and `.pcap` otherwise. The stem keeps only letters, digits, `.`, `_` and `-`, up to 60 characters. The original name is recorded only in the audit log.
- **Permissions and audit.** Stored files are set to mode `0640`. Each upload is recorded as an `UPLOAD_PCAP` audit event with the original name and size.

There is no API endpoint for deleting captures. Remove files from `PCAP_DIRECTORY` on the server when they are no longer needed.

### Scenario parameters

`params` (at most 10 entries, integer, float or string values) are passed as keyword arguments to the scenario function in `scenarios.py`, for example `{"params": {"ports": 30}}` for `tcp_port_scan` or `{"params": {"port": 80}}` for `horizontal_scan`. An unknown parameter returns `422`, and so does a scenario of more than 2,000,000 packets. Generating a fixture is recorded as a `GENERATE_FIXTURE` audit event. The CLI `fixtures generate` command always uses the defaults.

### Path resolution

Every client-supplied path (`inspect`, `POST /replay`, and `pcap_path` in `POST /rules/test`) goes through `ReplayService.resolve`. The path is joined to `PCAP_DIRECTORY`, fully resolved (which also follows symbolic links), and rejected with `path is outside the PCAP directory` unless the result is inside that directory. Absolute paths and `..` traversal are refused this way. The resolved path must also be an existing regular file.

### Running and cancelling

- At most 2 replays run at once. A third start is refused.
- `speed` must be between 0 and 100. `limit`, when given, is between 1 and 100,000,000.
- Starting, cancelling and uploading are recorded as `START_REPLAY`, `CANCEL_REPLAY` and `UPLOAD_PCAP` audit events.
- Progress is published every 0.5 seconds as `replay.progress` and stored on the run record. The end of a run publishes `replay.completed` with status `completed`, `cancelled` or `failed`.
- A failed run stores the capture error message, or `<ExceptionType>: replay failed` for other errors.

## Replay isolation

`ReplayService._isolated_pipeline` builds a separate `Pipeline` for each replay:

- **Separate state.** Its feature windows, source profiles and correlation state are its own, so replayed traffic cannot mix with live detection state.
- **Forced dry run.** A deep copy of the settings is taken and `response.dry_run` is set to true and `response.firewall_backend` to `null`, whatever the live configuration is.
- **In-memory firewall.** The pipeline is given a `MemoryFirewall`, so even the simulated decisions have no path to nftables or iptables.
- **Decisions stay visible.** If the live response mode is `manual_approval`, the replay switches to `automatic` so the report shows what would have been decided instead of queueing approval requests. With dry run forced, those decisions are not applied.
- **Tagged output.** `pipeline.replay_id` is set, and every detection and incident event it publishes carries that ID. The persister stores the ID with each record, and live queries exclude records that have one.

The CLI replay without `--persist` uses the same safeguards in simpler form: it forces `dry_run` and passes a `MemoryFirewall`. `sentinelx monitor` does the same unless `--enforce` is given.

Replays differ from the live pipeline in what is attached to them:

| Component | Live platform | `sentinelx replay` | `--persist`, API and dashboard replays |
|---|---|---|---|
| Built-in detectors | yes | yes | yes |
| Rules | active rules from the database | rule files from `RULES_DIRECTORY` | active rules from the database |
| Statistical anomaly detector | when `anomaly.enabled` | when `anomaly.enabled` | no |
| Machine-learning anomaly detector | when `anomaly.ml_enabled` | no | no |
| Threat intelligence allowlist and denylist providers | yes | no | no |

Risk scores in a replay can therefore differ from live scores for addresses listed in the threat intelligence files. Detection timestamps record when the replay produced each detection; the capture's own time range is in the report's `file` block (CLI) or the run's `capture_span_seconds`.

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
| `--pcap FILE` | Run each rule over a capture (`run_rule_on_pcap`) |
| `--scenario TEXT` | Run each rule over one synthetic scenario |
| `--json` | Machine-readable output |

If both `--pcap` and `--scenario` are given, `--pcap` is used. Without either, the rules' embedded `tests:` are run and the command exits with code 1 if any test fails. Against a capture or scenario there is no expected outcome, so the exit code is 1 only when a rule file is invalid.

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

In Wireshark, **File > Save As** with the "Wireshark/tcpdump/... - pcap" file type writes classic pcap.

Guidelines:

- Capture on a named interface. SentinelX decodes a pcap written by `tcpdump -i any` (Linux cooked capture), but not a pcapng written on `any` (see the table below).
- Do not truncate packets with a small snapshot length. SentinelX's own live capture keeps 2,048 bytes per frame so that DNS, HTTP request lines and TLS ClientHello metadata are available to detectors and rules; tcpdump's default keeps whole packets.
- Detectors work on per-source rates inside windows of seconds. Capture long enough to cover the behaviour you want to test, and keep the original timestamps: do not merge or retime files with tools that rewrite timestamps.
- Put files you want to replay from the dashboard or API into `PCAP_DIRECTORY`, or upload them.

### Supported formats

Files are opened with Scapy's `RawPcapReader`, falling back to `RawPcapNgReader`; packet decoding is SentinelX's own. The decoder handles these link types: Ethernet (1, including stacked 802.1Q and 802.1ad VLAN tags), Linux cooked capture v1 (113) and v2 (276), raw IP (101, 228, 229) and BSD loopback (0). Any other link type counts every frame as a decode failure.

| File | Status |
|---|---|
| Classic pcap, microsecond timestamps, either byte order | Supported, with any of the link types above |
| pcapng with an Ethernet interface | Supported |
| pcapng with any other link type (for example captured on `any`, a raw IP tunnel interface or loopback) | Not decoded. The reader takes the link type from the file object, which pcapng readers do not expose, and falls back to Ethernet, so every frame fails to decode. Convert to classic pcap first |
| Classic pcap with nanosecond timestamps (`tcpdump --time-stamp-precision=nano`) | Accepted by the upload check and the reader, but timestamps are read incorrectly: the nanosecond field is treated as microseconds, which distorts timing and ordering. Capture with microsecond precision or convert first |

To convert a pcapng or nanosecond pcap file to a microsecond classic pcap with Wireshark's `editcap`:

```bash
editcap -F pcap capture.pcapng capture.pcap
```

Check the result before relying on it: `sentinelx replay capture.pcap --json` reports `decode_failures`, and `file.link_type` shows the link type that was used. `GET /api/v1/replay/files/inspect` reports the same metadata for a file in `PCAP_DIRECTORY`.

## Privacy when sharing captures

A packet capture can contain far more than the traffic you meant to share: internal addresses and host names, MAC addresses, DNS queries that reveal browsing, HTTP URLs, cookies and `Authorization` headers on unencrypted connections, TLS server names, and credentials of any cleartext protocol.

Before sharing a capture in an issue, a pull request or a vulnerability report:

- **Prefer a synthetic reproducer.** If the behaviour can be shown with a scenario from `scenarios.py`, possibly with changed parameters, share the scenario name and parameters instead of a capture. A rule that misbehaves can usually be shown with `sentinelx rules test --scenario`.
- **Capture only what is needed.** Use a BPF filter at capture time, or cut an existing file down to the relevant hosts, for example `tcpdump -r capture.pcap -w reduced.pcap 'host 203.0.113.45'`.
- **Keep it short.** Cut the file to the time range that triggers the behaviour, and confirm that the reduced file still reproduces it with `sentinelx replay reduced.pcap`.
- **Anonymise addresses consistently if you must.** Tools that rewrite IP addresses change what SentinelX sees: home network direction labels, allowlist and denylist matches, and per-source counting all depend on addresses. Rewrite every address with a consistent mapping and re-run the replay afterwards to check that the result is unchanged.
- **Remove payloads that are not needed.** Scan, flood and brute-force detections depend on headers and timing. DNS, HTTP and TLS rules need their protocol headers. Do not share cleartext credentials or session tokens at all.
- **Treat uploaded captures as sensitive data.** Files uploaded to the PCAP Lab stay in `PCAP_DIRECTORY/uploads` with mode `0640` until someone deletes them on the server, and every analyst can replay them.

For security vulnerabilities, follow [SECURITY.md](../SECURITY.md) and share captures only through the private reporting channel. The platform's threat model, including upload handling, is in [security.md](security.md).
