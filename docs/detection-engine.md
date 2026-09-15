# Detection engine

This document describes how SentinelX turns decoded packets into detections: the feature extractor that keeps per-source state, the detection engine that runs detectors and applies shared policy, every built-in detector, the statistical and machine-learning anomaly layers, and the limits of all of them.

It is written for operators tuning a sensor and for contributors adding detectors. Custom YAML rules have their own document, [rule-engine.md](rule-engine.md). What happens after a detection is emitted is covered in [risk-scoring.md](risk-scoring.md) and [response-engine.md](response-engine.md). The overall pipeline is in [architecture.md](architecture.md).

## Contents

- [Where detection sits in the pipeline](#where-detection-sits-in-the-pipeline)
- [Feature extraction and source profiles](#feature-extraction-and-source-profiles)
- [The detection engine](#the-detection-engine)
- [Detection modes](#detection-modes)
- [The Detection model](#the-detection-model)
- [Built-in detector catalogue](#built-in-detector-catalogue)
- [Statistical anomaly detection](#statistical-anomaly-detection)
- [Machine-learning anomaly detection](#machine-learning-anomaly-detection)
- [Writing a new detector](#writing-a-new-detector)
- [Settings reference](#settings-reference)
- [Limits](#limits)

## Where detection sits in the pipeline

For every captured frame the pipeline (`packages/sentinelx/pipeline.py`) does the following, synchronously:

1. The decoder turns the frame into a `PacketEvent` (`packages/sentinelx/common/models.py`). Protocol decoders add `metadata["dns"]`, `metadata["http"]` and `metadata["tls"]` when they recognise the payload.
2. `FeatureExtractor.process()` updates the sender's `SourceProfile` and the conversation's `FlowState`, and returns a `FeatureContext`.
3. `DetectionEngine.evaluate()` runs every enabled detector against that context and returns the detections that pass engine policy.
4. Each detection goes on to threat intelligence, risk scoring, correlation and response.

The feature extractor and the detection engine perform no I/O and read no wall clock: all windows are measured in packet capture time, and every emitted detection is stamped with the capture time of the packet that triggered it. Live capture, PCAP replay, the benchmark harness and unit tests therefore produce identical detections, with identical timestamps, for identical input.

Which detectors a pipeline gets is decided in one place, `packages/sentinelx/assembly.py`. Live capture (the platform), API and dashboard replays, `sentinelx replay`, `sentinelx monitor` and the benchmark all use it, so they run the same built-in detectors, custom rules, statistical and optional ML anomaly detectors and local threat-intelligence providers for the same configuration. See [Detection modes](#detection-modes).

## Feature extraction and source profiles

Code: `packages/sentinelx/features/extractor.py`, `packages/sentinelx/features/profiles.py`, `packages/sentinelx/common/windows.py`.

Detectors do not keep their own counters. All counting happens once per packet in the feature extractor, and detectors read the result. This keeps per-packet cost proportional to packets rather than to the number of detectors, and it means rules, built-in detectors and the ML model all see the same numbers.

### State kept

| Structure | Keyed by | Holds |
|---|---|---|
| `SourceProfile` | source IP (the packet's sender) | Sliding-window counters and distinct-value sets describing what that source did |
| `FlowState` | canonical 5-tuple (both directions share one entry) | Initiator and responder, packet and byte counts, which TCP flags were seen |
| `GlobalStats` | none | Network-wide packet, byte and per-protocol counters |

### Windows

Every profile is sized to one window long enough for every detector, which this document calls the profile window W:

```
W = max(port_scan_window_seconds, brute_force_window_seconds,
        connection_rate_window_seconds, icmp_flood_window_seconds,
        dns_window_seconds, http_flood_window_seconds)
```

With default settings W is 60 seconds. Event series (packets, SYNs, connection attempts, ICMP, DNS and HTTP request times, SYN-ACKs and RSTs received) are `TimeSeriesCounter`s, which answer "how many in the last N seconds" in amortised constant time for every registered detector window and in O(log n) for any other window.

The scan structures are the exception. Distinct TCP destination ports and hosts used by the scan detectors (`scan_ports`, `scan_hosts`) and distinct UDP destination ports (`udp_ports`) are kept in separate structures sized to `port_scan_window_seconds` only (15 seconds by default), so that setting is honoured exactly rather than being widened to W.

### How the profile is updated

- **Packets sent by a source** are folded into that source's profile: packet size, destination host, TCP destination port, bare SYNs (which also count as connection attempts, and are counted per destination port in `syn_ports`), UDP destination ports, ICMP packets, DNS queries and HTTP requests.
- **ICMP echo replies to a request are not the replier's ICMP.** Request and reply share a flow, which remembers who sent the last echo request and when. An echo reply (type 0, or 129 for ICMPv6) sent back to that requester within `icmp_flood_window_seconds` is marked as a solicited reply: it is not added to the replier's `icmp_packets`, and the statistical anomaly detector does not count it towards the replier's share. A host answering a ping flood is the flood's target, not its source. Unsolicited replies, as in a reflection attack, still count.
- **Replies update the side that opened the connection.** When a SYN-ACK or RST is sent to a flow's initiator, it is recorded in the initiator's profile as `syn_ack_received`, or as `rst_received` and `refused_connections`, and the RST's source port in `refusals_by_port`. A reset sent the other way, such as a SYN flooder's own kernel resetting the SYN-ACKs it receives, is not a refusal and is not recorded against the target.
- **Completed handshakes are credited to the initiator.** When a flow's handshake completes and the initiator sends a packet, `handshakes_completed` in its profile goes up once for that flow. `syn_flood` uses this to tell a busy client from a flood.
- **Short sessions are recorded at teardown.** A flow is short-lived when its handshake completed (SYN, SYN-ACK and ACK all seen; a SYN-ACK timestamped before its SYN, as happens when captures from two taps are merged, still counts), a FIN or RST has been seen, and its duration is under 5 seconds. On the first FIN or RST of such a flow, the responder port is recorded in the initiator's `short_sessions`, once per flow. This is the brute-force signal.
- **UDP service replies are not counted as scanning.** A UDP packet from a port below 1024 to a port at or above 1024 is treated as a server reply and is not added to `udp_ports`; otherwise every DNS resolver would look like a UDP scanner.
- **DNS queries are classified once.** A query is added to `dns_suspicious` (keyed by its parent domain, the last two labels, or three when the second-to-last label has three characters or fewer) when its longest label is at least `dns_long_label_length`, or when its leftmost label is at least 20 characters and its entropy is at least `dns_high_entropy_threshold`.

### Windows are expired before detectors read them

Window structures drop old entries when something is added to them. A profile that did not receive a matching event on this packet could otherwise still hold entries from long ago: the attacker's `short_sessions` when the server's RST arrives, or `dns_suspicious` on an ordinary query. `SourceProfile.expire(now)` drops everything outside each window as of the current packet time. The feature extractor calls it on the sender's profile before returning the context, and `FeatureContext.profile_of(ip)` calls it on any other profile before handing it to a detector. Each call is amortised O(1).

Without this, a detector could count stale activity: for example, `ssh_brute_force` could fire again on a new session using attempts that had left the window long before.

### Bounded memory

An IDS is a resource-exhaustion target, so state is capped:

- At most `max_tracked_sources` profiles (default 50,000) and four times that many flows. When a new source arrives at the cap, profiles idle for longer than W are evicted first, then the least recently seen 10%. Flows are evicted the same way, using a 120-second idle limit.
- Every 2,048 packets a sweep removes flows idle for 120 seconds and profiles idle for 2W.
- Evictions are counted (`evicted_sources`, `evicted_flows` in `FeatureExtractor.state()`), so a quiet network can be told apart from one that is shedding state.
- Memory is roughly 16 KB per tracked source: 50,000 sources with 200,000 connections were measured at 823 MB. Size the sensor for `max_tracked_sources`, or lower it on a small host.

If packet time jumps backwards by more than W (a clock correction on the sensor, or captures concatenated out of order), all profiles and flows are discarded and the reset is counted in `clock_resets` in `FeatureExtractor.state()`. Windows only move forward, so after such a step nothing would expire until packet time caught up, and ordinary sources would accumulate events indefinitely. Reordering within W is unaffected.

Changing any window setting at runtime rebuilds the extractor, which discards all traffic state.

### The feature vector

`FeatureContext.features()` returns the flattened vector for the packet's source at that instant. It is built at most once per packet. Keys:

`source_ip`, `window_seconds`, `packet_count`, `packet_rate`, `observed_span`, `unique_dst_ports`, `unique_dst_ips`, `unique_udp_ports`, `syn_count`, `syn_ratio`, `syn_ack_ratio`, `rst_count`, `refusal_ratio`, `connection_attempts`, `failed_attempts`, `short_sessions`, `icmp_count`, `dns_query_count`, `dns_suspicious_queries`, `dns_unique_domains`, `http_request_count`, `http_unique_paths`, `packet_size_mean`, `packet_size_stddev`, `protocol_distribution`, `total_packets`, `total_bytes`, `detections_triggered`, `first_seen`, `last_seen`, plus the per-packet keys `protocol`, `destination_port`, `destination_ip`, `source_port`, `packet_length`, `direction`, `flow_duration`, `flow_packets`, `handshake_complete` and, for TCP, `tcp_flags`.

Counts and ratios in this vector cover W, except `unique_udp_ports`, which covers the scan window. The rule engine does not use this vector directly; it resolves fields itself so it can narrow counts to each rule's `within` window (see [rule-engine.md](rule-engine.md#field-reference)).

## The detection engine

Code: `packages/sentinelx/detection/engine.py`.

`DetectionEngine.evaluate(context)` calls `inspect()` on each enabled detector in order and passes any returned `Detection` through `_admit()`. Built-in detectors run first, in this order (cheap, precise detectors first): `denylist`, `tcp_flag_anomaly`, `tcp_port_scan`, `horizontal_scan`, `udp_scan`, `ssh_brute_force`, `syn_flood`, `connection_rate`, `icmp_flood`, `http_flood`, `dns_anomaly`. Detectors added later with `add_detector()` run after them, in the order they were added. The platform and API replays add the anomaly detectors and then one detector per custom rule; `sentinelx replay`, `sentinelx monitor` and the benchmark add rules first. Detectors are independent, so the order does not change which detections are produced.

Four policies are applied by the engine so that no detector has to implement them.

### 1. Fault isolation

An exception raised inside a detector's `inspect()` is caught. The engine logs it (`detector_failed`, with the packet summary), increments `detector_errors` and the `sentinelx_detector_errors_total{detector=...}` metric, and moves on to the next detector. One broken detector never stops the others or the pipeline.

A `Detection` whose constructor fails (confidence outside 0.0-1.0, or an empty `source_ip`) raises inside the detector and is handled the same way.

### 2. Evidence enforcement

A detection with an empty `evidence` list is discarded, logged as `detection_without_evidence_rejected`, and counted as a detector error. Explainability is enforced, not a convention. This check runs before the allowlist and cooldown checks.

### 3. Allowlist

**SentinelX's own storage traffic comes first.** When the database or Redis runs on another host or container, the API's own connections to it cross the capture interface, and a connection pool opening and closing connections under load looks like credential guessing. A detection is dropped, and counted in `suppressed_own_traffic` and `sentinelx_detections_suppressed_total{reason="own_traffic"}`, when its source is an address of this host and its destination address and port are the database or Redis endpoint from `STORAGE__DATABASE_URL` or `STORAGE__REDIS_URL` (host names are resolved lazily and cached for 60 seconds). The same packets are also left out of the statistical and ML anomaly detectors. Traffic from any other address to those services, and anything else this host sends, is analysed as usual (`packages/sentinelx/system/self_traffic.py`).

If the detection's `source_ip` falls inside any network in `DETECTION__ALLOWLIST_NETWORKS`, the detection is dropped and counted in `suppressed_allowlist` and `sentinelx_detections_suppressed_total{reason="allowlist"}`.

Two details matter:

- The check is applied to the detection after the detector has run, not before. Detector counters still move for allowlisted traffic.
- It is applied to the address the detector attributes the finding to. For most detectors that is the packet sender; `ssh_brute_force` uses the flow initiator, `denylist` uses the listed address, and `statistical_anomaly` uses the top contributor.

This allowlist is separate from `RESPONSE__ALLOWLIST_NETWORKS` (addresses that may never be blocked; see [response-engine.md](response-engine.md)) and from the threat-intelligence allowlist in `rules/intel/allowlist.txt` (which lowers risk; see [risk-scoring.md](risk-scoring.md)).

### 4. Cooldown and escalation

A port scan is thousands of packets, and a threshold detector would otherwise fire on every packet past its threshold. The engine remembers, for each `(detection.detector, detection.source_ip)` pair, the packet time, severity and confidence of the last detection it let through. A new detection for the same pair within `DETECTION__DETECTION_COOLDOWN_SECONDS` (default 60) of that time, in either direction, is suppressed and counted in `suppressed_cooldown` and `sentinelx_detections_suppressed_total{reason="cooldown"}`, unless it escalates.

A repeat escalates, and is emitted despite the cooldown, when either:

- its severity rank is higher than the last reported severity (`info` < `low` < `medium` < `high` < `critical`), or
- its confidence is at least 0.2 higher than the last reported confidence.

Escalations are counted in `escalations`. Every emitted detection, escalated or not, resets the pair's cooldown start to the current packet time and records its severity and confidence as the new reference.

The reason for escalation: detectors fire as soon as a threshold is crossed, when evidence is thinnest. Without it, the record of a scan would stay frozen at "20 ports, confidence 0.6" while the scan grew to thousands of ports. Because confidence saturates below 1.0 and severity has five levels, each pair can escalate only a few times per cooldown. The test `test_cooldown_collapses_repeats_but_allows_escalation` in `tests/detection/test_detectors.py` pins this: a 1,200-packet ICMP flood produces between one and four `icmp_flood` detections, with more than 500 suppressed.

Behaviour that persists after the cooldown has elapsed is reported again. The comparison uses the absolute time difference, so if packet time steps back by more than the cooldown, the earlier report does not suppress the source until packet time catches up with it. Cooldown state is pruned of expired entries once it exceeds 100,000 pairs. The cooldown length is read from the settings on every evaluation, so a runtime change to `detection_cooldown_seconds` (dashboard or `PATCH /api/v1/config/detection`) takes effect immediately in the running server.

For emitted detections the engine also:

- replaces the detection's `timestamp` with the capture time of the triggering packet (`context.now`), so a replay reproduces the original timeline, and the risk engine's history and the correlation engine's windows (see [architecture.md](architecture.md)) follow capture time rather than replay speed;
- increments the source profile's `detections_triggered` and the `sentinelx_detections_total{detector,severity,category}` metric; and
- logs a `detection` event.

### Engine statistics

`DetectionEngine.stats()` reports `detectors`, `enabled`, `detections_emitted`, `suppressed_cooldown`, `escalations`, `suppressed_allowlist`, `suppressed_own_traffic`, `detector_errors`, and per-detector `evaluations` and `hits`. `GET /api/v1/detectors` returns each detector's name, description, category, default severity, references and live counters. `PATCH /api/v1/detectors/{name}/enabled` enables or disables a built-in or anomaly detector at runtime and persists the change to `disabled_detectors`; rule detectors are toggled through the rules endpoints instead. On restart, a built-in or anomaly detector named in `disabled_detectors` is attached but switched off (`attach_anomaly_detectors` in `assembly.py` does this for `statistical_anomaly` and `ml_anomaly`), so it can be switched back on from the dashboard or this endpoint without a restart. The endpoint returns 404 only for a detector that is not attached at all, for example an anomaly detector in `signature_only` mode or with `ANOMALY__ENABLED=false`, or the ML detector when its model did not load. See [api.md](api.md).

## Detection modes

`DETECTION_MODE` (nested form `DETECTION__MODE`; both are read from the environment and from `.env`, the environment wins over `.env`, and the nested form wins when both are set at the same level) selects the detector set. Values are defined in `packages/sentinelx/common/enums.py`. Built-in detectors are selected by `default_detectors()` in `detection/engine.py`; rules and anomaly detectors are attached by `packages/sentinelx/assembly.py` (and, in the platform, by the rule service).

| Value | Built-in detectors | Custom rules | Statistical and ML anomaly detectors |
|---|---|---|---|
| `disabled` | none | none | none |
| `signature_only` | `denylist` and `tcp_flag_anomaly` only (the detectors that match facts rather than rates) | attached | not attached |
| `balanced` (default) | all eleven | attached | attached as configured |
| `aggressive` | all eleven | attached | attached as configured |

`aggressive` currently selects exactly the same detectors as `balanced` and changes no thresholds. It is reserved for more sensitive thresholds.

Within the mode:

- If `DETECTION__ENABLED_DETECTORS` is non-empty, only detectors whose names appear in it are kept: built-in detectors, and the anomaly detectors (`statistical_anomaly`, `ml_anomaly`) too. It does not affect rules. Every name must be a registered detector name (the eleven built-in names listed above, or `statistical_anomaly` or `ml_anomaly`); an unknown name raises `ConfigurationError` listing the known names when the detection engine is built (`default_detectors()`), instead of silently enabling nothing. Use registered names, not detection names: the brute-force detector is `ssh_brute_force`, not `auth_brute_force`.
- Built-in and anomaly detectors named in `DETECTION__DISABLED_DETECTORS` are instantiated but start disabled, so they can be re-enabled at runtime.
- The statistical detector is attached when `ANOMALY__ENABLED=true`; the ML detector when `ANOMALY__ML_ENABLED=true` and a trusted model loads (see [Model file checks](#model-file-checks)).
- In the platform and API replays, rules disabled in the dashboard or with `sentinelx rules` are left out. `sentinelx replay`, `sentinelx monitor` and the benchmark have no database and load every valid rule file from the rules directory.

Built-in and anomaly detectors are chosen when the pipeline is constructed, so a mode change affects them on the next start. Rule detectors are rebuilt whenever the rule service re-applies rules (at startup and after a rule is created, changed, deleted or toggled), and that rebuild reads the current mode.

### Custom rules as detectors

Each enabled rule becomes one `RuleDetector` named `rule:<id>`, subject to the same engine policy as built-in detectors. The rule format is documented in [rule-engine.md](rule-engine.md); three properties matter for the engine:

- **Restricted YAML.** Rule files and rule definitions are parsed by `load_rule_yaml()` in `signatures/rules.py`, a `SafeLoader` that refuses YAML anchors and aliases and nesting deeper than 32 levels (`MAX_YAML_DEPTH`), so a small document cannot expand into a very large one. Rule files larger than 1 MiB are skipped.
- **Validated tests.** The synthetic scenarios named in a rule's `tests` are checked with `validate_scenario_params()` when the rule is validated: unknown scenarios, unknown parameters, wrong types and out-of-range values (for example counts above 50,000, durations above 3,600 seconds, or a `dns_rate_spike` that would generate more than 2,000,000 packets) make the rule invalid. The same checks apply to scenarios requested through the API.
- **Block duration.** A rule's `duration` is carried on its detections as `recommended_duration_seconds` and sets the length of the automatic block or rate limit.

## The Detection model

Code: `packages/sentinelx/common/models.py`.

Every detector, whatever its method, returns the same frozen dataclass. That is what lets scoring, correlation, the API and the dashboard stay detector-agnostic.

### Detection

| Field | Type | Meaning |
|---|---|---|
| `detector` | str | Stable identifier of the producing detector, such as `tcp_port_scan` or `rule:ssh_brute_force` |
| `category` | ThreatCategory | `reconnaissance`, `brute_force`, `denial_of_service`, `exfiltration`, `protocol_anomaly`, `policy_violation`, `malicious_reputation`, `anomaly`, `lateral_movement`, `other` |
| `severity` | Severity | `info`, `low`, `medium`, `high`, `critical` |
| `confidence` | float | 0.0-1.0; construction raises `ValueError` outside that range |
| `title`, `description` | str | Human-readable summary |
| `source_ip` | str | The address the finding is attributed to; construction raises `ValueError` if empty |
| `evidence` | list[Evidence] | Must be non-empty to pass the engine |
| `destination_ip`, `source_port`, `destination_port`, `protocol` | optional | Taken from the triggering packet unless the detector overrides them |
| `recommended_action` | ActionType | `alert` by default. A recommendation only; whether anything happens depends on risk and response settings |
| `recommended_duration_seconds` | int or None | How long an automatic `temporary_block` or `rate_limit` should last. Set from a custom rule's `duration`; `None` means `RESPONSE__DEFAULT_BLOCK_SECONDS`. See [response-engine.md](response-engine.md#action-types) |
| `timestamp` | datetime | UTC capture time of the packet that triggered the detection, set by the engine when it admits the detection |
| `detection_id` | str | Random hex identifier |
| `rule_name` | str or None | Set for detections from custom rules |
| `observation_window_seconds`, `packet_count` | optional | Size of the evidence window |
| `tags` | tuple[str, ...] | Free-form labels |

### Evidence

| Field | Meaning |
|---|---|
| `key` | Machine-readable name, such as `unique_destination_ports` |
| `value` | The observed value |
| `description` | A sentence an analyst can read and check |
| `threshold` | The value it was compared against, when there is one |
| `weight` | Relative importance, 0-1, used by the risk engine |

`Detection.evidence_dict()` returns `{key: value}` for all evidence. `Detection.explain()` renders the reasoning as plain text for the CLI and logs:

```text
Threat:     Cleartext Telnet session
Detector:   cleartext_telnet
Category:   policy_violation
Severity:   low  (confidence 90%)
Source:     192.168.1.20
Target:     192.168.1.5
Evidence:
  - the session's service port is 23 (Telnet), which sends credentials in cleartext
  - the three-way handshake completed, so this is a real session, not a probe
Recommends: alert
```

The `Target:` line is omitted when there is no destination. This output comes from the example detector in [Writing a new detector](#writing-a-new-detector).

### Confidence curve

Most threshold detectors use `Detector.scaled_confidence(observed, threshold, floor, ceiling, saturation)`:

- if `observed / threshold <= 1`, the result is `floor`;
- otherwise it is `floor + (ceiling - floor) * min((ratio - 1) / (saturation - 1), 1)`, rounded to four decimal places.

Confidence therefore rises from `floor` at the threshold to `ceiling` at `saturation` times the threshold, and never reaches 1.0. The per-detector values are listed in the catalogue.

## Built-in detector catalogue

Common notation in this section:

- **W** is the profile window (60 s by default).
- **Scan window** is `port_scan_window_seconds` (15 s by default).
- **Confidence** is given as floor-ceiling at saturation multiple, using the curve above. Saturation is 3 unless stated.
- Environment variable names are listed in [Settings reference](#settings-reference).

### Summary

| Detector | Evaluated on | Category | Severity | Recommended action |
|---|---|---|---|---|
| `denylist` | every packet | malicious_reputation | high | `block_ip` if the listed address is the sender, else `alert` |
| `tcp_flag_anomaly` | TCP packets | protocol_anomaly | medium | `alert` |
| `tcp_port_scan` | bare SYNs | reconnaissance | high, or critical | `temporary_block` |
| `horizontal_scan` | bare SYNs | reconnaissance | high, or critical | `temporary_block` |
| `udp_scan` | UDP packets with a destination port | reconnaissance | medium | `alert` |
| `ssh_brute_force` / `auth_brute_force` | TCP FIN or RST on a monitored service port | brute_force | high, or critical | `temporary_block` |
| `syn_flood` | bare SYNs | denial_of_service | high, or critical | `rate_limit` |
| `connection_rate` | bare SYNs | denial_of_service | medium, or high | `rate_limit` |
| `icmp_flood` | ICMP and ICMPv6 packets | denial_of_service | medium, or high | `rate_limit` |
| `http_flood` | decoded HTTP requests | denial_of_service | medium, or high | `rate_limit` |
| `dns_anomaly` | decoded DNS queries (not responses) | exfiltration | high (tunnelling) or medium (volume) | `alert` |

A "bare SYN" is a TCP packet with SYN set and none of ACK, RST or FIN.

### denylist

Code: `packages/sentinelx/detection/policy.py` (`DenylistDetector`).

**Detects** traffic to or from an address inside any network in `denylist_networks`.

**Signals.** The packet's source address is checked first, then its destination. The first match produces a detection. No window or baseline is involved.

**Settings.** `denylist_networks` (default empty; with an empty list the detector does nothing). A runtime change to `denylist_networks` is applied to the running detector.

**Output.** Severity high, confidence 0.9, category `malicious_reputation`. The detection's `source_ip` is the listed address, whichever direction the packet travelled, so blocking and correlation act on the right party. Evidence: `denylist_match`, `direction`, `first_packet`. Recommended action is `block_ip` when the listed address sent the packet and `alert` when it received it. Repeats are limited by the engine cooldown.

**Limits.** Only as good as the list. This detector reads only `DETECTION__DENYLIST_NETWORKS`; the threat-intelligence file `rules/intel/denylist.txt` is consumed by the risk engine, not by this detector (see [risk-scoring.md](risk-scoring.md)).

### tcp_flag_anomaly

Code: `packages/sentinelx/detection/policy.py` (`TcpFlagAnomalyDetector`).

**Detects** TCP flag combinations that conforming stacks do not send, as used by NULL, XMAS and similar scans and by OS fingerprinting.

**Signals.** Each TCP packet is classified, in this order:

| Kind | Condition |
|---|---|
| `NULL` | no flags set |
| `XMAS` | FIN, PSH and URG set, ACK not set |
| `SYN+FIN` | SYN and FIN set |
| `SYN+RST` | SYN and RST set |
| `FIN without connection` | FIN set, ACK not set, and the flow's handshake has not completed |

A per-source counter of such packets is incremented. The detector reports once the count reaches 3. The counter is not windowed: it accumulates for the life of the process and is cleared entirely when more than 50,000 sources have counts.

**Settings.** None. The minimum of 3 packets is a class constant (`_MIN_PACKETS`).

**Output.** Severity medium, category `protocol_anomaly`, action `alert`. Confidence 0.85 for `NULL`, `XMAS` and `SYN+FIN`; 0.65 for `SYN+RST` and `FIN without connection`. Evidence: `flag_combination`, `anomalous_packets`.

**Known evasions.** ACK scans and FIN+ACK (Maimon) probes do not match any of the combinations above. Sending fewer than three anomalous packets per source is never reported.

### tcp_port_scan

Code: `packages/sentinelx/detection/scanning.py` (`TcpPortScanDetector`).

**Detects** a vertical scan: one source probing many TCP ports on a host without completing handshakes.

**Signals**, checked on every bare SYN, in order:

1. Distinct TCP destination ports from the source in the scan window is at least `port_scan_unique_ports`.
2. `syn_ratio` over the scan window (bare SYNs divided by all packets from the source) is at least `port_scan_min_syn_ratio`. A client that completes handshakes has a low ratio and is not reported; this is the main false-positive filter.
3. If the source touched more than one host in the scan window and averages fewer than 4 distinct ports per host, the detector defers to `horizontal_scan` and does not report.

**Severity.** High, raised to critical when the distinct-port count is at least five times `port_scan_unique_ports`, or when any port in the sensitive set (22, 23, 445, 3389, 3306, 5432, 6379, 27017, 9200, 11211, 1433, 1521, 2049) was probed in the scan window.

**Confidence.** 0.60-0.97 at 4 times the threshold, plus 0.05 (capped at 0.98) when fewer than 10% of the source's SYNs in W received a SYN-ACK.

**Evidence.** `unique_destination_ports`, `observation_window_seconds`, `syn_ratio`, `syn_ack_ratio`, `connection_attempts`, and when present `refusal_ratio` and `sensitive_ports_probed`.

**Settings.** `port_scan_window_seconds` (15.0), `port_scan_unique_ports` (20), `port_scan_min_syn_ratio` (0.7).

**Known evasions.**

- **Slow scans.** Probes spaced so that fewer than `port_scan_unique_ports` distinct ports fall inside the scan window are not reported. The `slow_port_scan` scenario (60 ports, one every 1.2 s) is missed with default settings and detected with `port_scan_window_seconds=90`; `TestDocumentedEvasions` in `tests/detection/test_detectors.py` pins both results, and [benchmarking.md](benchmarking.md) reports a 0% detection rate for it.
- **Connect scans against open ports.** When the source completes handshakes (SYN, ACK, RST per port), `syn_ratio` falls below 0.7 and the scan is not reported.
- **Diluting the SYN ratio.** Other traffic from the same source in the scan window lowers `syn_ratio`.
- **Non-SYN scans.** FIN, NULL and XMAS scans are not counted here; `tcp_flag_anomaly` covers some of them.
- **Thin spread.** A source that probes many distinct ports spread across many hosts (fewer than 4 distinct ports per host on average, and more distinct ports in total than `horizontal_scan` accepts) matches neither scan detector. For example, 40 hosts probed on 3 different ports each is not reported.
- **Distributed scans.** Profiles are per source, so a scan split across many source addresses is judged per address.

### horizontal_scan

Code: `packages/sentinelx/detection/scanning.py` (`HorizontalScanDetector`).

**Detects** a sweep: one TCP port (or very few) probed across many hosts, as worms and lateral-movement tools do.

**Signals**, checked on every bare SYN:

1. Distinct TCP destination hosts from the source in the scan window is at least `horizontal_scan_unique_hosts`.
2. Distinct TCP destination ports in the scan window is at most `max(4, hosts // 8)`.
3. `syn_ratio` over the scan window is at least `port_scan_min_syn_ratio`.

**Severity.** High; critical when the current packet's destination port is in the sensitive set listed under `tcp_port_scan`.

**Confidence.** 0.62-0.96 at 4 times the threshold.

**Evidence.** `unique_destination_hosts`, `unique_destination_ports`, `observation_window_seconds`, `syn_ratio`, and `targeted_service` when the port has a known service name.

**Settings.** `horizontal_scan_unique_hosts` (25), `port_scan_window_seconds` (15.0), `port_scan_min_syn_ratio` (0.7).

**Known evasions.** Slow sweeps (fewer than 25 hosts per scan window), distributed sweeps, sweeps that complete handshakes, and sweeps that vary the port per host (see the thin-spread case above).

### udp_scan

Code: `packages/sentinelx/detection/scanning.py` (`UdpScanDetector`).

**Detects** one source contacting many distinct UDP ports.

**Signals**, checked on every UDP packet with a destination port:

1. Distinct UDP destination ports in the scan window is at least `udp_scan_unique_ports`. Packets from a source port below 1024 to a destination port at or above 1024 are not counted (they look like service replies).
2. The detection is suppressed when DNS queries from the source are more than 80% of its UDP packets. The DNS count covers W, while the UDP packet count covers the scan window.

The detector does not use ICMP port-unreachable replies.

**Output.** Severity medium, action `alert`, confidence 0.55-0.90 at 4 times the threshold. Evidence: `unique_udp_ports`, `observation_window_seconds`, `udp_packets`.

**Settings.** `udp_scan_unique_ports` (25), `port_scan_window_seconds` (15.0).

**Known evasions.** Slow scans; distributed scans; scans sent from a privileged source port (for example `nmap -g 53`) to destination ports at or above 1024, which are excluded by the service-reply rule.

### ssh_brute_force and auth_brute_force

Code: `packages/sentinelx/detection/behavioral.py` (`BruteForceDetector`).

**Detects** repeated short-lived sessions from one source to an authentication service. The detector does not inspect payloads and cannot see a failed login. It uses a proxy: a completed handshake torn down within 5 seconds, repeated many times. The detector is registered as `ssh_brute_force`. Its detections are named `ssh_brute_force` when the service port is 22 and `auth_brute_force` for the other monitored ports; enabling, disabling and API toggling use the registered name `ssh_brute_force`, which covers both.

**Signals.** On a TCP packet with FIN or RST whose flow responder port is in `brute_force_ports`, the detector reads the initiator's profile and counts short sessions to that port in W (see [how the profile is updated](#how-the-profile-is-updated) for the definition). It reports when the count is at least `brute_force_attempts`.

**Severity.** High; critical when the count is at least four times `brute_force_attempts`.

**Confidence.** 0.60-0.95 at 4 times the threshold.

**Evidence.** `failed_attempts`, `observation_window_seconds` (with the attempt rate per minute), `session_pattern`, `target_service`, and `server_resets` when the initiator has received RSTs from that service's port (resets from other ports, such as a scan's refusals, are not counted). The detection's source is the flow initiator, its destination the responder.

**Settings.** `brute_force_attempts` (15), `brute_force_ports` (`[22, 23, 21, 3389, 445, 5900, 1433, 3306, 5432]`), `brute_force_window_seconds` (60.0). Short sessions are held for W, so `brute_force_window_seconds` is only exact while it is the longest detection window, which it is by default.

**Known evasions.**

- **Low-rate guessing.** Fewer than 15 attempts per 60 seconds is not reported. The `low_rate_brute_force` scenario (30 attempts, one every 8 s) is missed with default settings; `TestDocumentedEvasions` pins this and [benchmarking.md](benchmarking.md) reports 0% detection for it.
- **Long sessions.** Sessions that last 5 seconds or more are not counted, so tools that keep each connection open longer, or try several passwords per connection, are not seen.
- **Unlisted ports.** Services on ports outside `brute_force_ports` are not monitored.
- **Distributed guessing** from many source addresses.

### syn_flood

Code: `packages/sentinelx/detection/behavioral.py` (`SynFloodDetector`).

**Detects** a high count of half-open connections from one source against few ports, whether or not those ports are open.

**Signals**, on every bare SYN:

1. Bare SYNs from the source in W is at least `syn_flood_threshold`. There is no separate window setting for this detector.
2. Either distinct TCP destination ports in W is 5 or fewer (more is treated as scanning), or bare SYNs to this packet's destination port alone reach `syn_flood_threshold`. The second case catches a source that scans and then floods one port, which has touched many ports by the time it floods.
3. Handshake completion (handshakes the source completed per SYN it sent, over W) is at most 0.5. A busy client completes almost every connection. Whether the server answered is not the test: against an open port every SYN gets a SYN-ACK, and a flood simply never sends the final ACK.

**Output.** Severity high, critical at four times the threshold. Confidence 0.65-0.96. Action `rate_limit`. Evidence: `syn_count` (SYNs to the destination port when condition 2 was met through that port), `syn_rate`, `handshake_completion`, and `syn_ack_ratio`, which notes when the port is open and each SYN holds a half-open slot.

**Settings.** `syn_flood_threshold` (500).

**Known evasions.** Floods from many or spoofed source addresses, each below the per-source threshold (the `statistical_anomaly` detector's `syn_per_second` metric may still flag the aggregate); floods spread across more than 5 ports.

### connection_rate

Code: `packages/sentinelx/detection/behavioral.py` (`ConnectionRateDetector`).

**Detects** excessive new TCP connections from one source, regardless of target.

**Signals.** On every bare SYN, connection attempts (bare SYNs) from the source in `connection_rate_window_seconds` is at least `connection_rate_threshold`.

**Output.** Severity medium, high at three times the threshold. Confidence 0.55-0.90. Action `rate_limit`. Evidence: `connection_attempts`, `connection_rate`, `unique_destinations`.

**Settings.** `connection_rate_window_seconds` (10.0), `connection_rate_threshold` (200).

**Known evasions.** Staying below the rate; distributing across sources.

### icmp_flood

Code: `packages/sentinelx/detection/behavioral.py` (`IcmpFloodDetector`).

**Detects** a high rate of ICMP or ICMPv6 packets from one source.

**Signals.** On every ICMP or ICMPv6 packet, ICMP packets from the source in `icmp_flood_window_seconds` is at least `icmp_flood_threshold`. When the standard deviation of the source's packet sizes over W is below 2 bytes, a `uniform_packet_size` evidence item is added.

**Output.** Severity medium, high at three times the threshold. Confidence 0.60-0.95. Action `rate_limit`. Evidence: `icmp_packets`, `icmp_rate`, optionally `uniform_packet_size`.

**Settings.** `icmp_flood_window_seconds` (10.0), `icmp_flood_threshold` (200).

**Known evasions.** Staying below the rate; distributing across sources.

### http_flood

Code: `packages/sentinelx/detection/behavioral.py` (`HttpFloodDetector`).

**Detects** a layer-7 request flood from one source.

**Signals.** On every packet the HTTP decoder marked as a request, HTTP requests from the source in `http_flood_window_seconds` is at least `http_flood_threshold`. The HTTP decoder only parses cleartext payloads on TCP ports 80, 8080, 8000, 8008, 8888 and 3000 (`packages/sentinelx/parser/decoder.py`).

**Output.** Severity medium, high at three times the threshold. Confidence 0.60-0.94. Action `rate_limit`. Evidence: `http_requests`, `request_rate`, `unique_paths` (distinct paths over W, annotated as cache-busting when they exceed 80% of the request count), and `target_host` when a Host header was seen.

**Settings.** `http_flood_window_seconds` (10.0), `http_flood_threshold` (300).

**Known evasions.** HTTPS floods and HTTP on other ports are invisible to this detector; staying below the rate; distributing across sources.

### dns_anomaly

Code: `packages/sentinelx/detection/dns.py` (`DnsAnomalyDetector`).

**Detects** two patterns in DNS queries (not responses). The DNS decoder only runs on traffic to or from ports 53, 5353 and 5355. The tunnelling check runs first; the volume check runs only if it did not report.

**Tunnelling signals:**

1. The current query's longest label is at least `dns_long_label_length`, or its leftmost-label entropy is at least `dns_high_entropy_threshold`.
2. The source has at least 20 suspicious queries in W (`_MIN_SUSPICIOUS_QUERIES`, a class constant).
3. At least 60% of those suspicious queries share one parent domain.

Tunnelling output: severity high, confidence 0.60-0.92 at 5 times the minimum, action `alert`. Evidence: `suspicious_queries`, `max_label_length`, `label_entropy`, `parent_domain`, and `query_type` when it is TXT, NULL or CNAME.

**Volume signals.** DNS queries from the source in `dns_window_seconds` is at least `dns_query_threshold`, or distinct names queried in W is at least `dns_unique_domain_threshold`.

Volume output: severity medium, action `alert`, confidence 0.55-0.90, computed from the larger of the two ratios to their thresholds, saturating at 4. Evidence: `dns_queries`, `unique_domains`.

Both paths use category `exfiltration`.

**Settings.** `dns_window_seconds` (30.0), `dns_query_threshold` (300), `dns_unique_domain_threshold` (100), `dns_long_label_length` (52, range 10-63), `dns_high_entropy_threshold` (3.8). The distinct-name count covers W, not `dns_window_seconds`.

**Known evasions.** Tunnels using labels shorter than the length threshold with low entropy; fewer than 20 suspicious queries per W; spreading queries across several parent domains so no single one reaches 60%; DNS over HTTPS or TLS, and DNS on non-standard ports, which the decoder does not parse.

## Statistical anomaly detection

Code: `packages/sentinelx/anomaly/statistical.py` (`StatisticalAnomalyDetector`, registered as `statistical_anomaly`), `EwmaBaseline` in `packages/sentinelx/common/windows.py`.

Thresholds cannot be right for every network: 300 DNS queries per second is normal for a large resolver and alarming in a small office. The statistical detector learns what is normal for a set of network-wide metrics and reports departures.

It is attached when `ANOMALY__ENABLED=true` (the default) and `DETECTION_MODE` is `balanced` or `aggressive`. If `statistical_anomaly` is listed in `DETECTION__DISABLED_DETECTORS`, it is attached switched off.

### Metrics

Traffic is accumulated in intervals of `sample_interval_seconds` of packet time (default 1 s). At the end of each interval these metrics are computed:

| Metric | Label | Minimum value worth reporting |
|---|---|---|
| `syn_per_second` | TCP connection attempts (bare SYNs) | 10 |
| `dns_per_second` | DNS query rate | 10 |
| `icmp_per_second` | ICMP rate | 10 |
| `unique_sources` | distinct active sources | 20 |
| `packets_per_second` | total packet rate | 50 |
| `bytes_per_second` | total byte rate | 50,000 |

An interval closes when the first packet after its end arrives. Empty intervals in a gap are closed as observations of zero traffic, up to 3,600 per packet; after a longer gap the sampler resynchronises to the current packet. If packet time steps backwards by more than one interval, the current interval restarts at the new packet time, so the packets that follow are not piled into one interval and scored as a rate spike.

### Baseline and score

Each metric has an exponentially weighted moving mean and variance with decay `baseline_alpha` (default 0.05). For a value `v`:

- deviation = `(v - mean) / stddev`; when the standard deviation is effectively zero, `(v - mean) / max(|mean|, 1)` is used instead;
- anomaly score = `min(1.0, deviation / sigma_saturation)` for positive deviations, and 0 for zero or negative ones (less traffic than usual is not treated as an intrusion signal).

A metric is anomalous for an interval when all three hold: its baseline has at least `min_samples` intervals (default 60, so one minute of warm-up at the default interval), its score is at least `anomaly_threshold` (default 0.85), and its value is at least the minimum in the table above. Nothing is reported during warm-up.

### Order of scoring and updating

At the close of each interval:

1. **Every metric is scored against the baseline as it stood before this interval.** The detection, including its evidence about the mean and standard deviation, is built from that same pre-update state, so the evidence describes the baseline the value was actually compared against.
2. If one or more metrics are anomalous, one detection is produced for the highest-scoring metric. On a tie, the metric earlier in the table wins, so the specific metric (for example DNS rate) is reported rather than the aggregate.
3. **Baselines are then updated.** Metrics that were not anomalous update normally. **Anomalous metrics update the mean at one tenth of `baseline_alpha` and do not update the variance at all.**

The last rule resists baseline poisoning. If anomalous intervals were allowed to widen the variance, every later deviation would shrink, and a sustained attack would stop scoring as anomalous and be absorbed as normal. With this rule a sustained attack keeps scoring as anomalous, while a genuine lasting change in traffic is still absorbed slowly through the mean. `test_sustained_attack_does_not_become_normal` in `tests/detection/test_anomaly.py` checks that after 60 seconds of a DNS rate spike the spike rate still scores above the threshold and the standard deviation stays below 10.

### Output

- `source_ip` is the top contributor to the metric in that interval: the source with the most SYNs, DNS queries or ICMP packets for the three per-protocol metrics, and the source with the most packets for the others. Only packets sent by the side that opened their flow, and not solicited ICMP echo replies, count towards a source's share. The rates themselves still count every packet. Without this, a server answering an HTTP flood packet for packet can edge past the flooder and be named as the source.
- Severity is high when the score is at least 0.97 and the top contributor produced at least half of the metric; otherwise medium.
- Confidence is `min(0.85, 0.4 + 0.45 * score * max(share, 0.3))`, capped below the rule-based detectors because deviation is weaker evidence than a matched pattern.
- The title is `Unusual <metric label>`, with the label's first letter lowercased unless it starts an acronym (for example `Unusual total packet rate`, `Unusual DNS query rate`, `Unusual TCP connection attempts`).
- Action is always `alert`; category is `anomaly`.
- Evidence: `metric`, `anomaly_score` (with the deviation in standard deviations), `baseline` (mean, stddev, samples), `top_contributor`.
- The detection is returned on the packet that closed the interval, which may be up to one interval after the traffic it describes.

`StatisticalAnomalyDetector.baseline_report()` returns each metric's label, unit, readiness, mean, standard deviation and sample count.

### Where it runs

The statistical detector is attached through `assembly.py` everywhere a pipeline runs: the live platform, API and dashboard replays, `sentinelx replay`, `sentinelx monitor` and the benchmark. Each replay pipeline has its own detector instance, so a replay starts with an empty baseline and does not disturb the live one. Baselines are in memory and start empty on every start.

## Machine-learning anomaly detection

Code: `packages/sentinelx/anomaly/ml.py` (`MlAnomalyDetector`, registered as `ml_anomaly`).

The ML layer is optional and off by default (`ANOMALY__ML_ENABLED=false`). Its dependencies (NumPy, scikit-learn and joblib) are not installed by default; install the `ml` extra, for example `pip install "sentinelx[ml]"` or `pip install -e ".[ml]"` (the Docker image includes it). Without them, training, saving and loading a model raise `ConfigurationError` naming the missing packages (`require_ml_dependencies()` in `anomaly/ml.py`); `sentinelx anomaly train` checks this before reading any capture. When `ANOMALY__ML_ENABLED=true`, `sentinelx doctor` reports a "machine learning" check: FAIL when the packages are missing or when the model at `ANOMALY__ML_MODEL_PATH` fails the same loading checks the server applies (see [Model file checks](#model-file-checks)), PASS with the model's sample count and training time when it loads. It scores per-source behaviour with a scikit-learn Isolation Forest trained on the sensor's own normal traffic. It finds combinations of behaviour that are rare on that network. Rare is not the same as malicious, attacks that resemble normal traffic are invisible to it, and its quality depends entirely on the training capture being clean. Its detections are leads for review, which is why they are capped at low confidence and always recommend `alert`.

### Feature vector

The model sees 14 features from the source's feature vector, in this order:

`packet_rate`, `unique_dst_ports`, `unique_dst_ips`, `unique_udp_ports`, `syn_ratio`, `syn_ack_ratio`, `refusal_ratio`, `short_sessions`, `icmp_count`, `dns_query_count`, `dns_unique_domains`, `http_request_count`, `packet_size_mean`, `packet_size_stddev`.

The three ratios are used as-is. Every other feature is transformed with `log1p`, because network counts are heavy-tailed and on a raw scale they dominate the forest's splits. Changing this list or the scaling changes `MODEL_FORMAT_VERSION` (currently 2) and invalidates saved models.

### Training

```bash
sentinelx anomaly train normal-monday.pcap normal-tuesday.pcap --output models/isolation_forest.joblib
```

Verified options (`sentinelx anomaly train --help`):

| Argument or option | Meaning |
|---|---|
| `PCAPS...` | One or more captures of normal traffic (required). Frames from all files are merged and sorted by timestamp |
| `--output`, `-o` | Where to write the model. Defaults to `ANOMALY__ML_MODEL_PATH` (`models/isolation_forest.joblib`) |
| `--contamination` | Isolation Forest contamination, 0.001-0.4, default `ANOMALY__ML_CONTAMINATION` (0.02) |

Training replays the captures through the decoder and feature extractor using the current detection settings, and samples each source's feature vector at most once every 5 seconds of packet time, and only when the source has at least 10 packets in its window. This mirrors how the detector scores at runtime. At least 50 vectors are required; with fewer the command exits with status 1 and asks for more normal traffic. The forest uses 200 trees and a fixed random seed of 0.

The saved score scale maps the fitted model's decision boundary (`offset_`) to 0.0 and the lowest score seen in training to 1.0.

Without `--contamination` the command uses `ANOMALY__ML_CONTAMINATION` (default 0.02).

After saving, the command loads the model back with the server's checks. If SentinelX would refuse to load it (for example because its directory is writable by other users), the command prints the reason and exits 1, although the file was written. A directory or file that cannot be written also exits 1 with a message.

### Model file checks

Model files are joblib pickles, and loading a pickle can execute code. `save_model()` writes the file with mode 600. `load_model()` refuses a file, raising `ConfigurationError`, when:

- it does not exist;
- it is group-writable or world-writable;
- it is not owned by the user running SentinelX;
- its directory is writable by the group or by other users, unless the directory has the sticky bit set (another user could replace the file; `chmod 700` the directory);
- its stored format is not `MODEL_FORMAT_VERSION`;
- its stored feature list differs from the current feature list.

The permission, ownership and directory checks are POSIX checks and are skipped on Windows, where ownership is expressed in ACLs that SentinelX does not inspect; there, keep the model in a directory only you can write, such as one under your user profile. The ML dependencies must also be installed. These checks reduce the risk of loading a tampered model; they do not make it safe to load a model from an untrusted source. When a pipeline is assembled, a model that fails any check is logged as `ml_model_unavailable` and the ML detector is left out; detection continues without it.

### Scoring at runtime

- A source is scored only when it has at least 10 packets in its window.
- The same source is rescored after 5 seconds of packet time, or sooner if its packet count has doubled since the last scoring, so a short burst is judged on its full shape.
- A detection is emitted when the normalised score is at least `ANOMALY__ML_MIN_SCORE` (default 0.75).
- Severity is medium when the score is at least 0.95, otherwise low. Confidence is `min(0.6, 0.3 + 0.3 * score)`. Action is `alert`; category `anomaly`.
- Evidence: `anomaly_score`, `model` (version, training time, samples, contamination), up to four `feature:<name>` items for the largest non-zero feature values (a heuristic, not a feature attribution), and `interpretation: lead`.

The ML detector is attached through `assembly.py` wherever the statistical detector is: the live platform, API and dashboard replays, `sentinelx replay`, `sentinelx monitor` and the benchmark, when `ANOMALY__ML_ENABLED=true`, `DETECTION_MODE` is `balanced` or `aggressive`, and the model loads. With `ml_anomaly` in `DETECTION__DISABLED_DETECTORS` it is attached switched off.

## Writing a new detector

Code: `packages/sentinelx/detection/base.py`.

### The interface

Subclass `Detector` and implement one method:

```python
def inspect(self, context: FeatureContext) -> Detection | None: ...
```

It is called once per packet with the fully populated context. Return `None` in the common case, or a `Detection`.

Class attributes:

| Attribute | Purpose |
|---|---|
| `name` | Stable identifier. It appears in metrics, the API, `disabled_detectors` and cooldown keys, so it must not change once released |
| `description` | One-line description for the API and dashboard |
| `category` | Default `ThreatCategory` |
| `default_severity` | Severity used by `build()` when none is passed |
| `references` | Tuple of reference URLs, for example MITRE ATT&CK techniques |

The constructor takes an optional `DetectionSettings` and stores it as `self.settings`. Instances also carry `enabled`, `evaluations` and `hits`; increment the counters yourself, as the built-in detectors do.

Helpers:

- `self.build(context=..., title=..., description=..., evidence=[...], confidence=..., ...)` creates a `Detection` with the detector's name, category, default severity and packet addressing filled in. Optional keyword arguments: `severity`, `recommended_action`, `source_ip`, `destination_ip`, `destination_port`, `observation_window`, `packet_count`, `tags`.
- `Detector.scaled_confidence(observed, threshold, floor=0.55, ceiling=0.98, saturation=3.0)` implements the [confidence curve](#confidence-curve).

What the context offers:

| Attribute | Content |
|---|---|
| `context.packet` | The `PacketEvent`, including `tcp_flags` and decoder `metadata` |
| `context.profile` | The sender's `SourceProfile` |
| `context.profile_of(ip)` | Any tracked profile, for when the party you care about is not the sender (for example a server's RST closing an attacker's session) |
| `context.flow` | The conversation's `FlowState` (`initiator_ip`, `responder_port`, `handshake_complete`, `short_lived`, ...) |
| `context.stats` | Network-wide `GlobalStats` |
| `context.now` | The packet timestamp; use it for all window arithmetic |
| `context.features()` | The flattened feature vector |

### Rules for detectors

1. **Always attach evidence.** A detection without evidence is rejected and counted as an error. Each item should say what was observed and, where relevant, the threshold it crossed.
2. **Never raise on traffic.** Malformed and surprising packets are normal. The engine isolates exceptions, but relying on that hides bugs and costs a log line per packet.
3. **Do not count in the detector.** Add counters to `SourceProfile` in `profiles.py` so they are updated once per packet and shared. Keep per-packet work constant-time; windows in `common/windows.py` exist for this.
4. **Gate early.** Return on the cheapest check first (protocol, flags, metadata presence), before touching windows.
5. **Use packet time.** Never call `time.time()` for detection logic, or replay results will not match live results.
6. **Do not implement cooldown or allowlisting.** The engine does both.

### Example

A detector that reports completed Telnet sessions. It was run against a synthetic handshake before being included here and produced the `explain()` output shown in [The Detection model](#the-detection-model).

```python
from sentinelx.common.enums import ActionType, Protocol, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext


class CleartextTelnetDetector(Detector):
    """A completed TCP session to Telnet (port 23)."""

    name = "cleartext_telnet"
    description = "A TCP session to Telnet completed its handshake."
    category = ThreatCategory.POLICY_VIOLATION
    default_severity = Severity.LOW

    def inspect(self, context: FeatureContext) -> Detection | None:
        packet = context.packet
        if packet.protocol is not Protocol.TCP:
            return None
        flow = context.flow
        if flow.responder_port != 23 or not flow.handshake_complete:
            return None
        self.evaluations += 1
        self.hits += 1
        return self.build(
            context=context,
            title="Cleartext Telnet session",
            description=f"{flow.initiator_ip} completed a Telnet session to {flow.responder_ip}.",
            evidence=[
                Evidence(
                    key="service_port",
                    value=23,
                    description="the session's service port is 23 (Telnet), which sends credentials in cleartext",
                    weight=1.0,
                ),
                Evidence(
                    key="handshake_complete",
                    value=True,
                    description="the three-way handshake completed, so this is a real session, not a probe",
                    weight=0.6,
                ),
            ],
            confidence=0.9,
            recommended_action=ActionType.ALERT,
            source_ip=flow.initiator_ip,
            destination_ip=flow.responder_ip,
            destination_port=23,
        )
```

Every later packet of the same session also matches; the engine cooldown turns that into one detection per source per cooldown period.

### Registering it

- **As a library:** `DetectionEngine.add_detector(CleartextTelnetDetector(settings))`, or `Pipeline(settings, extra_detectors=[...])`. A detector added with the same name as an existing one replaces it.
- **As a built-in:** add the class to `BUILTIN_DETECTORS` in `packages/sentinelx/detection/engine.py`, add any thresholds to `DetectionSettings` in `packages/sentinelx/config/settings.py` (they become `DETECTION__...` environment variables automatically), and, if the detector matches facts rather than rates, consider adding its name to `_SIGNATURE_DETECTORS` so it runs in `signature_only` mode. Built-in detectors reach every pipeline automatically.
- **As an always-attached extra** (like the anomaly detectors): attach it in `packages/sentinelx/assembly.py`, so live capture, replays, the monitor and the benchmark all get it.

If the logic can be expressed as a condition over existing fields, a YAML rule is simpler and needs no code; see [rule-engine.md](rule-engine.md).

### Testing it

`tests/detection/test_detectors.py` holds positive, negative and edge-case tests for every built-in detector. The `run_detection` fixture in `tests/conftest.py` feeds frames through decode, features and detection. Synthetic traffic comes from `sentinelx.testing.scenarios`: named scenarios such as `tcp_port_scan` or `normal_traffic` (via `get_scenario`), and packet builders such as `build_tcp`, `build_udp`, `build_icmp`, `build_dns_query` and `build_http_request`. A new detector should have at least one positive test, one negative test built from traffic that shares a surface feature with the attack but not its shape, and, where known, a test pinning an evasion. See [contributing.md](contributing.md).

## Settings reference

Settings live in `packages/sentinelx/config/settings.py`. Environment variables use a double underscore between section and field, are case-insensitive, and may be placed in `.env`. List values are given as JSON, for example `DETECTION__BRUTE_FORCE_PORTS='[22, 2222]'`. Every detection setting except `max_tracked_sources`, and some anomaly settings, can also be changed while the server runs, from the dashboard or `PATCH /api/v1/config/<section>` (see [api.md](api.md)). What a runtime change does depends on the setting: the cooldown, allowlist, denylist and thresholds read by detectors apply immediately; a window change rebuilds the feature extractor and discards traffic state; the mode and the detector lists apply to built-in and anomaly detectors at the next start. `sentinelx config set detection <key> <json-value>` persists a change that takes effect on the next server start.

### DetectionSettings

| Environment variable | Default | Constraint | Used by |
|---|---|---|---|
| `DETECTION__MODE` (alias `DETECTION_MODE`) | `balanced` | `disabled`, `signature_only`, `balanced`, `aggressive` | Engine |
| `DETECTION__ENABLED_DETECTORS` | `[]` | detector names | Engine |
| `DETECTION__DISABLED_DETECTORS` | `[]` | detector names | Engine |
| `DETECTION__PORT_SCAN_WINDOW_SECONDS` | `15.0` | > 0 | `tcp_port_scan`, `horizontal_scan`, `udp_scan` |
| `DETECTION__PORT_SCAN_UNIQUE_PORTS` | `20` | >= 2 | `tcp_port_scan` |
| `DETECTION__PORT_SCAN_MIN_SYN_RATIO` | `0.7` | 0.0-1.0 | `tcp_port_scan`, `horizontal_scan` |
| `DETECTION__HORIZONTAL_SCAN_UNIQUE_HOSTS` | `25` | >= 2 | `horizontal_scan` |
| `DETECTION__UDP_SCAN_UNIQUE_PORTS` | `25` | >= 2 | `udp_scan` |
| `DETECTION__BRUTE_FORCE_WINDOW_SECONDS` | `60.0` | > 0 | `ssh_brute_force` (through W) |
| `DETECTION__BRUTE_FORCE_ATTEMPTS` | `15` | >= 2 | `ssh_brute_force` |
| `DETECTION__BRUTE_FORCE_PORTS` | `[22, 23, 21, 3389, 445, 5900, 1433, 3306, 5432]` | 1-65535 | `ssh_brute_force` |
| `DETECTION__CONNECTION_RATE_WINDOW_SECONDS` | `10.0` | > 0 | `connection_rate` |
| `DETECTION__CONNECTION_RATE_THRESHOLD` | `200` | >= 1 | `connection_rate` |
| `DETECTION__SYN_FLOOD_THRESHOLD` | `500` | >= 1 | `syn_flood` |
| `DETECTION__ICMP_FLOOD_WINDOW_SECONDS` | `10.0` | > 0 | `icmp_flood` |
| `DETECTION__ICMP_FLOOD_THRESHOLD` | `200` | >= 1 | `icmp_flood` |
| `DETECTION__HTTP_FLOOD_WINDOW_SECONDS` | `10.0` | > 0 | `http_flood` |
| `DETECTION__HTTP_FLOOD_THRESHOLD` | `300` | >= 1 | `http_flood` |
| `DETECTION__DNS_WINDOW_SECONDS` | `30.0` | > 0 | `dns_anomaly` |
| `DETECTION__DNS_QUERY_THRESHOLD` | `300` | >= 1 | `dns_anomaly` |
| `DETECTION__DNS_UNIQUE_DOMAIN_THRESHOLD` | `100` | >= 1 | `dns_anomaly` |
| `DETECTION__DNS_LONG_LABEL_LENGTH` | `52` | 10-63 | `dns_anomaly`, profile classification |
| `DETECTION__DNS_HIGH_ENTROPY_THRESHOLD` | `3.8` | >= 0 | `dns_anomaly`, profile classification |
| `DETECTION__MAX_TRACKED_SOURCES` | `50000` | >= 100; not editable at runtime | Feature extractor |
| `DETECTION__DETECTION_COOLDOWN_SECONDS` | `60.0` | >= 0; runtime changes apply immediately | Engine |
| `DETECTION__DENYLIST_NETWORKS` | `[]` | valid networks | `denylist` |
| `DETECTION__ALLOWLIST_NETWORKS` | `[]` | valid networks | Engine |

All six window settings together determine W, which also caps the `within` window of custom rules ([rule-engine.md](rule-engine.md#durations-and-the-within-window)).

### AnomalySettings

| Environment variable | Default | Constraint | Meaning |
|---|---|---|---|
| `ANOMALY__ENABLED` | `true` | | Attach the statistical detector (in `balanced` and `aggressive` modes) |
| `ANOMALY__BASELINE_ALPHA` | `0.05` | 0.0-1.0 | EWMA decay; lower adapts more slowly |
| `ANOMALY__MIN_SAMPLES` | `60` | >= 5 | Intervals before deviations are reported |
| `ANOMALY__SAMPLE_INTERVAL_SECONDS` | `1.0` | > 0 | Interval length in packet time |
| `ANOMALY__ANOMALY_THRESHOLD` | `0.85` | 0.0-1.0 | Score at or above which a metric is anomalous |
| `ANOMALY__SIGMA_SATURATION` | `6.0` | > 0 | Deviation, in standard deviations, that maps to a score of 1.0 |
| `ANOMALY__ML_ENABLED` | `false` | needs the `ml` extra | Load the Isolation Forest model and attach `ml_anomaly` (in `balanced` and `aggressive` modes) |
| `ANOMALY__ML_MODEL_PATH` | `models/isolation_forest.joblib` | | Model file to load, and default training output |
| `ANOMALY__ML_CONTAMINATION` | `0.02` | > 0, < 0.5 | Default contamination for `sentinelx anomaly train` when `--contamination` is not given |
| `ANOMALY__ML_MIN_SCORE` | `0.75` | 0.0-1.0 | Normalised score at or above which `ml_anomaly` reports |

### Tuning

Defaults are tuned against the synthetic scenarios in `packages/sentinelx/testing/scenarios.py` and the benchmark in [benchmarking.md](benchmarking.md). They are starting points. To tune for a site:

1. Capture a period of known-normal traffic and replay it with `sentinelx replay <file>`. Anything reported is a false positive to tune away, or an allowlist candidate. The replay runs the same detector set as the live sensor.
2. Replay attack traffic, or scenario captures written with `sentinelx fixtures generate`, and confirm it is still detected.
3. Lowering thresholds or lengthening windows catches slower attacks at the cost of more false positives and more state per source. Lengthening any window also lengthens W for every profile.

See [pcap-lab.md](pcap-lab.md) for the replay workflow.

## Limits

These are properties of the current design, not configuration mistakes.

- **Threshold detectors miss what stays under their thresholds.** Slow port scans and low-rate brute force are confirmed misses with default settings ([benchmarking.md](benchmarking.md), `TestDocumentedEvasions`, and the committed captures in `tests/pcaps/evasion/`, which `tests/capture/test_pcap_suite.py` asserts are not detected). Any rate-based detector can be evaded by an attacker who knows its threshold and window.
- **Profiles are per source address.** Distributed or spoofed activity, each source below threshold, is not correlated by the built-in detectors. The statistical detector sees aggregates but attributes them to a single top contributor.
- **No payload-level signatures.** SentinelX does not match exploit payloads. Brute force is inferred from session timing, not from failed logins.
- **Encrypted traffic exposes metadata only.** HTTP floods over TLS, DNS over HTTPS or TLS, and anything inside a VPN are invisible to the application-layer checks. TLS decoding is limited to handshake metadata such as SNI and version.
- **Protocol decoders are port-based.** DNS is decoded on ports 53, 5353 and 5355, HTTP on 80, 8080, 8000, 8008, 8888 and 3000, and TLS handshakes on 443, 8443, 993, 995, 465, 587, 636, 989, 990 and 5061. Services on other ports get transport-layer detection only.
- **Some features cover W rather than the named window.** The distinct-name count in `dns_anomaly`, `syn_flood`'s SYN count, the SYN-ACK and refusal ratios, and short-session counts use the profile window.
- **Bounded state can be exhausted.** Beyond `max_tracked_sources` active sources, profiles are evicted and their history lost. Evictions are counted but not alerted on.
- **Heuristics produce false positives.** Short-lived sessions to monitored ports can come from health checks and monitoring systems; high-entropy DNS names come from some CDNs and security products. Use the allowlist, tune thresholds, or disable detectors that do not fit the network.
- **The statistical detector starts cold.** Baselines are in memory; after every restart there is a warm-up of `min_samples` intervals with no statistical detections, and a baseline learned during an attack will treat that attack as normal.
- **The ML model is only as good as its training data.** A capture that contains an attack teaches the model that the attack is normal. The model is not retrained online.
- **`aggressive` mode has no distinct behaviour** in the current release; it selects the same detectors as `balanced`.
- **Replayed detections are filed at capture time.** A replay of an older capture produces detections, incidents and risk history dated when the traffic was captured. Time-filtered views such as the dashboard's default "last 24 hours" do not show them (`scripts/seed_demo.py` shifts scenario timestamps to the present for that reason). Retention does not use those timestamps for replay results: stored replay detections, incidents and response actions expire together with their replay record, `STORAGE__RETENTION_DAYS` after the replay ran.
