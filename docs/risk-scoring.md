# Risk scoring, correlation and threat intelligence

This document describes how SentinelX turns a detection into a 0-100 risk score, how related detections are grouped into incidents, and how threat intelligence changes both. It is written against:

| Component | File |
| --- | --- |
| Risk engine | `packages/sentinelx/scoring/engine.py` |
| Risk bands | `packages/sentinelx/common/enums.py` (`RiskBand.from_score`) |
| Settings | `packages/sentinelx/config/settings.py` (`ScoringSettings`, `CorrelationSettings`) |
| Correlation engine | `packages/sentinelx/correlation/engine.py` |
| Threat intelligence | `packages/sentinelx/threat_intel/providers.py` |
| Wiring | `packages/sentinelx/pipeline.py`, `packages/sentinelx/services/platform.py` |

For where scoring sits in the processing chain, see [architecture.md](architecture.md). For how detections are produced, see [detection-engine.md](detection-engine.md) and [rule-engine.md](rule-engine.md). For what happens after scoring, see [response-engine.md](response-engine.md).

## Where scoring happens

The pipeline runs these steps for every detection that passes the detection engine's allowlist and cooldown checks (`Pipeline._handle_detection`):

1. Threat intelligence is looked up for the detection's **source address**.
2. The correlation engine reports how many *other* detectors have already fired for the same group (source address by default).
3. The risk engine scores the detection with that context and records it in the source's history.
4. The detection and its risk assessment are published.
5. The correlation engine folds the detection into an incident, or holds it as pending.
6. The response engine handles the detection, and also the incident if it was just created or its severity changed.

Scoring runs only after a detector has fired, never per packet.

## The risk model

The score is an additive, weighted sum of named factors, clamped to 0-100. There is no base score and no learned component. Every point in the score belongs to one factor, and each factor that contributes is recorded along with a sentence explaining it.

### Factors

Weights and parameters come from `ScoringSettings`. Defaults are shown in the second column.

| Factor (key in `contributions`) | Default maximum | Formula | Applied when |
| --- | --- | --- | --- |
| `severity` | 45 | `severity_weight * (severity_rank / 4)` | Always. Ranks: info 0, low 1, medium 2, high 3, critical 4. |
| `confidence` | 20 | `confidence_weight * confidence` (confidence is 0-1) | Always. |
| `frequency` | 10 | `frequency_weight * min(n_same / frequency_saturation, 1)` | `n_same` is the number of earlier detections from the **same detector** for this source still inside the history window, and it is at least 1. |
| `history` | 10 | `history_weight * min(n_other / history_saturation, 1)` | `n_other` is the number of **distinct other detectors** that fired for this source inside the history window, and it is at least 1. |
| `correlation` | 15 | `correlation_weight * min(n_correlated / 3, 1)` | `n_correlated` is the number of distinct other detectors in this source's open incident or pending group, and it is at least 1. The divisor 3 is fixed in code. |
| `threat_intel` | 15 | `intel_weight * intel_score` (intel score is 0-1) | The merged intel score is above 0. |
| `sensitive_target` | 10 | `sensitive_target_weight` (flat) | The destination port is in `SENSITIVE_PORTS`, or the destination address is in `RiskContext.sensitive_destinations`. |
| `previous_responses` | 10 | `min(5 * responses, 10)` | Preventive actions have already been applied against this source. Not configurable. |
| `allowlist` | -40 | `-allowlist_penalty` | Threat intelligence marked the source as trusted (see [Threat intelligence](#threat-intelligence)). |

Details that affect the numbers:

- **Sensitive ports** (`packages/sentinelx/common/netutils.py`): 22, 23, 445, 1433, 1521, 2049, 3306, 3389, 5432, 6379, 9200, 11211, 27017.
- **Sensitive destinations**: `RiskContext.sensitive_destinations` exists in the engine, but the pipeline does not fill it in and no setting controls it. In the current release, only the port list triggers this factor in a running platform.
- **History** is kept per source address in memory. Entries older than `history_window_seconds` (default 3600) are dropped before each assessment. Each source keeps at most 500 entries, and the engine tracks at most 50,000 sources. When that limit is reached, the oldest-inserted tenth of the sources is discarded.
- **A detection never counts toward its own history.** It is recorded after it has been scored.
- **External inputs are sanitised before scoring.** The intel score is clamped to 0-1 (a non-finite value becomes 1 if positive, otherwise 0), and a negative correlated-detector count is treated as 0, so an out-of-range value from an intel provider or caller cannot exceed a factor's weight, subtract points, or put `inf` or `nan` into the stored contributions. A detection with a NaN confidence cannot be constructed (confidence must be within 0.0-1.0), and NaN scoring weights fail settings validation.
- **Previous responses** are counted only when the response engine actually applies a block, temporary block, quarantine or rate limit. Simulated (dry-run), skipped and refused decisions do not count, and this counter never expires.
- **Repeats are already rate-limited upstream.** The detection engine suppresses a repeat of the same detector and source for `detection_cooldown_seconds` (default 60) unless the repeat raises the severity or increases confidence by at least 0.2. The `frequency` factor therefore counts reported escalations and re-reports, not packets.

### Clamping and rounding

```
raw   = sum(contributions)
score = round(max(0, min(100, raw)), 1)
```

If `raw` is above 100, the rationale gets an extra line, `score capped at 100 (uncapped total N)`. With default weights, the positive factors add up to at most 135, so a score of 100 can hide a larger raw total. Contributions are stored rounded to two decimal places. Rationale lines show one decimal place, so a stored contribution of `33.75` appears as `+33.8` in the text.

### Risk bands

`RiskBand.from_score` compares the score with `<=` at each upper bound:

| Score | Band |
| --- | --- |
| `score <= 20` | `informational` |
| `20 < score <= 40` | `low` |
| `40 < score <= 60` | `medium` |
| `60 < score <= 80` | `high` |
| `score > 80` | `critical` |

Scores have one decimal place, so a score of 40.5 is `medium`. The worked example below includes one.

### Stored rationale

Each assessment is a `RiskAssessment` (`packages/sentinelx/common/models.py`) with these fields:

- `score`: 0-100, validated on construction.
- `band`: the `RiskBand`.
- `contributions`: factor key mapped to points.
- `rationale`: one human-readable line per factor, in the order the factors are evaluated.
- `assessed_at`: timestamp.

The whole assessment is serialised by `risk_to_dict` (`packages/sentinelx/events/serialize.py`) and stored as JSON in the `risk` column of the `detections` table, with `risk_score` and `risk_band` also kept as separate indexed columns. Incidents store their own assessment in the same way (`incidents.risk`, `incidents.risk_score`). You can read the rationale with `sentinelx detections --id <detection_id>`, from `GET /api/v1/detections/{detection_id}` (see [api.md](api.md)), and on the dashboard.

## Worked example

This example runs the bundled `tcp_port_scan` scenario (`packages/sentinelx/testing/scenarios.py`) through the real `Pipeline` with default settings, no threat-intelligence providers and the in-memory firewall. Run it from the repository root:

```python
import asyncio

from sentinelx.config.settings import Settings
from sentinelx.pipeline import Pipeline
from sentinelx.testing.scenarios import get_scenario


async def main() -> None:
    pipeline = Pipeline(Settings())
    await pipeline.start()
    try:
        for frame in get_scenario("tcp_port_scan").frames:
            for record in await pipeline.process_frame(frame):
                d, risk = record.detection, record.risk
                print(f"{d.detector} severity={d.severity.value} confidence={d.confidence}")
                print(f"  score={risk.score} band={risk.band.value}")
                print(f"  contributions={risk.contributions}")
                for line in risk.rationale:
                    print(f"    {line}")
                if record.incident:
                    inc = record.incident
                    print(f"  incident rule={inc.correlation_rule} severity={inc.severity.value} "
                          f"risk={inc.risk.score}")
                    for line in inc.risk.rationale:
                        print(f"    {line}")
                for decision in record.decisions:
                    print(f"  decision {decision.action.value}: {decision.outcome}")
    finally:
        await pipeline.stop()


asyncio.run(main())
```

Run it with `.venv/bin/python example.py`. With no `.env` file and no SentinelX environment variables set, it prints the following (log lines omitted):

```
tcp_port_scan severity=high confidence=0.65
  score=46.8 band=medium
  contributions={'severity': 33.75, 'confidence': 13.0}
    +33.8 severity high (3/4)
    +13.0 detector confidence 65%
  decision alert: executed
  decision temporary_block: skipped
tcp_port_scan severity=high confidence=0.8535
  score=51.8 band=medium
  contributions={'severity': 33.75, 'confidence': 17.07, 'frequency': 1.0}
    +33.8 severity high (3/4)
    +17.1 detector confidence 85%
    +1.0 repetition: tcp_port_scan already fired 1 time(s) for this source
  decision alert: executed
  decision temporary_block: skipped
tcp_port_scan severity=critical confidence=0.98
  score=66.6 band=high
  contributions={'severity': 45.0, 'confidence': 19.6, 'frequency': 2.0}
    +45.0 severity critical (4/4)
    +19.6 detector confidence 98%
    +2.0 repetition: tcp_port_scan already fired 2 time(s) for this source
  decision alert: executed
  decision temporary_block: skipped
connection_rate severity=medium confidence=0.55
  score=40.5 band=medium
  contributions={'severity': 22.5, 'confidence': 11.0, 'history': 2.0, 'correlation': 5.0}
    +22.5 severity medium (2/4)
    +11.0 detector confidence 55%
    +2.0 source history: previously triggered tcp_port_scan
    +5.0 correlated with 1 other detector(s) in an open incident
  incident rule=recon_and_disruption severity=critical risk=83.6
    66.6 highest member risk (TCP port scan)
    +4.0 2 distinct detectors agree
    +3.0 spans 2 categories: denial_of_service, reconnaissance
    +10.0 matches pattern 'recon_and_disruption'
  decision alert: executed
  decision rate_limit: skipped
```

The dashboard sign-in page shows the third detection as its example (66.6, with Severity 45, Confidence 19.6 and Repetition 2). Here is how that score is built:

| Factor | Formula with defaults | Points |
| --- | --- | --- |
| severity | 45 x 4/4 | 45.0 |
| confidence | 20 x 0.98 | 19.6 |
| frequency | 10 x min(2/10, 1): two earlier `tcp_port_scan` detections for this source | 2.0 |
| Total | | 66.6, band `high` |

The same run also shows:

- **Escalation re-reports.** The first two detections were re-reported inside the cooldown because severity or confidence rose. Each one adds to the `frequency` count for the next.
- **Correlation.** The fourth detection comes from a different detector, `connection_rate`. It gets `history` (one other detector, 10 x 1/5 = 2.0) and `correlation` (one other detector in the pending group, 15 x 1/3 = 5.0). Two distinct detectors meet `min_detections`, so an incident opens. Its risk is described in [Incident risk](#incident-risk).
- **Response decisions.** Every preventive decision is `skipped`, because each detection score is below `auto_block_threshold` (85) and the incident risk (83.6) is below it too. See [response-engine.md](response-engine.md).

### The same scan with threat intelligence

Running the same scenario with a `LocalDenylistProvider` that contains `203.0.113.0/24` (the scenario's attacker range) adds `+15.0 threat intelligence reputation 100% (local_denylist)` to every detection. The third detection scores 81.6 (`critical`) instead of 66.6, and the incident risk reaches 98.6. Running it with a `LocalAllowlistProvider` that contains `203.0.113.45/32` instead subtracts `40.0 source is allowlisted`. The third detection then scores 26.6 (`low`), the `connection_rate` detection scores 0.5, and the incident risk is 43.6.

## Scoring settings

Scoring settings are read from the environment with the `SCORING__` prefix and a double underscore between section and field, or from `.env`. They can also be changed at runtime through `PATCH /api/v1/config/scoring` or `sentinelx config set scoring <key> <value>`, because every `ScoringSettings` field can be edited at runtime (`packages/sentinelx/services/config.py`). A change made through the API takes effect immediately. A change made with `sentinelx config set` is persisted and applies when the server next starts.

| Setting | Environment variable | Default | Range | Meaning |
| --- | --- | --- | --- | --- |
| `severity_weight` | `SCORING__SEVERITY_WEIGHT` | 45.0 | 0-100 | Points for a critical detection. |
| `confidence_weight` | `SCORING__CONFIDENCE_WEIGHT` | 20.0 | 0-100 | Points at confidence 1.0. |
| `frequency_weight` | `SCORING__FREQUENCY_WEIGHT` | 10.0 | 0-100 | Maximum for repeats of the same detector. |
| `history_weight` | `SCORING__HISTORY_WEIGHT` | 10.0 | 0-100 | Maximum for other detectors in the source's history. |
| `intel_weight` | `SCORING__INTEL_WEIGHT` | 15.0 | 0-100 | Points at intel score 1.0. |
| `correlation_weight` | `SCORING__CORRELATION_WEIGHT` | 15.0 | 0-100 | Maximum for correlated detectors. |
| `sensitive_target_weight` | `SCORING__SENSITIVE_TARGET_WEIGHT` | 10.0 | 0-100 | Flat points for a sensitive destination. |
| `history_window_seconds` | `SCORING__HISTORY_WINDOW_SECONDS` | 3600.0 | > 0 | How long per-source history is kept. |
| `frequency_saturation` | `SCORING__FREQUENCY_SATURATION` | 10 | >= 1 | Repeat count at which `frequency` reaches its full weight. |
| `history_saturation` | `SCORING__HISTORY_SATURATION` | 5 | >= 1 | Distinct-detector count at which `history` reaches its full weight. |
| `allowlist_penalty` | `SCORING__ALLOWLIST_PENALTY` | 40.0 | 0-100 | Points subtracted for an intel-trusted source. |
| `auto_block_threshold` | `SCORING__AUTO_BLOCK_THRESHOLD` | 85.0 | 0-100 | Detection or incident risk at or above which the response engine proposes a preventive action. Actions are only applied under the conditions in [response-engine.md](response-engine.md). |
| `incident_threshold` | `SCORING__INCIDENT_THRESHOLD` | 60.0 | 0-100 | Declared and editable, but not read by the correlation or response engines in this release. Incident creation is controlled by `CorrelationSettings`. |

## Correlation

The correlation engine groups detections into incidents so that an analyst reads one story, not several unrelated alerts.

### Grouping

The group key is built from:

- the source address, when `group_by_source` is true (default); and
- the destination address, when `group_by_destination` is true (default false). Detections without a destination use `*`.

If both are false, the source address is used.

### Settings

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | `CORRELATION__ENABLED` | true | When false, no incidents are created. |
| `window_seconds` | `CORRELATION__WINDOW_SECONDS` | 600.0 | How long an incident accepts new detections after its last one. Also the look-back for pending detections. |
| `min_detections` | `CORRELATION__MIN_DETECTIONS` | 2 | Number of **distinct detectors** (not detections) needed in the pending group to open an incident. |
| `standalone_risk_threshold` | `CORRELATION__STANDALONE_RISK_THRESHOLD` | 85.0 | A single `critical`-severity detection with risk at or above this opens an incident on its own. |
| `max_open_incidents` | `CORRELATION__MAX_OPEN_INCIDENTS` | 1000 | When reached, the incident with the oldest `last_seen` stops correlating to make room. |
| `group_by_source` | `CORRELATION__GROUP_BY_SOURCE` | true | See [Grouping](#grouping). |
| `group_by_destination` | `CORRELATION__GROUP_BY_DESTINATION` | false | See [Grouping](#grouping). |

All `CorrelationSettings` fields can be edited at runtime.

### How incidents are created

For each detection:

1. Incidents whose `last_seen` is more than `window_seconds` before this detection's timestamp are closed for correlation. Their status is not changed, because "no longer receiving detections" is not the same as "resolved".
2. If the group has an open incident, the detection extends it (see [How incidents are updated](#how-incidents-are-updated)). A detection whose id the incident already holds (for example an event delivered twice) is not counted again; the check uses the incident's `detection_ids`, which keeps the most recent 1,000 ids.
3. Otherwise, the detection is added to the group's pending list, and pending entries older than `window_seconds` are dropped. A detection whose id is already pending is ignored.
4. An incident is created from the whole pending list if either of these holds:
   - the pending list contains at least `min_detections` distinct detectors; or
   - this detection has severity `critical` **and** risk at or above `standalone_risk_threshold`.
5. If neither holds, `correlate` returns nothing and the detection stays pending.

When an incident is created:

- `title` and `correlation_rule` come from the first matching kill-chain pattern.
- `severity` is the highest member severity, raised to the pattern's severity floor if it is lower.
- `risk` is calculated as described in [Incident risk](#incident-risk).
- The incident also records affected sources, destinations and services (destination ports), categories, first and last seen, and a timeline with one entry per member (timestamp, detection id, detector, title, severity, risk, source, destination, destination port).

### How incidents are updated

When a detection joins an open incident:

- It is added to the detection ids, affected sets, categories and timeline, and `last_seen` moves forward.
- The pattern is matched again against the combined categories. Title, `correlation_rule` and summary can change.
- Severity is recalculated and never decreases.
- Risk is recalculated from all members.
- The result reports `severity_changed` and the previous severity when severity increased.

The pipeline publishes `incident.opened` or `incident.updated`, plus a severity-change event when severity rose. The response engine's incident handler runs **only** when the incident was just created, its severity changed, or this detection pushed the incident's risk from below `auto_block_threshold` to at or above it (`Pipeline._incident_needs_response`). Other updates do not trigger an incident-level response.

### Incidents closed by an analyst

Setting an incident's status to `resolved` or `false_positive` with `PATCH /api/v1/incidents/{incident_id}` also closes it in the live correlation engine (`CorrelationEngine.close_incident`). Later detections from the same group then open a new incident instead of extending the closed one, and the closed incident's risk no longer drives automatic responses. Other status changes (`investigating`, `contained`) leave the incident open for correlation.

### Kill-chain patterns

Patterns are checked in the order below, and the first match wins. A pattern matches when all of its required categories are present among the incident's member detections and the incident has at least `min_detections` members. Every pattern currently requires 2 members.

| Order | `correlation_rule` | Title | Required categories | Severity floor | Risk bonus |
| --- | --- | --- | --- | --- | --- |
| 1 | `recon_to_credential_attack` | Potential host compromise attempt | reconnaissance and brute_force | critical | 15 |
| 2 | `known_bad_actor_activity` | Activity from a known-malicious source | malicious_reputation | high | 10 |
| 3 | `recon_and_disruption` | Reconnaissance with service disruption | reconnaissance and denial_of_service | high | 10 |
| 4 | `possible_exfiltration` | Possible data exfiltration | exfiltration | high | 10 |
| 5 | `sustained_brute_force` | Sustained credential attack | brute_force | high | 5 |
| 6 | `sustained_reconnaissance` | Sustained reconnaissance | reconnaissance | medium | 5 |
| 7 | `denial_of_service` | Denial-of-service activity | denial_of_service | high | 5 |
| none matched | `multiple_detections` | Multiple suspicious detections | none | medium | 0 |

The `malicious_reputation` category is produced by the `denylist` detector, which reads `DETECTION__DENYLIST_NETWORKS`. It is not produced by the threat-intelligence denylist file. An incident opened by the standalone rule includes every pending detection for the group. If that is a single detection, no pattern can match, and the incident is named `multiple_detections` until more members arrive.

### Incident risk

Incident risk is derived from the members' stored assessments. It is not a fresh score.

| Contribution | Formula |
| --- | --- |
| `highest_detection` | Highest member risk score. The maximum is used, not the mean, so minor detections cannot dilute a severe one. |
| `corroboration` | `min(4 * (distinct_detectors - 1), 12)` |
| `category_breadth` | `min(3 * (distinct_categories - 1), 9)` |
| `pattern` | The matched pattern's risk bonus |

The total is clamped to 0-100 and rounded to one decimal place, and it is given a band in the same way as a detection score. Running the bundled `mixed_intrusion` scenario (a port scan, then SSH brute force, then an ICMP flood from one source) with default settings creates a `recon_to_credential_attack` incident at risk 88.6 when the SSH detection arrives:

```
66.6 highest member risk (TCP port scan)
+4.0 2 distinct detectors agree
+3.0 spans 2 categories: brute_force, reconnaissance
+15.0 matches pattern 'recon_to_credential_attack'
```

When the ICMP flood joins, the risk rises to 95.6 (`+8.0 3 distinct detectors agree`, `+6.0 spans 3 categories`). The incident's 88.6 at creation is above `auto_block_threshold`, so the response engine proposes a temporary block for its sources. In the default `detect_only` mode, that proposal is recorded as `skipped`.

## Threat intelligence

### Providers

Providers implement `ThreatIntelProvider.lookup(address)` and return an `IntelVerdict`, or `None` when they know nothing about the address. Each verdict has a score from 0.0 (unknown or good) to 1.0 (known malicious) and a `trusted` flag.

| Provider | `name` | Verdict on match |
| --- | --- | --- |
| `LocalDenylistProvider` | `local_denylist` | Score 1.0, category `denylist`. The description is the entry's label. |
| `LocalAllowlistProvider` | `local_allowlist` | Score 0.0, `trusted=True`, category `allowlist`. |
| `HttpReputationProvider` | `http_reputation` | The API's `score` (0-100) divided by 100 and clamped to 0-1. No verdict if the score is 0 or missing. |

### Local list files

The platform (`Platform.start`) always loads these two providers from the rules directory (`rules_directory`, default `rules`):

- `rules/intel/allowlist.txt` goes to `LocalAllowlistProvider`.
- `rules/intel/denylist.txt` goes to `LocalDenylistProvider`.

File format (`load_network_file`):

- One IPv4 or IPv6 address or CIDR per line.
- Blank lines and lines starting with `#` are ignored.
- Text after `#` on an entry line becomes the entry's label, which is quoted in verdict descriptions.
- Invalid lines are not skipped. Loading raises `ThreatIntelError` listing every bad line with its line number, and platform startup fails.
- A missing file is treated as an empty list.

The files are read when the platform starts. Edit them and restart to apply changes.

### Optional HTTPS reputation provider

`HttpReputationProvider(url, api_key="", timeout=3.0, cache_seconds=3600.0)` is a generic JSON adapter:

- The URL must start with `https://`. Any other URL raises `ValueError` at construction.
- It sends `GET {url}/{address}` with `Accept: application/json`, plus `Authorization: Bearer <api_key>` when a key is given.
- It expects `{"score": 0-100, "categories": [...]}`. Adapt `_parse` for a specific vendor.
- **It never looks up private or loopback addresses.** For those it returns no verdict and sends no request.
- Results, including "no verdict", are cached per address for `cache_seconds`. The cache is cleared once it holds more than 50,000 entries.
- HTTP errors and invalid JSON raise `ThreatIntelError`.

This provider is **not enabled by any setting** in this release. `Platform` builds only the two local providers. To use the HTTPS provider, construct a `ThreatIntelService` that includes it and pass it to `Pipeline(..., intel=...)`.

### Merging and failure handling

`ThreatIntelService.evaluate(address)` queries every provider concurrently:

- Each lookup is limited to the service `timeout` (default 2.0 seconds).
- A provider that raises `ThreatIntelError`, times out or raises `ValueError` is skipped. The failure is counted per provider and logged as `threat_intel_lookup_failed`. The detection is still scored.
- If **any** verdict is trusted, the result is score 0.0 with `trusted=True`, and the allowlist wins outright.
- Otherwise, the result is the **highest** score among verdicts above 0, together with the names of those providers.

### Offline behaviour

The local providers need no network access, and the default platform uses only them, so SentinelX scores detections fully offline. With no providers at all (for example `Pipeline(Settings())` in library use), `evaluate` returns score 0 and no intel factor is applied.

### How intelligence affects the score

The pipeline looks up the detection's **source address** only.

| Intel result | Effect on the detection score |
| --- | --- |
| Denylisted (score 1.0) | `+intel_weight`, 15 points by default, with the provider names in the rationale. |
| External score s | `+intel_weight * s` |
| Trusted (allowlisted) | No intel points, plus `-allowlist_penalty`, 40 points by default. |
| No verdict or all providers failed | No change. |

Intelligence does not create detections. A denylisted address that triggers no detector produces nothing. To alert on any traffic from an address, add it to `DETECTION__DENYLIST_NETWORKS`, which feeds the `denylist` detector (see [detection-engine.md](detection-engine.md)).

### Three different allowlists

SentinelX has three allowlists, and they do different things:

| List | Where configured | Effect |
| --- | --- | --- |
| Detection allowlist | `DETECTION__ALLOWLIST_NETWORKS` | Sources are never reported on. Applied before any detector runs. |
| Intel allowlist | `rules/intel/allowlist.txt` | Detections are still produced, but score `allowlist_penalty` points lower. |
| Response allowlist | `RESPONSE__ALLOWLIST_NETWORKS` | The safety guard refuses every preventive action against these networks. See [response-engine.md](response-engine.md). |

Only the response allowlist guarantees that an address is never blocked. The intel allowlist lowers detection scores, but incident risk is computed from member scores plus corroboration, breadth and pattern bonuses, so an incident involving an intel-allowlisted source can still reach `auto_block_threshold`. Put addresses that must never be blocked in `RESPONSE__ALLOWLIST_NETWORKS` or `RESPONSE__MANAGEMENT_ADDRESSES`.

## Tuning guidance

- **Measure before you change anything.** Replay representative captures (`sentinelx replay <pcap>`) or generate the bundled scenarios (`sentinelx fixtures list`, `sentinelx fixtures generate`). Then look at the `contributions` of the detections you consider noise or misses. Change the factor responsible, not the threshold.
- **Keep `auto_block_threshold` high.** With default weights, one detection needs to be critical, highly confident and supported by repetition, history, correlation, intel or a sensitive target to reach 85. Lowering the threshold makes single, uncorroborated detections eligible for blocking, and spoofed-source traffic can then get a victim address blocked (see [security.md](security.md)).
- **Weigh intelligence to match its quality.** Raise `intel_weight` if your denylist is curated and trusted. Lower it or leave it at the default if the lists are broad.
- **Account for scanners you run yourself.** Add authorised scanners to the intel allowlist to keep their findings visible at low risk, or to the detection allowlist to silence them. Also add them to `RESPONSE__ALLOWLIST_NETWORKS` so they are never blocked.
- **Adjust how sensitive the score is to history.** `history_window_seconds`, `frequency_saturation` and `history_saturation` decide how quickly returning sources gain risk. A short window forgets a slow attacker quickly. A long window keeps stale context for sources that are reassigned, such as addresses behind NAT or on DHCP.
- **Adjust correlation.** Raise `CORRELATION__MIN_DETECTIONS` to open fewer incidents. Raise `CORRELATION__WINDOW_SECONDS` to catch slower multi-stage activity, at the cost of merging unrelated activity from shared addresses. Enable `group_by_destination` to split incidents per target.
- **Change one weight at a time and re-run the same replay.** Scores are deterministic for the same input and settings, so the before-and-after `contributions` show exactly what moved.
- **Remember that changes are audited.** Runtime changes to `scoring` and `correlation` are recorded in the audit log with a before-and-after diff (`UPDATE_SETTINGS`).
