# Response engine and prevention

This document describes what SentinelX does after a detection has been scored: how it decides on a response, the safety guard every preventive action must pass, the firewall adapters, how to enable prevention safely, and how to roll it back. It is written against:

| Component | File |
| --- | --- |
| Response engine | `packages/sentinelx/response/engine.py` |
| Safety guard | `packages/sentinelx/response/safety.py` |
| Enums | `packages/sentinelx/common/enums.py` (`ResponseMode`, `ActionType`) |
| Settings and safety banner | `packages/sentinelx/config/settings.py` (`ResponseSettings`, `Settings.safety_banner`) |
| Firewall adapters | `packages/sentinelx/firewall/__init__.py`, `base.py`, `nftables.py`, `iptables.py`, `pf.py`, `windows.py`, `memory.py` |
| Privileges and host addresses | `packages/sentinelx/system/privileges.py`, `packages/sentinelx/system/interfaces.py` |
| Runtime configuration | `packages/sentinelx/services/config.py` |
| Operator addresses, block record reconciliation | `packages/sentinelx/services/platform.py` |
| API routes | `packages/sentinelx/api/routes/firewall.py`, `packages/sentinelx/api/routes/stats.py` |
| CLI | `packages/sentinelx/cli/security.py`, `packages/sentinelx/cli/admin.py` |

Risk scores and the `auto_block_threshold` are described in [risk-scoring.md](risk-scoring.md). The threat model behind these controls is in [security.md](security.md). Container capabilities and host setup are in [deployment.md](deployment.md).

> **Warning:** Prevention changes the firewall of the host SentinelX runs on. A wrong allowlist, a spoofed source address or an overly low threshold can block legitimate traffic, including your own access to the host. Before you enable it, read [Enabling prevention safely](#enabling-prevention-safely) and have out-of-band access (a console or a second management path) available.

## Safe defaults

A fresh install observes and explains, and never touches traffic:

| Environment variable | Default | Setting |
| --- | --- | --- |
| `RESPONSE_MODE` | `detect_only` | `response.mode` |
| `DRY_RUN` | `true` | `response.dry_run` |
| `FIREWALL_BACKEND` | `null` | `response.firewall_backend` |

Automatic prevention is active (`ResponseSettings.prevention_active`) **only** when `RESPONSE_MODE=automatic` and `DRY_RUN=false` are both set. Once `DRY_RUN=false`, manual blocks and approved actions are also applied, in every mode.

### Safety banner

`Settings.safety_banner()` returns one line describing every path that can change the firewall. It is logged at startup, shown in `sentinelx status`, `sentinelx block`, `sentinelx blocked` and the capability report, and returned by the API as `safety`. The part before ` - ` is the posture shown on the dashboard.

| Posture | Condition | Full text |
| --- | --- | --- |
| `DETECTION ONLY` | `DRY_RUN=true`, mode `detect_only` | `DETECTION ONLY - no traffic will be modified` |
| `DRY RUN` | `DRY_RUN=true`, mode `manual_approval` or `automatic` | `DRY RUN - response decisions are recorded and shown but not applied` |
| `MANUAL BLOCKS ENFORCED` | `DRY_RUN=false`, mode `detect_only` | `MANUAL BLOCKS ENFORCED - automatic responses are off; administrator blocks are enforced <target>` |
| `MANUAL APPROVAL` | `DRY_RUN=false`, mode `manual_approval` | `MANUAL APPROVAL - approved responses are enforced <target>` |
| `PREVENTION ACTIVE` | `DRY_RUN=false`, mode `automatic` | `PREVENTION ACTIVE - automatic responses are enforced <target>` |

`<target>` is `and will modify the <backend> firewall on this host`, or, with `FIREWALL_BACKEND=null` (possible only with `detect_only`), `but no firewall backend is configured, so they will be refused`.

Boolean settings are validated strictly. `DRY_RUN` accepts the usual true and false spellings (`true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`); anything else, including a typo such as `ture`, stops startup with a validation error. Flat aliases (`RESPONSE_MODE`, `DRY_RUN`, `FIREWALL_BACKEND`) are read from the environment and from `.env`; the nested form (`RESPONSE__...`) wins when both are set at the same level, and the environment wins over `.env`.

### The settings guard

`ResponseSettings` refuses to load when `mode` is `automatic` or `manual_approval`, `dry_run` is false, and `firewall_backend` is `null`:

```
RESPONSE_MODE=automatic with DRY_RUN=false requires a real FIREWALL_BACKEND for this host, not 'null'
```

This check applies at startup and to every runtime change, because runtime changes are validated by the same model. `detect_only` with `DRY_RUN=false` and the `null` backend is allowed, but every manual block then fails with the `NullFirewall` refusal (see [No firewall](#no-firewall-null-and-unavailable-backends)); nothing is ever reported as executed.

## Response modes

`ResponseMode` controls how much autonomy the engine has over **automatic**, detector-driven preventive actions.

| `RESPONSE_MODE` | `DRY_RUN` | Outcome of an automatic preventive action at or above the threshold |
| --- | --- | --- |
| `detect_only` (default) | any | `skipped`. The reason ends with `not applied (RESPONSE_MODE=detect_only)`. |
| `manual_approval` | any | The safety guard runs first. If it passes, the action is queued and the outcome is `pending_approval`. If the guard refuses, the outcome is `failed`. |
| `automatic` | `true` | The safety guard runs. If it passes, the outcome is `simulated` and the reason ends with `[DRY RUN - not applied]`. |
| `automatic` | `false` | The safety guard runs, then the action is applied to the firewall. The outcome is `executed` or `failed`. |

**Manual actions** (`sentinelx block` and `unblock`, the API block and unblock endpoints, the dashboard, and approvals of queued actions) ignore `RESPONSE_MODE`, because a person made the decision. They still honour `DRY_RUN` and pass the safety guard. Unblocking is the one exception to the guard (see [Manual actions](#manual-actions)).

Running `mixed_intrusion` from `packages/sentinelx/testing/scenarios.py` through a `Pipeline` with default settings and no rules opens an incident at risk 88.6. The incident-level temporary block for the attacking source is then recorded as follows:

| Settings | Recorded outcome |
| --- | --- |
| defaults | `skipped`, reason `incident 'Potential host compromise attempt' risk 89/100; not applied (RESPONSE_MODE=detect_only)` |
| `RESPONSE_MODE=automatic DRY_RUN=true` | `simulated`, reason `incident 'Potential host compromise attempt' risk 89/100 [DRY RUN - not applied]` |
| `RESPONSE_MODE=manual_approval` | `pending_approval`, reason `incident 'Potential host compromise attempt' risk 89/100` |
| `RESPONSE_MODE=automatic DRY_RUN=false FIREWALL_BACKEND=nftables`, with the pipeline given the in-memory firewall | `executed` |

## Action types

`ActionType` defines the following values. The table shows what the response engine does with each one.

| Value | Preventive | Behaviour in `response/engine.py` |
| --- | --- | --- |
| `alert` | no | Created for **every** scored detection, with outcome `executed`. It is counted in metrics but not published, stored or audited, because the detection itself is the record. |
| `log` | no | No behaviour. If a detector or rule recommends it, only the `alert` decision is produced. |
| `webhook` | no | Queued for delivery when `RESPONSE__WEBHOOK_URL` is set and the detection's risk is at or above `webhook_min_risk`. See [Webhook](#webhook). |
| `block_ip` | yes | Adds the target to the firewall block list with no expiry. |
| `temporary_block` | yes | Same as `block_ip`, with a duration. |
| `rate_limit` | yes | Adds the target to the firewall rate-limit list, with a duration when one applies. The rate is `rate_limit_packets_per_second`. Only nftables and iptables support it. |
| `quarantine` | yes | Handled exactly like `block_ip`: the source address is blocked with no expiry. No separate isolation is implemented. |
| `unblock_ip` | yes | Removes the target from the block and rate-limit lists. Only possible as a manual action. Automatic handling ignores it, and rules may not use it. |
| `none` | no | No behaviour beyond the `alert` decision. |

"Preventive" is `ActionType.is_preventive`. Preventive actions are the ones gated by mode, dry run and the safety guard.

**Durations of automatic actions.** For `temporary_block` and `rate_limit` recommended by a detection, the duration is the detection's `recommended_duration_seconds` if set, otherwise `default_block_seconds`, in both cases capped at `max_block_seconds`. A custom rule's `duration` field (30 to 86,400 seconds; required for `temporary_block`) sets `recommended_duration_seconds`, so a rule controls how long its automatic block lasts. Built-in detectors do not set it. Incident-level blocks always use `default_block_seconds`.

## Decision flow

### `handle_detection(detection, risk)`

The pipeline calls this for every scored detection.

1. Record an `alert` decision (`executed`).
2. If `webhook_url` is set and `risk.score >= webhook_min_risk`, queue the webhook (see [Webhook](#webhook)).
3. Read `detection.recommended_action`. If it is not preventive, or it is `unblock_ip`, stop.
4. If `risk.score < scoring.auto_block_threshold` (default 85), record the action as `skipped` with the reason `not applied: risk N is below the automatic response threshold of 85` and stop. This decision is not published or audited.
5. Otherwise, pass the action to the automatic path with the detection's source address as the target and the duration described above.

### `handle_incident(incident)`

The pipeline calls this after `handle_detection` when the correlation result for the detection shows that the incident response could have changed:

- the incident was just created;
- its severity increased; or
- its risk crossed `auto_block_threshold` with this detection (the previous incident risk was below the threshold and the new one is at or above it), which can happen without a change in severity.

The engine then:

1. does nothing if `incident.risk.score < auto_block_threshold`;
2. for each address in `incident.affected_sources`, sorted, that is not already in the block registry: sends a `temporary_block` for `default_block_seconds` to the automatic path. The incident's risk rationale becomes the evidence.

### The block registry

The engine keeps a registry of active entries keyed by canonical network. Targets are normalised before lookup, so `203.0.113.9` and `203.0.113.9/32` are the same entry. The registry is loaded from the firewall at startup, updated by every block, rate limit, unblock and expiry, and reconciled with the firewall whenever the active list is read with a refresh (`GET /api/v1/firewall`, `GET /api/v1/firewall/blocked`, the dashboard Firewall page, `sentinelx blocked`). A refresh adds entries the firewall holds but the registry does not (for example a block made by a CLI command while the server runs) and, for any backend other than `null`, removes entries the firewall no longer holds.

### The automatic path

`ResponseEngine._automatic` handles each proposed action in this order:

1. **Already blocked.** For `block_ip` and `temporary_block`, if the target is already in the block registry, the decision is `skipped` with the reason suffix `; already blocked`. It is not published or audited.
2. **`detect_only`.** The decision is `skipped` and audited.
3. **Safety guard.** If the guard refuses the target, the decision is `failed` with the error `safety guard: <reason>`, and it is audited. This check runs **before** queueing, so an administrator is never asked to approve an action that cannot be carried out.
4. **`manual_approval`.** A `PendingAction` is queued with action, target, reason, risk, duration, detection or incident id, evidence, `action_id` and `created_at`, and `response.pending_approval` is published. If an action of the same type for the same target is already pending, no duplicate is queued. The decision is `pending_approval`. See [Manual approval](#manual-approval) for the queue's limits.
5. **`automatic`.** The action is executed (see [Execution](#execution)).

### Execution

`_execute` handles automatic, manual and approved actions in the same way:

- **Dry run on.** The decision is `simulated` and the firewall is not called.
- **Dry run off.** The adapter is called under the engine lock:
  - If the firewall has not been set up in this process, `setup()` runs first (see [Engine startup](#engine-startup)).
  - For blocks and rate limits, the safety guard checks the target **again**.
  - `block_ip`, `temporary_block` and `quarantine` call `firewall.block(network, duration, comment)`. The comment is the decision reason cut to 120 characters. `ip.blocked` is published.
  - `rate_limit` calls `firewall.rate_limit(network, packets_per_second, duration)`. `ip.blocked` is published.
  - `unblock_ip` calls `firewall.unblock(network)`, and `ip.unblocked` is published. The outcome is `executed` if the firewall removed an entry, and `skipped` if nothing was there to remove.
- A `FirewallError` (including a failed setup, a permission error, or a refusal by the `null` backend), `SafetyViolationError` or `ValueError` during execution produces a `failed` decision that contains the error message. It is never raised to the caller.
- A successful block, temporary block, quarantine or rate limit also increments the source's `previous_responses` count in the risk engine.

### Decision outcomes

`ResponseDecision.outcome` is derived from the decision's fields, in this order:

| Outcome | Condition |
| --- | --- |
| `failed` | `error` is set (safety refusal, firewall error or webhook error). |
| `pending_approval` | `requires_approval` is true. |
| `simulated` | `dry_run` is true. |
| `executed` | `executed` is true. |
| `skipped` | Anything else: `detect_only`, below threshold, already blocked, or an unblock with nothing to remove. |

Every finalised decision is counted in `sentinelx_responses_total{action,outcome}`. Decisions other than `alert` are published as `response.decided` and stored in the `response_actions` table, except those recorded as non-actions (below threshold, already blocked, webhook). Preventive decisions are also written to the audit log (see [Audit trail](#audit-trail)). The engine keeps the most recent decisions in memory, dropping the oldest 1,000 when it holds more than 5,000.

**Replays.** A pipeline running a replay tags every published decision (and every detection and incident) with its `replay_id`. The firewall action log (`GET /api/v1/firewall/actions`, the Firewall page) excludes decisions with a `replay_id` and any stored `alert` rows unless `include_replays=true` or `include_alerts=true` is passed. Replays never change the firewall: they run with `DRY_RUN=true` against the in-memory simulator.

### Manual approval

In `manual_approval` mode, queued actions are held **in memory** by the running server. They are not persisted, and a restart discards them.

| Limit | Value |
| --- | --- |
| Pending actions held | 1,000 (`MAX_PENDING_APPROVALS`). When full, the oldest is dropped and `pending_approval_evicted` is logged |
| Time limit | 24 hours (`PENDING_APPROVAL_TTL`). Older actions are removed when a new action is queued |

| Operation | API |
| --- | --- |
| List pending actions | `GET /api/v1/firewall/approvals` (viewer role) |
| Approve | `POST /api/v1/firewall/approvals/{action_id}/approve` (administrator role) |
| Reject | `POST /api/v1/firewall/approvals/{action_id}/reject` with body `{"reason": "..."}` (administrator role) |

Both approve and reject return 404 for an unknown `action_id`.

- **Approve** removes the pending action and runs it as a manual action with the reason `approved: <original reason>` and source `approval`. The safety guard runs again, and `DRY_RUN` still applies: with `DRY_RUN=true`, an approved action is `simulated`.
- **Reject** removes the pending action and writes a `REJECT_RESPONSE` audit record with the pending action's details.

### Temporary block expiry

When the engine starts, it launches a reaper task that wakes **every 5 seconds** and calls `expire_due()`. For each registry entry whose `expires_at` has passed, the reaper:

1. takes the engine lock (the same lock blocks use) and re-checks that the entry is still the one it found, so a block an administrator placed or replaced in the meantime is never removed;
2. calls `firewall.unblock(network)`;
3. on success, removes the entry, publishes `ip.unblocked` with the reason `temporary block expired`, and writes an `UNBLOCK_IP` audit record with actor `system`, source `engine`, outcome `executed`;
4. on failure, logs `expiry_unblock_failed`, **keeps** the entry so the next pass retries it, and writes an `UNBLOCK_IP` audit record with outcome `failed` and the error. A failed unblock is never reported as done.

Where each backend keeps the deadline:

| Backend | Expiry deadline stored in | Expires while SentinelX is stopped |
| --- | --- | --- |
| nftables | The set element's kernel timeout | Yes. The reaper then only updates the registry |
| iptables | The rule comment, `sentinelx:exp=<unix seconds>` | No. The reaper removes the rule, including after a restart, because the deadline is read back from the rule |
| Windows Firewall | The rule description, `exp=<unix seconds>` | No. The reaper removes the rules, including after a restart |
| pf | Adapter memory only | No. At server start, the platform restores deadlines from the `blocked_sources` table (`expires_at` of active records) for entries the firewall reports without one |

A temporary block created by a short-lived CLI command is expired by whichever SentinelX server knows about it: a server learns about it on its next registry refresh or start. With pf, a CLI command stores no database record (CLI commands run without persistence), so its deadline is lost when the command exits and the block stays until removed.

### Engine startup

`ResponseEngine.start(known_expiries)`:

1. Calls `firewall.setup()` when prevention is active or the mode is `manual_approval`. If setup fails, startup is aborted with the error.
2. Loads the firewall's current entries (`list_blocked`) into the block registry, so blocks that survived a restart are known. Entries without an expiry take one from `known_expiries` when given. A listing failure is logged as `firewall_list_failed` and does not stop startup.
3. Starts the expiry reaper and the webhook delivery worker.

In every other mode, setup runs **lazily**, the first time the engine changes the firewall: the first manual block with `DRY_RUN=false`, or the first automatic action after prevention was enabled at runtime. The table or chain therefore exists whenever SentinelX needs it, without a restart. Setup is idempotent.

After the engine starts, `Platform.start()` reconciles the `blocked_sources` history with the firewall: records still marked active whose network the firewall no longer holds (for example a kernel-expired nftables element, or a table flushed by hand) are marked inactive with the removal reason `no longer present in the firewall`.

### Webhook

When `RESPONSE__WEBHOOK_URL` is set, each detection with risk at or above `RESPONSE__WEBHOOK_MIN_RISK` (default 60.0) is sent as a JSON `POST` with this body:

```
type ("sentinelx.detection"), title, detector, severity, risk, risk_band,
source_ip, destination_ip, evidence, timestamp
```

- **HTTPS only.** `webhook_url` must use `https://`, include a host, and contain no spaces or control characters; other values are rejected when settings load or change.
- **Public destinations only.** Before each delivery, the host is resolved and every address it resolves to must be a public unicast address. Loopback, private, link-local, reserved and multicast addresses are refused with `webhook host '<host>' resolves to non-public address <address>; set RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES=true to allow internal receivers`. Set `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES=true` (environment only) for an internal receiver. A DNS answer that changes between the check and the connection is not prevented. Redirects are not followed.
- **Never on the detection path.** `handle_detection` puts the webhook on a bounded queue of 200 (`WEBHOOK_QUEUE_SIZE`) and returns immediately with a `webhook` decision whose reason ends with `queued for delivery`. One background worker delivers queued webhooks in order. When the queue is full, the webhook is dropped, `sentinelx_webhook_failures_total` is incremented, `webhook_queue_full` is logged, and the returned decision carries the error `webhook queue full; delivery skipped`.
- **Delivery results.** The request uses a timeout of `RESPONSE__WEBHOOK_TIMEOUT_SECONDS` (default 5.0, at most 30). A failed or refused delivery produces a `webhook` decision with outcome `failed` and the error `webhook failed: <ExceptionName>` (or the refusal reason), increments `sentinelx_webhook_failures_total` and logs `webhook_failed`. Delivery results (`executed` or `failed`) are counted in `sentinelx_responses_total{action="webhook"}`; webhook decisions are not published, stored or audited.
- **Display.** Webhook URLs often carry their secret in the path or query. Decision targets, webhook log lines and the settings view (`GET /api/v1/config`) show only `scheme://host[:port]/…`. The `UPDATE_SETTINGS` audit record and `config.changed` event of a runtime change to `webhook_url` currently contain the full URL, and both are visible to the analyst role.

## Safety guard

`SafetyGuard.check(target)` (`packages/sentinelx/response/safety.py`) validates every target before a preventive action. It runs:

- in the automatic path, before queueing or executing;
- in every manual block or rate limit; and
- again immediately before the firewall adapter is called.

The guard does not normalise suspicious input; it rejects it. When it refuses, it:

- raises `SafetyViolationError(target, reason)`;
- increments `SafetyGuard.refusals`, which is reported as `safety_refusals` in the response status;
- increments `sentinelx_safety_refusals_total{reason=<code>}`; and
- logs `safety_refusal` with the `rule` field set to the code.

The decision's `error` contains `safety guard: <reason>`. The code itself appears in the metric and the log, not in the decision.

### Checks, in order

| # | Code | Refused when | Example reason text |
| --- | --- | --- | --- |
| 1 | `invalid_address` | The target is empty, has leading or trailing whitespace, or contains any whitespace or non-printable (control) character. Rejecting these prevents forged audit and log entries. | `target contains whitespace or control characters` |
| 2 | `invalid_address` | Python's `ipaddress.ip_network(target, strict=False)` cannot parse the target. A bare address becomes a /32 or /128, and host bits are cleared (`203.0.113.7/28` becomes `203.0.113.0/28`). | `'not-an-ip' is not a valid IP network` |
| 3 | `default_route` | The prefix length is 0. | `a /0 prefix would block all traffic` |
| 4 | `prefix_too_wide` | The prefix covers more addresses than `max_block_prefix_hosts` (default 256, which is a /24). | `10.0.0.0/16 (65536 addresses) exceeds the maximum of 256 addresses (response.max_block_prefix_hosts)` |
| 5 | `special_address` | The first or last address of the prefix is loopback, link-local, multicast, unspecified or reserved. | `127.0.0.1 is loopback, link-local, multicast or reserved` |
| 6 | `allowlisted` | The prefix overlaps any network in the response allowlist (same IP version). | `192.0.2.8/32 overlaps allowlisted network 192.0.2.0/28` |
| 7 | `management_address` | The prefix overlaps any configured management address (same IP version). | `198.51.100.0/29 overlaps management address 198.51.100.7/32` |
| 8 | `local_addresses_unknown` | `protect_management_addresses` is true (default) and this host's interface addresses cannot be enumerated. The guard fails closed rather than risk blocking the host itself. | `could not list this host's addresses (<error>); refusing to block` |
| 9 | `local_address` | `protect_management_addresses` is true and the prefix contains an address assigned to any interface on this host. | `10.0.0.0/24 contains 10.0.0.5, an address of this host` |
| 10 | `operator_address` | `protect_management_addresses` is true and the prefix contains the address of an operator who made an authenticated API request to this server in the last hour. | `203.0.113.64/26 contains 203.0.113.77, the address of an operator signed in within the last hour` |
| 11 | `block_limit_reached` | The engine already holds `max_blocked_addresses` or more active entries (default 10,000). Blocks and rate limits both count. | `1 blocks already active (response.max_blocked_addresses)` |

The example reasons were produced by `SafetyGuard.evaluate()` with an allowlist of `192.0.2.0/28`, a management address of `198.51.100.7`, a local address of `10.0.0.5` and an operator address of `203.0.113.77` injected in place of discovery, a failing address enumeration for check 8, and, for check 11, `max_blocked_addresses=1` with one active block.

Overlap is checked in both directions. Blocking `10.0.0.0/24` fails when the sensor is `10.0.0.5`, even though the /24 itself is not listed.

**Host addresses** come from `psutil` (`system/interfaces.py`), include every IPv4 and IPv6 address on every interface (IPv6 zone suffixes removed), and are cached for 10 seconds so a burst of blocks does not enumerate interfaces each time. A failed enumeration is never cached.

**Operator addresses** are recorded by the API server for every authenticated request. The address is the TCP peer, or, when the peer is in `API__TRUSTED_PROXIES`, the first untrusted address in `X-Forwarded-For` read from the right. The server remembers up to 1,024 addresses. Only the server process has them: a CLI command's engine knows no operator addresses, so a `sentinelx block` from the CLI is not protected by check 10.

### Loopback is always allowlisted

`127.0.0.0/8` and `::1/128` are always in the response allowlist, whatever you configure:

- The `ResponseSettings` validator appends them if they are missing.
- `SafetyGuard.update_allowlist()` re-adds them when the allowlist is replaced at runtime.

For example, `RESPONSE__ALLOWLIST_NETWORKS='["192.0.2.0/28"]'` loads as `['192.0.2.0/28', '127.0.0.0/8', '::1/128']`.

### Previewing a target

`SafetyGuard.evaluate(target)` runs the same checks without raising, counting or logging. It is exposed as:

```
POST /api/v1/firewall/check        (analyst role)
{"target": "203.0.113.0/28"}
```

The response is `{"target", "allowed", "network", "reason", "dry_run"}`. Use it to confirm that your management addresses are protected before you enable prevention.

### Guard settings

| Setting | Environment variable | Default | Runtime-editable |
| --- | --- | --- | --- |
| `allowlist_networks` | `RESPONSE__ALLOWLIST_NETWORKS` | `["127.0.0.0/8", "::1/128"]` | yes |
| `management_addresses` | `RESPONSE__MANAGEMENT_ADDRESSES` | `[]` | yes |
| `protect_management_addresses` | `RESPONSE__PROTECT_MANAGEMENT_ADDRESSES` | `true` (enables checks 8, 9 and 10) | no |
| `max_block_prefix_hosts` | `RESPONSE__MAX_BLOCK_PREFIX_HOSTS` | `256` (1-65,536) | yes |
| `max_blocked_addresses` | `RESPONSE__MAX_BLOCKED_ADDRESSES` | `10000` (1-1,000,000) | yes |

List values in environment variables are JSON arrays. Invalid networks are rejected when settings load. The allowlist can also be replaced with `PUT /api/v1/firewall/allowlist` and the body `{"networks": [...]}` (administrator role, at most 1,000 entries). Loopback is always retained. A runtime change to the allowlist or management addresses is applied to the running guard immediately, including while prevention is active.

Add workstations and jump hosts that reach the host by other paths than the API (SSH, VPN, monitoring) to `management_addresses` explicitly; check 10 covers only API users of this server.

## Other response settings

| Setting | Environment variable | Default | Runtime-editable |
| --- | --- | --- | --- |
| `mode` | `RESPONSE_MODE` or `RESPONSE__MODE` | `detect_only` | yes |
| `dry_run` | `DRY_RUN` or `RESPONSE__DRY_RUN` | `true` | yes |
| `firewall_backend` | `FIREWALL_BACKEND` or `RESPONSE__FIREWALL_BACKEND` | `null` (`null`, `auto`, `nftables`, `iptables`, `pf`, `windows_firewall`) | no |
| `nft_table` | `RESPONSE__NFT_TABLE` | `sentinelx` (`^[A-Za-z0-9_]{1,32}$`) | no |
| `nft_set` | `RESPONSE__NFT_SET` | `blocklist` (`^[A-Za-z0-9_]{1,32}$`) | no |
| `nft_family` | `RESPONSE__NFT_FAMILY` | `inet` (`inet`, `ip`, `ip6`) | no |
| `pf_anchor` | `RESPONSE__PF_ANCHOR` | `com.apple/sentinelx` | no |
| `default_block_seconds` | `RESPONSE__DEFAULT_BLOCK_SECONDS` | `900` (30-86,400) | yes |
| `max_block_seconds` | `RESPONSE__MAX_BLOCK_SECONDS` | `86400` (60-2,592,000) | yes |
| `rate_limit_packets_per_second` | `RESPONSE__RATE_LIMIT_PACKETS_PER_SECOND` | `100` (>= 1) | yes, but adapters read it only at construction, so a change applies after a restart |
| `webhook_url` | `RESPONSE__WEBHOOK_URL` | empty (disabled); `https://` only | yes |
| `webhook_allow_private_addresses` | `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES` | `false` | no |
| `webhook_timeout_seconds` | `RESPONSE__WEBHOOK_TIMEOUT_SECONDS` | `5.0` (> 0, <= 30) | yes |
| `webhook_min_risk` | `RESPONSE__WEBHOOK_MIN_RISK` | `60.0` | yes |

The automatic threshold is `SCORING__AUTO_BLOCK_THRESHOLD`, default 85.0. See [risk-scoring.md](risk-scoring.md).

**Environment and stored overrides.** Runtime changes are stored in the database and normally applied on top of the environment at every start. `mode` and `dry_run` are the exception: when the environment or `.env` explicitly sets `RESPONSE_MODE`/`RESPONSE__MODE` or `DRY_RUN`/`RESPONSE__DRY_RUN`, that value wins over the stored one at startup, and `stored_setting_overridden_by_environment` is logged. An operator can therefore always turn prevention off by editing the environment and restarting. The Docker Compose stack always sets both variables, so there a runtime change to them lasts only until the next restart.

## Firewall adapters

`create_firewall(settings.response)` (`firewall/__init__.py`) builds the adapter selected by `FIREWALL_BACKEND`. The response engine is the only component that calls an adapter, and it only passes networks that have already passed the safety guard.

| Backend | Platforms | Mechanism | Native expiry | Rate limiting | Tested against |
| --- | --- | --- | --- | --- | --- |
| `nftables` | Linux | `nft` sets with kernel timeouts | yes | yes | Real netfilter with real traffic |
| `iptables` | Linux | `iptables`/`ip6tables` chain, `hashlimit` | no | yes | Real netfilter with real traffic |
| `pf` | macOS, FreeBSD, OpenBSD | `pfctl` anchor and table | no | no | Unit tests with recorded command output only |
| `windows_firewall` | Windows | NetSecurity PowerShell cmdlets | no | no | Unit tests with recorded command output only |
| `memory` | any | In-process simulator | n/a | simulated | Unit tests |
| `null` | any | No firewall; every change is refused | n/a | no | Unit tests |

`auto` picks the first usable backend for the platform (nftables, then iptables on Linux; pf on macOS and BSD; Windows Firewall on Windows). A backend is usable when its tool is installed and `firewall_privilege()` grants the privilege (on Linux: root, or `CAP_NET_ADMIN` that can be passed to child processes; on macOS: root; on Windows: an elevated process). If none is usable, `auto` resolves to `null` and the reason is kept for health and the capability report.

A configured backend that cannot be constructed here (tool missing, wrong operating system) does not stop startup: `create_firewall` returns an `UnavailableFirewall` that reports `ok: false` in health, marks the platform `degraded`, and fails every change with `the <backend> firewall backend is unavailable: <reason>`. Detection keeps working.

`sentinelx capabilities` and `GET /api/v1/system/capabilities` report "Firewall control" (whether the configured backend can enforce here), "Automatic blocking" (whether it is possible and whether it is on), and one row per backend for the platform with its native-expiry and rate-limit support. `sentinelx doctor` fails the "firewall backend" check when `DRY_RUN=false` with a mode other than `detect_only` and no usable backend.

`tests/kernel/test_firewall.py`, run by `make test-kernel` inside a private network namespace, verifies block, restoration after unblock, temporary expiry, a permanent re-block over a temporary block, rate limiting and teardown for nftables and iptables by sending real packets. An nftables block and its restoration were also verified through the dashboard with the Docker images, using a local Compose override that granted the API container `NET_ADMIN` and `NET_RAW`; the stock `api` service drops all capabilities and cannot change the host firewall (use the `capture` profile's `sensor` service or a bare-metal install, see [deployment.md](deployment.md)). The pf and Windows Firewall adapters have not been run on real hosts.

### Command execution

The nftables, iptables, pf and Windows Firewall adapters run commands through `CommandRunner` (`packages/sentinelx/firewall/base.py`):

- **Arguments are passed as a list.** No code path invokes a shell. On Linux and macOS commands run with `asyncio.create_subprocess_exec`; on Windows they run with `subprocess.run` in a worker thread, which works with every event loop type.
- **The binary path is fixed once.** It is resolved with `shutil.which` at construction, and a missing binary raises `FirewallError` (`<binary> is not installed or not on PATH`). Windows PowerShell is located under `%SYSTEMROOT%` rather than through `PATH`.
- **Arguments are checked.** Every argument must be a `str`, and any argument that contains a control character (any code below 0x20, or 0x7F) is refused (`refusing firewall argument containing control characters`).
- **Addresses come from `ipaddress` objects**, never from raw input.
- **Every command has a timeout** (10 seconds by default, 30 for PowerShell). On timeout the process is killed and `FirewallError` is raised. If the calling task is cancelled, the child process is killed before the cancellation propagates.
- **Every command is logged** at debug level as `firewall_command`, with its return code and duration. A non-zero exit raises `FirewallError` with the command's stderr, unless the caller passed `check=False`.
- **Capabilities are passed to child processes on Linux.** Capabilities granted by file capabilities (`setcap` on the interpreter) belong to the Python process only and are dropped when it executes `nft` or `iptables`. Before each command, the runner raises `CAP_NET_ADMIN` into the process's ambient set (adding it to the inheritable set first), so child processes inherit it. Without this, blocks under `setcap` failed with `Operation not permitted`. Root needs nothing; a process that does not hold the capability raises nothing, and the command fails with a permission error.

The runner can prefix `sudo -n`, but no setting enables this. SentinelX therefore needs root, `CAP_NET_ADMIN` (Linux) or an elevated process (Windows) to change the firewall. `sentinelx doctor` and `sentinelx capabilities` report whether the configured backend's tool is installed and whether firewall privileges are available.

### nftables

`NftablesAdapter` owns one table and never modifies any other. With default settings, `setup()` creates:

```
table inet sentinelx {
    set blocklist_v4 { type ipv4_addr; flags interval,timeout; }
    set blocklist_v6 { type ipv6_addr; flags interval,timeout; }
    set ratelimit_v4 { type ipv4_addr; flags interval,timeout; }
    set ratelimit_v6 { type ipv6_addr; flags interval,timeout; }
    chain input   { type filter hook input   priority -10; policy accept;
                    ip  saddr @blocklist_v4 counter drop
                    ip6 saddr @blocklist_v6 counter drop
                    ip  saddr @ratelimit_v4 limit rate over 100/second counter drop
                    ip6 saddr @ratelimit_v6 limit rate over 100/second counter drop }
    chain forward { ...same hook type, priority, policy and rules... }
}
```

- **Names.** The table name is `RESPONSE__NFT_TABLE` and the family is `RESPONSE__NFT_FAMILY`. The block sets are named `<RESPONSE__NFT_SET>_v4` and `<RESPONSE__NFT_SET>_v6`. The rate-limit sets are always `ratelimit_v4` and `ratelimit_v6`.
- **Chain policy is `accept`.** The table can only drop traffic that matches a set. It cannot make the host default-deny.
- **Setup is idempotent.** Each chain is flushed and its rules re-added, so rules are never duplicated.
- **Blocks are set elements, not rules.** A single host is written as its bare address.
- **Adding replaces.** `nft add element` alone leaves an existing element and its timeout unchanged, so a re-block with a new duration, or a permanent block over a temporary one, would keep the old expiry. The adapter instead runs one atomic nft batch: `add element ... { <addr> } ; delete element ... { <addr> } ; add element ... { <addr> [timeout <N>s] }`. The address is never unblocked in between, and the result is exactly the requested element.
- **Temporary blocks use kernel timeouts.** The kernel removes the element when the timeout expires.
- **Rate limits use one rate for all sources.** The rate is in the rule, not in each element, so a request for a different rate logs `rate_limit_uses_configured_rate` and uses the rate the adapter was built with.
- **Unblocking** deletes the element from both the block set and the rate-limit set for that IP version. It returns false only when the element was in neither. An nft error whose message says `No such file or directory` or `does not exist` means "absent"; any other failure, such as a permission error, raises `FirewallError` and is never reported as "was not blocked".
- **Listing** reads `nft -j list set` for each of the four sets. A missing table or set means nothing is blocked yet; any other failure raises `FirewallError`.
- **Health** reports `ok: true` when the table exists or has not been created yet (`state: "not set up yet"`), and `enforcing: true` only when the table exists.
- **`teardown()`** runs `nft delete table <family> <table>`. No CLI command or API call runs it. See [Rolling back](#rolling-back).

### iptables

`IptablesAdapter` owns one chain, `SENTINELX`, in both `iptables` and `ip6tables`:

- **Setup** creates the chain (`-N SENTINELX`) and inserts `-j SENTINELX` at position 1 of `INPUT` and `FORWARD` if that jump is not already present. Every command uses `-w`.
- **Block** inserts `-s <net> -m comment --comment <tag> -j DROP` at position 1 of `SENTINELX`.
- **Rate limit** appends `-s <net> -m hashlimit --hashlimit-above <pps>/sec --hashlimit-mode srcip --hashlimit-name sx<12 hex chars> -m comment --comment <tag> -j DROP`.
- **Expiry in the comment.** `<tag>` is `sentinelx` for a permanent entry and `sentinelx:exp=<unix seconds>` for a temporary one. `list_blocked` reads the deadline back, so the engine expires the rule after a SentinelX restart.
- **Replacing.** A block or rate limit first lists the chain's existing rules for that network, inserts the new rule, and only then deletes the old ones. The address is never unblocked in between, and a failed insert leaves the old rule in force. A block therefore replaces an existing rate limit for the same network, and the reverse.
- **Unblock** deletes every rule in the chain for the network, whatever its comment, by rule specification as printed by `iptables -S`. A deletion failure raises `FirewallError`.
- **Listing** uses `iptables -S SENTINELX`. A missing chain means nothing is blocked; any other failure raises `FirewallError`.
- **IPv6.** If `ip6tables` is not installed, the adapter logs `ip6tables_unavailable`, and every IPv6 action fails with `ip6tables is not installed; cannot block IPv6 addresses`.
- **Health** reports `ok: true` when the chain exists or has not been created yet, and `enforcing: true` only when it exists.

Temporary iptables blocks are removed only while a SentinelX server with a running engine is up. Prefer nftables where available.

### pf (macOS and BSD)

`PfAdapter` loads a small ruleset into its own anchor and keeps blocked addresses in a table inside it:

```
table <sentinelx_block> persist
block drop in quick from <sentinelx_block> to any
block drop out quick from any to <sentinelx_block>
```

- **Anchor.** `RESPONSE__PF_ANCHOR`, default `com.apple/sentinelx`, which the stock macOS `/etc/pf.conf` evaluates through its `anchor "com.apple/*"` line, so no system file is edited. On other systems, add `anchor "sentinelx"` to `pf.conf` and set `RESPONSE__PF_ANCHOR=sentinelx`.
- **Setup** loads the ruleset with `pfctl -a <anchor> -f <file>` and enables pf with `pfctl -E`, keeping the returned reference token. Teardown flushes the anchor and releases only that token (`pfctl -X <token>`), so SentinelX never disables a pf that something else enabled.
- **Block** adds the address to the table and kills existing states from that address (`pfctl -k`), so established connections stop immediately.
- **No rate limiting.** `rate_limit` fails with `the pf backend cannot rate-limit traffic; use a block or a temporary block`.
- **Expiry** is enforced by the reaper; see [Temporary block expiry](#temporary-block-expiry).
- **Permissions.** A permission failure is reported as `pf refused to <action>: run the sensor as root`.
- **Health** is `ok` only when pf is enabled and the anchor's rules are loaded.

### Windows Firewall

`WindowsFirewallAdapter` creates, for each blocked network, an inbound and an outbound block rule in the rule group `SentinelX`, named `SentinelX-<16 hex characters>-inbound` and `-outbound`, using the NetSecurity PowerShell cmdlets.

- **Expiry in the description.** The rule description is `exp=<unix seconds>` for a temporary block and `exp=never` otherwise. `list_blocked` reads it back, and the reaper removes expired rules, including after a restart.
- **Replacing.** A block removes any existing rules of the same name before creating the new pair.
- **No rate limiting.** `rate_limit` fails with `Windows Firewall cannot rate-limit traffic; use a block or a temporary block`.
- **Scripts contain only generated values**: validated addresses, hexadecimal rule names and integers. Block reasons are never interpolated.
- **Permissions.** "Access is denied" is reported as `Windows Firewall refused the change: run SentinelX from an elevated (Administrator) terminal`.
- **Health** is `ok` only when the firewall is enabled for every profile; disabled profiles are listed. Group Policy can override local rules.

### In-memory simulator (`memory`)

`MemoryFirewall` (backend name `memory`) keeps entries, including expiry times, in a Python dictionary, reports `enforcing: false` in its health output and **changes nothing on the host**. It is the adapter used by `Pipeline` when none is given, by PCAP replays (CLI and API), by `sentinelx monitor` without `--enforce`, by benchmarks and by tests. It cannot be selected with `FIREWALL_BACKEND`.

### No firewall: `null` and unavailable backends

`NullFirewall` is what `FIREWALL_BACKEND=null` (or `auto` with nothing usable) means: there is no firewall. `block`, `rate_limit` and `unblock` all raise `FirewallError` (`no firewall backend is configured (FIREWALL_BACKEND=null), so nothing can be enforced; set FIREWALL_BACKEND to a backend this host supports`), so with `DRY_RUN=false` a block is recorded as `failed`, never as `executed`. With `DRY_RUN=true`, decisions are `simulated` as usual, because the firewall is not called. Its listing is always empty and its health reports `ok: true, enforcing: false`. `UnavailableFirewall` behaves the same way but reports `ok: false` with the reason.

## Manual actions

`ResponseEngine.manual_action(action, target, actor, reason, duration, source)`:

- ignores `RESPONSE_MODE`;
- honours `DRY_RUN` (a dry-run request returns a `simulated` decision);
- runs the safety guard for every action except `unblock_ip`, so an unblock is never refused by the allowlist;
- clamps `duration` to between 1 second and `max_block_seconds`; and
- uses `default_block_seconds` when a `temporary_block` has no duration.

### CLI

Each command starts its own short-lived platform instance using the same environment and database as the server, and runs the action through that instance's response engine.

```
sentinelx block [TARGET] [--reason/-r TEXT] [--duration/-t SECONDS>=30] [--rate-limit] [--yes/-y] [--json]
sentinelx unblock [TARGET] [--reason/-r TEXT] [--yes/-y] [--json]
sentinelx blocked [--json]
```

- **Prompts.** A missing target or reason is prompted for. The reason is recorded in the audit log.
- **Action type.** `--rate-limit` selects `rate_limit`. Otherwise, `--duration` selects `temporary_block`, and no duration selects a permanent `block_ip`.
- **Confirmation.** When `DRY_RUN=false`, the command shows the safety banner and asks for confirmation unless `--yes` is given.
- **Output and exit code.** The command prints the outcome and reason, and exits with status 1 when the decision has an error (for example, a safety refusal).
- **Audit fields.** The audit source is `cli`, and the actor is `cli:<local username>`.
- **`sentinelx blocked`** refreshes the registry from the configured backend, then shows the active entries and the 10 most recent entries of block history from the database.

Examples:

```
sentinelx block 203.0.113.45 --duration 3600 --reason "SSH brute force from incident 1234"
sentinelx block 203.0.113.0/28 --rate-limit --reason "HTTP flood"
sentinelx unblock 203.0.113.45 --reason "false positive, customer NAT"
sentinelx blocked
```

Operational notes that follow from each CLI command using its own engine:

- **`null` backend.** With `DRY_RUN=false`, a CLI block fails with the `NullFirewall` refusal.
- **Setup.** In `detect_only` or dry-run `automatic` mode the CLI engine does not set up the firewall at start, but the first real change does, so a CLI block creates the nftables table or iptables chain if it does not exist.
- **Privileges.** When prevention is active or the mode is `manual_approval`, each CLI command runs firewall setup at startup and needs the same privileges as the service, even for commands that only read.
- **No persistence.** CLI commands run with persistence off, so their decisions reach the audit log but not the `response_actions` or `blocked_sources` tables.
- **Server state.** A running server learns about a CLI block on its next registry refresh (see [The block registry](#the-block-registry)) or restart.

### API

All of these endpoints require an authenticated user (see [api.md](api.md)).

| Method and path | Role | Body or parameters |
| --- | --- | --- |
| `POST /api/v1/firewall/block` | admin | `{"target": str (2-64), "reason": str (3-500), "duration_seconds": int 30-604800 or null, "rate_limit": bool}` |
| `POST /api/v1/firewall/unblock` | admin | `{"target": str (2-64), "reason": str (3-500)}` |
| `POST /api/v1/firewall/check` | analyst | `{"target": str}` |
| `GET /api/v1/firewall` | viewer | Response status, adapter health, active entries (refreshed), block history, recent actions, pending approvals |
| `GET /api/v1/firewall/blocked` | viewer | Active entries, refreshed from the adapter |
| `GET /api/v1/firewall/actions` | viewer | `target`, `outcome` (repeatable), `include_alerts`, `include_replays`, `limit` (1-500), `offset` |
| `GET /api/v1/firewall/approvals` | viewer | Pending approvals |
| `POST /api/v1/firewall/approvals/{action_id}/approve` | admin | none |
| `POST /api/v1/firewall/approvals/{action_id}/reject` | admin | `{"reason": str (0-500)}` |
| `GET /api/v1/firewall/allowlist` | viewer | Response allowlist, detection allowlist, management addresses |
| `PUT /api/v1/firewall/allowlist` | admin | `{"networks": [str, ...]}` |

For block requests, `rate_limit: true` selects `rate_limit`. Otherwise, a `duration_seconds` value selects `temporary_block`, and no duration selects `block_ip`. The duration is then clamped to `max_block_seconds`.

Block, unblock and approve return the decision payload: `decision_id`, `action`, `target`, `reason`, `outcome`, `executed`, `dry_run`, `requires_approval`, `duration_seconds`, `detection_id`, `incident_id`, `error`, `decided_at` and `replay_id`. A refused or failed action still returns HTTP 200, and the payload then includes `http_note` and a non-null `error`. Always check `outcome`.

```
curl -sS -X POST https://sentinelx.example/api/v1/firewall/block \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target": "203.0.113.45", "reason": "confirmed scanner", "duration_seconds": 3600}'
```

## Audit trail

Audit records are written directly to the `audit_events` table, not through the event bus. They can be read with `GET /api/v1/audit` (analyst role), which accepts the filters `actor`, `action`, `target`, `since`, `limit` (1-500) and `offset`.

| Event | `action` | `actor` | `source` |
| --- | --- | --- | --- |
| Preventive decision, including `skipped` in detect-only mode, `pending_approval`, `simulated`, `executed` and `failed` (for example, safety refusals) | Upper-case action type: `BLOCK_IP`, `TEMPORARY_BLOCK`, `RATE_LIMIT`, `QUARANTINE`, `UNBLOCK_IP` | `system` for automatic decisions, otherwise the user | `engine`, `api`, `dashboard`, `cli` or `approval` |
| Rejected approval | `REJECT_RESPONSE` | Administrator | `approval` |
| Temporary block expired | `UNBLOCK_IP` (reason `temporary block expired`, outcome `executed`) | `system` | `engine` |
| Temporary block could not be removed | `UNBLOCK_IP` (reason `temporary block expired`, outcome `failed`, details with the error and `will_retry: true`) | `system` | `engine` |
| Runtime settings change | `UPDATE_SETTINGS` | User | `api`, `dashboard` or `cli` |
| Runtime change that turns dry run off or enables automatic prevention | `ENABLE_PREVENTION` | User | `api`, `dashboard` or `cli` |

Each response audit record carries `target`, `reason`, `outcome` and the full decision payload in `details`. Settings records carry a `{"changes": {field: {"from", "to"}}}` diff, and details pass through the same secret redaction as logs before storage.

These events are **not** audited: `alert` and `webhook` decisions, below-threshold proposals and "already blocked" skips. They are still counted in `sentinelx_responses_total`.

If an audit write fails inside the response engine, the error is logged as `audit_write_failed` and the firewall change is kept.

The following tables are also kept:

- **`response_actions`**: every published decision, from `response.decided` events, with `replay_id` for decisions made during replays.
- **`blocked_sources`**: block history with `active`, `expires_at`, `removed_at`, `removal_reason` and `backend`, from `ip.blocked` and `ip.unblocked` events, and reconciled with the firewall at server start.

The server writes both through its event persister.

## Enabling prevention safely

> **Warning:** Each step below changes how much SentinelX can do to traffic on this host. Do them in order, one at a time, and keep console or out-of-band access until you have verified the result.

1. **Run in detection-only mode first.** Keep the defaults. Replay representative captures (`sentinelx replay <pcap>`) and watch live detections for long enough to see normal peaks. Tune scores and thresholds as described in [risk-scoring.md](risk-scoring.md). Leave `SCORING__AUTO_BLOCK_THRESHOLD` at 85 or higher.

2. **Protect what must never be blocked.** Set `RESPONSE__MANAGEMENT_ADDRESSES` (operator workstations, jump hosts, monitoring, VPN egress) and `RESPONSE__ALLOWLIST_NETWORKS` (DNS resolvers, gateways, partners, your own scanners). Keep `RESPONSE__PROTECT_MANAGEMENT_ADDRESSES=true`. Confirm each critical address with `POST /api/v1/firewall/check`. The response must be `"allowed": false`. These lists can also be changed later, while prevention is active.

3. **Select and check a firewall backend.** Set `FIREWALL_BACKEND=auto`, or name one: `nftables` (preferred on Linux), `iptables`, `pf` or `windows_firewall`. Grant the service root or `CAP_NET_ADMIN` on Linux (in Docker Compose only the `capture` profile's `sensor` service has `NET_ADMIN`; the default `api` service cannot change the firewall; see [deployment.md](deployment.md)), root on macOS, or an elevated process on Windows. Run `sentinelx capabilities` and check that "Firewall control" is `AVAILABLE`, then run `sentinelx doctor` and fix every failure.

4. **Simulate automatic responses.** Set `RESPONSE_MODE=automatic` with `DRY_RUN=true` and restart. Review the `simulated` decisions (`GET /api/v1/firewall/actions?outcome=simulated`, or the Firewall page on the dashboard). Every simulated target should be one you would have blocked.

5. **Optionally, require approval.** Set `RESPONSE_MODE=manual_approval` with `DRY_RUN=false` and restart. The engine runs firewall setup at startup in this mode. Proposed actions wait for an administrator. Approve a few, then verify that they appear in `sentinelx blocked` and in the firewall itself (for example `nft list table inet sentinelx`), and that they expire when expected.

6. **Enable automatic prevention.** Use one of these:
   - **Environment (recommended):** set `RESPONSE_MODE=automatic` and `DRY_RUN=false`, then restart. Check that the startup banner reads `PREVENTION ACTIVE - automatic responses are enforced and will modify the <backend> firewall on this host`.
   - **Dashboard:** in Settings, under Response mode, choose Automatic, clear dry run and save. A dialog asks you to type the confirmation phrase `ENABLE PREVENTION`.
   - **API:** send `PATCH /api/v1/config/response` (administrator role). A change that turns dry run off, or that makes automatic prevention active, is refused without the exact phrase: `this change allows SentinelX to modify this host's firewall; resend with confirmation 'ENABLE PREVENTION'`.

     ```
     {"changes": {"mode": "automatic", "dry_run": false}, "confirmation": "ENABLE PREVENTION"}
     ```

   - **CLI:** run `sentinelx config set response mode '"automatic"'`, then `sentinelx config set response dry_run false --confirm-prevention`. `--confirm-prevention` is required for any change that turns dry run off or activates automatic prevention, and asks for an interactive confirmation. This persists the change, which applies on the next server start.

   Every runtime path is validated by the same settings guard, so it fails with the `null` backend, and it is audited as `ENABLE_PREVENTION`. A runtime change takes effect in the running server immediately; the firewall is set up on the first action. If `RESPONSE_MODE` or `DRY_RUN` is set in the environment, a runtime change to that field is overridden at the next start (see [Environment and stored overrides](#other-response-settings)).

7. **Verify.** Run `sentinelx status`, which reports the firewall with `enforcing=`, or call `GET /api/v1/firewall` and check `health.enforcing`. For nftables and iptables, `enforcing` becomes true once the table or chain exists. Then watch `sentinelx_safety_refusals_total`, `sentinelx_blocked_addresses` and `sentinelx_responses_total` over the first hours.

## Rolling back

### 1. Stop new enforcement

Use the fastest path available:

- **Dashboard:** in Settings, under Response mode, select dry run or Detection only and save. Disabling prevention needs no confirmation phrase.
- **API:** send `PATCH /api/v1/config/response` with `{"changes": {"dry_run": true}}`, or `{"changes": {"mode": "detect_only"}}`.
- **CLI:** run `sentinelx config set response dry_run true`. Because the CLI starts its own platform, this needs firewall privileges while prevention is active, and the running server picks the change up on its next start.
- **Environment:** set `DRY_RUN=true` and `RESPONSE_MODE=detect_only`, and restart. Explicit environment values for these two fields win over stored runtime overrides, so this works whatever was enabled at runtime.

After this step, existing blocks remain in force.

### 2. Remove individual blocks

```
sentinelx blocked
sentinelx unblock 203.0.113.45 --reason "rollback"
```

You can also use `POST /api/v1/firewall/unblock`. Unblocks are applied only when `DRY_RUN=false`; with dry run on, an unblock is `simulated`. To remove blocks after dry run is back on, use the firewall commands below.

### 3. Remove everything SentinelX added to the firewall

Stop SentinelX first. Otherwise, an engine that starts with prevention active or in `manual_approval` mode, or that makes its next change, creates the table or chain again. These commands follow the adapters' own teardown and use the default names; substitute `RESPONSE__NFT_FAMILY`, `RESPONSE__NFT_TABLE`, `RESPONSE__NFT_SET` and `RESPONSE__PF_ANCHOR` if you changed them.

nftables:

```
# inspect
nft list table inet sentinelx

# clear blocks and rate limits but keep the table
nft flush set inet sentinelx blocklist_v4
nft flush set inet sentinelx blocklist_v6
nft flush set inet sentinelx ratelimit_v4
nft flush set inet sentinelx ratelimit_v6

# remove the table entirely (what NftablesAdapter.teardown() does)
nft delete table inet sentinelx
```

iptables (repeat with `ip6tables`):

```
iptables -w -D INPUT -j SENTINELX
iptables -w -D FORWARD -j SENTINELX
iptables -w -F SENTINELX
iptables -w -X SENTINELX
```

pf:

```
pfctl -a com.apple/sentinelx -t sentinelx_block -T show     # inspect
pfctl -a com.apple/sentinelx -F all                          # remove the anchor's rules and table
```

Windows Firewall (elevated PowerShell):

```
Get-NetFirewallRule -Group SentinelX                          # inspect
Remove-NetFirewallRule -Group SentinelX
```

These commands only touch objects SentinelX owns. The nftables table has `policy accept` chains, so deleting it cannot leave the host default-deny. `pfctl -F all` on the anchor does not disable pf itself.

When you next start SentinelX, its registry is loaded from the firewall, so the removed entries are gone from `sentinelx blocked` and `GET /api/v1/firewall/blocked`, and the platform marks their `blocked_sources` history rows inactive with the reason `no longer present in the firewall`.

### 4. Confirm

Start SentinelX again and check the startup banner (`DETECTION ONLY` or `DRY RUN`). Then confirm that `sentinelx blocked` lists no active entries, and that `GET /api/v1/audit?action=ENABLE_PREVENTION` and `?action=UPDATE_SETTINGS` show the expected history.
