# Response engine and prevention

This document describes what SentinelX does after a detection has been scored: how it decides on a response, the safety guard every preventive action must pass, the firewall adapters, how to enable prevention safely, and how to roll it back. It is written against:

| Component | File |
| --- | --- |
| Response engine | `packages/sentinelx/response/engine.py` |
| Safety guard | `packages/sentinelx/response/safety.py` |
| Enums | `packages/sentinelx/common/enums.py` (`ResponseMode`, `ActionType`) |
| Settings | `packages/sentinelx/config/settings.py` (`ResponseSettings`) |
| Firewall adapters | `packages/sentinelx/firewall/base.py`, `nftables.py`, `iptables.py`, `memory.py`, `__init__.py` |
| Runtime configuration | `packages/sentinelx/services/config.py` |
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

Prevention is active (`ResponseSettings.prevention_active`) **only** when `RESPONSE_MODE=automatic` and `DRY_RUN=false` are both set. On startup, the platform logs one of three safety banners from `Settings.safety_banner()`:

| Banner | Condition |
| --- | --- |
| `PREVENTION ACTIVE - responses will modify the <backend> firewall on this host` | Mode is `automatic` and dry run is off. |
| `DRY RUN - response decisions are recorded and shown but not applied` | Dry run is on and mode is not `detect_only`. |
| `DETECTION ONLY - no traffic will be modified` | Any other combination. |

`DETECTION ONLY` also appears for `detect_only` or `manual_approval` with `DRY_RUN=false`. In those combinations, automatic prevention is off, but manual and approved actions are applied to the firewall. See [Response modes](#response-modes).

> **Warning:** For the flat `DRY_RUN` variable, only `1`, `true`, `yes` and `on` (case-insensitive) mean true. **Any other value, including a typo, is read as false.** Check the startup banner after every configuration change.

### The settings guard

`ResponseSettings` refuses to load when `mode` is `automatic`, `dry_run` is false and `firewall_backend` is `null`:

```
RESPONSE_MODE=automatic with DRY_RUN=false requires a real FIREWALL_BACKEND (nftables or iptables), not 'null'
```

This check applies at startup and to every runtime change, because runtime changes are validated by the same model. It does **not** cover `manual_approval` or `detect_only` with `DRY_RUN=false`. With the `null` backend, those combinations report `executed` outcomes against the in-memory firewall, which enforces nothing.

## Response modes

`ResponseMode` controls how much autonomy the engine has over **automatic**, detector-driven preventive actions.

| `RESPONSE_MODE` | `DRY_RUN` | Outcome of an automatic preventive action at or above the threshold |
| --- | --- | --- |
| `detect_only` (default) | any | `skipped`. The reason ends with `not applied (RESPONSE_MODE=detect_only)`. |
| `manual_approval` | any | The safety guard runs first. If it passes, the action is queued and the outcome is `pending_approval`. If the guard refuses, the outcome is `failed`. |
| `automatic` | `true` | The safety guard runs. If it passes, the outcome is `simulated` and the reason ends with `[DRY RUN - not applied]`. |
| `automatic` | `false` | The safety guard runs, then the action is applied to the firewall. The outcome is `executed` or `failed`. |

**Manual actions** (`sentinelx block` and `unblock`, the API block and unblock endpoints, the dashboard, and approvals of queued actions) ignore `RESPONSE_MODE`, because a person made the decision. They still honour `DRY_RUN` and always pass the safety guard. Unblocking is the one exception to the guard (see [Manual actions](#manual-actions)).

Running `mixed_intrusion` from `packages/sentinelx/testing/scenarios.py` through the pipeline with default settings opens an incident at risk 88.6. The incident-level temporary block for the attacking source is then recorded as follows:

| Environment | Recorded outcome |
| --- | --- |
| defaults | `skipped`, reason `incident 'Potential host compromise attempt' risk 89/100; not applied (RESPONSE_MODE=detect_only)` |
| `RESPONSE_MODE=automatic DRY_RUN=true` | `simulated`, reason `incident 'Potential host compromise attempt' risk 89/100 [DRY RUN - not applied]` |
| `RESPONSE_MODE=manual_approval` | `pending_approval`, reason `incident 'Potential host compromise attempt' risk 89/100` |
| `RESPONSE_MODE=automatic DRY_RUN=false FIREWALL_BACKEND=nftables`, with the pipeline given the in-memory firewall | `executed` |

## Action types

`ActionType` defines the following values. The table shows what the response engine actually does with each one.

| Value | Preventive | Behaviour in `response/engine.py` |
| --- | --- | --- |
| `alert` | no | Created for **every** scored detection, with outcome `executed`. It is counted in metrics but not published as a response decision or audited, because the detection itself is the record. |
| `log` | no | No behaviour. If a detector or rule recommends it, only the `alert` decision is produced. |
| `webhook` | no | Sent when `RESPONSE__WEBHOOK_URL` is set and the detection's risk is at or above `webhook_min_risk`. See [Webhook](#webhook). |
| `block_ip` | yes | Adds the target to the firewall block list with no expiry. |
| `temporary_block` | yes | Same as `block_ip`, with a duration. Automatic temporary blocks use `default_block_seconds`. |
| `rate_limit` | yes | Adds the target to the firewall rate-limit list. Automatic rate limits use `default_block_seconds` as their duration. The rate is `rate_limit_packets_per_second`. |
| `quarantine` | yes | Handled exactly like `block_ip`: the source address is blocked with no expiry. No separate isolation is implemented. |
| `unblock_ip` | yes | Removes the target from the block and rate-limit lists. Only possible as a manual action. Automatic handling ignores it, and rules may not use it. |
| `none` | no | No behaviour beyond the `alert` decision. |

"Preventive" is `ActionType.is_preventive`. Preventive actions are the ones gated by mode, dry run and the safety guard.

Automatic durations come from `RESPONSE__DEFAULT_BLOCK_SECONDS`. A rule's own `duration` field is validated when the rule loads, but the response engine does not currently use it.

## Decision flow

### `handle_detection(detection, risk)`

The pipeline calls this for every scored detection.

1. Record an `alert` decision (`executed`).
2. If `webhook_url` is set and `risk.score >= webhook_min_risk`, send the webhook and record a `webhook` decision.
3. Read `detection.recommended_action`. If it is not preventive, or it is `unblock_ip`, stop.
4. If `risk.score < scoring.auto_block_threshold` (default 85), record the action as `skipped` with the reason `not applied: risk N is below the automatic response threshold of 85` and stop. This decision is not published or audited.
5. Otherwise, pass the action to the automatic path with the detection's source address as the target. The duration is `default_block_seconds` for `temporary_block` and `rate_limit`, and none for the other actions.

### `handle_incident(incident)`

The pipeline calls this after `handle_detection`, only when the incident was **just created** or its **severity increased**.

1. If `incident.risk.score < auto_block_threshold`, do nothing.
2. For each address in `incident.affected_sources`, sorted, that is not already in the engine's block registry: send a `temporary_block` for `default_block_seconds` to the automatic path. The incident's risk rationale becomes the evidence.

### The automatic path

`ResponseEngine._automatic` handles each proposed action in this order:

1. **Already blocked.** For `block_ip` and `temporary_block`, if the target is already in the block registry, the decision is `skipped` with the reason suffix `; already blocked`. It is not published or audited.

   In the current release, this check (and the matching one in `handle_incident`) compares the bare target address, for example `203.0.113.9`, with registry keys, which are normalised networks such as `203.0.113.9/32`. It therefore does not match single-host targets, and a repeated automatic block of the same address is sent to the firewall again.
2. **`detect_only`.** The decision is `skipped` and audited.
3. **Safety guard.** If the guard refuses the target, the decision is `failed` with the error `safety guard: <reason>`, and it is audited. This check runs **before** queueing, so an administrator is never asked to approve an action that cannot be carried out.
4. **`manual_approval`.** A `PendingAction` is queued with action, target, reason, risk, duration, detection or incident id, evidence and an `action_id`. `response.pending_approval` is published. If an action of the same type for the same target is already pending, no duplicate is queued. The decision is `pending_approval`.
5. **`automatic`.** The action is executed (see [Execution](#execution)).

### Execution

`_execute` handles automatic, manual and approved actions in the same way:

- **Dry run on.** The decision is `simulated` and the firewall is not called.
- **Dry run off.** The adapter is called under a lock. For blocks and rate limits, the safety guard checks the target **again** first:
  - `block_ip`, `temporary_block` and `quarantine` call `firewall.block(network, duration, comment)`. The comment is the decision reason cut to 120 characters. `ip.blocked` is published.
  - `rate_limit` calls `firewall.rate_limit(network, packets_per_second, duration)`. `ip.blocked` is published.
  - `unblock_ip` calls `firewall.unblock(network)`, and `ip.unblocked` is published. The outcome is `executed` if the firewall removed an entry, and `skipped` if nothing was there to remove.
- A `FirewallError`, `SafetyViolationError` or `ValueError` during execution produces a `failed` decision that contains the error message. It is never raised to the caller.
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

Every decision is counted in `sentinelx_responses_total{action,outcome}`. Decisions other than `alert` are published as `response.decided` and stored in the `response_actions` table, except those recorded as non-actions (below threshold, already blocked, webhook). Preventive decisions are also written to the audit log (see [Audit trail](#audit-trail)).

### Manual approval

In `manual_approval` mode, queued actions are held **in memory** by the running server. They are not persisted, and a restart discards them.

| Operation | API (administrator role) |
| --- | --- |
| List pending actions | `GET /api/v1/firewall/approvals` (viewer role is enough) |
| Approve | `POST /api/v1/firewall/approvals/{action_id}/approve` |
| Reject | `POST /api/v1/firewall/approvals/{action_id}/reject` with body `{"reason": "..."}` |

Both approve and reject return 404 for an unknown `action_id`.

- **Approve** removes the pending action and runs it as a manual action with the reason `approved: <original reason>` and source `approval`. The safety guard runs again, and `DRY_RUN` still applies: with `DRY_RUN=true`, an approved action is `simulated`.
- **Reject** removes the pending action and writes a `REJECT_RESPONSE` audit record with the pending action's details.

### Temporary block expiry

When the engine starts, it launches a reaper task that wakes **every 5 seconds**. For each registry entry whose `expires_at` has passed, the reaper:

1. calls `firewall.unblock(network)`. A `FirewallError` is logged as `expiry_unblock_failed`, and the entry is removed from the registry anyway;
2. publishes `ip.unblocked` with the reason `temporary block expired`; and
3. writes an `UNBLOCK_IP` audit record with actor `system`, source `engine`, outcome `executed`.

For nftables, the kernel also expires the set element on its own, so a temporary block lapses on time even if SentinelX is not running. For iptables, the reaper is the only expiry mechanism. See [iptables](#iptables) for the consequences.

### Engine startup

`ResponseEngine.start()`:

1. Calls `firewall.setup()` **only** when prevention is active or the mode is `manual_approval`. If setup fails, startup is aborted with the error.
2. Loads the firewall's current entries (`list_blocked`) into the block registry, so blocks that survived a restart are known.
3. Starts the expiry reaper.

The nftables table and the iptables chain are therefore **not** created in `detect_only` mode or in `automatic` with dry run on. They are also not created when prevention is enabled at runtime from one of those modes. Restart the server after enabling prevention (see [Enabling prevention safely](#enabling-prevention-safely)).

### Webhook

When `RESPONSE__WEBHOOK_URL` is set, each detection with risk at or above `RESPONSE__WEBHOOK_MIN_RISK` (default 60.0) is sent as a JSON `POST` with this body:

```
type ("sentinelx.detection"), title, detector, severity, risk, risk_band,
source_ip, destination_ip, evidence, timestamp
```

The request uses a timeout of `RESPONSE__WEBHOOK_TIMEOUT_SECONDS` (default 5.0). A failed request produces a `webhook` decision with the outcome `failed` and the error `webhook failed: <ExceptionName>`. The decision target is the URL without its query string. Webhook decisions are not audited.

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
| 8 | `local_address` | `protect_management_addresses` is true (default) and the prefix contains an address assigned to any interface on this host. | `10.0.0.0/24 contains 10.0.0.5, an address of this host` |
| 9 | `block_limit_reached` | The engine already holds `max_blocked_addresses` or more active entries (default 10,000). Blocks and rate limits both count. | `1 blocks already active (response.max_blocked_addresses)` |

The example reasons were produced by `SafetyGuard.evaluate()` with an allowlist of `192.0.2.0/28`, a management address of `198.51.100.7`, a local address of `10.0.0.5` injected in place of interface discovery, and, for check 9, `max_blocked_addresses=1` with one active block.

Overlap is checked in both directions. Blocking `10.0.0.0/24` fails when the sensor is `10.0.0.5`, even though the /24 itself is not listed.

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
| `protect_management_addresses` | `RESPONSE__PROTECT_MANAGEMENT_ADDRESSES` | `true` | no |
| `max_block_prefix_hosts` | `RESPONSE__MAX_BLOCK_PREFIX_HOSTS` | `256` (>= 1) | yes |
| `max_blocked_addresses` | `RESPONSE__MAX_BLOCKED_ADDRESSES` | `10000` (>= 1) | yes |

List values in environment variables are JSON arrays. Invalid networks are rejected when settings load. The allowlist can also be replaced with `PUT /api/v1/firewall/allowlist` and the body `{"networks": [...]}` (administrator role). Loopback is always retained.

`protect_management_addresses` protects addresses assigned to local interfaces. It does not detect remote clients connected to the API, so add your workstation and jump hosts to `management_addresses` explicitly.

## Other response settings

| Setting | Environment variable | Default | Runtime-editable |
| --- | --- | --- | --- |
| `mode` | `RESPONSE_MODE` or `RESPONSE__MODE` | `detect_only` | yes |
| `dry_run` | `DRY_RUN` or `RESPONSE__DRY_RUN` | `true` | yes |
| `firewall_backend` | `FIREWALL_BACKEND` or `RESPONSE__FIREWALL_BACKEND` | `null` (`nftables`, `iptables`, `null`) | no |
| `nft_table` | `RESPONSE__NFT_TABLE` | `sentinelx` (`^[A-Za-z0-9_]{1,32}$`) | no |
| `nft_set` | `RESPONSE__NFT_SET` | `blocklist` (`^[A-Za-z0-9_]{1,32}$`) | no |
| `nft_family` | `RESPONSE__NFT_FAMILY` | `inet` (`inet`, `ip`, `ip6`) | no |
| `default_block_seconds` | `RESPONSE__DEFAULT_BLOCK_SECONDS` | `900` (30-86400) | yes |
| `max_block_seconds` | `RESPONSE__MAX_BLOCK_SECONDS` | `86400` (>= 60) | yes |
| `rate_limit_packets_per_second` | `RESPONSE__RATE_LIMIT_PACKETS_PER_SECOND` | `100` (>= 1) | yes, but adapters read it only at construction, so a change applies after a restart |
| `webhook_url` | `RESPONSE__WEBHOOK_URL` | empty (disabled) | yes |
| `webhook_timeout_seconds` | `RESPONSE__WEBHOOK_TIMEOUT_SECONDS` | `5.0` | yes |
| `webhook_min_risk` | `RESPONSE__WEBHOOK_MIN_RISK` | `60.0` | yes |

When both the flat and the nested form of a variable are set, the nested form (`RESPONSE__...`) wins. The automatic threshold is `SCORING__AUTO_BLOCK_THRESHOLD`, default 85.0. See [risk-scoring.md](risk-scoring.md).

## Firewall adapters

`create_firewall(settings.response)` builds the adapter selected by `FIREWALL_BACKEND`. The response engine is the only component that calls an adapter, and it only passes networks that have already passed the safety guard.

### Command execution

The nftables and iptables adapters run commands through `CommandRunner` (`packages/sentinelx/firewall/base.py`):

- **Arguments are passed as a list**, using `asyncio.create_subprocess_exec`. No code path invokes a shell.
- **The binary path is fixed once.** It is resolved with `shutil.which` at construction, and a missing binary raises `FirewallError` (`<binary> is not installed or not on PATH`).
- **Arguments are checked.** Every argument must be a `str`, and any argument that contains a NUL byte or a newline is refused (`refusing firewall argument containing control characters`).
- **Addresses come from `ipaddress` objects**, never from raw input.
- **Every command has a timeout** (default 10 seconds). On timeout the process is killed and `FirewallError` is raised.
- **Every command is logged** at debug level as `firewall_command`, with its return code and duration. A non-zero exit raises `FirewallError` with the command's stderr, unless the caller passed `check=False`.

The runner can prefix `sudo -n`, but no setting enables this. SentinelX therefore needs root or `CAP_NET_ADMIN` to change the firewall. `sentinelx doctor` reports whether the configured backend's binary is installed and whether firewall privileges are available.

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
- **Blocks are set elements, not rules.** A block runs `nft add element <family> <table> <set> { <address-or-prefix> [timeout <N>s] }`. A single host is written as its bare address.
- **Temporary blocks use kernel timeouts.** The kernel removes the element when the timeout expires.
- **Rate limits use one rate for all sources.** The rate is in the rule, not in each element, so a request for a different rate logs `rate_limit_uses_configured_rate` and uses `rate_limit_packets_per_second`.
- **Unblocking** deletes the element from both the block set and the rate-limit set for that IP version.
- **Listing** reads `nft -j list set` for each of the four sets.
- **`teardown()`** runs `nft delete table <family> <table>`. No CLI command calls it. See [Rolling back](#rolling-back).

### iptables

`IptablesAdapter` owns one chain, `SENTINELX`, in both `iptables` and `ip6tables`:

- **Setup** creates the chain (`-N SENTINELX`) and inserts `-j SENTINELX` at position 1 of `INPUT` and `FORWARD` if that jump is not already present. Every command uses `-w`.
- **Block** inserts `-s <net> -m comment --comment sentinelx -j DROP` at the top of `SENTINELX`, unless an identical rule already exists (checked with `-C`).
- **Rate limit** appends `-s <net> -m hashlimit --hashlimit-above <pps>/sec --hashlimit-mode srcip --hashlimit-name sx<12 hex chars> -m comment --comment sentinelx -j DROP`.
- **Unblock** deletes every copy of both rule forms for the network.
- **IPv6.** If `ip6tables` is not installed, the adapter logs `ip6tables_unavailable`, and every IPv6 action fails with `ip6tables is not installed; cannot block IPv6 addresses`.

> **Warning:** iptables has no per-rule expiry. Temporary blocks are removed only by the reaper of the SentinelX process that created them, and the deadline is kept in that process's memory. A temporary block created by a short-lived CLI command (`sentinelx block --duration ...`), or one still active when the server restarts, stays in place until it is removed manually. Prefer nftables.

### Memory (`null` backend)

`MemoryFirewall` is the `null` backend. It is also the adapter used by `Pipeline` when none is given, and by PCAP replays. It keeps entries, including expiry times, in a Python dictionary, reports `enforcing: false` in its health output and **changes nothing on the host**. Each process has its own instance, so blocks recorded by one process (for example a CLI command) are not visible to another (the server).

## Manual actions

`ResponseEngine.manual_action(action, target, actor, reason, duration, source)`:

- ignores `RESPONSE_MODE`;
- honours `DRY_RUN` (a dry-run request returns a `simulated` decision);
- runs the safety guard for every action except `unblock_ip`, so an unblock is never refused by the allowlist;
- clamps `duration` to at most `max_block_seconds`; and
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
- **Confirmation.** When `DRY_RUN=false` or prevention is active, the command asks for confirmation unless `--yes` is given.
- **Output and exit code.** The command prints the outcome and reason, and exits with status 1 when the decision has an error (for example, a safety refusal).
- **Audit fields.** The audit source is `cli`, and the actor is `cli:<local username>`.
- **`sentinelx blocked`** shows the active entries reported by the configured backend and the 10 most recent entries of block history from the database.

Examples:

```
sentinelx block 203.0.113.45 --duration 3600 --reason "SSH brute force from incident 1234"
sentinelx block 203.0.113.0/28 --rate-limit --reason "HTTP flood"
sentinelx unblock 203.0.113.45 --reason "false positive, customer NAT"
sentinelx blocked
```

Operational notes that follow from each CLI command using its own engine:

- **`null` backend.** A block from the CLI only exists in that command's memory. It does not affect the running server, and `sentinelx blocked` in another process cannot see it.
- **nftables in `detect_only` mode.** The CLI engine does not run `setup()`, so a block fails unless the `inet sentinelx` table already exists. The table is created when an engine starts with prevention active or in `manual_approval` mode.
- **Privileges.** When prevention is active or the mode is `manual_approval`, each CLI command runs firewall setup at startup and needs the same privileges as the service.

### API

All of these endpoints require an authenticated user (see [api.md](api.md)). Block, unblock, approve, reject and allowlist changes require the administrator role.

| Method and path | Role | Body or parameters |
| --- | --- | --- |
| `POST /api/v1/firewall/block` | admin | `{"target": str, "reason": str (3-500), "duration_seconds": int 30-604800 or null, "rate_limit": bool}` |
| `POST /api/v1/firewall/unblock` | admin | `{"target": str, "reason": str (3-500)}` |
| `POST /api/v1/firewall/check` | analyst | `{"target": str}` |
| `GET /api/v1/firewall` | viewer | Response status, adapter health, active entries, block history, recent actions, pending approvals |
| `GET /api/v1/firewall/blocked` | viewer | Active entries, reconciled with the adapter |
| `GET /api/v1/firewall/actions` | viewer | `target`, `outcome` (repeatable), `limit` (1-500), `offset` |
| `GET /api/v1/firewall/allowlist` | viewer | Response allowlist, detection allowlist, management addresses |
| `PUT /api/v1/firewall/allowlist` | admin | `{"networks": [str, ...]}` |

For block requests, `rate_limit: true` selects `rate_limit`. Otherwise, a `duration_seconds` value selects `temporary_block`, and no duration selects `block_ip`. The duration is then clamped to `max_block_seconds`.

Block and unblock return the decision payload: `decision_id`, `action`, `target`, `reason`, `outcome`, `executed`, `dry_run`, `requires_approval`, `duration_seconds`, `detection_id`, `incident_id`, `error` and `decided_at`. A refused or failed action still returns HTTP 200, and the payload then includes `http_note` and a non-null `error`. Always check `outcome`.

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
| Temporary block expired | `UNBLOCK_IP` (reason `temporary block expired`) | `system` | `engine` |
| Runtime settings change | `UPDATE_SETTINGS` | User | `api`, `dashboard` or `cli` |
| Runtime change that enables prevention | `ENABLE_PREVENTION` | User | `api`, `dashboard` or `cli` |

Each response audit record carries `target`, `reason`, `outcome` and the full decision payload in `details`. Settings records carry a `{"changes": {field: {"from", "to"}}}` diff, and secrets are redacted before storage.

These events are **not** audited: `alert` and `webhook` decisions, below-threshold proposals and "already blocked" skips. They are still counted in `sentinelx_responses_total`.

If an audit write fails inside the response engine, the error is logged as `audit_write_failed` and the firewall change is kept.

The following tables are also kept:

- **`response_actions`**: every published decision, from `response.decided` events.
- **`blocked_sources`**: block history with `active`, `expires_at`, `removed_at`, `removal_reason` and `backend`, from `ip.blocked` and `ip.unblocked` events.

The server writes both through its event persister. CLI commands run with persistence off, so their decisions reach the audit log but not these two tables.

## Enabling prevention safely

> **Warning:** Each step below changes how much SentinelX can do to traffic on this host. Do them in order, one at a time, and keep console or out-of-band access until you have verified the result.

1. **Run in detection-only mode first.** Keep the defaults. Replay representative captures (`sentinelx replay <pcap>`) and watch live detections for long enough to see normal peaks. Tune scores and thresholds as described in [risk-scoring.md](risk-scoring.md). Leave `SCORING__AUTO_BLOCK_THRESHOLD` at 85 or higher.

2. **Protect what must never be blocked.** Set `RESPONSE__MANAGEMENT_ADDRESSES` (operator workstations, jump hosts, monitoring, VPN egress) and `RESPONSE__ALLOWLIST_NETWORKS` (DNS resolvers, gateways, partners, your own scanners). Keep `RESPONSE__PROTECT_MANAGEMENT_ADDRESSES=true`. Confirm each critical address with `POST /api/v1/firewall/check`. The response must be `"allowed": false`.

   Make these changes **before** step 6. While prevention is active, the runtime configuration service refuses any `response` change that would leave prevention on, including `PUT /api/v1/firewall/allowlist`, and returns `stored settings would enable prevention; refusing to apply them without confirmation`. To change the allowlist at that point, turn dry run back on, make the change, then re-enable prevention. Alternatively, set the value in the environment and restart.

3. **Select and check a firewall backend.** Set `FIREWALL_BACKEND=nftables` (preferred) or `iptables`. Grant the service root or `CAP_NET_ADMIN`; the compose `sensor` service adds `NET_ADMIN` (see [deployment.md](deployment.md)). Run `sentinelx doctor` and fix every failure.

4. **Simulate automatic responses.** Set `RESPONSE_MODE=automatic` with `DRY_RUN=true` and restart. Review the `simulated` decisions (`GET /api/v1/firewall/actions?outcome=simulated`, or the Firewall page on the dashboard). Every simulated target should be one you would have blocked.

5. **Optionally, require approval.** Set `RESPONSE_MODE=manual_approval` with `DRY_RUN=false` and restart. The engine runs firewall setup at startup in this mode. Proposed actions wait for an administrator. Approve a few, then verify that they appear in `sentinelx blocked` and in `nft list table inet sentinelx`, and that they expire when expected.

6. **Enable automatic prevention.** Use one of these:
   - **Environment (recommended):** set `RESPONSE_MODE=automatic` and `DRY_RUN=false`, then restart. Check that the startup banner reads `PREVENTION ACTIVE - responses will modify the nftables firewall on this host`.
   - **Dashboard:** in Settings, under Response mode, choose Automatic, clear dry run and save. A dialog asks you to type the confirmation phrase `ENABLE PREVENTION`.
   - **API:** send `PATCH /api/v1/config/response` (administrator role). Without the exact phrase, the request is refused with `enabling prevention allows SentinelX to modify this host's firewall automatically; resend with confirmation 'ENABLE PREVENTION'`.

     ```
     {"changes": {"mode": "automatic", "dry_run": false}, "confirmation": "ENABLE PREVENTION"}
     ```

   - **CLI:** run `sentinelx config set response mode '"automatic"'`, then `sentinelx config set response dry_run false --confirm-prevention`. This persists the change, which applies on the next server start.

   Every runtime path is validated by the same settings guard, so it fails with the `null` backend. It is also audited as `ENABLE_PREVENTION`. A change made at runtime does not run firewall setup, so if the server was not started in `manual_approval` mode, **restart it** so the table or chain is created.

7. **Verify.** Run `sentinelx status`, which reports the firewall with `enforcing=`, or call `GET /api/v1/firewall` and check `health.enforcing`. Then watch `sentinelx_safety_refusals_total`, `sentinelx_blocked_addresses` and `sentinelx_responses_total` over the first hours.

> **Warning:** Runtime settings changes are stored in the database and applied **on top of** the environment at every start. If prevention was enabled from the dashboard, API or `sentinelx config set`, setting `DRY_RUN=true` in the environment alone will **not** disable it after a restart. Disable it through the same runtime path, as described in the next section. The same applies in the other direction: a stored `dry_run: true` or `mode` override takes precedence over environment values you set in step 6.

## Rolling back

### 1. Stop new enforcement

Use the fastest path available:

- **Dashboard:** in Settings, under Response mode, select dry run or Detection only and save. Disabling prevention needs no confirmation phrase.
- **API:** send `PATCH /api/v1/config/response` with `{"changes": {"dry_run": true}}`, or `{"changes": {"mode": "detect_only"}}`.
- **CLI:** run `sentinelx config set response dry_run true`. Because the CLI starts its own platform, this needs firewall privileges while prevention is active, and the running server picks the change up on its next start.
- **Environment:** set `DRY_RUN=true` and `RESPONSE_MODE=detect_only`, and restart. As the warning above explains, this is sufficient only if no runtime override keeps prevention on.

After this step, existing blocks remain in force.

### 2. Remove individual blocks

```
sentinelx blocked
sentinelx unblock 203.0.113.45 --reason "rollback"
```

You can also use `POST /api/v1/firewall/unblock`. Unblocks are applied only when `DRY_RUN=false`; with dry run on, an unblock is `simulated`. To remove blocks after dry run is back on, use the firewall commands below.

### 3. Remove everything SentinelX added to the firewall

Stop SentinelX first. Otherwise, an engine that starts with prevention active or in `manual_approval` mode creates the table or chain again. These commands follow the adapters' own teardown and use the default names; substitute `RESPONSE__NFT_FAMILY`, `RESPONSE__NFT_TABLE` and `RESPONSE__NFT_SET` if you changed them.

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

These commands only touch objects SentinelX owns. The nftables table has `policy accept` chains, so deleting it cannot leave the host default-deny.

When you next start SentinelX, its in-memory registry is loaded from the firewall, so the removed entries are gone from `sentinelx blocked` and `GET /api/v1/firewall/blocked`. The `blocked_sources` history rows in the database are not updated by manual firewall commands, and they still show those entries as active.

### 4. Confirm

Start SentinelX again and check the startup banner (`DETECTION ONLY` or `DRY RUN`). Then confirm that `sentinelx blocked` lists no active entries, and that `GET /api/v1/audit?action=ENABLE_PREVENTION` and `?action=UPDATE_SETTINGS` show the expected history.
