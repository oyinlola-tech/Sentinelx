# Security model

SentinelX sits in a sensitive position. It reads network traffic, stores information about hosts, and, in prevention mode, changes firewall rules. This document describes what SentinelX protects, what it assumes, the controls that enforce that, and the residual risks an operator must manage.

To report a vulnerability, follow [SECURITY.md](../SECURITY.md). Do not open a public issue.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| Firewall state on the sensor host | A wrong block cuts off legitimate users, or the operator's own access. |
| Captured traffic metadata | Addresses, DNS names, HTTP hosts and paths, TLS server names. This is personal data in many jurisdictions. |
| User accounts and sessions | An administrator can enable prevention and block addresses. |
| Configuration and secrets | `JWT_SECRET`, database and Redis credentials, the metrics token, reputation API keys. |
| Detection integrity | An attacker who can suppress or forge detections can hide or frame activity. |

| Boundary | Untrusted side |
|---|---|
| Packets entering the decoder | Anyone who can send traffic past the sensor. Every byte is hostile. |
| HTTP API and WebSocket | Any network client that can reach the API port. |
| Uploaded PCAP files and rule definitions | Authenticated users, who may still be wrong or compromised. |
| Threat-intelligence feeds | The feed provider and the network path to it. |
| The host, database and Redis | Trusted. SentinelX does not defend against a root-level attacker on its own host. |

## Controls

### Safe defaults

- `RESPONSE_MODE=detect_only` and `DRY_RUN=true` out of the box. SentinelX observes and explains; it does not touch traffic until an administrator changes both.
- `FIREWALL_BACKEND=null` by default. Settings validation refuses automatic response without dry run unless a real firewall backend is configured, so "prevention on" can never silently mean "prevention not working".
- Enabling prevention from the dashboard requires typing the confirmation phrase `ENABLE PREVENTION`, and the change is written to the audit log.
- `ENVIRONMENT=production` turns insecure configuration into a startup error instead of a warning. It refuses a missing or short (fewer than 32 characters) `JWT_SECRET`, disabled authentication, a wildcard CORS origin and SQLite. It also forces `Secure` cookies and disables the interactive API docs.

### Response safety guard

Every block, whether automatic, manual from the CLI, API or dashboard, or from a replay, passes through `SafetyGuard` in `packages/sentinelx/response/safety.py`. See [response-engine.md](response-engine.md) for each refusal code. In summary:

- Targets are parsed with Python's `ipaddress` module. Strings containing whitespace or control characters are rejected outright, which also prevents log injection.
- Loopback ranges are always in the allowlist and cannot be removed by configuration.
- Allowlisted networks, configured management addresses and the sensor's own interface addresses are never blocked, including when a requested prefix merely overlaps them.
- Prefixes larger than `max_block_prefix_hosts` (default 256 addresses, a /24) are refused, so a malformed rule cannot block an entire network.
- The number of concurrent blocks is capped (`max_blocked_addresses`, default 10,000), so a runaway detector hits a limit instead of exhausting the firewall.
- Temporary blocks are enforced with kernel-side set timeouts in nftables, so they expire even if SentinelX crashes.
- Firewall chains use `policy accept`. SentinelX only adds drop entries for specific addresses and never changes the host's default policy.
- Replays from the PCAP Lab run in an isolated pipeline forced into dry run with an in-memory firewall. A replayed capture cannot change the real firewall.

### Command execution

- Firewall commands run through `CommandRunner` in `packages/sentinelx/firewall/base.py`. It takes an argument vector, never a shell string, and rejects arguments containing control characters.
- Table and set names are validated against `^[A-Za-z0-9_]{1,32}$` in settings.
- Addresses reach the firewall only after the safety guard has normalised them.

### Hostile packet input

- Decoders are total: malformed, truncated or adversarial packets produce `None` or a partial result and increment a counter. They never raise into the pipeline.
- DNS name decompression detects pointer loops and bounds label and name lengths.
- The HTTP parser keeps only an allowlist of headers, and sensitive ones such as `Authorization` are reduced to a presence marker, so credentials seen on the wire never reach storage or logs.
- Per-source state is bounded (`max_tracked_sources`, default 50,000) with eviction, and every sliding-window structure in `packages/sentinelx/common/windows.py` updates in constant time. An earlier implementation was quadratic in window contents, which would have let an attacker slow the sensor by sending traffic that fills windows; scaling tests in `tests/unit/test_windows.py` guard against regression.
- Detector faults are isolated. An exception in one detector is logged and counted, and the other detectors still run.
- Detection cooldowns stop one attack from producing an unbounded stream of identical alerts. Genuine escalation (a higher severity, or a confidence increase of at least 0.2) is still reported.

### Rules and models

- The rule condition language is parsed by a hand-written tokenizer and recursive-descent parser. There is no `eval`, `exec` or template execution. Rule size, nesting depth and list lengths are bounded. See [rule-engine.md](rule-engine.md).
- A rule that triggers a preventive action must have a count threshold on every branch of its condition, so a rule matching a single packet cannot block addresses.
- Machine-learning model files are loaded with `joblib`, which can execute code embedded in the file. SentinelX therefore refuses to load a model file that is group- or world-writable or not owned by the current user, writes models with mode `0600`, and checks a format version and feature list. **Only load models you trained yourself.**

### Authentication and sessions

- Passwords are hashed with Argon2id. The policy favours length (minimum 12 characters by default) and rejects passwords that contain the username, are very common, or use very few distinct characters.
- A login with an unknown username is verified against a dummy hash, and every failure returns the same message, so usernames can't be enumerated by response content or timing.
- Accounts lock after `lockout_threshold` consecutive failures (default 5) for `lockout_seconds` (default 900). Login attempts are also rate-limited per client address (default 8 per 300 seconds).
- Access tokens are short-lived HS256 JWTs (default 15 minutes) with the accepted algorithms pinned when verifying, so `alg: none` and algorithm-confusion tokens are rejected. Refresh tokens are tracked server-side and rotated on every use; presenting an already-rotated refresh token revokes every refresh token for that user.
- A generated bootstrap administrator password is printed once to the server's standard error, never logged, and must be changed at first sign-in.
- The dashboard receives tokens in `HttpOnly`, `SameSite=Strict` cookies, and state-changing requests must carry a double-submit CSRF token in `X-CSRF-Token`. Scripts use bearer tokens instead.
- The dashboard proxies `/api` to the backend, so the browser talks to one origin and CORS can remain closed.
- WebSocket connections authenticate with a single-use ticket valid for 30 seconds, so a long-lived token never appears in a URL. The `Origin` header is checked against the configured origins. Invalid tickets close with code 4401; disallowed origins close with 1008.

### Authorisation

Three roles, checked on the server for every endpoint:

| Role | Can |
|---|---|
| `viewer` | Read detections, incidents, statistics and network views. |
| `analyst` | Everything a viewer can, plus triaging detections and updating incidents, validating and testing rules, uploading and replaying captures, previewing safety-guard decisions, and reading configuration and the audit log. |
| `admin` | Everything, including blocking, configuration changes, rule changes, sensor control and user management. |

Security decisions live in the service layer (`packages/sentinelx/services/`), not in route handlers, so the CLI and the API enforce the same rules. The full endpoint-to-role table is in [api.md](api.md).

### Transport, headers and rate limits

- API responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Cache-Control: no-store` on API routes, and `Strict-Transport-Security` when cookies are marked secure.
- API requests are rate-limited per client (default 300 per 60 seconds), shared across workers through Redis.
- `X-Forwarded-For` is ignored unless the direct peer is in `trusted_proxies`, so clients cannot spoof their address past the rate limiter or the audit log.
- SentinelX does not terminate TLS itself. In production, put it behind a reverse proxy that does, and set `trusted_proxies`. See [deployment.md](deployment.md).
- The Prometheus endpoint is served only to loopback clients unless `API__METRICS_TOKEN` is set, in which case a bearer token is required.

### Uploads

- PCAP uploads are streamed to disk with a size limit (the smaller of `max_upload_mb` and `max_pcap_size_mb`), their magic number is checked, and they are stored under a generated name.
- Replay paths are resolved inside the configured PCAP directory, with `.pcap`, `.pcapng` or `.cap` extensions only; path traversal is refused.

### Secrets and logging

- Secrets come from environment variables or an `.env` file that is git-ignored. No credential is hard-coded; `docker-compose.yml` refuses to start without the required passwords.
- Every log record passes through a redaction processor that replaces the values of sensitive keys (passwords, tokens, secrets, API keys, cookies, authorisation headers) and inline patterns such as `password=...` and `user:pass@` in URLs. It can't be disabled.
- Database URLs are shown with the password redacted in `sentinelx config show` and the API.
- Security-relevant actions are written to the audit log with the acting user, outcome and client address: sign-ins and failed sign-ins, sign-outs, password and user changes, response decisions that were executed or attempted (blocks, unblocks, rate limits, approvals and rejections), configuration changes (enabling prevention is recorded as its own action), rule changes, capture start and stop, PCAP uploads and replays, and detection and incident triage. Account lockouts and refresh-token reuse are recorded as warnings in the structured application log.

### Containers

- API and dashboard images run as non-root users. The API container is read-only with all capabilities dropped, and host ports are bound to loopback by default.
- Only the optional `capture` profile adds `NET_RAW` and `NET_ADMIN` and uses host networking, because live capture and firewall changes require them.

## Residual risks and operator responsibilities

- **Prevention can lock you out.** Add your management addresses and jump hosts to the allowlist or management list before enabling prevention. Test in `manual_approval` mode first.
- **Attackers can spoof sources.** A spoofed-source flood could get a victim address blocked. The safety guard protects configured addresses, not arbitrary third parties. Prefer rate limiting and short temporary blocks for flood detections, and keep `auto_block_threshold` high.
- **Detection is evadable.** Threshold detectors miss slow attacks by design. See [benchmarking.md](benchmarking.md). Encrypted traffic exposes metadata only.
- **The sensor is a target.** It processes hostile input in Python and keeps state in memory. Keep it patched, monitor its resource use, and don't run it on a host that holds unrelated secrets.
- **Stored traffic metadata is sensitive.** Set `RETENTION_DAYS` to the shortest period that meets your needs, restrict database access, and be clear about lawful basis and notice where your jurisdiction requires it.
- **Single-factor authentication.** SentinelX does not implement MFA or SSO. Put the dashboard behind your VPN or an authenticating reverse proxy if it must be reachable beyond a trusted network.
- **HS256 tokens share one secret.** Anyone holding `JWT_SECRET` can mint tokens. Rotating it invalidates all sessions.
- **Threat-intelligence feeds are trusted input.** A poisoned denylist raises scores for the listed addresses. The safety guard still applies to any resulting block.

## Hardening checklist

- [ ] `ENVIRONMENT=production`, with a random `JWT_SECRET` of at least 32 characters.
- [ ] PostgreSQL with a unique password; Redis with a password; neither reachable from untrusted networks.
- [ ] TLS terminated by a reverse proxy; `trusted_proxies` set to that proxy only.
- [ ] `CORS_ORIGINS` set to the dashboard's exact origin.
- [ ] The bootstrap administrator password changed, and personal accounts created with the least role needed.
- [ ] Management addresses and critical infrastructure added to the allowlist before prevention is enabled.
- [ ] Prevention trialled in `manual_approval` mode and with `DRY_RUN=true` before automatic mode.
- [ ] `RETENTION_DAYS` set deliberately.
- [ ] `API__METRICS_TOKEN` set if Prometheus scrapes from another host.
- [ ] The audit log reviewed regularly.
