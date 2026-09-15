# Security model

SentinelX sits in a sensitive position. It reads network traffic, stores information about hosts, and, in prevention mode, changes firewall rules. This document describes what SentinelX protects, what it assumes, the controls that enforce that, and the residual risks an operator must manage.

To report a vulnerability, follow [SECURITY.md](../SECURITY.md). Do not include vulnerability details in a public issue.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| Firewall state on the sensor host | A wrong block cuts off legitimate users, or the operator's own access. |
| Captured traffic metadata | Addresses, DNS names, HTTP hosts and paths, TLS server names. This is personal data in many jurisdictions. |
| Uploaded capture files | Full packet contents, including any cleartext credentials they happen to contain. |
| User accounts and sessions | An administrator can enable prevention and block addresses. |
| Configuration and secrets | `JWT_SECRET`, database and Redis credentials, the metrics token, the webhook URL (which often embeds a secret), reputation API keys. |
| Detection integrity | An attacker who can suppress or forge detections can hide or frame activity. |

| Boundary | Untrusted side |
|---|---|
| Packets entering the decoder | Anyone who can send traffic past the sensor. Every byte is hostile. |
| HTTP API and WebSocket | Any network client that can reach the API port or the dashboard proxy. |
| Uploaded PCAP files, rule definitions and scenario parameters | Authenticated analysts, who may still be wrong or compromised. |
| Threat-intelligence feeds | The feed provider and the network path to it. |
| Webhook receivers | The receiving service, and DNS for its host name. |
| The host, database and Redis | Trusted. SentinelX does not defend against a root-level attacker on its own host. |

## Controls

### Safe defaults

- `RESPONSE_MODE=detect_only` and `DRY_RUN=true` out of the box. SentinelX observes and explains; it does not touch traffic until an administrator changes both.
- `FIREWALL_BACKEND=null` by default. Settings validation refuses `automatic` or `manual_approval` mode without dry run unless a real firewall backend is configured, so "prevention on" can never silently mean "prevention not working".
- Any runtime change that lets SentinelX modify the firewall where it cannot now requires the confirmation phrase `ENABLE PREVENTION`: switching dry run off (manual blocks and approvals become real) as well as turning automatic prevention on. The dashboard asks the operator to type the phrase, the API refuses the change without it, and the change is written to the audit log as `ENABLE_PREVENTION`.
- The safety banner describes every path that can change the firewall, not only automatic responses. With dry run off in `detect_only` mode it reads `MANUAL BLOCKS ENFORCED - automatic responses are off; administrator blocks are enforced ...`, and it says so when no firewall backend is configured and blocks would be refused.
- Runtime settings stored in the database are re-applied at startup, but when the environment explicitly sets `RESPONSE_MODE` or `DRY_RUN`, the environment wins and a warning is logged. An operator can always switch prevention off by editing the environment and restarting, whatever was enabled from the dashboard.
- `ENVIRONMENT=production` turns insecure configuration into a startup error instead of a warning. It refuses a missing or short (fewer than 32 characters) `JWT_SECRET`, disabled authentication, a wildcard CORS origin and SQLite. It also forces `Secure` cookies and disables the interactive API docs.

### Response safety guard

Every block, whether automatic, manual from the CLI, API or dashboard, or from a replay, passes through `SafetyGuard` in `packages/sentinelx/response/safety.py`. See [response-engine.md](response-engine.md) for each refusal code. In summary:

- Targets are parsed with Python's `ipaddress` module. Strings containing whitespace or control characters are rejected outright, which also prevents log injection. A `/0` prefix is refused.
- Loopback ranges are always in the allowlist and cannot be removed by configuration. Loopback, link-local, multicast, unspecified and reserved addresses are refused.
- Allowlisted networks and configured management addresses are never blocked, including when a requested prefix merely overlaps them.
- With `protect_management_addresses` (default `true`), the sensor's own interface addresses are never blocked; if they cannot be listed, the guard refuses rather than guessing. The same setting protects the address of every operator who made an authenticated API request in the last hour, so an administrator cannot block their own workstation or a prefix containing it. These operator addresses are remembered in the API process (at most 1,024).
- Prefixes larger than `max_block_prefix_hosts` (default 256 addresses, a /24) are refused, so a malformed rule cannot block an entire network.
- The number of concurrent blocks is capped (`max_blocked_addresses`, default 10,000), so a runaway detector hits a limit instead of exhausting the firewall.
- Temporary blocks are enforced with kernel-side set timeouts in nftables, so they expire even if SentinelX crashes.
- Firewall chains use `policy accept`. SentinelX only adds drop entries for specific addresses and never changes the host's default policy.
- Replays from the PCAP Lab run in an isolated pipeline forced into dry run with the `null` backend and an in-memory firewall. A replayed capture cannot change the real firewall. Its decisions are tagged with the replay id and excluded from the live firewall history.

### Command execution

- Firewall commands run through `CommandRunner` in `packages/sentinelx/firewall/base.py`. It takes an argument vector, never a shell string, rejects arguments containing control characters, and kills a command that exceeds its timeout. It is the only place the package starts a subprocess.
- Table and set names are validated against `^[A-Za-z0-9_]{1,32}$` in settings.
- Addresses reach the firewall only after the safety guard has normalised them. The guard refuses IPv6 zone identifiers (`fe80::1%eth0`), whose text after `%` is free-form, and every adapter refuses them again through `firewall_address()` in `packages/sentinelx/firewall/base.py`, so that text never reaches `nft`, `iptables`, `pfctl` or a PowerShell script. An unblock, which skips the guard, validates its target the same way.
- IPv6 targets that embed a protected IPv4 address (IPv4-mapped, 6to4, Teredo or NAT64 forms of loopback, this host's addresses, management or operator addresses, or the allowlist) are refused as if the IPv4 address had been given. See [response-engine.md](response-engine.md#safety-guard).
- Capabilities granted to the interpreter with `setcap` apply to the Python process only and are dropped when it executes `nft` or `iptables`. On Linux, before running a firewall command, `CommandRunner` raises `CAP_NET_ADMIN` into the process's ambient capability set (`ensure_ambient_capability` in `packages/sentinelx/system/privileges.py`) so the child process receives it. This only happens when the process already holds the capability in its permitted set; nothing is raised otherwise, and the command then fails with a permission error. Once raised, the ambient capability is inherited by any child process the sensor starts afterwards, which today means only firewall commands.

### Hostile packet input

- Decoders are total: malformed, truncated or adversarial packets produce `None` or a partial result and increment a counter. They never raise into the pipeline. As a backstop, `PacketDecoder.decode()` catches any unexpected exception and counts it as a decode failure (`layer="internal"`), so one hostile frame cannot stop capture.
- DNS name decompression detects pointer loops and bounds label and name lengths.
- The HTTP parser keeps only an allowlist of headers, and sensitive ones such as `Authorization` are reduced to a presence marker, so credentials seen on the wire never reach storage or logs.
- Per-source state is bounded (`max_tracked_sources`, default 50,000) with eviction, and every sliding-window structure in `packages/sentinelx/common/windows.py` updates in constant time. An earlier implementation was quadratic in window contents, which would have let an attacker slow the sensor by sending traffic that fills windows; scaling tests in `tests/unit/test_windows.py` guard against regression.
- Detector faults are isolated. An exception in one detector is logged and counted, and the other detectors still run.
- Detection cooldowns stop one attack from producing an unbounded stream of identical alerts. Genuine escalation (a higher severity, or a confidence increase of at least 0.2) is still reported.

### Capture files

- Capture files are read by SentinelX's own streaming reader (`packages/sentinelx/capture/pcapfile.py`), not by a third-party library. It reads one record at a time, so a file of any size uses constant memory.
- Every length field is validated before data is read: a pcap record larger than the file's snapshot length (treated as at least 65,535) or 262,144 bytes, whichever is smaller, a pcapng packet larger than its block or 262,144 bytes, a pcapng block larger than about 1 MiB, a block length that is not a multiple of 4 or does not match its trailer, or a packet for an undeclared interface raises `PcapError`. A corrupt or malicious file cannot make the reader allocate an attacker-chosen amount of memory.

### Rules, scenarios and models

- The rule condition language is parsed by a hand-written tokenizer and recursive-descent parser. There is no `eval`, `exec` or template execution. Rule size, nesting depth and list lengths are bounded. See [rule-engine.md](rule-engine.md).
- Rule YAML is parsed with a restricted subclass of PyYAML's `SafeLoader` (`load_rule_yaml` in `packages/sentinelx/signatures/rules.py`). It refuses anchors and aliases, and refuses nesting deeper than 32 levels (checked on flow brackets before scanning, and again while composing). Before this change a definition of about 400 bytes using aliases expanded into a response of about 30 MB from `POST /rules/validate`, which any analyst could send. Definitions sent to the API are also limited to 20,000 characters, and rule files to 1 MiB.
- Scenario parameters, from `POST /replay/scenarios/{name}` and from rules' embedded tests, are validated before anything is generated: unknown parameters, wrong types and booleans are refused, counts are limited to 50,000, rates to 50,000 per second, durations to 3,600 seconds, intervals to 0.001 to 600 seconds, string parameters must be IP addresses, and `dns_rate_spike` is refused above 2,000,000 packets. Previously an analyst could request a scenario large enough to exhaust the server's memory.
- A rule that triggers a preventive action must have a count threshold on every branch of its condition, so a rule matching a single packet cannot block addresses.
- Machine-learning model files are loaded with `joblib`, which can execute code embedded in the file. On POSIX systems SentinelX therefore refuses to load a model file that is group- or world-writable or not owned by the current user, or whose directory is writable by the group or others without the sticky bit (another user could replace the file). It writes models with mode `0600` and checks a format version and feature list. On Windows the permission and ownership checks are skipped, because ownership there is expressed in ACLs that SentinelX does not inspect: keep models in a directory only you can write. **Only load models you trained yourself.**

### Authentication and sessions

- Passwords are hashed with Argon2id. The policy favours length (minimum 12 characters by default) and rejects passwords that contain the username, are very common, or use very few distinct characters.
- Argon2 hashing and verification run in worker threads under one limit of 4 concurrent operations per process: login verification, and hashing for user creation, the bootstrap administrator, password changes and resets. A flood of login attempts or password operations therefore neither stalls the event loop (and with it the packet pipeline) nor exhausts memory (each Argon2 operation uses about 64 MiB). Re-hashing a password at login when the stored hash uses outdated Argon2 parameters runs in a worker thread outside that limit.
- A login with an unknown username is verified against a dummy hash, and every failure returns the same message, so usernames can't be enumerated by response content or timing.
- Lockout has two levels. `lockout_threshold` failures (default 5) for one account from one client address lock that account-and-address pair for `lockout_seconds` (default 900). Failures for an account from any addresses within `lockout_seconds` lock the account itself at 4 times the threshold (20 by default). Unknown usernames are counted and locked in the same shared state with the same thresholds, so the lockout responses are identical for real and unknown names and cannot be used to enumerate accounts. Previously only real accounts had the account-wide lock, which let about 20 source addresses tell real usernames from unknown ones. Failures older than `lockout_seconds` no longer count towards the account lock; before, the database counter kept them until a successful login. This replaced a single per-account lockout that let anyone lock any user out by guessing their password five times. Login attempts are also rate-limited per client address (default 8 per 300 seconds).
- Access tokens are short-lived HS256 JWTs (default 15 minutes) with the accepted algorithm pinned when verifying, so `alg: none` and algorithm-confusion tokens are rejected. A token whose subject is not an ASCII decimal user id from 1 to 2^31-1 is refused as invalid. Every request re-reads the user, so deactivation and role changes apply at the next request.
- The last active administrator cannot be deactivated, demoted or deleted. The check is made after the change inside the same transaction, with the administrator rows locked (`FOR UPDATE` on PostgreSQL; SQLite serialises writers), so two concurrent changes cannot each remove a different last administrator. A refused change returns 422 and is rolled back: `cannot demote the last administrator` or `cannot delete the last administrator` when the pre-check catches it, and `at least one active administrator must remain` for a deactivation or a change that only the post-change check catches (for example two concurrent requests).
- Signing out signs the user out on all devices. Sign-out, a password change and an administrative password reset delete the user's unused refresh tokens and record a per-user cut-off in the database (`users.sessions_ended_at`, whole seconds), so every access token issued to that user before that second stops working immediately. The cut-off is checked on every request when the user is re-read, so it survives Redis outages and restarts and applies in every process. The access token used to sign out or change the password is also revoked. A password change then issues the caller a fresh session, which keeps working. The cut-off has one-second resolution: a token issued in the same second as the cut-off stays valid. Revocations of individual access tokens are recorded in Redis (in process memory when Redis is unavailable, and written back to Redis when it reconnects).
- Refresh tokens are tracked server-side and rotated on every use. Rotation claims the token with a single conditional `UPDATE`, so two concurrent refreshes with the same token cannot both succeed; the loser is treated as reuse. Presenting a token that cannot be claimed (rotated, revoked or raced) revokes every refresh token for that user. Used and revoked refresh tokens are kept until they expire, so reuse of a stolen token is still detected; the retention job deletes only expired ones. Because sign-out and password changes delete unused tokens rather than revoking them, an old session that refreshes after a password change is refused without revoking the new session.
- A generated bootstrap administrator password is printed once to the server's standard error, never logged, and must be changed at first sign-in.
- The dashboard receives tokens in `HttpOnly`, `SameSite=Strict` cookies, and state-changing requests must carry a double-submit CSRF token in `X-CSRF-Token`. Scripts use bearer tokens instead. `POST /auth/refresh` uses the refresh cookie only together with the `X-SentinelX-Client: dashboard` header, which a page on another site cannot add to a cross-site request without a CORS preflight; without it the request is refused with 403, so the cookie alone never rotates a session.
- The browser talks to one origin for the dashboard, the API and the event stream (the Next.js rewrite in development, the nginx proxy in Docker Compose), so CORS can remain closed.
- WebSocket connections authenticate with a single-use ticket valid for 30 seconds, so a long-lived token never appears in a URL. Tickets are redeemed with an atomic read-and-delete (Redis `GETDEL`), so a ticket cannot be used twice even by concurrent connections. The `Origin` header is checked against the configured origins. Refusals are sent as close codes after the handshake: 4401 for an invalid or expired ticket, 1008 for a disallowed origin, an unknown event type, or a `types` filter that names only event types the role may not receive, and 4429 when a user already holds 10 streams in the process. Events of a type the stream did not subscribe to are never sent. Every stream, idle or busy, re-checks the account at least once per ping interval (25 seconds) and closes with 4401 if it was deactivated or 4403 if its role changed.

### Authorisation

Three roles, checked on the server for every endpoint:

| Role | Can |
|---|---|
| `viewer` | Read detections, incidents, statistics, host capabilities and network views. |
| `analyst` | Everything a viewer can, plus triaging detections and updating incidents, validating and testing rules, uploading and replaying captures, generating fixtures, previewing safety-guard decisions, and reading configuration and the audit log. |
| `admin` | Everything, including blocking, configuration changes, rule changes, sensor control and user management. |

Security decisions live in the service layer (`packages/sentinelx/services/`), not in route handlers, so the CLI and the API enforce the same rules. The full endpoint-to-role table is in [api.md](api.md).

### Transport, headers, client addresses and rate limits

- API responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Cache-Control: no-store` on API routes, and `Strict-Transport-Security` when cookies are marked secure.
- Dashboard pages (production builds) carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'` (`apps/dashboard/next.config.ts`). Next.js hydration uses inline scripts, so `'unsafe-inline'` is allowed; the policy still refuses scripts and connections to other origins, framing, plugins and `<base>` changes. Development servers (`npm run dev`) send no CSP, because React Refresh needs `eval`.
- API requests are rate-limited per client (default 300 per 60 seconds), shared across workers through Redis. With `API__ROOT_PATH` set, requests that arrive with the prefix still get rate limiting, the security headers and the forced-password-change restriction, because path checks strip the prefix first.
- Request bodies larger than 1 MiB are refused with 413 `{"detail": "request body too large"}` on every endpoint except the streamed capture upload (`BodySizeLimitMiddleware` in `packages/sentinelx/api/security.py`). A declared `Content-Length` over the limit is refused before the body is read; a chunked body is counted as it arrives. Without this, a bare uvicorn deployment would buffer an unbounded JSON body on any route, including sign-in.
- Database outages during a request (connection loss, refused connections, an exhausted pool) return 503 `{"detail": "storage unavailable", "error_id": "..."}`; the error id is logged with the underlying error, which is not returned.
- `X-Forwarded-For` is ignored unless the direct peer is in `trusted_proxies`. When it is used, it is read right to left, skipping trusted proxies, so the address a client writes at the left of the header is never believed. This address feeds the rate limiter, login lockout, the audit log and operator-address protection.
- SentinelX does not terminate TLS itself. In production, put it behind a reverse proxy that does, and set `trusted_proxies`. See [deployment.md](deployment.md).
- The Prometheus endpoint, without `API__METRICS_TOKEN`, is served only to direct loopback requests that carry no `X-Forwarded-For`, `Forwarded` or `X-Real-IP` header; requests relayed by a local proxy are refused. With the token set, a bearer token is required, compared as bytes in constant time: the header bytes as sent against the UTF-8 token, so a non-ASCII token sent as UTF-8 matches (a non-ASCII header used to cause a 500).

### Uploads

- `POST /replay/upload` takes the capture as the raw request body. Authentication and the role check run before any body byte is read, followed by the `Content-Type` check (415) and the declared `Content-Length` against the size limit (413), so an unauthenticated or oversized upload never reaches the disk.
- The body is streamed to `PCAP_DIRECTORY/uploads` and the size is enforced again while streaming, against the smaller of `max_upload_mb` and `max_pcap_size_mb` and the space left in the upload quota (`CAPTURE__UPLOAD_QUOTA_MB`, default 2048). A streamed body over that limit is refused with 413, and a full uploads directory refuses further uploads with 507.
- The first four bytes must be a pcap or pcapng signature, and the whole file must parse with the validating reader. Rejected files are deleted.
- Files are stored under a generated name (timestamp, random hex, sanitised stem) with mode `0640`. The response gives the path relative to the capture directory, never the absolute server path. Uploaded files older than `RETENTION_DAYS` are deleted by the retention job, which touches nothing outside `uploads/`.
- Replay paths are resolved inside the configured PCAP directory (following symbolic links); path traversal is refused. The file listing shows only `.pcap`, `.pcapng` and `.cap` files.

### Outbound webhooks

- `response.webhook_url` must use `https://` and include a host.
- At delivery time the host is resolved, and delivery is refused if any resolved address is loopback, private, link-local, reserved or multicast. This stops a changed setting from turning SentinelX into a proxy for internal services or cloud metadata endpoints. `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES=true` (environment only) allows internal receivers. Redirects are not followed.
- The webhook URL is shown and logged only as `scheme://host[:port]/…`, because chat and incident webhooks carry their secret in the path or query.

### Secrets and logging

- Secrets come from environment variables or an `.env` file that is git-ignored. No credential is hard-coded; `docker-compose.yml` refuses to start without the required passwords.
- Every log record passes through a redaction processor (`packages/sentinelx/telemetry/logging.py`) that replaces the values of sensitive keys (passwords, tokens, secrets, API keys, cookies, sessions, authorisation headers), including nested values, and scrubs inline patterns such as `password=...`, `Bearer ...`, `Basic ...` and `user:pass@` in URLs (including an empty user, as in `redis://:pass@host`) from strings. Sensitive keys include `passphrase`, `ticket`, `dsn`, `database_url` and `redis_url`, and any key whose parts join to end in `apikey`, such as `X-Api-Key`. It can't be disabled.
- uvicorn's loggers are routed through SentinelX logging at WARNING, so its access log, which prints query strings, never writes WebSocket `?ticket=` credentials. Alembic's plugin announcements are silenced at INFO; migration lines remain.
- Redaction also covers exceptions. Tracebacks are rendered to plain text before the redaction processor runs, so secrets inside exception messages (a database URL in a driver error, for example) are scrubbed like any other value, and console logs never print frame local variables. Previously the development console renderer used Rich tracebacks, which print every frame's locals; an exception while a settings object was in scope wrote the JWT secret and bootstrap password to the log, and an unauthenticated request could trigger such an exception. `tests/unit/test_config_and_logging.py` covers both console and JSON formats.
- `GET /config` and `sentinelx config` use the same redaction (`redacted_settings` in `packages/sentinelx/services/config.py`). Secrets are removed by field name: any field whose name contains `secret`, `token`, `password`, `api_key`, `apikey` or `credential` is shown as `[redacted]`, so a new secret setting is hidden by default as long as its name says what it is. `access_token_ttl_seconds`, `refresh_token_ttl_seconds` and `password_min_length` are durations and policy, not secrets, and are shown. Database and Redis URLs are shown with the password hidden, and the webhook URL as `scheme://host[:port]/…`. The change diff in `UPDATE_SETTINGS` and `ENABLE_PREVENTION` audit records and in `config.changed` events is shown the same way: webhook URLs as scheme and host, secret-named fields as `[redacted]`.
- Unhandled errors in the `sentinelx` command are printed without frame local variables (`pretty_exceptions_show_locals=False` in `packages/sentinelx/cli/main.py`), so a crash does not print the settings object or its secrets.
- Security-relevant actions are written to the audit log with the acting user, outcome and client address: sign-ins and failed sign-ins, sign-outs, password and user changes, response decisions that were executed or attempted (blocks, unblocks, rate limits, approvals and rejections), configuration changes (enabling prevention is recorded as its own action), rule changes, capture start and stop, PCAP uploads, fixture generation and replays, and detection and incident triage. Account lockouts and refresh-token reuse are recorded as warnings in the structured application log.

### Containers

- The API image runs as a non-root user (uid 10001). In Docker Compose the `api` and `migrate` containers are read-only (`api` has a `/tmp` tmpfs), drop all capabilities and set `no-new-privileges`. The dashboard and nginx proxy containers are read-only or unprivileged with all capabilities dropped. Host ports are bound to loopback by default.
- The image contains a copy of the interpreter, `/usr/local/bin/python3-sensor`, which is the only file with capabilities (`cap_net_raw,cap_net_admin+eip`). The shared `python3` has none, so the API and migration containers start with every capability dropped. Only the optional `capture` profile runs `python3-sensor`, adds `NET_RAW` and `NET_ADMIN`, allows privilege gain so the file capabilities apply, and uses host networking. That sensor does not listen on `0.0.0.0`: it binds only the `frontend` network's gateway address (`API_HOST=${FRONTEND_GATEWAY:-172.31.250.1}`, port `SENSOR_PORT`, default 8001), where the proxy reaches it, so it is not reachable from other hosts or on `127.0.0.1`.
- The nginx proxy is the browser's single origin. It returns 404 for `/api/v1/metrics`, so metrics are never exposed through it, and it appends the real client address to `X-Forwarded-For`. The API trusts that header only from the proxy's network (`API__TRUSTED_PROXIES`, the frontend subnet).

## Residual risks and operator responsibilities

- **Prevention can lock you out.** Operator-address protection only covers addresses that used the API in the last hour. Add your management addresses and jump hosts to the allowlist or management list before enabling prevention. Test in `manual_approval` mode first.
- **Attackers can spoof sources.** A spoofed-source flood could get a victim address blocked. The safety guard protects configured addresses, not arbitrary third parties. Prefer rate limiting and short temporary blocks for flood detections, and keep `auto_block_threshold` high.
- **Detection is evadable.** Threshold detectors miss slow attacks by design. See [benchmarking.md](benchmarking.md). Encrypted traffic exposes metadata only.
- **The sensor is a target, and Python limits its throughput.** It processes hostile input in Python and keeps state in memory. The measured pipeline throughput is a few thousand packets per second on one core ([benchmarking.md](benchmarking.md)), so a sustained flood above that causes capture drops. Keep it patched, monitor its resource use and drop counters, and don't run it on a host that holds unrelated secrets.
- **Stored traffic metadata and uploaded captures are sensitive.** Set `RETENTION_DAYS` to the shortest period that meets your needs (it also governs uploaded captures), restrict database and capture-directory access, and be clear about lawful basis and notice where your jurisdiction requires it.
- **Single-factor authentication.** SentinelX does not implement MFA or SSO. Put the dashboard behind your VPN or an authenticating reverse proxy if it must be reachable beyond a trusted network.
- **HS256 tokens share one secret.** Anyone holding `JWT_SECRET` can mint tokens for any user and role. Rotating it invalidates all sessions.
- **Redis outages weaken shared limits.** Without Redis, rate limits, login throttling, per-address lockout counters, WebSocket tickets and the access-token revocation list fall back to process memory (the account-wide login lockout included; a real account's lock is also kept in the database). They then apply per process, and entries are lost if that process restarts before Redis returns (revocations still held in memory are written back on reconnect). The per-user session cut-off set by sign-out, password changes and resets is stored in the database and is not affected. Set `storage.redis_required=true` if that is unacceptable.
- **DNS rebinding against the webhook check.** The webhook host is resolved for the address check and again by the HTTP client when connecting. A DNS answer that changes between the two is not prevented. Enable `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES` only for receivers you trust, and prefer a webhook host whose DNS you control.
- **pf and Windows Firewall adapters are unverified on real hosts.** Their command construction and output parsing are tested against recorded results (`tests/response/test_platform_firewalls.py`), but enforcement has not been exercised on a real macOS or Windows host. Only the nftables and iptables adapters are tested against a real kernel (`make test-kernel`).
- **Threat-intelligence feeds are trusted input.** A poisoned denylist raises scores for the listed addresses. The safety guard still applies to any resulting block.

## Hardening checklist

- [ ] `ENVIRONMENT=production`, with a random `JWT_SECRET` of at least 32 characters.
- [ ] PostgreSQL with a unique password; Redis with a password; neither reachable from untrusted networks.
- [ ] TLS terminated by a reverse proxy; `trusted_proxies` set to that proxy only.
- [ ] `CORS_ORIGINS` set to the dashboard's exact origin.
- [ ] The bootstrap administrator password changed, and personal accounts created with the least role needed.
- [ ] Management addresses and critical infrastructure added to the allowlist before prevention is enabled.
- [ ] Prevention trialled in `manual_approval` mode and with `DRY_RUN=true` before automatic mode.
- [ ] `RETENTION_DAYS` and `CAPTURE__UPLOAD_QUOTA_MB` set deliberately.
- [ ] `API__METRICS_TOKEN` set if Prometheus scrapes from another host.
- [ ] Webhook receivers use public HTTPS endpoints, or `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES` is enabled only for a trusted internal receiver.
- [ ] With the Docker `capture` profile, the sensor listens only on `FRONTEND_GATEWAY` (the default), not on `0.0.0.0`.
- [ ] The audit log reviewed regularly.
