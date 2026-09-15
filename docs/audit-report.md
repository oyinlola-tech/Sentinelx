# SentinelX final verification report

Verification completed on 2026-09-15 against SentinelX 0.1.0, on the working tree after all fixes below.

This report records what was run, on which systems, what failed, what was fixed and what remains open. Every result here comes from a command or test that was executed during this pass. "Not tested" means exactly that. Raw benchmark output is committed in `benchmarks/results/`.

## 1. Executive summary

SentinelX was taken through a full verification pass rather than a rebuild:

- Six parallel audits: static code, parser and detectors, API and auth, database and Redis, CLI and doctor, and rules, risk, correlation and response.
- A fresh-machine install following the README.
- Browser tests of every dashboard page and every failure state.
- Deliberate failure injection.
- A complete end-to-end prevention run on a clean Docker stack, using real captured traffic and a real kernel firewall.

**The application works on Linux x86_64 and in Docker on a Linux host.** Every link of the required end-to-end chain was exercised and passed on the final images (19 of 19 steps):

- **Detection:** the dashboard started live capture, and a controlled TCP scan from a throwaway container on the stack's private network was captured and detected, explained with evidence and risk.
- **Correlation and alerting:** the detections were correlated into an incident, streamed over the WebSocket, shown in the dashboard and raised as an alert.
- **Prevention:**
  - A dry-run block left the kernel untouched.
  - Prevention was enabled with the confirmation phrase.
  - A real nftables block appeared in the kernel and was audited and shown in the dashboard.
  - Unblocking restored the kernel, and the incident was closed.

The pass found and fixed **more than 70 defects**, each with a regression test; most tests were confirmed to fail on the old code. The most serious:

- **Security events were being lost:**
  - The event persister kept only 1,600 of 5,000 detections in a burst and dropped events while the database was paused.
  - The event bus dropped detections when its queue filled.
- **Visibility and filter bypasses:**
  - A viewer could subscribe to analyst-only WebSocket events (audit and configuration changes).
  - An automatic rate limit could downgrade an administrator's permanent block, letting traffic through again on iptables (reproduced in a network namespace).
  - IPv6 zone identifiers and IPv4-in-IPv6 forms of protected addresses passed the firewall safety guard.
- **Credentials and sessions:**
  - `start --port 99999` silently bound a random port.
  - An inherited environment variable could start live capture without `--capture`.
  - uvicorn logged one-time WebSocket tickets.
  - Log redaction missed `redis://:password@host` URLs, the exact form Docker Compose uses.
  - Sign-out and password changes stopped protecting sessions during a Redis outage.
- **Dishonest status:**
  - With the database stopped, the API answered 500 instead of 503.
  - Prevention could be enabled, and the banner showed "PREVENTION ACTIVE", while the firewall could not be changed at all.

**Verdict: BETA READY** for Linux x86_64 and Docker on a Linux host. It is not a release candidate, for these reasons:

- Windows, macOS and WSL2 have never been run.
- A silent network partition to PostgreSQL can still stall requests.
- Throughput is single-process, about 5,000 packets per second on the test machine.
- A handful of low-severity issues remain (section 9).

## 2. Feature matrix

**PASS** means the feature was exercised against real components and worked. **PARTIAL** means it works with a documented gap. **NOT TESTABLE** means this environment could not run it.

| Feature | Status | Tested | Result | Notes |
|---|---|---|---|---|
| Installation (README path, clean container) | PASS | Fresh `python:3.12-slim` and `node:22-slim` containers built from the committed source | Backend and dashboard install, replay, capabilities and doctor work; clean suite passed (see section 7) | Needs network access to PyPI and npm |
| Configuration and `.env` | PASS | Static reconciliation of every variable read; strict validation tests | `.env.example` complete; typos such as `DRY_RUN=ture` are errors | `.env` never committed (checked in git history) |
| Backend API startup | PASS | Local, clean container, Docker | Starts cleanly with no tracebacks; noisy Alembic plugin lines removed | |
| Database (SQLite, PostgreSQL 17) | PASS | Migrations up/down/up on both, schema diff, constraints, CRUD, pool, N+1 counts | No drift; downgrades work; 50 indexes match the models | New migration `60413ece4dff` |
| Security-event persistence | PASS | 5,000-event burst, paused and stopped database, bad rows | All events stored exactly once; bad rows isolated | Was losing events (fixed) |
| Redis | PASS | TTLs, counters, tickets, outage and reconnection | Degraded mode works; revocations written back on reconnect | |
| Live packet capture | PASS | AF_PACKET and libpcap in a network namespace; the dashboard started capture in Docker; real scan captured | 1,506 packets, detection raised | Linux only |
| PCAP replay | PASS | Committed PCAP suite, dashboard, API and CLI replays | Same pipeline as live; byte-identical results across runs | |
| Packet parser | PASS | 394 tests: link layers, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, TLS; truncation at every length; 11,000 fuzzed frames | Never raises; 8 parser bugs fixed | |
| Feature extraction | PASS | Exact-value tests; 200k packets from 50k sources | Bounded state | About 16 KB per tracked source |
| Detection engine | PASS | Every detector: normal, attack, malformed input, exact threshold boundaries; 19 injected bugs all caught | 0 false positives in benchmarks | Slow and low-rate attacks evade (by design) |
| Rule engine | PASS | 176 tests incl. 16 hostile conditions and 4 hostile YAML files | No code execution; no `eval`/`exec` anywhere | |
| Risk engine | PASS | Determinism, factor direction, 2,100 random assessments | Always 0–100 and explained | Inputs now clamped |
| Correlation and incidents | PASS | Grouping, escalation, duplicates, closure; incident closed from the dashboard | Unrelated sources stay separate | |
| Response engine and dry run | PASS | Every mode; dry run sends zero mutating commands on every path | Failures reported as `failed` with the real error | |
| Firewall: nftables | PASS | Network namespace and Docker, real traffic | Block, expiry, rate limit, unblock, restoration | |
| Firewall: iptables | PASS | Network namespace, real traffic | Same as nftables | |
| Firewall: pf, Windows Firewall | NOT TESTABLE | Unit tests against recorded command output only | | No macOS or Windows host |
| Firewall safety | PASS | 58 refused and 6 allowed targets; unprivileged container | Blocks never reported when they failed | |
| API | PASS | 212-test endpoint matrix covering all 67 operations | Correct status codes, no leaks, 503 on database outage | |
| Authentication | PASS | 24-test matrix and hardening tests | Tampered or expired tokens rejected; nothing sensitive logged | |
| Authorization | PASS | Every operation × role | Enforced by the backend, not the dashboard | |
| WebSocket | PASS | Tickets, origin, multiple clients, reconnect, per-user cap, role filtering, live event reaching the dashboard | Viewer subscription leak fixed | |
| Frontend pages | PASS | Headless Chrome on every page, local and Docker | No console errors; CSP verified | |
| Frontend states | PASS | Network failure, 500, malformed JSON, wrong-shaped JSON, slow API, expired session, stream loss | Nothing crashes | Wrong-shaped data shows the page's error panel |
| CLI | PASS | All 31 leaf commands × help, usage errors, `--json`, services down | Exit codes 0/1/2 | 19 bugs fixed |
| `doctor` | PASS | Scenarios (a)–(g) incl. privileged namespace and a fake service | Never reports PASS for anything unavailable | |
| Capability detection | PASS | Unprivileged host, privileged namespace, Docker, unprivileged container | Accurate, with remedies | |
| Docker Compose | PASS | Clean start, health checks, order, migrations, capture profile, restart, persistence | Ready in about 32 s | |
| Benchmarks | PASS | Platform and detection benchmarks re-run | Section 6 | |
| Windows, macOS, WSL2 | NOT TESTABLE | Static review only | | |

## 3. Platform matrix

| Feature | Linux | Windows | macOS | WSL2 | Docker |
|---|---|---|---|---|---|
| Install (backend and dashboard) | PASS | NOT TESTED | NOT TESTED | NOT TESTED | PASS |
| CLI, API, WebSocket, dashboard | PASS | NOT TESTED | NOT TESTED | NOT TESTED | PASS |
| PCAP replay and detection | PASS | NOT TESTED | NOT TESTED | NOT TESTED | PASS |
| Capability detection and doctor | PASS | NOT TESTED | NOT TESTED | NOT TESTED | PASS |
| Live packet capture | PASS | NOT TESTED | NOT TESTED | NOT TESTED | PASS (container namespace, or host network with the capture profile) |
| Firewall control and prevention | PASS (nftables, iptables) | NOT TESTED | NOT TESTED | NOT TESTED | PASS (nftables inside the container's own namespace, verification override) |
| Temporary blocks and unblock | PASS | NOT TESTED | NOT TESTED | NOT TESTED | PASS |

Notes:

- **Linux:** tested on Kali (kernel 7.1.5, x86_64) with Python 3.14 locally and Python 3.12 in Debian-based containers.
- **ARM64:** exercised only under QEMU user-mode emulation in the previous pass (476 passed, 15 skipped, 0 failed; fixtures byte-identical to x86_64). It was **not re-run on this pass's final code**.
- **Windows and macOS (supported by design, not tested):**
  - Capture goes through libpcap (Npcap on Windows, `/dev/bpf*` on macOS), and firewall adapters exist for Windows Firewall and pf.
  - The static audit found no platform assumptions in the core packages. All OS-specific code is behind adapters or platform checks.
  - A Windows-only defect (ML models could never load) was found and fixed statically.
  - The CI jobs for Windows and macOS are defined but have not run.
- **WSL2 (supported by design, not tested):** capture and firewall changes apply to the WSL virtual machine, not the Windows host. SentinelX detects WSL and says so. PCAP replay has no platform dependency.
- **Docker:** the stock API container is deliberately unprivileged. It reports capture and firewall control as unavailable, with remedies. It refuses capture (409) and refuses to enable prevention (422). Host network capture needs the `capture` profile.

## 4. Bugs found

Line references are approximate: the files changed during the pass. "Verified" names the regression test. Where noted, the test was confirmed to fail on the pre-fix code.

### High

| Location | Problem | Root cause | Fix | Verification |
|---|---|---|---|---|
| `storage/persister.py` | Security events lost: 1,600 of 5,000 detections kept in a burst; paused database dropped 500; failed batches discarded | Database writes ran inside the event bus handler, blocking its bounded queue; no retry | Buffered background writer (50,000 cap), retries with backoff, per-row isolation of bad data, counted and logged drops | `tests/integration/test_storage_matrix.py` (all events stored exactly once; failed before the fix) |
| `events/bus.py` | Detections dropped when the handler queue was full | `publish` never yielded and dropped on a full queue | Security event types wait up to 10 s for room; statistics are still shed | `tests/unit/test_event_bus.py` (failed before the fix) |
| `api/websocket.py` | A viewer could receive audit and configuration events | A filter of only analyst-only types became empty, which the bus reads as "all types" | Close with 1008; never send unsubscribed types | `test_websocket_viewer_cannot_subscribe_to_analyst_only_events` |
| `response/engine.py` | An automatic rate limit replaced an existing block (iptables deleted the DROP rule at once; nftables expiry later removed it) | The "already blocked" check ignored whether the entry was a rate limit | A rate limit never replaces a block; a block may replace a rate limit | Unit tests and a kernel test in a network namespace |
| `response/safety.py`, all firewall adapters | IPv6 zone identifiers (`2001:db8::1%'+$(calc)+'`) passed the guard and reached pfctl, nft and the PowerShell script | `ipaddress` accepts any text after `%` | Refused in the guard, on unblock and by `firewall_address()` in every adapter | Adapter and guard matrix tests |
| `cli/main.py` | `start --port 99999` bound a random port; `--port 0` fell back to the default | No range check; `port or default` | Port must be 1–65535 | `tests/unit/test_cli_matrix.py` |
| `cli/main.py` | An inherited `SENTINELX_START_CAPTURE` started live capture without `--capture` | Server read the variable unconditionally | Removed unless `--capture` is given | CLI matrix test |
| `cli/main.py` | uvicorn logged WebSocket ticket URLs, bypassing redaction | uvicorn default logging | uvicorn loggers routed through SentinelX logging at WARNING | Verified on a live server: 0 ticket lines |

### Medium

| Location | Problem | Fix | Verification |
|---|---|---|---|
| `telemetry/logging.py` | Redaction missed `redis://:pass@host`, `Basic` credentials, `X-Api-Key`, `ticket`, `passphrase` | Patterns and keys extended | `test_audit_gaps_in_redaction_are_closed` (failed before the fix) |
| `services/auth.py`, `storage/models.py` | A logout or password-change cut-off lived only in Redis or process memory, so sessions came back during an outage or restart | Cut-off stored in `users.sessions_ended_at` (migration `60413ece4dff`) | `TestSessionCutOffSurvivesCacheLoss` |
| `storage/redis_state.py` | Tokens revoked during a Redis outage became valid when Redis returned | Degraded-mode entries written back on reconnect | Storage matrix test |
| `storage/database.py`, `api/errors.py` | Stopped database: API answered 500 | Driver network errors (for example `socket.gaierror` when Docker DNS drops the host) are raised as `StorageError` and mapped to 503; SQLAlchemy outage errors mapped to 503 | `test_driver_network_errors_become_storage_errors`; failure injection in Docker |
| `storage/database.py` | PostgreSQL connections had no connect, statement or pool timeouts | New `STORAGE__CONNECT_TIMEOUT_SECONDS`, `STATEMENT_TIMEOUT_SECONDS`, `POOL_TIMEOUT_SECONDS` | Applied and documented; the silent-partition case remains (section 9) |
| `services/config.py` | Prevention could be enabled, with "PREVENTION ACTIVE" shown, while the firewall could not be changed | Enabling is refused while the firewall reports itself unusable | `TestPreventionNeedsAWorkingFirewall`; unprivileged container in Docker |
| `api/routes/detections.py` | Resolving an incident did not reach the live correlation engine, which kept extending it and could auto-block from it | `PATCH` to resolved or false_positive calls `close_incident()` | `test_resolving_an_incident_stops_live_correlation_into_it` (failed before the fix) |
| `api/security.py` | No request body limit outside nginx, including unauthenticated login | `BodySizeLimitMiddleware` (1 MiB, streamed upload exempt) returns 413 | `TestRequestBodyLimit` (failed before the fix) |
| `api/routes/auth.py` | Two administrators changing each other concurrently could leave no active administrator | Row locks and a recount in the same transaction | Concurrent admin tests (SQLite) |
| `response/engine.py` | A manual or approved rate limit could downgrade a block | Refused with "unblock it first" | `test_manual_rate_limit_never_downgrades_an_existing_block` |
| `response/safety.py` | IPv4-mapped, 6to4, Teredo and NAT64 forms of protected addresses could be blocked | Embedded IPv4 checked against every protection | Guard matrix |
| `signatures` | Condition literals unchecked (port 65536, `999.1.1.1`); `within: .nan` accepted; one unreadable file aborted all rule loading | Literal validation, finiteness check, per-file problems | Rule matrix |
| `scoring/engine.py` | Out-of-range, infinite or negative inputs distorted scores | Inputs sanitised and clamped | Risk matrix (random property test) |
| `correlation/engine.py` | A redelivered detection was double-counted and could trigger escalation | Deduplicated by detection id | Correlation matrix |
| `parser/layers.py`, `parser/decoder.py` | IPv6 non-first fragments decoded as transport headers; IPv6 AH offsets wrong; DNS over TCP misparsed | Fragment offset honoured; AH length rule; TCP length prefix | Parser matrix (failed before the fix) |
| `features/extractor.py` | A backwards time step over 60 s stopped window expiry, causing false `connection_rate` detections | State reset (`clock_resets`) | Feature matrix |
| `features/profiles.py` | A non-numeric DNS label length from a parser raised outside error isolation | Type checks | Feature matrix |
| `anomaly/statistical.py` | A backwards time step was scored as a huge spike | Interval restarts | Detector matrix |
| `anomaly/ml.py` | On Windows every model was rejected; on POSIX a model in a directory others can write was trusted | POSIX checks skipped on Windows; parent directory checked | `test_model_in_a_directory_others_can_write_is_refused` |
| `storage/migrate.py`, `database.py` | Databases built from the models got stuck: startup refused, and `db upgrade` failed with DuplicateTableError | Unversioned databases adopted and stamped | Three adoption scenarios |
| `cli` | `db current/upgrade`, `anomaly train` and unwritable directories printed tracebacks; `rules validate` exited 0 for a missing path; `monitor --duration` never stopped on a quiet interface | Clear errors and correct exit codes | CLI matrix |
| `services/diagnostics.py` | `doctor` aborted without a report when Redis was required; no ML model check; crashed on an IPv6 API host | Fixed | CLI matrix |
| Dashboard shell | A wrong-shaped overview response crashed every page (footer called `.split` on a missing field) | Shell tolerates malformed data | `states.mjs` browser test: every page, 7/7 |

### Low

- **Detection engine:** unknown names in `DETECTION__ENABLED_DETECTORS` silently enabled nothing, and the allow-list did not govern anomaly detectors. Both fixed with tests.
- **Firewall and response:**
  - A manual unblock of an invalid target was recorded as simulated; it is now refused.
  - The banner read "will modify the auto firewall", and the capabilities remedy for `auto` gave the wrong advice.
  - A firewall setup failure crashed startup; it is now retried per action.
  - In dry run with manual approval, SentinelX created nftables objects; it no longer does.
- **Uploads:** an oversized streamed upload returned 422; it now returns 413, and a full quota returns 507.
- **Tokens:** a non-numeric token subject caused a 500; it now returns 401.
- **API paths and bodies:**
  - With `root_path` set, prefixed requests skipped rate limiting and headers.
  - Invalid JSON sent to `/auth/refresh` caused a 500.
  - Equal-valued rows paged unstably.
- **Health:** persister health stayed unhealthy forever after one retried failure; it now follows the retry state.
- **Dashboard:** the block dialog gave no feedback when the safety check failed; it now shows an error and a "Check again" button.
- **CLI:** assorted exit codes and messages (unknown `--id`, missing target on a pipe, unknown `--section`, Rich markup swallowing text).
- **Logs:** Alembic plugin noise at startup.
- **Docker:** the runtime image shipped `pip` 25.0.1 with published advisories; it is now removed.
- **Frontend headers:** dashboard pages sent no Content-Security-Policy; a production CSP was added and verified in the browser.

### Found on the clean machine (newer dependency releases)

A fresh install resolved Typer 0.27, Click 8.5, FastAPI 0.141 and Starlette 1.6, where the development environment had Typer 0.20, Click 8.3, FastAPI 0.135 and Starlette 1.3. That exposed two product defects and three test assumptions:

| Severity | Location | Problem | Root cause | Fix | Verification |
|---|---|---|---|---|---|
| Medium | `cli/security.py` | On a fresh install, `sentinelx block` or `unblock` without a target in a script crashed with an exception (exit 1) instead of a usage message (exit 2) | Typer 0.27 vendors its own copy of Click, so a `click.UsageError` from the installed click package is not recognised | Message on stderr and `typer.Exit(2)`; no direct Click imports remain in the product | CLI matrix passes under both Typer releases; `sentinelx block` in the rebuilt image exits 2 |
| Low | `api/security.py` | Prometheus `path` labels lost the `/api/v1` prefix under FastAPI 0.141, changing metric series (and breaking dashboards or alert rules) with the dependency version | Newer FastAPI matches the router's own route, whose path has no include prefix | Labels normalised to the full template | Same labels under FastAPI 0.135 and 0.141 |
| Test | `tests/unit/test_cli_matrix.py`, `tests/api/test_endpoint_matrix.py` | Command tree and route table introspection found nothing | The same vendoring, and FastAPI 0.141 keeping included routers as lazy entries | Version-independent walking | Pass on both environments |
| Test | `tests/detection/test_rule_matrix.py` | The unreadable-file assertion failed as root | Root can read mode-000 files | Root-aware assertion | Passes as root and as a user |

### Test infrastructure

- Log-capture tests failed depending on test order, because structlog caches module loggers on first use; `tests/conftest.py` now uncaches them.
- Fixed sleeps in two API tests failed on slow machines; they now poll with a bound.

## 5. Security findings

### Critical

None found.

### High (all fixed)

1. Loss of security events under load or during database trouble (persister and event bus).
2. Viewer access to analyst-only event types over the WebSocket.
3. Firewall safety-guard bypass with IPv6 zone identifiers, a potential PowerShell injection path on Windows for an authenticated administrator.
4. Weakening of an administrator's block by an automatic rate limit.
5. One-time WebSocket tickets written to server logs.
6. Unintended live capture from an inherited environment variable.
7. Binding an unexpected random port.

### Medium (all fixed)

- **Leakage:** incomplete log redaction of Redis URLs and API keys.
- **Sessions:** session cut-offs lost during a Redis outage; revocations lost across a Redis outage.
- **Firewall safety:** blocking IPv4-in-IPv6 forms of protected addresses; manual rate limits weakening blocks.
- **Denial of service:** no request body limit without nginx.
- **Administration:** a zero-administrator race.
- **Honesty:** "PREVENTION ACTIVE" with an unusable firewall; a closed incident still driving automatic responses.
- **Model files:** untrusted-directory model loading.
- **Rules:** unvalidated rule literals that silently never matched.

### Low

- **Open:**
  - With about 20 source addresses, account lockout can tell real usernames from unknown ones.
  - `/auth/refresh` through the cookie does not require the client header; SameSite=Strict mitigates this.
  - `/system/status` shows viewers the database location (SQLite path, or PostgreSQL host and user; never the password).
  - An unauthenticated request with malformed JSON gets 422 before 401, because FastAPI parses the body before authentication.
- **Fixed:** the other Low items in section 4.

### Informational

- **Execution and injection:** no `eval`, `exec`, `shell=True` or string-built commands. Every subprocess uses an argument list through `CommandRunner`. Rule YAML uses a restricted loader. Every database query is parameterized through SQLAlchemy.
- **Path traversal and uploads:** replay paths are resolved inside `PCAP_DIRECTORY` and traversal is refused. Uploads are streamed after authentication, with size, quota and magic-number checks.
- **SSRF:** webhooks must be https and resolve to public addresses unless explicitly allowed.
- **Browser protections:** CORS is limited to configured origins. Cookies are HttpOnly and SameSite=Strict, with CSRF double-submit. The API sends a strict CSP, and the dashboard now sends a production CSP.
- **Tokens:** JWTs are HS256 with a shared secret. There is no MFA or SSO.
- **Repository settings:** GitHub private vulnerability reporting is disabled on the repository, although `SECURITY.md` refers to it.

### Dependency audit

- **Python:**
  - The runtime dependency closure (49 packages) and the packages shipped in the API image (53) have no known vulnerabilities (`pip-audit`, 2026-09-15).
  - The only earlier hits were `pip` itself in the image (removed) and python-dotenv 1.2.1 (floor already raised to 1.2.2).
- **Dashboard:** production npm dependencies have 0 vulnerabilities (`npm audit --omit=dev`).
- **Hygiene:** no packages were mass-upgraded, and no unused or duplicate runtime dependencies were found.

## 6. Performance results (measured)

All runs used an Intel Core i5-8350U (8 logical CPUs) with Python 3.14.6, on a single uvicorn worker over loopback. API tests ran against SQLite without Redis. Reports: `benchmarks/results/platform-20260915T075621Z.md` and `benchmarks/results/20260915T075712Z.md`.

### API latency

| Endpoint | Sequential p50 | Sequential p99 | Concurrency 10 p50 | Requests/s at concurrency 10 |
|---|---|---|---|---|
| GET /system/health | 1.8 ms | 4.4 ms | 22.6 ms | 382.5 |
| GET /detections?limit=50 | 19.7 ms | 26.2 ms | 216.8 ms | 45.4 |
| GET /incidents?limit=50 | 9.1 ms | 12.1 ms | 92.4 ms | 105.3 |
| GET /stats/overview | 72.3 ms | 100.9 ms | 393.5 ms | 24.9 |
| POST /auth/login (Argon2id) | 81.7 ms | 92.1 ms | 549.1 ms | 17.7 |

The overview endpoint is slower than in the previous run (35 ms); this run seeded 2,347 detections, against 832 then.

### Event delivery and storage

- **WebSocket, publish to client:** p50 30.1 ms, max 43.5 ms, over 10 events during a replay.
- **Storage, detections produced and stored including pipeline processing:**
  - SQLite: 2,347 of 2,347 stored, 163.8 per second.
  - PostgreSQL 17: 2,347 of 2,347 stored, 103.8 per second.

### Pipeline under increasing volume

| Packets | Packets/s | p50 | p99 | RSS growth |
|---|---|---|---|---|
| 1,000 | 4,513.8 | 0.176 ms | 0.651 ms | 0.0 MB |
| 10,000 | 5,126.4 | 0.178 ms | 0.376 ms | 0.0 MB |
| 50,000 | 5,141.4 | 0.182 ms | 0.341 ms | 0.0 MB |

### Detection experiments

Synthetic traffic with known ground truth, 5 runs each:

| Measure | Result |
|---|---|
| Detection rate, 14 attack experiments | 100% |
| False positives | 0 in every experiment |
| Slow port scan and low-rate brute force (expected misses) | 0% |
| Throughput | 3,207–5,594 packets/s |
| Latency per detection | 0.41–0.80 ms |
| Peak RSS | 120.8–124.7 MB |
| Decoder | 48,896 frames/s, 2.2 times Scapy |

### Elevated rates, from the storage and bus tests

- 5,000 detections published in a burst were all stored exactly once.
- 200,000 packets from 50,000 sources stayed within the configured state caps. 50,000 sources with 200,000 connections used about 823 MB.

## 7. Test results

| Check | Result |
|---|---|
| Backend test suite with real PostgreSQL 17 and Redis 7 | 1,820 passed, 14 skipped, 0 failed |
| Coverage | 88.0% (was 78.8% at the start of the pass) |
| Kernel tests (network namespace, real AF_PACKET, libpcap, nftables, iptables) | 13 passed |
| New tests this pass | 1,322 (1,834 collected against 498 at the start of the pass, excluding kernel tests), in the endpoint, auth, parser, feature, detector, rule, risk, correlation, response, storage, CLI and event bus matrices |
| ruff check, ruff format | Pass (174 files) |
| mypy (strict) | Pass (116 source files) |
| Dashboard lint, typecheck, production build | Pass |
| OpenAPI contract | Regenerated from the code; the only change is one parameter description (`include_alerts`) |
| Rules | 7 valid; embedded rule tests pass |
| Browser end-to-end chain (final images, clean stack) | 19/19 |
| Failure injection (final images) | 15/15 |
| Unprivileged-container honesty checks (final images) | Capture 409; block `failed` with the real nftables error; prevention refused 422; banner stays DETECTION ONLY |
| Frontend failure states (final dashboard) | 7/7 |
| Browser smoke test under the new CSP | 15/15 |
| Clean-machine run of the final working tree (`python:3.12-slim`, README steps, newest releases from PyPI) | Install, fixture generation, replay, capabilities, doctor and `pip check` pass. Full suite: 1,777 passed, 40 skipped, 5 failed on the first run, 1 failed on the second (details below); all fixed, and the failing tests re-run and pass there. Locally, the affected suites pass (742 passed, 1 skipped) |
| Clean-machine install of the committed source before this pass's fixes | 476 passed, 15 skipped; dashboard built and served through its proxy |
| Security checks | pip-audit: 0 vulnerabilities (runtime closure and image); npm audit: 0; secret scan of logs during auth flows: nothing found; `.env` not tracked |

The 14 skips in the main run are the kernel tests, which run separately, plus tests that need privileges or are platform specific.

## 8. Known limitations

- **Platforms:** only Linux x86_64 has been run natively. Windows, macOS and WSL2 have not been run. ARM64 ran only under emulation, and not on this pass's final code.
- **Capture and firewall scope:** live capture and firewall control on Windows (Npcap, Windows Firewall) and macOS (BPF, pf) are implemented but unverified. pf and Windows Firewall have no rate limiting, and their temporary blocks expire only while SentinelX runs.
- **Throughput:** a single Python process handles about 5,000 packets per second on the test CPU. That suits hosts, labs and small segments, not high-speed links.
- **Evasion:** threshold detectors can be evaded by slow or distributed attacks, as asserted in `tests/pcaps/evasion`.
- **Memory:** plan about 16 KB per tracked source (default cap 50,000 sources).
- **Silent database partitions:** a stopped or unreachable PostgreSQL server is reported immediately and events are buffered. A server that accepts connections but stops responding (packets dropped) can hold requests on open connections until the operating system gives up, because closing such a connection waits for the peer.
- **Redis:** without Redis, rate limits, WebSocket tickets and single-token revocations are per process. Session cut-offs are in the database.
- **Docker:** the stock container is unprivileged. Firewall control and capture there need explicit capabilities or the host-network capture profile.
- **Alert decisions:** they are not stored; the detection is the alert (`GET /alerts`, webhooks).
- **Encrypted traffic:** only metadata (flows, DNS, TLS SNI and ALPN) is inspected.
- **Authentication:** no MFA or SSO.

## 9. Remaining issues

Only genuine unresolved problems are listed.

1. **Medium:** a silent network partition to PostgreSQL can stall API requests on already-open connections (above). This needs a request-level deadline or a different connection-close strategy.
2. **Low:** in `firewall/iptables.py`, if inserting the new rule succeeds but deleting the old rule fails, the decision is reported failed while the rule stays in the kernel, missing from the registry.
3. **Low:** capability detection treats a firewall as available when the tool is installed and privileges are held, without a functional probe. Enabling prevention now performs a real probe.
4. **Low:** account lockout lets roughly 20 source addresses tell real usernames from unknown ones.
5. **Low:** `/auth/refresh` through the cookie does not require the dashboard client header; SameSite=Strict mitigates this.
6. **Low:** `/system/status` shows viewers the database location, without the password.
7. **Low:** the threats view ranks only the 500 highest-risk detections in its window, so per-source counts can be cut off on busy windows.
8. **Low:** `doctor`'s database check creates an empty SQLite file when none exists.
9. **Low:** `config set` with an unknown section exits 1 instead of 2.
10. **Medium (process):** dependency ranges are open-ended (for example `fastapi>=0.110`, `typer>=0.12`). This pass showed that new upstream releases change behaviour: Typer vendoring Click, FastAPI's router layout. There is no lock or constraints file, and no CI job against the newest releases. Add tested upper bounds or a constraints file, plus a scheduled job against the latest versions.
11. **Low:** unused settings (`scoring.incident_threshold`, `anomaly.ml_contamination`, `telemetry.metrics_enabled`, `metrics_path`, `profile_pipeline`); `HttpReputationProvider` is not wired in.
12. **Process:**
    - Run the Windows and macOS CI jobs and fix what they find.
    - Test capture and firewall control on real Windows, macOS and WSL2 hosts.
    - Re-run ARM64 on native hardware.
    - Turn on GitHub private vulnerability reporting.

## 10. Final verdict

**BETA READY**

On Linux x86_64 and in Docker on a Linux host, every required subsystem was run and verified:

- Capture and replay, detection, risk and correlation.
- WebSocket, dashboard, CLI and doctor.
- Real prevention and restoration.
- Failure handling, security controls and the full end-to-end chain.

The defects found were fixed and regression-tested, and the full regression suite passes.

It is not a release candidate:

- Three platforms the project targets (Windows, macOS, WSL2) have never been run, and their CI jobs have not run.
- One medium issue remains (silent database partitions).
- It has had no long-running operation on a real network.
