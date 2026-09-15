# SentinelX verification and production-readiness audit

Audit completed 2026-09-15 against SentinelX 0.1.0.

This report records what was tested, on which systems, what failed, what was fixed and what remains open. Every number here was measured during the audit, and the raw benchmark output is committed under `benchmarks/results/`. "Not verified" means exactly that: the code path exists but was not run on that system.

## 1. Executive summary

SentinelX works end to end on Linux x86_64 and in Docker on a Linux host. This was verified with real traffic, a real kernel firewall and a real browser, on these paths:

- **Detection:** live capture or PCAP replay, detection, risk scoring and correlation into incidents.
- **Streaming:** the WebSocket event stream reaching the dashboard.
- **Prevention:** a dry-run block, then enabling prevention with the confirmation phrase, a real nftables block visible in the kernel, the audit trail, and an unblock that restores the kernel state.

The audit found and fixed a substantial number of real defects. Among the most serious:

- An unauthenticated request could make the API log the JWT secret.
- CLI crashes printed the JWT secret and database credentials.
- A 400-byte YAML rule could expand to a 30 MB response.
- The default Docker API image could not start at all.
- Firewall commands failed under file capabilities.
- The null firewall reported blocks as executed.
- The retention job deleted replay results within a minute of starting.
- A password change could end the session it was made from.

Each fix has a regression test, and most of those tests were checked to fail against the old code.

Cross-platform support is real in the code but only partly verified:

| Platform | Status |
| --- | --- |
| Linux x86_64 | Fully tested |
| Docker on Linux | Fully tested |
| Linux ARM64 | Exercised under QEMU emulation only |
| macOS | Implemented; adapters unit-tested against recorded command output, never run on a real host |
| Windows | Implemented; adapters unit-tested against recorded command output, never run on a real host |
| WSL2 | Behaviour detected and documented; not run |

**Recommendation: BETA READY for Linux (x86_64, and Docker on a Linux host).** It is not ready for production use on macOS, Windows or WSL2. It is not production ready anywhere until the open items in sections 9 and 10 are closed, the Windows and macOS CI jobs have run, and it has had operational time on real networks.

## 2. Feature verification matrix

Key:

- **Verified** means exercised against real components during this audit.
- **Tested** means covered by automated tests with in-process fakes.
- **Not verified** means not exercised.

| Feature | Result | How it was verified |
| --- | --- | --- |
| Backend API (FastAPI) | Verified | 498 tests collected; in-process API tests; Docker stack through the proxy |
| Dashboard (Next.js) | Verified | Lint, typecheck and production build pass; headless Chrome signs in and renders every console page with no console errors, error boundaries or crashes, on the local build and the Docker stack |
| CLI | Verified | CLI tests (exit codes, JSON on stdout, secret redaction); `capabilities`, `doctor`, `fixtures`, `replay` run on x86_64 and ARM64 |
| REST API validation, pagination, errors | Tested | API tests: bounds on offsets and ids, 413/415/422/507 upload codes, no stack traces in responses |
| WebSocket stream | Verified | Through the nginx proxy: ticket authentication, foreign origin refused (1008), per-user cap (4429), deactivation (4401) on idle and busy streams, detections delivered live |
| Authentication and authorisation | Tested | Role matrix; refresh rotation and reuse detection; lockout per account and address; logout and password change end other sessions |
| Database: SQLite | Verified | Suite; automatic migration of SQLite files |
| Database: PostgreSQL | Verified | `make test-integration`; Docker stack; outdated schema refused |
| Redis | Verified | Integration tests; degraded per-process mode when unreachable, confirmed locally |
| Live capture: AF_PACKET | Verified | Kernel tests in a network namespace (`lo`, `any`, BPF filter); Docker capture profile on the host network |
| Live capture: libpcap | Verified on Linux | Kernel tests; not verified with Npcap on Windows or BPF devices on macOS |
| PCAP replay | Verified | Same pipeline as live (`assembly.py`); two replays give identical results; pcapng and nanosecond pcap from Wireshark `editcap` replay identically |
| Committed PCAP suite | Verified | `tests/pcaps`: benign, attacks, evasion and malformed files, with a manifest of exact results |
| Parsing | Tested | Decoder tests; hostile and truncated captures rejected with `PcapError` |
| Feature extraction, detectors, rules | Tested | Detector tests; rule YAML with no `eval` and a restricted loader; rules validate and pass their embedded tests |
| Risk scoring and explanations | Tested | Rationale present in the API and dashboard |
| Correlation and incidents | Verified | Replay in Docker: 9 detections gave 1 incident, "Potential host compromise attempt", final when the replay reports completion |
| Alerts (webhooks) | Tested | https only; private destinations refused; secrets redacted in the view, audit and events |
| Response engine and dry run | Verified | A dry-run block left the kernel unchanged |
| Prevention: nftables | Verified | Network namespace and Docker: block, timeout, re-block, rate limit, unblock, teardown |
| Prevention: iptables | Verified | Network namespace, with real traffic |
| Prevention: pf (macOS) | Not verified | Unit tests against recorded output only |
| Prevention: Windows Firewall | Not verified | Unit tests against recorded output only |
| Safety guard | Verified | Loopback refusal in Docker; allowlist, management and operator-address protection tested |
| Audit log | Verified | `ENABLE_PREVENTION`, `TEMPORARY_BLOCK`, `BLOCK_IP` (refused), `UNBLOCK_IP` and `START_REPLAY` recorded in Docker |
| Real data in the dashboard | Verified | Every page fetches from the API; no simulated timers (frontend audit) |
| Rule management | Tested | Create, test, toggle and delete; disabled anomaly detectors can be re-enabled |
| Analytics | Tested | Timeline and false-positive counts |
| Platform capabilities | Verified | Detected, not hardcoded: reports x86_64 vs arm64, container, privileges, and unavailable features with remedies |
| `doctor` | Verified | Never reports PASS for an unavailable feature; a foreign service on port 3000 is reported as "not SentinelX" |
| Docker Compose | Verified | Default stack, capture profile, proxy, restarts; API image built from current code |
| Reproducible replay and fixtures | Verified | Byte-identical fixtures across runs and across x86_64 and ARM64 |
| Retention | Tested | Live data expires by timestamp; replay data expires with its replay |
| Graceful handling of unsupported features | Verified | Missing `nft` or `iptables` reported as unavailable; ioctls refused under QEMU no longer crash enumeration |

## 3. Cross-platform matrix

| Capability | Linux x86_64 | Docker (Linux host) | Linux ARM64 | macOS | Windows | WSL2 |
| --- | --- | --- | --- | --- | --- | --- |
| Install | Verified | Verified | Verified (QEMU) | Not verified | Not verified | Not verified |
| CLI, API, dashboard | Verified | Verified | CLI verified (QEMU) | Expected, not verified | Expected, not verified | Expected, not verified |
| PCAP replay and detection | Verified | Verified | Verified (QEMU) | Expected, not verified | Expected, not verified | Expected, not verified |
| Capability detection | Verified | Verified (reports container) | Verified (reports arm64) | Implemented | Implemented | Implemented (WSL1/2 from kernel release) |
| Live capture | Verified (AF_PACKET, libpcap) | Verified (capture profile, host network) | Not verified | Implemented (libpcap, `/dev/bpf*`) | Implemented (Npcap) | Captures the WSL VM, not the Windows host |
| Firewall control | Verified (nftables, iptables) | Verified (nftables in its own namespace, with an override) | Not verified | Implemented (pf anchor) | Implemented (NetSecurity cmdlets) | Changes the WSL VM only |
| Test suite | 487 passed, 11 skipped; kernel 11 passed | Not run in the image | See section 7 | CI job defined, not run | CI job defined, not run | Not run |

The 11 tests skipped in the normal run are the kernel tests, which run separately in a network namespace. For ARM64, QEMU user mode does not emulate the ioctls and netlink behaviour that capture and firewall control need, so those remain unverified on ARM64 hardware.

## 4. Bugs found

All of these were fixed during the audit unless marked open. "Mutation-verified" means the regression test was confirmed to fail on the code before the fix.

### Correctness and data integrity

- **Retention deleted replay results early.** Detections carry capture time, so replays of captures older than `RETENTION_DAYS` were purged at the first retention run, 60 seconds after start. Fixed: replay data now expires with its replay. Mutation-verified.
- **Replays were marked `completed` before their results were stored.** Clients read intermediate incidents. Fixed: the bus drains and the persister flushes first. Mutation-verified; confirmed on PostgreSQL in Docker.
- **Detections were stamped with wall-clock time.** Replays were not reproducible. Fixed: packet capture time is used.
- **Stale detection windows.** Old attempts could re-fire a brute-force detection. Fixed: windows expire before detectors read them. Mutation-verified.
- **Fixture generation was not deterministic.** IP IDs, TCP sequence numbers and DNS IDs came from an unseeded RNG. Fixed. Mutation-verified.
- **Block registry mismatch.** A bare IP and its `/32` were tracked as different blocks. Fixed.
- **Temporary iptables blocks became permanent after a restart.** Fixed: the expiry is stored in the rule comment.
- **The 24-hour approval limit was not enforced.** Expired requests could still be approved. Fixed.
- **Anomaly detectors disabled in the dashboard could not be re-enabled** (the toggle returned 404). Fixed.
- **CLI replay queued approvals in manual-approval mode** where API replays show simulated decisions. Fixed. Mutation-verified.
- **`sentinelx monitor -i` ignored the capture settings:** backend, BPF, promiscuous mode, buffer and queue sizes. Fixed.
- **The API sometimes returned 500s:** huge offsets or ids, a NUL byte in the inspect path, a bad pcapng upload, invalid scenario parameters. Fixed.

### Capture and platform

- **AF_PACKET on `any`** decoded nothing, because it used one link type for all frames. Fixed.
- **An invalid BPF filter silently fell back** to an unfiltered capture. Fixed.
- **Scapy could not decode Linux loopback** (link type 772). Fixed.
- **Interface enumeration crashed** when the kernel refused `SIOCETHTOOL` (QEMU, sandboxed kernels). This also crashed pytest collection on ARM64. Fixed. Mutation-verified.

### Firewall

- **Under file capabilities, `nft` and `iptables` did not inherit `CAP_NET_ADMIN`,** so every block failed with "Operation not permitted". Fixed with ambient capabilities.
- **The null backend reported blocks as executed.** Fixed: it refuses.
- **nftables could not refresh a timeout or re-block an address permanently.** Fixed with an atomic add-delete-add.
- **The expiry reaper had a race and dropped failed unblocks.** Fixed: it runs under the engine lock and retries.

### Docker and deployment

- **The API and migrate containers could not start** (exec failed with EPERM) because capabilities were set on the shared interpreter. Fixed: a separate `python3-sensor` interpreter holds them.
- **The capture-profile sensor listened on `0.0.0.0` on the host.** Fixed: it binds the proxy network's gateway.
- **The sensor healthcheck** probed 127.0.0.1 regardless of `API_HOST`. Fixed.
- **Firewall health reported an error** before the nftables table existed. Fixed.
- **WebSocket disconnects** logged tracebacks. Fixed.

### Configuration and diagnostics

- **Flat aliases such as `DRY_RUN` were ignored in `.env`,** and a typo such as `DRY_RUN=ture` read as false. Fixed: values are parsed strictly.
- **`doctor` gave false results:**
  - PASS for missing rules;
  - PASS for a foreign service on the dashboard port;
  - FAIL for a fresh SQLite database that SentinelX would migrate.

  All fixed.

### Tests

- **Fixed sleeps made tests fail on slow hosts.** Replaced with bounded polling.

## 5. Security findings

Severities are this audit's assessment of impact in a default deployment.

### Critical

No open critical findings.

### High (all fixed)

- **H1.** An unauthenticated request could trigger a Rich traceback that logged frame locals, including the `Settings` object and JWT secret. Fixed: tracebacks carry no locals, and exception text is scrubbed of secrets. Regression test.
- **H2.** CLI crashes printed the settings, including the JWT secret and database URL. Fixed. Regression test.
- **H3.** Uploads were accepted before authentication and without size limits (multipart). Fixed: raw-body upload, with authentication and Content-Length checked before the body is read, plus streaming limits and a quota.
- **H4.** YAML alias expansion: a 400-byte rule produced a 30 MB response. Scenario parameters were also unbounded, so an analyst could exhaust memory. Fixed: restricted loader and parameter bounds.
- **H5.** Token races:
  - concurrent refresh-token reuse went undetected;
  - WebSocket tickets could be redeemed twice;
  - a global login lockout let anyone lock out the administrator.

  Fixed: atomic claim, GETDEL, and lockout per account-address pair plus account.
- **H6.** The safety banner did not reflect all enforcement paths, and dry run could be switched off without confirmation. Fixed: truthful banner and confirmation phrase.
- **H7.** A block could be reported as successful when nothing was enforced (null backend). Fixed.

### Medium (all fixed)

- **M1.** The configuration view could expose secrets and the full webhook URL. It is now redacted by pattern, including in audit diffs and `config.changed` events.
- **M2.** A spoofed `X-Forwarded-For` was believed (leftmost hop). The client address is now the rightmost untrusted hop.
- **M3.** Metrics were served to proxied requests that appeared to come from loopback. Fixed.
- **M4.** Webhook SSRF: private and internal destinations were allowed. Now refused unless explicitly permitted.
- **M5.** WebSocket streams ignored deactivation and role changes, busy streams were never rechecked, and there was no per-user connection cap. Fixed.
- **M6.** Logout and password change left other sessions' access tokens valid until expiry. A stale session's refresh after a password change revoked the caller's new session. Fixed.
- **M7.** The Compose capture sensor was reachable from other hosts. Fixed.
- **M8.** An absolute server path leaked in upload responses and errors. Fixed.
- **M9.** The operator's own address could be blocked. It is now protected for an hour after any API use.

### Low (open unless noted)

- **L1.** Dashboard pages send no Content-Security-Policy; the API responses do.
- **L2.** A refused manual block returns HTTP 200 with `executed: false` and an error, rather than a 4xx status.
- **L3.** Dry-run unblock does not validate the target as strictly as a real one.
- **L4.** A 6to4 address that embeds a loopback address (`2002:7f00:1::1`) is not refused. Blocking it does not affect loopback traffic.
- **L5.** Access-token cut-off after logout has one-second resolution. Without Redis, the cut-off, rate limits and tickets are per process.
- **L6.** Refused configuration and user operations are not all audited.
- **L7.** DNS rebinding between the webhook destination check and the connection is possible.
- **L8.** python-dotenv 1.2.1 has PYSEC-2026-2270 (`set_key` follows symlinks). SentinelX never calls it; the dependency floor is now `>=1.2.2`. Fixed.

### Info

- JWTs are signed with HS256 using a shared secret. There is no MFA or SSO.
- Analysts can see the host's interface addresses and cancel other users' replays. Viewers can see interface MAC addresses.
- GitHub private vulnerability reporting is disabled on the repository, although `SECURITY.md` refers to it. Turn it on in the repository settings.
- `npm audit --omit=dev` reports 0 vulnerabilities. `pip-audit` on the runtime dependency closure finds only L8.

## 6. Performance results (measured)

All figures come from an Intel Core i5-8350U (8 logical CPUs) with Python 3.14.6.

The API figures use a single uvicorn worker on loopback, SQLite and no Redis (`benchmarks/results/platform-20260915T003639Z.md`). The detection figures use synthetic traffic, 5 runs per experiment (`benchmarks/results/20260914T213750Z.md`).

### API latency

| Endpoint | Sequential p50 | Sequential p99 | Concurrency 10 p50 | req/s at concurrency 10 |
| --- | --- | --- | --- | --- |
| GET /system/health | 1.8 ms | 3.5 ms | 22.4 ms | 415.7 |
| GET /detections?limit=50 | 14.8 ms | 20.8 ms | 233.9 ms | 43.0 |
| GET /incidents?limit=50 | 8.9 ms | 13.6 ms | 92.2 ms | 108.0 |
| GET /stats/overview | 35.1 ms | 54.5 ms | 287.0 ms | 34.5 |
| POST /auth/login (Argon2id) | 65.1 ms | 105.0 ms | 658.1 ms | 15.2 |

### Event delivery and storage

- **WebSocket delivery, publish to client:** p50 28.9 ms, max 46.9 ms. Only 10 events were measured.
- **Storage throughput:** detections produced and stored, including pipeline processing.

| Database | Stored | Stored per second |
| --- | --- | --- |
| SQLite | 832 of 832 | 123.7 |
| PostgreSQL | 832 of 832 | 92.3 |

### Pipeline load

| Packets | Packets/s | p50 | p99 | RSS growth |
| --- | --- | --- | --- | --- |
| 1,000 | 4,926.9 | 0.177 ms | 0.348 ms | 0.0 MB |
| 10,000 | 5,311.9 | 0.165 ms | 0.465 ms | 0.5 MB |
| 50,000 | 4,922.4 | 0.173 ms | 0.609 ms | 0.0 MB |

### Detection quality

These results come from synthetic scenarios with known ground truth and do not predict real-world detection rates.

| Measure | Result |
| --- | --- |
| Detection rate, 14 attack experiments | 100% |
| False positives | 0 in every experiment |
| Evasion (slow port scan, low-rate brute force) | 0%, as expected |
| Throughput | 2,890–4,634 packets/s |
| Latency per detection | 0.39–0.81 ms |
| Peak RSS | 119–124 MB |
| Decoder | 41,433 frames/s, 2.1 times Scapy |

The detection run predates `assembly.py`, so it ran without local threat intelligence.

The pipeline is single-process Python at about 5,000 packets per second on this CPU. That suits hosts and small links, not high-bandwidth network taps.

## 7. Test results

| Check | Result |
| --- | --- |
| `ruff check`, `ruff format --check` | Pass, 160 files |
| `mypy` (strict, 116 source files) | Pass |
| `pytest` with real PostgreSQL 17 and Redis 7 (`make test-integration`) | 487 passed, 11 skipped (the kernel tests) |
| Kernel tests in a network namespace (`make test-kernel`) | 11 passed |
| PCAP suite (`tests/capture/test_pcap_suite.py`) | 38 passed (part of the main run) |
| Dashboard lint, typecheck, production build | Pass |
| OpenAPI contract regenerated from code | In sync after regeneration (the new `system` tag on `/system/capabilities` changed `openapi.json`); dashboard typecheck passes |
| Rules | 7 valid; embedded tests pass |
| Docker prevention chain, API level through the proxy, final image | 16 of 16 steps passed |
| Docker browser smoke test, final image | 15 of 15 checks passed |
| Local browser smoke test (`.env` configuration) | Every existing page passes |
| ARM64 under QEMU | ARM64_RESULT |

An earlier browser run of the full UI prevention chain (buttons and pages) passed 16 of 17 on the previous image. The one failure was a harness check that assumed live capture was unavailable in the container.

### Coverage

Coverage was measured on the SQLite run, and separately on the kernel run.

| Module | Main run | Kernel run |
| --- | --- | --- |
| All modules | 78.8% | — |
| config/settings.py | 96% | — |
| api/security.py | 95% | — |
| response/safety.py | 93% | — |
| signatures/rules.py | 93% | — |
| api/websocket.py | 92% | — |
| system/interfaces.py | 92% | — |
| telemetry/logging.py | 92% | — |
| services/config.py | 90% | — |
| storage/repositories.py | 90% | — |
| services/auth.py | 87% | — |
| nftables adapter | 84% | 80% |
| capture/pcapfile.py | 84% | — |
| response/engine.py | 80% | — |
| api/routes/auth.py | 80% | — |
| iptables adapter | 59% | 82% |
| capture/afpacket.py | 37% | 76% |
| capture/libpcap.py | 25% | 71% |
| Windows Firewall adapter | 71% | — |
| pf adapter | 64% | — |
| system/privileges.py | 50% | 40% |

Most of the privilege code is for other operating systems.

## 8. Known limitations

- **Unverified platforms.** macOS, Windows and WSL2 have never been run. The pf and Windows Firewall adapters and Npcap/BPF capture are unverified on real hosts.
- **Unverified on ARM64.** Live capture and firewall control are not verified on ARM64 hardware.
- **Docker networking.** Docker Desktop on macOS and Windows captures its virtual machine, not the computer. WSL2 capture and firewall changes apply to the WSL virtual machine.
- **Throughput.** About 5,000 packets per second in one Python process, with no multi-sensor scale-out beyond running separate sensors.
- **Evasion.** Slow and low-rate attacks below the default thresholds are not detected. This is asserted in `tests/pcaps/evasion`.
- **Aggressive mode.** `aggressive` detection mode currently selects the same detectors as `balanced`.
- **No Redis.** Without Redis, rate limits, WebSocket tickets and session cut-offs are per process.
- **No rate limiting on pf and Windows Firewall.** Their expiry depends on SentinelX's reaper, with deadlines restored from the database at start.
- **libpcap on Linux loopback** sees packets twice; `af_packet` is preferred and selected by `auto`.
- **Authentication.** HS256 JWTs with a shared secret; no MFA or SSO.

## 9. Remaining work

1. Run the new `portability` CI job on Windows and macOS and fix what it finds. Then test live capture and firewall control on real hosts: an elevated Windows session with Npcap, and root on macOS with pf.
2. Run the `kernel` CI job on GitHub Actions and confirm it runs rather than skips.
3. Verify on native ARM64 hardware, including the kernel tests.
4. Add a Content-Security-Policy to the dashboard (L1). Return a 4xx for refused manual blocks (L2). Close L3, L4 and L6.
5. Turn on GitHub private vulnerability reporting.
6. Re-run the detection benchmark now that pipelines include threat intelligence. Benchmark the API with PostgreSQL and Redis and more than one worker.
7. Make `aggressive` mode meaningful or remove it. Consider longer-window detectors for slow scans.
8. Soak test: a multi-day live capture on a real network, watching memory, database growth and false positives.

## 10. Release recommendation

**BETA READY**, scoped to Linux x86_64 and Docker on a Linux host.

The core promise holds under test on those platforms:

- Detection is explainable and reproducible.
- Prevention is off by default and needs an explicit phrase to enable.
- The kernel firewall changes when prevention is on, reverts on unblock, and every change is audited.
- The security hardening is covered by regression tests.

It is not PRODUCTION READY. Three platforms the project claims to support have never run it. The Windows and macOS CI jobs have not run. Low-severity security items remain open, and there has been no long-running operation on a real network. For macOS, Windows and WSL2 the honest status is DEVELOPMENT READY.
