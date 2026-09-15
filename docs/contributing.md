# Contributing

This guide covers the development setup, the repository layout, the checks every change must pass, and the conventions for adding detectors, protocol parsers, rules, API endpoints, migrations and dashboard views.

## Contents

- [Development setup](#development-setup)
- [Repository layout](#repository-layout)
- [Make targets](#make-targets)
- [Continuous integration](#continuous-integration)
- [Coding standards](#coding-standards)
- [Adding a detector](#adding-a-detector)
- [Adding a protocol parser](#adding-a-protocol-parser)
- [Adding a rule](#adding-a-rule)
- [Adding an API endpoint](#adding-an-api-endpoint)
- [Database migrations](#database-migrations)
- [Dashboard conventions](#dashboard-conventions)
- [Tests](#tests)
- [Benchmark policy](#benchmark-policy)
- [Commits and pull requests](#commits-and-pull-requests)
- [Reporting security issues](#reporting-security-issues)

## Development setup

| Requirement | Version | Source |
|---|---|---|
| Python | 3.12 or newer | `requires-python = ">=3.12"` in `pyproject.toml`. CI and the API image (`docker/Dockerfile.api`) use 3.12 |
| Node.js | 20.9 or newer | `engines.node` in `apps/dashboard/package.json`. CI uses Node 22 and the dashboard image (`docker/Dockerfile.dashboard`) uses `node:24-alpine` |
| Docker | any recent version | Only for `make test-integration` and the `docker-*` targets |
| Linux with unprivileged user namespaces, `iproute2`, `nft`, `iptables` and libpcap | | Only for `make test-kernel` |

```bash
make install                    # uses python3; override with: make install PYTHON=python3.12
source .venv/bin/activate
```

`make install`:

1. creates `.venv` with `$(PYTHON) -m venv` if it does not exist,
2. runs `pip install -e ".[dev,ml]"`, which installs SentinelX in editable mode with the development tools (pytest, pytest-asyncio, pytest-cov, mypy, ruff, types-PyYAML) and the optional machine-learning dependencies (numpy, scikit-learn),
3. runs `npm ci` in `apps/dashboard`,
4. copies `.env.example` to `.env` if `.env` does not exist. Review it before starting the platform.

The `sentinelx` command is installed into `.venv/bin`. Run pytest as `.venv/bin/python -m pytest` (this is what the Makefile does), not through a separate `pytest` executable, so the virtual environment's interpreter and packages are always the ones used.

To try the platform without capture privileges, generate fixtures and replay one:

```bash
make fixtures
make replay                     # replays pcaps/fixtures/mixed_intrusion.pcap
make dev                        # API on :8000 and dashboard on :3000, with reload
make seed                       # fill the development database from synthetic scenarios
```

See [pcap-lab.md](pcap-lab.md) for the offline workflow.

### Without make (Windows)

The Makefile needs `make` and `bash`. On Windows, run the underlying commands directly from the repository root. In PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev,ml]"
npm ci --prefix apps/dashboard
Copy-Item .env.example .env              # only if .env does not exist

# make test
.venv\Scripts\python -m pytest
# make lint
.venv\Scripts\ruff check packages apps tests scripts
.venv\Scripts\ruff format --check packages apps tests scripts
npm run --prefix apps/dashboard -s lint
# make typecheck
.venv\Scripts\mypy
npm run --prefix apps/dashboard -s typecheck
# make rules
.venv\Scripts\sentinelx rules validate
.venv\Scripts\sentinelx rules test rules
# make openapi
.venv\Scripts\python scripts\export_openapi.py
npm run --prefix apps/dashboard -s generate:api
# make fixtures and make replay
.venv\Scripts\sentinelx fixtures generate --output pcaps/fixtures
.venv\Scripts\sentinelx replay pcaps/fixtures/mixed_intrusion.pcap
# make api and make dashboard (two terminals)
.venv\Scripts\sentinelx start --reload
$env:SENTINELX_API_URL = "http://127.0.0.1:8000"; npm run --prefix apps/dashboard dev
```

`make test-kernel` is Linux-only; on other systems the kernel tests are collected and skipped. `make test-integration` uses `bash` and `docker`; on Windows, start PostgreSQL and Redis yourself and set the two variables described under [Make targets](#make-targets).

## Repository layout

| Path | Contents |
|---|---|
| `packages/sentinelx/` | The Python package. The package map is in [architecture.md](architecture.md#package-map) |
| `packages/sentinelx/assembly.py` | The single place that decides which detectors, rules and threat intelligence a pipeline gets. The live platform, replays, the CLI and the benchmarks all use it |
| `packages/sentinelx/storage/migrations/` | Alembic environment and revisions (`versions/`) |
| `apps/dashboard/` | Next.js dashboard |
| `apps/api/main.py`, `apps/cli/main.py` | Thin entry points for uvicorn and for running the CLI from a checkout |
| `rules/` | YAML detection rules (`authentication.yml`, `dns-and-web.yml`, `network-recon.yml`) and threat intelligence lists (`rules/intel/allowlist.txt`, `rules/intel/denylist.txt`) |
| `tests/` | Test suite (see [Tests](#tests)) |
| `scripts/` | `benchmark.py` (detection experiments), `benchmark_platform.py` (API, WebSocket, storage and pipeline load), `export_openapi.py`, `generate_test_pcaps.py` (the committed PCAP suite in `tests/pcaps/`), `seed_demo.py` |
| `benchmarks/results/` | Benchmark reports cited by [benchmarking.md](benchmarking.md). Committed |
| `pcaps/` | Capture files and generated fixtures. Ignored by git except `.gitkeep` |
| `docker/` | `Dockerfile.api`, `Dockerfile.dashboard`, and `proxy/default.conf.template` (the nginx front proxy); `docker-compose.yml` is at the root |
| `docs/` | Documentation |
| `.github/workflows/ci.yml` | CI (see [Continuous integration](#continuous-integration)) |
| `alembic.ini` | Alembic configuration (`script_location = packages/sentinelx/storage/migrations`) |

The traffic-processing core (`capture`, `parser`, `features`, `detection`, `signatures`, `anomaly`, `scoring`, `correlation`, `threat_intel`, `response`, `firewall` and `pipeline.py`) does not import from `api`, `cli`, `services` or `storage`. Keep it that way: the core must stay usable from a test, the benchmark harness or a script with no database, Redis or HTTP server.

## Make targets

Run `make help` for the full list. The quality targets:

| Target | What it runs |
|---|---|
| `make test` | `.venv/bin/python -m pytest`. Uses SQLite and needs no external services. PostgreSQL, Redis and kernel tests are skipped |
| `make test-integration` | Starts `postgres:17-alpine` on `127.0.0.1:55432` and `redis:7-alpine` on `127.0.0.1:56379` in throwaway containers, waits for PostgreSQL, runs the full suite with `SENTINELX_TEST_POSTGRES_URL` and `SENTINELX_TEST_REDIS_URL` set, and removes the containers on exit |
| `make test-kernel` | Real packet capture and real firewall tests (`tests/kernel`), inside a private network namespace. See [Kernel tests](#kernel-tests) |
| `make coverage` | `.venv/bin/python -m pytest --cov --cov-report=term-missing` (coverage source `packages/sentinelx`) |
| `make lint` | `ruff check` and `ruff format --check` on `packages apps tests scripts`, then `npm run -s lint` (ESLint) in the dashboard |
| `make typecheck` | `mypy` (strict, configured in `pyproject.toml`), then `npm run -s typecheck` (`tsc --noEmit`) |
| `make format` | `ruff check --fix` and `ruff format` on `packages apps tests scripts` |
| `make rules` | `sentinelx rules validate`, then `sentinelx rules test rules` (every rule's embedded tests) |
| `make openapi` | `python scripts/export_openapi.py`, then `npm run -s generate:api` in the dashboard |
| `make check` | `lint`, `typecheck`, `test`, `rules`, then `npm run -s build` in the dashboard |
| `make benchmark` | `python scripts/benchmark.py --runs 5` |

You can run the integration tests against services you already have by setting the two variables yourself:

```bash
SENTINELX_TEST_POSTGRES_URL=postgresql://user:password@127.0.0.1:5432/sentinelx_test \
SENTINELX_TEST_REDIS_URL=redis://127.0.0.1:6379/0 \
.venv/bin/python -m pytest
```

Point the PostgreSQL variable at a disposable database. The storage tests drop and recreate its `public` schema, and `tests/integration/test_schema.py` creates and drops a separate database named `sx_schema_test`, so the user needs permission to create databases.

### Kernel tests

`make test-kernel` runs:

```bash
unshare -rn sh -c 'ip link set lo up && ip link add sx0 type dummy && \
  ip addr add 203.0.113.5/32 dev sx0 && ip addr add 203.0.113.6/32 dev sx0 && \
  ip link set sx0 up && .venv/bin/python -m pytest tests/kernel -p no:cacheprovider'
```

`unshare -rn` creates a user namespace in which you are root and a new, empty network namespace. The tests there hold `CAP_NET_RAW` and `CAP_NET_ADMIN` for that namespace only, so they can open capture sockets and change netfilter rules without touching the host's network or needing `sudo`. A dummy interface carries the test attacker and victim addresses.

- `tests/kernel/test_live_capture.py` captures from `lo` and `any` with the AF_PACKET and libpcap backends and with `auto`, checks that every frame decodes, that a BPF filter is applied in the kernel, and that an invalid BPF filter is refused rather than ignored.
- `tests/kernel/test_firewall.py` runs the nftables and iptables adapters through the response engine and verifies with real UDP traffic: block, unblock, expiry, re-block, rate limiting and teardown.
- `tests/kernel/test_response_modes.py` runs automatic response against real netfilter: duplicate decisions, rate limits and escalation from a rate limit to a block.

`tests/kernel/conftest.py` marks every kernel test `root` and skips it unless the process has both capabilities and the two test addresses are assigned locally, so `make test`, the CI backend and portability jobs, and other operating systems skip them. The CI kernel job runs them and fails if any is skipped. The target needs unprivileged user namespaces to be enabled (some distributions disable them) and the `ip`, `nft` and `iptables` commands.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and on every pull request. A newer run for the same ref cancels one in progress. It has five jobs:

**Backend (lint, types, tests)** on `ubuntu-latest` with Python 3.12, and `postgres:17-alpine` and `redis:7-alpine` service containers:

1. Installs `libpcap0.8` and `pip install -e ".[dev,ml]"`, so the machine-learning tests run too.
2. `ruff check` and `ruff format --check` on `packages apps tests scripts`.
3. `mypy`.
4. `python -m pytest --cov --cov-report=term-missing` with `SENTINELX_TEST_POSTGRES_URL` and `SENTINELX_TEST_REDIS_URL` set, so the SQLite, PostgreSQL and Redis tests all run. Kernel tests are skipped.
5. Migrations: creates an empty `sentinelx_ci_migrations` database, runs `sentinelx db upgrade` against it, then `alembic check`, which fails if the models and the migrated schema differ.
6. `sentinelx rules validate` and `sentinelx rules test rules`.

**Dashboard (lint, types, build, API contract)** with Python 3.12 and Node 22:

1. `pip install -e .` and `npm ci`.
2. Regenerates the OpenAPI document and the TypeScript schema (`scripts/export_openapi.py`, `npm run generate:api`) and fails if `apps/dashboard/src/lib/openapi.json` or `apps/dashboard/src/lib/api-schema.d.ts` differ from the committed files.
3. ESLint, `tsc` type check and `next build`.

**Kernel (real capture and firewall, network namespace)** on `ubuntu-latest` with Python 3.12: installs `libpcap0.8`, `nftables`, `iptables` and `iproute2` and a `.venv` with `.[dev]`, allows unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=0`), then runs `make test-kernel` (see [Kernel tests](#kernel-tests)). The job fails if pytest reports any skipped test, so kernel tests cannot pass by skipping.

**Portability** on `windows-latest` and `macos-latest` with Python 3.12 (`fail-fast: false`): `pip install -e ".[dev]"`, `sentinelx capabilities` and `sentinelx doctor` as a report (`continue-on-error`, so a doctor FAIL does not fail the job), the test suite (`python -m pytest -p no:cacheprovider`), and `sentinelx fixtures generate tcp_port_scan` followed by `sentinelx replay` of that file. Live capture and firewall control are not exercised there. At the time of writing this job is defined but has not yet run, so no macOS or Windows result is known.

**Container images build**, after the backend, kernel and dashboard jobs pass: `docker build` of `docker/Dockerfile.api` and `docker/Dockerfile.dashboard`. The images are not pushed.

CI therefore covers more than `make check` (PostgreSQL and Redis tests, the machine-learning tests, the migration check, the kernel tests, the API contract and the images) but does not run either benchmark.

## Coding standards

### Python style and types

Ruff and mypy settings live in `pyproject.toml`.

| Setting | Value |
|---|---|
| Line length | 100 (`E501` is left to the formatter) |
| Target | `py312` |
| Rule sets | `E`, `W` (pycodestyle), `F` (pyflakes), `I` (isort), `B` (bugbear), `C4`, `UP` (pyupgrade), `S` (bandit), `ASYNC`, `RUF`, `SIM`, `TID`, `PTH` (pathlib), `N` (pep8-naming) |
| Ignored | `E501`; `S104` (binding `0.0.0.0` is a documented container default); `B008` (FastAPI `Depends()` defaults) |
| Per-file ignores | `tests/*`: `S101`, `S105`, `S106`, `S311`. `scripts/*`: `S101`, `S603`, `S607`. `packages/sentinelx/firewall/*`: `S603`. `packages/sentinelx/testing/*`: `S311` (reproducible, non-secret randomness) |
| Imports | Relative imports are banned (`ban-relative-imports = "all"`); `sentinelx` is first-party for isort |
| mypy | `strict = true`, `warn_unreachable`, `disallow_any_generics`, pydantic plugin. Checks the `sentinelx` package and excludes generated Alembic revisions. Missing stubs are ignored only for `scapy`, `sklearn`, `redis`, `psutil` and `joblib` |

Do not add a `# noqa` or `# type: ignore` to get past a check without a specific error code and a reason.

### Hot path

Code that runs once per packet (decoding, feature extraction, detection) is performance-sensitive.

- Per-packet models are `@dataclass(frozen=True, slots=True)`, not Pydantic models: `PacketEvent`, `Detection`, `Evidence` and the other models in `common/models.py`, and the `DnsInfo`, `HttpInfo` and `TlsInfo` results in `parser/application.py`. Use the same for new per-packet types.
- Long-lived per-packet workers declare `__slots__` (for example `PacketDecoder`).
- Header decoding uses `struct`, not Scapy. Capture files are read by SentinelX's own reader (`capture/pcapfile.py`); Scapy is used only by the libpcap live capture backend and the decoder microbenchmark.
- State must be bounded. See [architecture.md](architecture.md#state-and-memory-bounds) before adding per-source or per-flow state.
- Do not claim a speed-up without measuring it (see [Benchmark policy](#benchmark-policy)).

### Security rules

- **No `eval` or `exec`.** Rule conditions are parsed by the hand-written, bounded parser in `signatures/dsl.py`. Rule YAML is loaded with `load_rule_yaml` in `signatures/rules.py`, a restricted `SafeLoader` that refuses anchors, aliases and deep nesting; never call `yaml.load` with another loader, and use `yaml.safe_load` for other YAML. Ruff's bandit rules (`S`) flag violations.
- **Subprocesses take an argument vector, never a shell.** The only subprocess call in the package is the firewall command runner in `firewall/base.py`, which uses `asyncio.create_subprocess_exec` (a worker thread with `subprocess.run` on Windows), requires every argument to be a `str`, rejects arguments containing control characters, and applies a timeout. `S603` is ignored only for `packages/sentinelx/firewall/*`.
- **No security logic in route handlers.** Routes validate input, check the role and call a service in `packages/sentinelx/services/` or the core. Path checks, upload validation, quota and size enforcement, safety-guard decisions and audit records belong in services. For example, `api/routes/replay.py` checks only the content type and declared length, then passes client paths to `ReplayService.resolve` and the body stream to `ReplayService.store_upload`.
- **Check authentication before reading untrusted bodies.** A route that accepts a large body must take the role dependency and read the body itself (`request.stream()`), so an unauthenticated request is refused before any byte is read, as `POST /replay/upload` does.
- **Request bodies are strict.** API request models extend `StrictModel` (`extra="forbid"`) in `api/schemas.py` and bound every field (lengths, ranges, list sizes). Bound query and path parameters too, including offsets and ids.
- **Bound everything a user can make the server generate or parse.** Scenario parameters go through `validate_scenario_params`; add bounds there for any new scenario parameter.
- **State-changing actions are audited** with `AuditService.record(actor=..., action=..., target=..., source=...)`.
- **Errors are typed.** Raise a `SentinelXError` subclass from `common/errors.py`. `api/errors.py` maps them to HTTP responses (for example `PcapError` to 422), and the CLI's `run()` turns them into exit code 1 without a traceback.
- **Never log settings objects or secrets.** The log redaction processor is a safety net, not a licence. Name new secret settings so that they contain `secret`, `token`, `password`, `api_key` or `credential`; the configuration view hides fields by those names.

### Detections must carry evidence

A detection is only useful if an analyst can verify it. `DetectionEngine` discards any detection with no `Evidence` and counts it as a detector error (`detection_without_evidence_rejected`). Each `Evidence` item has a machine-readable `key` and `value`, a sentence in `description`, the `threshold` it was compared against where there is one, and a `weight`. The dashboard shows the descriptions verbatim.

Detectors must also never raise on traffic. The engine isolates exceptions, but a detector that relies on that is hiding a bug.

## Adding a detector

Read [detection-engine.md](detection-engine.md) first.

1. **Counting goes in the feature extractor.** Detectors are stateless with respect to counting. If the detector needs a new count or window, add it to the source profile or flow state in `packages/sentinelx/features/profiles.py` and update it in `features/extractor.py`, keeping it bounded.
2. **Write the detector.** Subclass `Detector` (`detection/base.py`) in the module that fits (`scanning.py`, `behavioral.py`, `dns.py`, `policy.py`) or a new module in `detection/`. Set:
   - `name`: a stable identifier. It appears in metrics, the API, stored detections and settings, so it must not change once released.
   - `description`, `category` (`ThreatCategory`), `default_severity` (`Severity`) and `references`.
3. **Implement `inspect(context)`.** Return `None` in the common case. When the criteria are met, return `self.build(context=..., title=..., description=..., evidence=[...], confidence=...)`, with optional `severity`, `recommended_action`, `observation_window`, `packet_count` and `tags`. Use `Detector.scaled_confidence(observed, threshold)` so confidence grows with how far past the threshold the value is. Do not set timestamps yourself: the engine stamps each detection with the capture time of the triggering packet.
4. **Add thresholds to `DetectionSettings`** in `config/settings.py`, with bounds and a `description`. They become settable as `DETECTION__<FIELD>` and are editable at runtime through the configuration service. If you add a window length, check `WINDOW_FIELDS` in `services/config.py` and `max_rule_window()` in `services/rules.py`.
5. **Register it** in `BUILTIN_DETECTORS` in `detection/engine.py`. Order matters: cheap, precise detectors run first. Add the name to `_SIGNATURE_DETECTORS` only if it matches facts rather than rates and should run in `signature_only` mode. A detector that is attached separately (like the anomaly detectors) must be attached in `assembly.py`, so live capture, replays and benchmarks all get it.
6. **Add a scenario** to `packages/sentinelx/testing/scenarios.py` and to the `SCENARIOS` dict, with `expected_detectors` and `expected_source`. Draw all randomness from the scenario's seeded generator so the fixture stays reproducible (header fields such as IP identifiers, TCP sequence numbers and DNS ids come from a header generator that `get_scenario` reseeds per scenario, so do not use the global `random` module), and add bounds for any new parameter to `validate_scenario_params`. If the scenario is a known evasion, say so in its description.
7. **Test it** in `tests/detection/test_detectors.py`: a positive case on the scenario, negative cases on traffic that shares a surface feature with the attack but not its shape, and edge cases. Assert that every detection has evidence with descriptions.
8. **Document it** in the detector catalogue in [detection-engine.md](detection-engine.md). If it should be benchmarked, add an `Experiment` in `packages/sentinelx/bench/experiments.py` and re-run the benchmark.

## Adding a protocol parser

Application-layer parsing is pluggable (`packages/sentinelx/parser/decoder.py`). A parser is a function `(payload: bytes, src_port: int, dst_port: int) -> dict[str, Any] | None`. Its result is merged into `PacketEvent.metadata`.

```python
from sentinelx.common.enums import Protocol
from sentinelx.parser.decoder import register_app_parser


def ntp(payload: bytes, src_port: int, dst_port: int) -> dict[str, object] | None:
    if 123 not in (src_port, dst_port) or len(payload) < 4:
        return None
    return {"ntp": {"mode": payload[0] & 0x07}}


register_app_parser("ntp", ntp, {Protocol.UDP})
```

- `name` is a unique key; registering the same name again replaces the parser. `protocols` defaults to TCP and UDP.
- Parsers run only for packets with a transport payload and ports, and only when application parsing is enabled on the decoder.
- Check the ports first and return `None` quickly: every registered parser is called for every matching packet.
- A parser that raises does not drop the packet. The exception is counted in the parse-error metric under the parser's name and the remaining parsers still run. Even so, treat all payload bytes as hostile: check lengths before indexing and bound any loop.

For a built-in parser, follow the existing pattern: put the decoding function in `parser/application.py` returning a frozen, slotted dataclass, add a wrapper in `decoder.py` that turns it into a metadata dict, and add it to `_APP_PARSERS`. To make new metadata usable in rules, add the field to `FIELDS` in `signatures/dsl.py` and a getter to the field table in `signatures/detector.py`; `sentinelx rules fields` then lists it.

Tests go in `tests/capture/test_parser.py`. `test_custom_app_parser_registration` shows how to register a parser in a test and remove it afterwards so it does not leak into other tests.

## Adding a rule

Rules are YAML files under `rules/` (any `*.yml` or `*.yaml` file, searched recursively). The format and the condition language are documented in [rule-engine.md](rule-engine.md).

Every rule in the repository must carry embedded tests. `tests/detection/test_rules.py` requires at least one `no_match` case for every rule, and at least one `match` case for every rule whose `action` is not `log`, and it requires all of them to pass:

```yaml
    tests:
      - scenario: tcp_port_scan
        expect: match
      - scenario: normal_traffic
        expect: no_match
      - scenario: tcp_port_scan
        params: {ports: 30}
        expect: no_match
```

`scenario` is a name from `scenarios.py`, `params` are passed to the scenario function, and `expect` is `match` or `no_match`. Scenario names and parameters are checked when the rule is validated. A rule's `within` may not exceed the longest built-in detector window, because the feature engine keeps no more history than that. Rule files may not use YAML anchors or aliases.

```bash
sentinelx rules validate                                     # all files in RULES_DIRECTORY; exit 1 if any are invalid
sentinelx rules test rules/network-recon.yml                 # embedded tests; exit 1 on failure
sentinelx rules test rules/network-recon.yml --pcap capture.pcap
sentinelx rules fields                                       # fields available in conditions
make rules                                                   # what CI runs
```

Because `tests/detection/test_rules.py` loads every file in `rules/` (with a 60-second window limit), an invalid rule, a missing test case or a failing test also fails `make test`. Testing a rule against your own captures is described in [pcap-lab.md](pcap-lab.md#testing-a-rule-against-a-capture).

## Adding an API endpoint

1. **Route.** Add the handler to the matching module in `packages/sentinelx/api/routes/` (`auth`, `system`, `detections`, `firewall`, `rules`, `stats`, `replay`). A new module must also be added to the router loop in `api/app.py`, which mounts routers under `/api/v1`. Give the route a `tags=[...]` entry so it is grouped in the OpenAPI document.
2. **Authorisation.** Take a role dependency from `api/security.py` as a parameter: `Viewer`, `Analyst` or `Admin`. Take the platform as `PlatformDep`.
3. **Input.** Define request bodies in `api/schemas.py` as `StrictModel` subclasses with bounded fields, and bound query and path parameters with `Query(...)` and `Path(...)` (for example `offset: int = Query(default=0, ge=0, le=1_000_000)`).
4. **Logic.** Call a service. Put validation that protects the system, file and path handling, response and firewall decisions, and audit recording in the service, not in the handler. If the change should reach other open dashboards, publish an event on `platform.bus`, as `PATCH /incidents/{incident_id}` does with `incident.updated`.
5. **Errors.** Raise typed errors and let `api/errors.py` map them, or raise `HTTPException` for plain request errors such as 404.
6. **Tests.** Add cases to `tests/api/test_api.py`, including the role check and invalid input. `tests/api/conftest.py` builds an isolated app with a file SQLite database and an unreachable Redis, and requests go through `httpx.ASGITransport` without opening a network port. Tests for abuse cases (races, lockout, forged headers, resource exhaustion, token revocation) belong in `tests/api/test_security_hardening.py`.
7. **Contract.** Regenerate and commit the dashboard's typed contract:

   ```bash
   make openapi
   # equivalent to:
   .venv/bin/python scripts/export_openapi.py        # writes apps/dashboard/src/lib/openapi.json
   cd apps/dashboard && npm run generate:api         # writes apps/dashboard/src/lib/api-schema.d.ts
   ```

   Commit both files. CI regenerates them and fails if they differ from the committed versions. `scripts/export_openapi.py` accepts an optional output path, which is useful for checking drift without touching the working tree.

8. **Dashboard types.** Request body types in `apps/dashboard/src/lib/types.ts` are aliases of the generated schema (for example `export type ReplayRequest = Schemas["ReplayRequest"]`), so a renamed or removed field becomes a TypeScript error. Response types in the same file are written by hand to mirror the serialisers in `packages/sentinelx/events/serialize.py` and `packages/sentinelx/services/queries.py`; update them when a response shape changes.
9. **Docs.** Update [api.md](api.md).

## Database migrations

SQLAlchemy models are in `packages/sentinelx/storage/models.py`; Alembic revisions are in `packages/sentinelx/storage/migrations/versions/`, named `YYYYMMDD_<revision>_<slug>.py`. The Alembic environment reads the database URL from SentinelX settings (`DATABASE_URL`), renders batch operations so that `ALTER TABLE` migrations also work on SQLite, and compares column types. Batch mode rebuilds the table on SQLite and cannot carry over an expression index, so for the `users` table (which has one on `lower(username)`) use a plain `op.add_column`, as revision `60413ece4dff` does.

How the schema is prepared at startup (`Database._prepare_schema` in `storage/database.py`):

- An in-memory SQLite database (the test default) is created directly from the models.
- A SQLite file is migrated to the latest revision automatically. A database with tables but no `alembic_version` is adopted first (`adopt_unversioned` in `storage/migrate.py`): stamped at the latest revision if its schema matches the models, otherwise at the initial revision. `sentinelx db upgrade` does the same on any database.
- PostgreSQL is never changed automatically. Startup fails with `database schema is at revision <x> but this version of SentinelX needs <head>; run: sentinelx db upgrade` unless the database is at the latest revision.

Every model change therefore needs a migration.

1. Change the models.
2. Point `DATABASE_URL` at a disposable scratch database and bring it to the current head **before** generating, so the new revision contains only your change:

   ```bash
   export DATABASE_URL=postgresql://sentinelx:password@127.0.0.1:5432/sentinelx_scratch
   sentinelx db upgrade
   ```

3. Generate the revision against that upgraded database and review it by hand. Autogenerate misses some changes and can produce wrong ones; the initial revision contains a hand correction for an expression-based index.

   ```bash
   .venv/bin/python -m alembic revision --autogenerate -m "add replay notes"
   ```

   Rename the file to the `YYYYMMDD_<revision>_<slug>.py` pattern if needed.

4. Apply it and check for drift:

   ```bash
   sentinelx db upgrade
   sentinelx db current            # applied and latest revisions
   .venv/bin/python -m alembic check
   ```

`alembic check` exits with an error if the models and the migrated schema still differ. CI runs it against an empty PostgreSQL database. Prefer PostgreSQL for this check: on SQLite, Alembic cannot reflect expression-based indexes and skips comparing them. If existing rows need values for a new column, write the data migration in the revision; existing SQLite files are upgraded on the next start. The PostgreSQL storage tests (`make test-integration`) build their schema through the migrations rather than `create_all`, and `tests/integration/test_schema.py` checks that an outdated SQLite file is upgraded and an outdated PostgreSQL schema is refused, so they also exercise the new revision. Generated revisions are excluded from mypy.

## Dashboard conventions

The dashboard is in `apps/dashboard` (Next.js 16 App Router, React 19, TypeScript 5.9 in strict mode with `noUncheckedIndexedAccess`, Tailwind CSS 4). Its dependencies are deliberately few: `swr` for data fetching, `lucide-react` for icons, and self-hosted `@fontsource` fonts loaded with `next/font/local` so the dashboard builds and runs without internet access.

```bash
cd apps/dashboard
SENTINELX_API_URL=http://127.0.0.1:8000 npm run dev    # or: make dashboard
npm run lint
npm run typecheck
npm run build
```

- **Pages.** Console pages live in `src/app/(console)/<name>/page.tsx`. Add navigation entries to `NAV` in `src/components/shell/app-shell.tsx`.
- **API access.** The browser only talks to its own origin. `next.config.ts` rewrites `/api/*` to `SENTINELX_API_URL`, and the development server also forwards WebSocket upgrades, so the event stream uses the same origin by default. Use the client in `src/lib/api.ts`: `useSWR<T>("/path")` for reads (the global fetcher is configured in `src/app/providers.tsx`) and `api<T>(path, { method, json })` for JSON writes. For a non-JSON body, pass `body` and `headers` instead of `json`, as the PCAP Lab upload does (`body: file`, `Content-Type: application/octet-stream`). The client attaches the CSRF header and refreshes the session on a 401. Do not call `fetch` directly for API requests.
- **Live updates.** Subscribe to WebSocket events with `useEvents().subscribe([...types], handler)` from `src/lib/events.tsx`.
- **No mock data.** Every view shows data from the API. Where the API has no data, show an empty state; do not invent sample rows or placeholder numbers. The login page's example explanation is the only fixed example: it is copied from the engine's real output for the `tcp_port_scan` fixture and labelled on screen as an example.
- **Loading, empty and error states.** Every data-driven view handles all three with the primitives in `src/components/ui/primitives.tsx`: `Skeleton` or `TableSkeleton` while loading, `EmptyState` when there is nothing to show, and `ErrorState` (with `onRetry` where a retry makes sense) on failure. A view that throws while rendering, for example on an API response of an unexpected shape, is caught by `src/app/(console)/error.tsx`, which shows an error panel with a **Try again** button. Components in the shell (top bar, footer, event tape) render on every page and must check the type of API data before using it, so that malformed data cannot take every page down.
- **Permissions.** Hide or disable actions the user's role cannot perform with `useSession().can("analyst")` or `can("admin")`. The API enforces roles regardless; this only keeps the interface honest.
- **Feedback.** Report the outcome of an action with `useToast()`.
- **Accessibility.** Give every form control a label (`Field` with `htmlFor`), give icon-only buttons an `aria-label`, mark decorative icons `aria-hidden`, use `role="status"` with `aria-live="polite"` for progress and validation messages, use `scope="col"` on table headers, and mark the current item in a list with `aria-current`. `eslint-config-next` enables a subset of `jsx-a11y` checks as warnings; they do not replace checking with a keyboard and a screen reader.
- **React Compiler lint rules.** `eslint.config.mjs` extends `eslint-config-next/core-web-vitals` and `eslint-config-next/typescript`, which enable the recommended `eslint-plugin-react-hooks` rules (version 7), including the React Compiler rules such as `react-hooks/set-state-in-effect`, `react-hooks/set-state-in-render`, `react-hooks/refs`, `react-hooks/purity`, `react-hooks/immutability` and `react-hooks/static-components`. Fix the code rather than disabling a rule. The project also sets `no-console` (only `console.warn` and `console.error` are allowed) and `react/jsx-no-target-blank`.
- **Generated files.** Never edit `src/lib/api-schema.d.ts` or `src/lib/openapi.json` by hand; run `make openapi`.

## Tests

Tests live under `tests/` and run with `.venv/bin/python -m pytest` (`make test`).

| Path | Covers |
|---|---|
| `tests/unit/` | CLI commands and exit codes, configuration and logging (including secret redaction in tracebacks), capability detection, network utilities and models, scoring and correlation, sliding windows. `test_cli_matrix.py` enumerates every command from the Typer app and checks help, usage errors, exit codes (0 success, 1 runtime failure, 2 usage error), JSON output and doctor accuracy; `test_event_bus.py` checks that security events wait for room in a full handler queue instead of being dropped |
| `tests/capture/` | Packet decoding and application parsers, capture sources, the capture-file reader (`test_pcapfile.py`: pcap and pcapng formats, timestamp resolutions, per-interface link types, hostile files, reproducible fixtures), and the committed PCAP suite (`test_pcap_suite.py`, see [PCAP test suite](#pcap-test-suite)) |
| `tests/detection/` | Built-in detectors (including `TestDocumentedEvasions`), rules (including every file in `rules/`), anomaly detection. The matrix files cover each area exhaustively: `test_parser_matrix.py` (every link type, IPv4 options and fragments, IPv6 extension headers, all TCP flag values, DNS edge cases, and a truncation and fuzz sweep proving `decode` never raises), `test_feature_matrix.py` (feature extraction with exact expected values), `test_detector_matrix.py` (every detector at its exact threshold boundary), `test_rule_matrix.py` (rule loading, validation, every field and operator, hostile rule content), `test_risk_matrix.py` (determinism, per-factor direction, bounds) and `test_correlation_matrix.py` (grouping, windows, duplicates, escalation, caps) |
| `tests/response/` | Response engine and safety guard; pf and Windows Firewall adapters against recorded command results (`test_platform_firewalls.py`); `test_response_matrix.py` (modes, approvals, expiry, duplicates, webhooks, failures and safety, with firewall commands observed through a recording runner or fake `nft` and `iptables` scripts) |
| `tests/api/test_api.py` | The HTTP API and WebSocket, with the fixtures in `tests/api/conftest.py` |
| `tests/api/test_endpoint_matrix.py` | Every HTTP operation listed once with its access level: the table must match the live routes; unauthenticated, per-role, malformed-input and hostile-path checks; pagination and filters, rate limiting, a database outage, and that no response leaks a traceback, file path, password hash or secret |
| `tests/api/test_auth_matrix.py` | Login and lockout, disabled accounts, forced password changes, token expiry and forgery, refresh rotation, logout, cookie sessions with CSRF, the password policy, secrets in logs, and role enforcement including the last-administrator guard |
| `tests/api/test_security_hardening.py` | Regression tests from the security review: concurrent refresh-token and WebSocket-ticket reuse, access-token revocation on sign-out, two-level lockout, forged `X-Forwarded-For`, metrics behind a proxy and non-ASCII metrics tokens, YAML alias expansion, oversized scenario parameters, prevention confirmation and environment precedence, replay and live detector parity, and operator-address protection |
| `tests/integration/` | The full pipeline, storage on SQLite and optionally PostgreSQL and Redis, and schema checks at startup (`test_schema.py`). `test_storage_matrix.py` covers schema, constraints, migrations, sessions, event persistence through database outages (simulated with an in-process TCP proxy), query counts and Redis shared state, on a SQLite file and, when the test URLs are set, on PostgreSQL and Redis |
| `tests/kernel/` | Real capture, firewall and automatic response tests, run only by `make test-kernel` (see [Kernel tests](#kernel-tests)) |

### PCAP test suite

`tests/pcaps/` holds small synthetic captures that are committed to the repository (source, licence and layout in `tests/pcaps/README.md`). `scripts/generate_test_pcaps.py` generates them and writes `tests/pcaps/MANIFEST.json`, which records each file's SHA-256, packet count, and the exact `detector@source` pairs and incident count a replay through the full detection pipeline (built-in detectors, anomaly detection, local threat intelligence and the rules in `rules/`) produces. `tests/capture/test_pcap_suite.py` checks that every file is in the manifest, that committed files are unchanged, that the generator still produces the committed bytes, and that each replay matches the manifest:

| Directory | Expectation |
|---|---|
| `benign/` | No detections. |
| `attacks/` | The intended detectors fire, and only against the attacking address. |
| `evasion/` | `slow_port_scan` and `low_rate_brute_force` stay below the default thresholds, and the test asserts that the intended detector does **not** fire. This is a known limitation, kept in the suite so a change in behaviour shows up. |
| `malformed/` | The reader rejects each file with `PcapError`. |

After an intended change to the scenarios or to detection, run `python scripts/generate_test_pcaps.py` and review the diff of `tests/pcaps/MANIFEST.json` before committing.

Configuration (`[tool.pytest.ini_options]` in `pyproject.toml`):

- `--strict-markers --strict-config`: an unregistered marker or a configuration typo is an error.
- `asyncio_mode = "auto"`: `async def` tests and fixtures need no decorator.
- `DeprecationWarning`s raised from `sentinelx.*` are errors.
- `pythonpath = ["packages"]`, so tests import `sentinelx` from the source tree.

Registered markers:

| Marker | Meaning | Current use |
|---|---|---|
| `integration` | Requires external services (PostgreSQL or Redis) | PostgreSQL storage test parameters and Redis tests in `tests/integration/test_storage.py` and `tests/integration/test_storage_matrix.py`. They run only when `SENTINELX_TEST_POSTGRES_URL` or `SENTINELX_TEST_REDIS_URL` is set. `tests/integration/test_schema.py` uses a plain `skipif` on the PostgreSQL variable |
| `root` | Requires root privileges (live capture or firewall) | Added to every test in `tests/kernel/` by its `conftest.py` |
| `slow` | Long-running benchmark or replay test | Registered, not currently applied to any test |

Select or exclude with `-m`, for example `.venv/bin/python -m pytest -m "not integration"`.

`tests/conftest.py` isolates every test: it removes SentinelX environment variables, changes into a temporary directory (so a local `.env` or `sentinelx.db` is never picked up), silences logging and resets the event bus. Shared fixtures include `settings` (in-memory SQLite), `detection_settings`, `bus`, `decoder`, `run_detection` (frames through decode, features and detection), `contexts`, and the helper `frames_from`.

Guidelines:

- Use the synthetic scenarios and frame builders (`build_tcp`, `build_udp`, `build_icmp`, `build_dns_query`, `build_dns_response`, `build_http_request`) from `sentinelx.testing.scenarios` for traffic with known ground truth. Do not add real captures to the repository.
- Every detector has positive, negative and edge-case tests. A negative case should share a surface feature with the attack.
- A security fix gets a regression test that fails without the fix.
- Tests must not need network access, root privileges or a running server, unless they carry the matching marker or live in `tests/kernel/`. API tests use `httpx.ASGITransport` or Starlette's `TestClient`, which do not bind a port.

## Benchmark policy

Do not make a performance or detection-quality claim in code, documentation, a commit message or a pull request without running the benchmark that measures it.

```bash
make benchmark                                            # detection experiments, --runs 5
.venv/bin/python scripts/benchmark.py --only tcp_port_scan ssh_brute_force
.venv/bin/python scripts/benchmark.py --no-rules
.venv/bin/python scripts/benchmark_platform.py            # API, WebSocket, storage and pipeline load
.venv/bin/python scripts/benchmark_platform.py --postgres postgresql://user:password@127.0.0.1:5432/scratch
```

`scripts/benchmark.py` writes `benchmarks/results/<UTC timestamp>.json` and `.md`; `scripts/benchmark_platform.py` writes `benchmarks/results/platform-<UTC timestamp>.json` and `.md` (both accept `--output`). Reports cited by [benchmarking.md](benchmarking.md) are committed, so every quoted figure can be traced to its report. When a change affects detectors, thresholds, the per-packet path, the API or storage, re-run the relevant benchmark, commit the new report, and update [benchmarking.md](benchmarking.md) from it, including its environment line. Do not edit figures by hand, and keep the evasion results next to the detection results. The method and metric definitions are in [benchmarking.md](benchmarking.md).

The replay report printed by `sentinelx replay` also contains throughput and latency. Those are single-run measurements on whatever machine ran them, not benchmark results.

## Commits and pull requests

Commit messages in this repository follow the Conventional Commits form `type(scope): summary`, for example `feat(rules): ...`, `refactor(signatures): ...`, `perf(sentinelx): ...`, `build(docker): ...`, `docs: ...`. Use the imperative mood and explain why in the body when the reason is not obvious.

Before opening a pull request:

- Run `make check`. It covers lint, types, tests, rules and the dashboard build.
- If you changed the API, run `make openapi` and commit `openapi.json` and `api-schema.d.ts`.
- If you changed `storage/models.py`, add a reviewed migration and run `alembic check` (see [Database migrations](#database-migrations)).
- If you changed PostgreSQL- or Redis-specific behaviour, run `make test-integration`.
- If you changed capture backends or firewall adapters, run `make test-kernel` on Linux.
- If you changed detection behaviour or the per-packet path, re-run the benchmark and update [benchmarking.md](benchmarking.md).
- Add or update tests for the behaviour you changed, and update the affected documents in `docs/`.
- Keep one logical change per pull request, and describe what changed, why, and how it was tested.
- Never commit `.env`, secrets, databases, model files or packet captures. `.gitignore` excludes `.env` and `.env.*` (except `.env.example`), `*.db`, `models/` and `pcaps/*`. If a capture is needed to explain a problem, follow the privacy guidance in [pcap-lab.md](pcap-lab.md#privacy-when-sharing-captures).

## Reporting security issues

Do not report vulnerabilities in public issues, pull requests or discussions. Follow [SECURITY.md](../SECURITY.md), which describes private reporting, what to include and what to expect. The threat model and the security controls that changes must preserve are described in [security.md](security.md).
