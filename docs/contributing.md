# Contributing

This guide covers the development setup, the repository layout, the checks every change must pass, and the conventions for adding detectors, protocol parsers, rules, API endpoints, migrations and dashboard views.

## Contents

- [Development setup](#development-setup)
- [Repository layout](#repository-layout)
- [Make targets](#make-targets)
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

```bash
make install                    # uses python3; override with: make install PYTHON=python3.12
source .venv/bin/activate
```

`make install`:

1. creates `.venv` with `$(PYTHON) -m venv` if it does not exist,
2. runs `pip install -e ".[dev]"`, which installs SentinelX in editable mode with pytest, pytest-asyncio, pytest-cov, mypy, ruff and types-PyYAML,
3. runs `npm ci` in `apps/dashboard`,
4. copies `.env.example` to `.env` if `.env` does not exist. Review it before starting the platform.

The `sentinelx` command is installed into `.venv/bin`. Run pytest as `.venv/bin/python -m pytest` (this is what the Makefile does), not through a separate `pytest` executable.

To try the platform without capture privileges, generate fixtures and replay one:

```bash
make fixtures
make replay                     # replays pcaps/fixtures/mixed_intrusion.pcap
make dev                        # API on :8000 and dashboard on :3000, with reload
make seed                       # fill the development database from synthetic scenarios
```

See [pcap-lab.md](pcap-lab.md) for the offline workflow.

## Repository layout

| Path | Contents |
|---|---|
| `packages/sentinelx/` | The Python package. The package map is in [architecture.md](architecture.md#package-map) |
| `packages/sentinelx/storage/migrations/` | Alembic environment and revisions (`versions/`) |
| `apps/dashboard/` | Next.js dashboard |
| `apps/api/main.py`, `apps/cli/main.py` | Thin entry points for uvicorn and for running the CLI from a checkout |
| `rules/` | YAML detection rules (`authentication.yml`, `dns-and-web.yml`, `network-recon.yml`) and threat intelligence lists (`rules/intel/allowlist.txt`, `rules/intel/denylist.txt`) |
| `tests/` | Test suite (see [Tests](#tests)) |
| `scripts/` | `benchmark.py`, `export_openapi.py`, `seed_demo.py` |
| `benchmarks/results/` | Benchmark output. Ignored by git |
| `pcaps/` | Capture files and generated fixtures. Ignored by git except `.gitkeep` |
| `docker/` | `Dockerfile.api`, `Dockerfile.dashboard`; `docker-compose.yml` is at the root |
| `docs/` | Documentation |
| `.github/workflows/ci.yml` | CI |
| `alembic.ini` | Alembic configuration (`script_location = packages/sentinelx/storage/migrations`) |

The traffic-processing core (`capture`, `parser`, `features`, `detection`, `signatures`, `anomaly`, `scoring`, `correlation`, `threat_intel`, `response`, `firewall` and `pipeline.py`) does not import from `api`, `cli`, `services` or `storage`. Keep it that way: the core must stay usable from a test, the benchmark harness or a script with no database, Redis or HTTP server.

## Make targets

Run `make help` for the full list. The quality targets:

| Target | What it runs |
|---|---|
| `make test` | `.venv/bin/python -m pytest`. Uses SQLite and needs no external services |
| `make test-integration` | Starts `postgres:17-alpine` on `127.0.0.1:55432` and `redis:7-alpine` on `127.0.0.1:56379` in throwaway containers, waits for PostgreSQL, runs the full suite with `SENTINELX_TEST_POSTGRES_URL` and `SENTINELX_TEST_REDIS_URL` set, and removes the containers on exit |
| `make coverage` | `pytest --cov --cov-report=term-missing` (coverage source `packages/sentinelx`) |
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

The PostgreSQL storage tests drop and recreate the `public` schema of that database, so point the variable at a disposable database.

CI (`.github/workflows/ci.yml`) runs more than `make check`. In addition to lint, mypy, tests against PostgreSQL and Redis with coverage, and the rule checks, it:

- applies the migrations to an empty PostgreSQL database with `sentinelx db upgrade` and runs `alembic check` to confirm the models and migrations match,
- regenerates the OpenAPI contract and fails if `apps/dashboard/src/lib/openapi.json` or `apps/dashboard/src/lib/api-schema.d.ts` differ from the committed files,
- builds both container images.

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
| mypy | `strict = true`, `warn_unreachable`, `disallow_any_generics`, pydantic plugin. Checks the `sentinelx` package and excludes generated Alembic revisions. Missing stubs are ignored only for `scapy`, `sklearn`, `pyshark`, `redis`, `psutil` and `joblib` |

Do not add a `# noqa` or `# type: ignore` to get past a check without a specific error code and a reason.

### Hot path

Code that runs once per packet (decoding, feature extraction, detection) is performance-sensitive.

- Per-packet models are `@dataclass(frozen=True, slots=True)`, not Pydantic models: `PacketEvent`, `Detection`, `Evidence` and the other models in `common/models.py`, and the `DnsInfo`, `HttpInfo` and `TlsInfo` results in `parser/application.py`. Use the same for new per-packet types.
- Long-lived per-packet workers declare `__slots__` (for example `PacketDecoder`).
- Header decoding uses `struct`, not Scapy. Scapy is used only to read capture files.
- State must be bounded. See [architecture.md](architecture.md#state-and-memory-bounds) before adding per-source or per-flow state.
- Do not claim a speed-up without measuring it (see [Benchmark policy](#benchmark-policy)).

### Security rules

- **No `eval` or `exec`.** Rule conditions are parsed by the hand-written, bounded parser in `signatures/dsl.py`. YAML is loaded with `yaml.safe_load`. Ruff's bandit rules (`S`) flag violations.
- **Subprocesses take an argument vector, never a shell.** The only subprocess call in the package is the firewall command runner in `firewall/base.py`, which uses `asyncio.create_subprocess_exec`, requires every argument to be a `str`, rejects arguments containing NUL or newline characters, and applies a timeout. `S603` is ignored only for `packages/sentinelx/firewall/*`.
- **No security logic in route handlers.** Routes validate input, check the role and call a service in `packages/sentinelx/services/` or the core. Path checks, upload validation, safety-guard decisions and audit records belong in services. For example, `api/routes/replay.py` passes client paths to `ReplayService.resolve` and uploads to `ReplayService.store_upload`.
- **Request bodies are strict.** API request models extend `StrictModel` (`extra="forbid"`) in `api/schemas.py` and bound every field (lengths, ranges, list sizes).
- **State-changing actions are audited** with `AuditService.record(actor=..., action=..., target=..., source=...)`.
- **Errors are typed.** Raise a `SentinelXError` subclass from `common/errors.py`. `api/errors.py` maps them to HTTP responses (for example `PcapError` to 422), and the CLI's `run()` turns them into exit code 1 without a traceback.

### Detections must carry evidence

A detection is only useful if an analyst can verify it. `DetectionEngine` discards any detection with no `Evidence` and counts it as a detector error (`detection_without_evidence_rejected`). Each `Evidence` item has a machine-readable `key` and `value`, a sentence in `description`, the `threshold` it was compared against where there is one, and a `weight`. The dashboard shows the descriptions verbatim.

Detectors must also never raise on traffic. The engine isolates exceptions, but a detector that relies on that is hiding a bug.

## Adding a detector

Read [detection-engine.md](detection-engine.md) first.

1. **Counting goes in the feature extractor.** Detectors are stateless with respect to counting. If the detector needs a new count or window, add it to the source profile or flow state in `packages/sentinelx/features/profiles.py` and update it in `features/extractor.py`, keeping it bounded.
2. **Write the detector.** Subclass `Detector` (`detection/base.py`) in the module that fits (`scanning.py`, `behavioral.py`, `dns.py`, `policy.py`) or a new module in `detection/`. Set:
   - `name`: a stable identifier. It appears in metrics, the API, stored detections and settings, so it must not change once released.
   - `description`, `category` (`ThreatCategory`), `default_severity` (`Severity`) and `references`.
3. **Implement `inspect(context)`.** Return `None` in the common case. When the criteria are met, return `self.build(context=..., title=..., description=..., evidence=[...], confidence=...)`, with optional `severity`, `recommended_action`, `observation_window`, `packet_count` and `tags`. Use `Detector.scaled_confidence(observed, threshold)` so confidence grows with how far past the threshold the value is.
4. **Add thresholds to `DetectionSettings`** in `config/settings.py`, with bounds and a `description`. They become settable as `DETECTION__<FIELD>` and are editable at runtime through the configuration service. If you add a window length, check `WINDOW_FIELDS` in `services/config.py` and `max_rule_window()` in `services/rules.py`.
5. **Register it** in `BUILTIN_DETECTORS` in `detection/engine.py`. Order matters: cheap, precise detectors run first. Add the name to `_SIGNATURE_DETECTORS` only if it matches facts rather than rates and should run in `signature_only` mode.
6. **Add a scenario** to `packages/sentinelx/testing/scenarios.py` and to the `SCENARIOS` dict, with `expected_detectors` and `expected_source`. If the scenario is a known evasion, say so in its description.
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

`scenario` is a name from `scenarios.py`, `params` are passed to the scenario function, and `expect` is `match` or `no_match`. A rule's `within` may not exceed the longest built-in detector window, because the feature engine keeps no more history than that.

```bash
sentinelx rules validate                                     # all files in RULES_DIRECTORY; exit 1 if any are invalid
sentinelx rules test rules/network-recon.yml                 # embedded tests; exit 1 on failure
sentinelx rules test rules/network-recon.yml --pcap capture.pcap
sentinelx rules fields                                       # fields available in conditions
make rules                                                   # what CI runs
```

Because `tests/detection/test_rules.py` loads every file in `rules/` (with a 60-second window limit), an invalid rule, a missing test case or a failing test also fails `make test`. Testing a rule against your own captures is described in [pcap-lab.md](pcap-lab.md#testing-a-rule-against-a-capture).

## Adding an API endpoint

1. **Route.** Add the handler to the matching module in `packages/sentinelx/api/routes/` (`auth`, `system`, `detections`, `firewall`, `rules`, `stats`, `replay`). A new module must also be added to the router loop in `api/app.py`, which mounts routers under `/api/v1`.
2. **Authorisation.** Take a role dependency from `api/security.py` as a parameter: `Viewer`, `Analyst` or `Admin`. Take the platform as `PlatformDep`.
3. **Input.** Define request bodies in `api/schemas.py` as `StrictModel` subclasses with bounded fields, and bound query parameters with `Query(...)`.
4. **Logic.** Call a service. Put validation that protects the system, file and path handling, response and firewall decisions, and audit recording in the service, not in the handler.
5. **Errors.** Raise typed errors and let `api/errors.py` map them, or raise `HTTPException` for plain request errors such as 404.
6. **Tests.** Add cases to `tests/api/test_api.py`, including the role check and invalid input. `tests/api/conftest.py` builds an isolated app with a file SQLite database and an unreachable Redis.
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

SQLAlchemy models are in `packages/sentinelx/storage/models.py`; Alembic revisions are in `packages/sentinelx/storage/migrations/versions/`, named `YYYYMMDD_<revision>_<slug>.py`. The Alembic environment reads the database URL from SentinelX settings (`DATABASE_URL`), renders batch operations so that `ALTER TABLE` migrations also work on SQLite, and compares column types.

The development server creates the schema directly on SQLite. PostgreSQL deployments must run `sentinelx db upgrade` before the first start, so every model change needs a migration.

1. Change the models.
2. Point `DATABASE_URL` at a disposable database and bring it to the current head:

   ```bash
   export DATABASE_URL=postgresql://sentinelx:password@127.0.0.1:5432/sentinelx_dev
   sentinelx db upgrade
   ```

3. Generate the revision and review it by hand. Autogenerate misses some changes and can produce wrong ones; the initial revision contains a hand correction for an expression-based index.

   ```bash
   .venv/bin/python -m alembic revision --autogenerate -m "add replay notes"
   ```

4. Apply it and check for drift:

   ```bash
   sentinelx db upgrade
   sentinelx db current            # applied and latest revisions
   .venv/bin/python -m alembic check
   ```

`alembic check` exits with an error if the models and the migrated schema still differ. CI runs it against PostgreSQL. Prefer PostgreSQL for this check: on SQLite, Alembic cannot reflect expression-based indexes and skips comparing them. The PostgreSQL storage tests (`make test-integration`) build their schema through the migrations rather than `create_all`, so they also exercise the new revision. Generated revisions are excluded from mypy.

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
- **API access.** The browser only talks to same-origin `/api/v1`, which `next.config.ts` proxies to `SENTINELX_API_URL`. Use the client in `src/lib/api.ts`: `useSWR<T>("/path")` for reads (the global fetcher is configured in `src/app/providers.tsx`) and `api<T>(path, { method, json })` for writes. The client attaches the CSRF header and refreshes the session on a 401. Do not call `fetch` directly for API requests unless the client cannot express the request. The multipart upload on the PCAP Lab page is the current exception, and it sends the CSRF and client headers itself.
- **Live updates.** Subscribe to WebSocket events with `useEvents().subscribe([...types], handler)` from `src/lib/events.tsx`.
- **No mock data.** Every view shows data from the API. Where the API has no data, show an empty state; do not invent sample rows or placeholder numbers. The login page's example explanation is the only fixed example: it is copied from the engine's real output for the `tcp_port_scan` fixture and labelled on screen as an example.
- **Loading, empty and error states.** Every data-driven view handles all three with the primitives in `src/components/ui/primitives.tsx`: `Skeleton` or `TableSkeleton` while loading, `EmptyState` when there is nothing to show, and `ErrorState` (with `onRetry` where a retry makes sense) on failure.
- **Permissions.** Hide or disable actions the user's role cannot perform with `useSession().can("analyst")` or `can("admin")`. The API enforces roles regardless; this only keeps the interface honest.
- **Feedback.** Report the outcome of an action with `useToast()`.
- **Accessibility.** Give every form control a label (`Field` with `htmlFor`), give icon-only buttons an `aria-label`, mark decorative icons `aria-hidden`, use `role="status"` with `aria-live="polite"` for progress and validation messages, use `scope="col"` on table headers, and mark the current item in a list with `aria-current`. `eslint-config-next` enables a subset of `jsx-a11y` checks as warnings; they do not replace checking with a keyboard and a screen reader.
- **React Compiler lint rules.** `eslint.config.mjs` extends `eslint-config-next/core-web-vitals` and `eslint-config-next/typescript`, which enable the recommended `eslint-plugin-react-hooks` rules (version 7), including the React Compiler rules such as `react-hooks/set-state-in-effect`, `react-hooks/set-state-in-render`, `react-hooks/refs`, `react-hooks/purity`, `react-hooks/immutability` and `react-hooks/static-components`. Fix the code rather than disabling a rule. The project also sets `no-console` (only `console.warn` and `console.error` are allowed) and `react/jsx-no-target-blank`.
- **Generated files.** Never edit `src/lib/api-schema.d.ts` or `src/lib/openapi.json` by hand; run `make openapi`.

## Tests

Tests live under `tests/` and run with `.venv/bin/python -m pytest` (`make test`).

| Directory | Covers |
|---|---|
| `tests/unit/` | CLI commands and exit codes, configuration and logging, network utilities and models, scoring and correlation, sliding windows |
| `tests/capture/` | Packet decoding and application parsers, capture sources |
| `tests/detection/` | Built-in detectors (including `TestDocumentedEvasions`), rules (including every file in `rules/`), anomaly detection |
| `tests/response/` | Response engine and safety guard |
| `tests/api/` | The HTTP API, with its own `conftest.py` |
| `tests/integration/` | The full pipeline and storage, on SQLite and optionally PostgreSQL and Redis |

Configuration (`[tool.pytest.ini_options]` in `pyproject.toml`):

- `--strict-markers --strict-config`: an unregistered marker or a configuration typo is an error.
- `asyncio_mode = "auto"`: `async def` tests and fixtures need no decorator.
- `DeprecationWarning`s raised from `sentinelx.*` are errors.
- `pythonpath = ["packages"]`, so tests import `sentinelx` from the source tree.

Registered markers:

| Marker | Meaning | Current use |
|---|---|---|
| `integration` | Requires external services (PostgreSQL or Redis) | PostgreSQL storage test parameters and Redis tests in `tests/integration/test_storage.py`. They run only when `SENTINELX_TEST_POSTGRES_URL` or `SENTINELX_TEST_REDIS_URL` is set |
| `root` | Requires root privileges (live capture or firewall) | Registered, not currently applied to any test |
| `slow` | Long-running benchmark or replay test | Registered, not currently applied to any test |

Select or exclude with `-m`, for example `.venv/bin/python -m pytest -m "not integration"`.

`tests/conftest.py` isolates every test: it removes SentinelX environment variables, changes into a temporary directory (so a local `.env` or `sentinelx.db` is never picked up), silences logging and resets the event bus. Shared fixtures include `settings` (in-memory SQLite), `detection_settings`, `bus`, `decoder`, `run_detection` (frames through decode, features and detection), `contexts`, and the helper `frames_from`.

Guidelines:

- Use the synthetic scenarios and frame builders (`build_tcp`, `build_udp`, `build_icmp`, `build_dns_query`, `build_dns_response`, `build_http_request`) from `sentinelx.testing.scenarios` for traffic with known ground truth. Do not add real captures to the repository.
- Every detector has positive, negative and edge-case tests. A negative case should share a surface feature with the attack.
- Tests must not need network access, root privileges or a running server, unless they carry the matching marker.

## Benchmark policy

Do not make a performance or detection-quality claim in code, documentation, a commit message or a pull request without running `scripts/benchmark.py`.

```bash
make benchmark                                            # --runs 5
.venv/bin/python scripts/benchmark.py --only tcp_port_scan ssh_brute_force
.venv/bin/python scripts/benchmark.py --no-rules
```

Results are written to `benchmarks/results/<UTC timestamp>.json` and `.md` (override with `--output`). The directory is ignored by git because results are machine-specific. When a change affects detectors, thresholds or the per-packet path, re-run the benchmark and update [benchmarking.md](benchmarking.md) from the generated report, including its environment block. Do not edit figures by hand, and keep the evasion results next to the detection results. The method and metric definitions are in [benchmarking.md](benchmarking.md).

The replay report printed by `sentinelx replay` also contains throughput and latency. Those are single-run measurements on whatever machine ran them, not benchmark results.

## Commits and pull requests

Commit messages in this repository follow the Conventional Commits form `type(scope): summary`, for example `feat(rules): ...`, `refactor(signatures): ...`, `perf(sentinelx): ...`, `build(docker): ...`, `docs: ...`. Use the imperative mood and explain why in the body when the reason is not obvious.

Before opening a pull request:

- Run `make check`. It covers lint, types, tests, rules and the dashboard build.
- If you changed the API, run `make openapi` and commit `openapi.json` and `api-schema.d.ts`.
- If you changed `storage/models.py`, add a reviewed migration and run `alembic check` (see [Database migrations](#database-migrations)).
- If you changed PostgreSQL- or Redis-specific behaviour, run `make test-integration`.
- If you changed detection behaviour or the per-packet path, re-run the benchmark and update [benchmarking.md](benchmarking.md).
- Add or update tests for the behaviour you changed, and update the affected documents in `docs/`.
- Keep one logical change per pull request, and describe what changed, why, and how it was tested.
- Never commit `.env`, secrets, databases, model files or packet captures. `.gitignore` excludes `.env`, `*.db`, `models/`, `pcaps/*` and `benchmarks/results/`. If a capture is needed to explain a problem, follow the privacy guidance in [pcap-lab.md](pcap-lab.md#privacy-when-sharing-captures).

## Reporting security issues

Do not report vulnerabilities in public issues, pull requests or discussions. Follow [SECURITY.md](../SECURITY.md), which describes private reporting, what to include and what to expect. The threat model and the security controls that changes must preserve are described in [security.md](security.md).
