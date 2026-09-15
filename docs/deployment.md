# Deployment

This document covers where SentinelX has been verified to run, how to install it on
each platform, how to check a host, the supported ways to run it (local, Docker
Compose, a bare-metal sensor with systemd), the complete configuration reference, and
the operational tasks around a deployment: database migrations, retention, Redis,
reverse proxies and TLS, the dashboard, backups and upgrades. It ends with a
production hardening checklist.

Related documents: [architecture.md](architecture.md) (components),
[packet-capture.md](packet-capture.md) (capture backends and privileges),
[response-engine.md](response-engine.md) (prevention and the safety guard),
[security.md](security.md) (threat model), [api.md](api.md) (REST and WebSocket API),
[benchmarking.md](benchmarking.md).

## Contents

- [Platform support](#platform-support)
- [Choosing a deployment](#choosing-a-deployment)
- [Installation by platform](#installation-by-platform)
- [Checking a host: capabilities and doctor](#checking-a-host-capabilities-and-doctor)
- [Local development](#local-development)
- [Docker Compose](#docker-compose)
- [Bare-metal sensor with systemd](#bare-metal-sensor-with-systemd)
- [Configuration reference](#configuration-reference)
- [Database migrations](#database-migrations)
- [Retention](#retention)
- [Redis and degraded mode](#redis-and-degraded-mode)
- [Reverse proxy and TLS](#reverse-proxy-and-tls)
- [Dashboard configuration](#dashboard-configuration)
- [Backups](#backups)
- [Upgrades](#upgrades)
- [Production hardening checklist](#production-hardening-checklist)

## Platform support

SentinelX has been run on Linux x86_64 only. Code paths for macOS and Windows exist
and are unit-tested against recorded command output, but they have not been run on
real macOS or Windows hosts.

Terms used below:

- **Tested**: run on that platform, as described under "How it was verified".
- **Expected to work, not yet verified**: the component contains no
  operating-system-specific code, but it has not been run on that platform.
- **Implemented, unverified**: platform-specific code exists and is unit-tested
  against recorded output, but has not been run on that platform.

| Feature | Linux x86_64 | Docker Compose, Linux host | Linux ARM64 | macOS | Windows | WSL2 | Docker Desktop (macOS, Windows) |
|---|---|---|---|---|---|---|---|
| CLI, API | Tested | Tested | Not yet verified | Expected to work, not yet verified | Expected to work, not yet verified | Expected to work, not yet verified | Expected to work, not yet verified |
| Dashboard | Tested | Tested (through the proxy, in a browser) | Not yet verified | Expected to work, not yet verified | Expected to work, not yet verified | Expected to work, not yet verified | Expected to work, not yet verified |
| PCAP replay and detection | Tested | Tested | Not yet verified | Expected to work, not yet verified | Expected to work, not yet verified | Expected to work, not yet verified | Expected to work, not yet verified |
| Interface enumeration and capability detection | Tested | Tested | Not yet verified | Implemented, unverified | Implemented, unverified | Implemented, unverified (reports WSL) | Not applicable to the computer |
| Live capture | Tested: `af_packet`, `libpcap` | Tested: `capture` profile, host network | Not yet verified | Implemented, unverified: `libpcap` on `/dev/bpf*` | Implemented, unverified: `libpcap` on Npcap | Captures the WSL virtual machine, not the Windows host | Captures Docker's virtual machine, not the computer |
| Firewall enforcement | Tested: nftables, iptables | Tested: nftables inside the API container | Not yet verified | Implemented, unverified: pf | Implemented, unverified: Windows Firewall | Changes the WSL virtual machine, not the Windows host | Not applicable to the computer |
| Rate limiting | Tested: nftables, iptables | Not separately verified | Not yet verified | Not supported by the pf adapter | Not supported by the Windows Firewall adapter | As Linux, inside the VM | Not applicable |
| Temporary block expiry | nftables: in the kernel. iptables: by SentinelX | As Linux | Not yet verified | By SentinelX | By SentinelX | As Linux, inside the VM | Not applicable |

How it was verified:

- **Linux x86_64.** Kali Linux with Python 3.14, and Python 3.12 in a
  `python:3.12-slim` container. Live capture with both backends, BPF filtering, and
  nftables and iptables block, unblock, expiry, re-block, rate limiting and teardown
  were run against a real kernel in an isolated network namespace
  (`tests/kernel`, `make test-kernel`) and inside a container.
- **Docker Compose on a Linux host.** The full stack (`postgres`, `redis`, `migrate`,
  `api`, `dashboard`, `proxy`) was run with `docker compose` and used end to end
  through a browser, including enabling prevention and a real nftables block inside
  the API container. The `capture` profile captured the host's traffic with the
  sensor on the host network. As shipped, the `api` service drops all capabilities and
  its interpreter has none, so firewall changes inside it need capabilities that
  `docker-compose.yml` does not grant (see
  [Container hardening](#container-hardening-in-the-default-stack)).
- **Linux ARM64.** Not yet verified. No benchmark or test result exists for it.
- **macOS and Windows.** The libpcap/Npcap capture path, the pf and Windows Firewall
  adapters and the capability detection are unit-tested against recorded command
  output only. The test suite has not been run on these operating systems. The CI
  workflow defines a portability job for macOS and Windows runners; no result from it
  is claimed here.
- **WSL2.** Not tested on a real WSL2 installation. SentinelX detects WSL from the
  kernel release string and the `WSL_DISTRO_NAME`/`WSL_INTEROP` variables, and
  `sentinelx capabilities` and `sentinelx doctor` then state that live capture and
  firewall changes apply to the WSL virtual machine, not to the Windows host. PCAP
  replay has no such limitation.
- **Docker Desktop.** Containers run in a virtual machine, so `network_mode: host`
  reaches that virtual machine's network, not the computer's. For live capture on
  macOS or Windows, install SentinelX natively.

## Choosing a deployment

| Option | Database | Live capture of real traffic | Use for |
|---|---|---|---|
| Local install (`make dev`, or `sentinelx start` and `npm run dev`) | SQLite (default) | Yes, with capture privileges (see [Installation by platform](#installation-by-platform)) | Development, evaluation, PCAP replay |
| Docker Compose, default stack | PostgreSQL | **No**: containers on a bridge network see only their own traffic | Replay, investigation, a demo of the full stack |
| Docker Compose, `capture` profile | PostgreSQL | Yes: the `sensor` service uses the host network (Linux hosts only) | A single Linux host that runs everything in containers |
| Bare metal with systemd | PostgreSQL | Yes | A dedicated Linux sensor on a SPAN/mirror port or gateway |

`sentinelx start` runs one API process (uvicorn with a single worker) that hosts the
REST API, the WebSocket stream, the detection pipeline and, with `--capture`, live
capture. One process is one sensor.

## Installation by platform

Requirements on every platform: Python 3.12 or newer (`requires-python = ">=3.12"`),
and Node.js 20.9 or newer with npm for the dashboard (`apps/dashboard/package.json`
engines). PostgreSQL 15+ and Redis 7+ are optional.

### First run, any platform

The lowest-barrier path needs no privileges, no capture library, no database server
and no Redis:

```sh
python3 -m venv .venv              # Windows: python -m venv .venv
.venv/bin/pip install -e .         # Windows: .venv\Scripts\python -m pip install -e .
.venv/bin/sentinelx fixtures generate
.venv/bin/sentinelx replay pcaps/fixtures/mixed_intrusion.pcap
```

`fixtures generate` writes synthetic scenario captures to `pcaps/fixtures` (nothing
is transmitted), and `replay` runs one through the detection pipeline with responses
simulated.

Optional extras (defined in `pyproject.toml`):

| Extra | Installs | Needed for |
|---|---|---|
| `ml` | `numpy`, `scikit-learn` | `ANOMALY__ML_ENABLED=true` and `sentinelx anomaly train`. Without it, `doctor` fails its "machine learning" check when ML is enabled, and the ML detector is disabled with a logged error. |
| `dev` | `pytest`, `pytest-asyncio`, `pytest-cov`, `mypy`, `ruff`, `types-PyYAML` | Development and tests |

```sh
.venv/bin/pip install -e ".[ml]"
.venv/bin/pip install -e ".[dev,ml]"
```

### Linux

- **Capture library.** Install libpcap (for example `libpcap0.8` on Debian, Ubuntu
  and Kali) to use BPF filters; SentinelX compiles filters with it. Without it,
  capture without a filter still works, and a configured filter is refused with an
  error rather than ignored.
- **Capture privileges.** Run as root, or grant `CAP_NET_RAW` to the interpreter:

  ```sh
  sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
  ```

  This is the command `sentinelx doctor` suggests. A default virtual environment's
  `python` is a symbolic link, so `readlink -f` resolves to the system interpreter and
  the capabilities apply to every program run with that binary. Use
  `python3 -m venv --copies .venv` to give SentinelX a separate interpreter binary.
- **Firewall privileges.** Firewall changes run `nft` or `iptables` as child
  processes. When SentinelX holds `CAP_NET_ADMIN` without being root (file
  capabilities as above, or systemd `AmbientCapabilities`), it raises the capability
  into its ambient set so those commands inherit it. If that is not possible, the
  firewall check says so and recommends running as root.
- **Firewall tooling.** Install `nftables` (preferred) or `iptables` for prevention.

### macOS

Not yet verified on a real Mac.

- Install with `python3 -m venv .venv` and `.venv/bin/pip install -e .`.
- **Live capture** uses the `libpcap` backend on `/dev/bpf*`. Run as root, or give your
  user read access to the BPF devices (Wireshark's ChmodBPF launch daemon does this).
- **Firewall** uses the `pf` adapter, which runs `pfctl` and needs root. It loads its
  rules into the anchor set by `RESPONSE__PF_ANCHOR` (default `com.apple/sentinelx`),
  which the stock `/etc/pf.conf` evaluates through its `anchor "com.apple/*"` line, so
  no system file is edited. On a `pf.conf` without that line, add `anchor "sentinelx"`
  and set `RESPONSE__PF_ANCHOR=sentinelx`. SentinelX enables pf with a reference token
  (`pfctl -E`) and releases only its own reference when it stops. pf does not support
  rate limiting, and temporary blocks are expired by SentinelX (see
  [Firewall backends](#firewall-backends)).

### Windows

Not yet verified on a real Windows host.

The `Makefile` requires bash. Use the plain commands in PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\sentinelx capabilities
.venv\Scripts\python -m pytest
cd apps\dashboard
npm ci
npm run dev
```

- **Live capture** needs [Npcap](https://npcap.com) (install it in WinPcap
  API-compatible mode, as the capability report's remedy says). If Npcap was
  installed with "restrict driver access to Administrators", run SentinelX from an
  elevated terminal; SentinelX reads that setting from the registry and reports it.
- **Firewall** uses the `windows_firewall` adapter, which runs Windows PowerShell's
  NetSecurity cmdlets and needs an elevated (Administrator) terminal. Each block is an
  inbound and an outbound rule in the `SentinelX` rule group. Group Policy can override
  local rules, and rules have no effect on a profile whose firewall is off; the
  adapter's health check reports disabled profiles. It does not support rate
  limiting, and temporary blocks are expired by SentinelX.

### WSL2 and Docker Desktop

Under WSL2, SentinelX runs as on Linux, but capture sees the WSL virtual machine's
traffic and firewall changes apply to that virtual machine, not to Windows. Under
Docker Desktop, host networking reaches Docker's virtual machine. To monitor or
protect the Windows or macOS computer itself, install SentinelX natively.

### Firewall backends

| Backend | Platforms | Tool | Rate limiting | Temporary block expiry |
|---|---|---|---|---|
| `nftables` | Linux | `nft` | Yes | In the kernel (set element timeouts) |
| `iptables` | Linux | `iptables`, `ip6tables` | Yes | By SentinelX (deadline in the rule comment) |
| `pf` | macOS (and BSD) | `pfctl` | No | By SentinelX |
| `windows_firewall` | Windows | Windows PowerShell | No | By SentinelX (deadline in the rule description) |
| `null` | any | none | n/a | n/a |

"By SentinelX" means a reaper task in the response engine removes expired blocks
while SentinelX is running; after a restart, deadlines are restored from the
database. A block whose deadline passes while SentinelX is stopped stays in the
firewall until shortly after the next start.

`FIREWALL_BACKEND=auto` resolves to the first usable backend for the operating system
(nftables, then iptables on Linux; pf on macOS and BSD; Windows Firewall on Windows)
and to `null` when none is usable. A named backend that cannot run here (tool missing,
wrong operating system) does not stop startup: detection continues, the health check
shows the backend as unavailable with the reason, and every firewall action fails
with that reason.

## Checking a host: capabilities and doctor

### `sentinelx capabilities`

Probes this host and prints, for each capability, whether it is available, what was
observed and how to make it available: detection engine, PCAP replay (a capture is
parsed from memory), interface enumeration (psutil), packet capture (a capture
backend exists), live capture (a raw socket is actually opened on Linux; BPF device
permissions on macOS; Npcap presence and its administrator-only setting on Windows),
firewall control (the configured backend's tooling and privileges), automatic
blocking, and privileged access (root or elevation, and on Linux the `CAP_NET_RAW`
and `CAP_NET_ADMIN` bits). It also lists every firewall backend for the platform with
its native expiry and rate-limit support. `--json` prints the report as JSON.

The same report is served by `GET /api/v1/system/capabilities` (viewer role or
higher) and shown in the dashboard under Settings, Platform capabilities.

### `sentinelx doctor`

Runs every check and prints one of `PASS`, `WARN`, `FAIL` or `INFO` for each, with a
remedy where one applies. It exits with status 1 if any check is `FAIL`.

| Check | Result |
|---|---|
| `python` | FAIL below 3.12. |
| `configuration` | FAIL (and exit 1) if settings fail validation. |
| `operating system` | INFO: operating system, architecture and Python version. |
| `wsl`, `container` | INFO, only when detected. |
| `dependencies` | FAIL if a required package, or the database driver for `DATABASE_URL`, cannot be imported. |
| `machine learning` | FAIL, only when `ANOMALY__ML_ENABLED=true` without the `ml` extra. |
| `pcap replay` | FAIL if the capture reader does not work. |
| `interface enumeration`, `packet capture backend`, `live capture` | WARN when unavailable. |
| `capture interface` | FAIL if `CAPTURE_INTERFACE` is not `any` and does not exist. |
| `firewall backend` | With `null`: INFO, or FAIL if the configuration needs a firewall (dry run off and mode not `detect_only`). Otherwise PASS, WARN when unusable, or FAIL when unusable and needed. |
| `automatic blocking` | PASS when a usable firewall exists; FAIL if prevention is active without one; INFO otherwise. |
| `safety posture` | WARN when automatic prevention is active. |
| `rules` | FAIL if the rules directory is missing or any rule file is invalid; WARN if no rules load. |
| `pcap directory` | FAIL if `PCAP_DIRECTORY` cannot be created or written. |
| `jwt secret` | FAIL if shorter than 32 characters. If not set in the environment or `.env`: WARN in development, FAIL in production. |
| `database` | FAIL if the database cannot be reached (remedy `check DATABASE_URL`). `doctor` connects without preparing the schema, so it never migrates the database it inspects. |
| `migrations` | PASS when the schema is at the latest revision. Behind the latest revision: WARN for SQLite ("SQLite databases are migrated automatically when SentinelX starts"; this includes a new SQLite file before the first `sentinelx start`), FAIL for PostgreSQL (remedy `run: sentinelx db upgrade`). |
| `redis` | WARN when unreachable; FAIL if `STORAGE__REDIS_REQUIRED=true`. |
| `api` | Probes `/api/v1/system/health` at `--api-url` (default `http://API_HOST:API_PORT`, with `0.0.0.0` read as `127.0.0.1`). |
| `dashboard` | Probes `/runtime-config` at `--dashboard-url` (default `SENTINELX_DASHBOARD_URL`, else `http://127.0.0.1:3000`). |

The two probes report PASS only when the answer identifies itself as SentinelX. Not
reachable is WARN; another service answering on the address is WARN; an HTTP 5xx is
FAIL. Run `doctor` from the directory that holds your `.env`, with the same
environment as the service.

## Local development

```sh
make install   # .venv, editable backend install with the dev and ml extras, dashboard npm ci, .env from .env.example
make dev       # API on :8000 and dashboard on :3000, both with reload; Ctrl-C stops both
```

What the targets do (from the `Makefile`, which needs bash):

| Target | Effect |
|---|---|
| `make install` | `python3 -m venv .venv`; `.venv/bin/pip install -e ".[dev,ml]"`; `npm ci` in `apps/dashboard`; copies `.env.example` to `.env` if `.env` does not exist. |
| `make dev` | `.venv/bin/sentinelx start --reload` and, in `apps/dashboard`, `SENTINELX_API_URL=http://127.0.0.1:8000 npm run dev`. |
| `make api` | Only the API, with reload. |
| `make dashboard` | Only the dashboard dev server. |
| `make fixtures` | `sentinelx fixtures generate --output pcaps/fixtures`. |
| `make replay PCAP=path/to/file.pcap` | `sentinelx replay <file>`; generates fixtures first if the file is missing. Default `PCAP` is `pcaps/fixtures/mixed_intrusion.pcap`. |
| `make seed` | Fills the development database with detections from synthetic scenarios (`scripts/seed_demo.py`). |
| `make test` | Test suite on SQLite; no external services. |
| `make test-integration` | Tests against throwaway PostgreSQL and Redis containers. |
| `make test-kernel` | `tests/kernel` inside a private network namespace (`unshare -rn`) with a dummy interface: real live capture, and real nftables and iptables changes. Linux only; needs unprivileged user namespaces, libpcap, `nft` and `iptables`. |
| `make check` | Lint, type checks, tests, rule validation and a dashboard build. |

On first start with an empty user table the API creates the administrator `admin`
and prints a one-time password to the terminal (unless
`API__BOOTSTRAP_ADMIN_PASSWORD` is set). You must change it at first login. Open
`http://localhost:3000`. Interactive API docs are at `http://127.0.0.1:8000/api/docs`
outside production.

Defaults in development:

- SQLite at `./sentinelx.db`, created and migrated to the latest schema automatically
  at startup.
- Redis at `redis://localhost:6379/0`; if it is not running, SentinelX logs a warning
  and continues in [degraded mode](#redis-and-degraded-mode).
- `JWT_SECRET` unset: a random per-process secret is used, so sessions end when the
  API restarts.
- `RESPONSE_MODE=detect_only`, `DRY_RUN=true`, `FIREWALL_BACKEND=null`: nothing on the
  host firewall is ever changed.

With capture privileges in place (see [Installation by platform](#installation-by-platform)):

```sh
.venv/bin/sentinelx start --capture --interface eth0
```

## Docker Compose

`docker-compose.yml` defines six services, plus a `sensor` service in the optional
`capture` profile.

| Service | Image | Role | Networks | Published port (host) |
|---|---|---|---|---|
| `postgres` | `postgres:17-alpine` | Database; data in the `postgres-data` volume | `backend` | `127.0.0.1:${POSTGRES_HOST_PORT:-5433}` |
| `redis` | `redis:7-alpine` | Rate-limit counters, WebSocket tickets, caches; password protected, persistence disabled | `backend` | `127.0.0.1:${REDIS_HOST_PORT:-6381}` |
| `migrate` | `sentinelx-api:local` (built from `docker/Dockerfile.api`) | Runs `sentinelx db upgrade` once and exits | `backend` | none |
| `api` | `sentinelx-api:local` | `sentinelx start`; PCAP files in the `pcaps` volume at `/data/pcaps` | `backend`, `frontend` | `127.0.0.1:${API_PORT:-8000}` (scripts and Prometheus) |
| `dashboard` | `sentinelx-dashboard:local` (built from `docker/Dockerfile.dashboard`) | Next.js standalone server | `frontend` | none |
| `proxy` | `nginxinc/nginx-unprivileged:1.27-alpine` | One origin for the dashboard, REST API and event stream | `frontend` | `127.0.0.1:${DASHBOARD_PORT:-3000}` |
| `sensor` (profile `capture`) | `sentinelx-api:local` | `python3-sensor -m sentinelx start --capture` on the host network | host | host network, `${FRONTEND_GATEWAY:-172.31.250.1}:${SENSOR_PORT:-8001}` only |

Start order: `postgres` becomes healthy, `migrate` completes successfully, then `api`
starts once `redis` is healthy. `proxy` waits for a healthy `dashboard` and a healthy
`api`; the `api` dependency is marked `required: false` so the proxy can run with the
`capture` profile when `api` is scaled to zero.

All published ports are bound to loopback. For access from other machines, put a
TLS-terminating reverse proxy in front of the `proxy` service (see
[Reverse proxy and TLS](#reverse-proxy-and-tls)). PostgreSQL and Redis are published
on loopback because the host-network `sensor` cannot resolve Compose service names.

### Secrets and environment

```sh
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, REDIS_PASSWORD and JWT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(48))"   # generates a JWT_SECRET
make docker-up        # or: docker compose up -d --build
make docker-logs      # follow API logs; shows the one-time admin password on first start
```

Then open `http://127.0.0.1:3000`.

Compose reads `.env` for variable substitution. Three variables are mandatory and use
the `${VAR:?message}` form, so `docker compose` refuses to start with an explicit
message when any of them is empty:

| Variable | Used for |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL superuser password and the API's `DATABASE_URL` |
| `REDIS_PASSWORD` | `redis-server --requirepass` and the API's `REDIS_URL` |
| `JWT_SECRET` | Token signing; must be at least 32 characters (enforced in production) |

Other Compose variables:

| Compose variable | Default | Becomes |
|---|---|---|
| `ENVIRONMENT` | `production` | `ENVIRONMENT` in `migrate`, `api` and `sensor` |
| `POSTGRES_USER`, `POSTGRES_DB` | `sentinelx`, `sentinelx` | part of `DATABASE_URL` |
| `API__BOOTSTRAP_ADMIN_PASSWORD` | empty | the same variable in the API containers |
| `API__METRICS_TOKEN` | empty | the same variable in the API containers |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | `CORS_ORIGINS` |
| `FRONTEND_SUBNET` | `172.31.250.0/24` | the `frontend` network's subnet, and `API__TRUSTED_PROXIES` |
| `FRONTEND_GATEWAY` | `172.31.250.1` | the `frontend` network's gateway address (set explicitly in its `ipam` configuration), and `API_HOST` of the `sensor` service. Must lie inside `FRONTEND_SUBNET` |
| `DETECTION_MODE` | `balanced` | `DETECTION_MODE` |
| `RESPONSE_MODE` | `detect_only` | `RESPONSE_MODE` |
| `DRY_RUN` | `true` | `DRY_RUN` |
| `FIREWALL_BACKEND` | `null` | `FIREWALL_BACKEND` |
| `CAPTURE_INTERFACE` | `any` | `CAPTURE_INTERFACE` |
| `LOG_LEVEL` | `INFO` | `LOG_LEVEL` |
| `RETENTION_DAYS` | `30` | `RETENTION_DAYS` |
| `SENSOR_NAME` | `sentinelx` | `SENSOR_NAME` |
| `API_PORT`, `DASHBOARD_PORT`, `POSTGRES_HOST_PORT`, `REDIS_HOST_PORT` | `8000`, `3000`, `5433`, `6381` | host port mappings only |
| `SENSOR_PORT` | `8001` | `API_PORT` of the `sensor` service |
| `SENTINELX_API_UPSTREAM` | `api:8000` | the proxy's API upstream; `${FRONTEND_GATEWAY}:${SENSOR_PORT}` (by default `172.31.250.1:8001`) with the `capture` profile |
| `SENTINELX_MAX_UPLOAD_MB` | `200` | the proxy's `client_max_body_size` |

The API image also sets `RULES_DIRECTORY=/app/rules`, `PCAP_DIRECTORY=/data/pcaps`,
`API_HOST=0.0.0.0`, `API_PORT=8000` and `LOG_FORMAT=json` (the `sensor` service
overrides `API_HOST` and `API_PORT`). Only variables listed in
`docker-compose.yml` reach the containers; to set any other setting (for example
`CAPTURE__BACKEND` or `API__MAX_UPLOAD_MB`), add it to the `x-api-env` block. If you
raise `API__MAX_UPLOAD_MB`, raise `SENTINELX_MAX_UPLOAD_MB` to match. A `.env` copied
from `.env.example` sets `CORS_ORIGINS=http://localhost:3000`, which replaces the
Compose default.

Because the stack defaults to `ENVIRONMENT=production`, the rules in
[Production validation](#production-validation) apply: authentication cookies are
`Secure`, interactive API docs are disabled (`make docker-up` still prints an
`/api/docs` URL, which returns 404 in production), SQLite is refused, and a short
`JWT_SECRET` stops the API from starting. Browsers send `Secure` cookies over plain
HTTP only to `localhost` and `127.0.0.1`; from any other address, serve the stack
over HTTPS.

Compose always sets `RESPONSE_MODE` and `DRY_RUN` in the API containers, so they count
as explicitly set by the environment: changing the response mode or dry run in the
dashboard takes effect immediately but is replaced by the Compose values when the
container restarts (see [Runtime overrides](#how-variables-are-read)). Set them in
`.env` to make them permanent.

### The front proxy

`docker/proxy/default.conf.template` is rendered by the nginx image at container
start, substituting only variables that start with `SENTINELX_`. The proxy listens on
port 8080 in the container and routes:

| Path | Upstream | Notes |
|---|---|---|
| `= /api/v1/metrics` | none | Returns 404. Prometheus scrapes the API directly. |
| `/api/v1/ws/` | `http://${SENTINELX_API_UPSTREAM}` | WebSocket upgrade headers; 1 hour read and send timeouts. |
| `/api/` | `http://${SENTINELX_API_UPSTREAM}` | Request bodies are streamed (`proxy_request_buffering off`); 120 s read timeout. |
| `/` | `http://dashboard:3000` | |

It forwards `Host` (as received), `X-Forwarded-For` (the incoming header with the peer
address appended) and `X-Forwarded-Proto`. Because the browser reaches everything on
one origin, session cookies stay `SameSite=Strict` and the dashboard needs no
separate public WebSocket URL. The proxy does not terminate TLS.

The API believes `X-Forwarded-For` only from `API__TRUSTED_PROXIES`, which Compose sets
to `FRONTEND_SUBNET`. Connections to a published port usually arrive from the Docker
network's gateway address, which is inside that subnet, so a client that can reach the
published proxy port can choose the address the API records. Keep the port on
loopback (the default), or put a proxy in front that replaces `X-Forwarded-For` rather
than appending to it. Change `FRONTEND_SUBNET` only if it overlaps a network you use.

Prometheus scrapes the API on `127.0.0.1:${API_PORT:-8000}`. Requests through a
published port do not arrive from a loopback address inside the container, so set
`API__METRICS_TOKEN` and configure Prometheus to send it as a bearer token.

### Container hardening in the default stack

`migrate`, `api`, `dashboard` and `proxy` run with `no-new-privileges` and all Linux
capabilities dropped; `api`, `dashboard` and `migrate` have a read-only root
filesystem, and `api`, `dashboard` and `proxy` a tmpfs `/tmp`. The API and dashboard
images run as the non-root user `sentinelx` (uid 10001) and include a `HEALTHCHECK`
(`/api/v1/system/health` for the API, `/login` for the dashboard). The API image's
check probes `API_HOST` on `API_PORT`, using `127.0.0.1` when `API_HOST` is `0.0.0.0`
or `::`, so it also works for the `sensor`, which listens on one address. The API
image is built by the `migrate` service (`build:` is declared there; `api` and
`sensor` only reference `sentinelx-api:local`), so rebuild it with
`docker compose build migrate` or `docker compose up -d --build`;
`docker compose build api` builds nothing. The proxy's health
check requests `/api/v1/system/health` through the proxy. The dashboard and proxy are
attached only to the `frontend` network; PostgreSQL and Redis only to `backend`.

The shared `python3` in the API image carries no file capabilities. (Setting them
there previously stopped `api` and `migrate` from starting with
`exec ... Operation not permitted`, because the kernel refuses to execute a binary
whose file capabilities are outside the container's bounding set.) A separate
interpreter, `/usr/local/bin/python3-sensor`, holds `CAP_NET_RAW` and `CAP_NET_ADMIN`
and is used only by the `sensor` service. As a consequence, the default `api`
container cannot capture or change a firewall; `sentinelx capabilities` inside it
reports live capture and firewall control as unavailable.

### What the default stack can see

Containers on a Docker bridge network see only traffic addressed to or from
themselves, never the host's other traffic. In the default stack SentinelX therefore
analyses PCAP replays (uploaded or generated in the PCAP lab) and traffic sent to the
stack itself. It is not a network sensor. For real traffic use the `capture` profile
on a Linux host, or a [bare-metal install](#bare-metal-sensor-with-systemd). On Docker
Desktop the host network is Docker's virtual machine, so the `capture` profile does
not see the computer's traffic.

### The `capture` profile

The `sensor` service replaces `api` for live capture on a Linux host:

- `network_mode: host`: it sees the host's interfaces.
- It runs `python3-sensor -m sentinelx start --capture`. `python3-sensor` has
  `cap_net_raw,cap_net_admin+eip` file capabilities, so the service must grant both
  (`cap_drop: [ALL]`, `cap_add: [NET_RAW, NET_ADMIN]`) and must allow privilege gain
  (`no-new-privileges:false`). Removing either capability makes the container fail to
  start with `Operation not permitted`.
- It connects to PostgreSQL and Redis through their loopback-published ports
  (`127.0.0.1:5433` and `127.0.0.1:6381` by default).
- It listens with `API_HOST=${FRONTEND_GATEWAY:-172.31.250.1}` and
  `API_PORT=${SENSOR_PORT:-8001}`: only on the host's address on the `frontend`
  network (that network's gateway, set explicitly in its `ipam` configuration), not
  on `0.0.0.0`.

Start it with the proxy pointed at the sensor:

```sh
SENTINELX_API_UPSTREAM=172.31.250.1:8001 \
  docker compose --profile capture up -d --build --scale api=0
```

`--scale api=0` stops the bridge-network `api` so only one pipeline writes to the
database. The proxy, on the `frontend` network, reaches the sensor at that network's
gateway address. If you change `FRONTEND_GATEWAY` or `SENSOR_PORT`, set
`SENTINELX_API_UPSTREAM=${FRONTEND_GATEWAY}:${SENSOR_PORT}` with the same values
(all three can be set in `.env`).

Notes:

- The sensor's API is reachable by the proxy but not from other hosts, and not on
  `127.0.0.1` either: use the proxy (`127.0.0.1:${DASHBOARD_PORT:-3000}`) or
  `http://172.31.250.1:8001` from the host itself.
- Set `CAPTURE_INTERFACE` in `.env` to the interface that carries the traffic you
  want to monitor (for example a mirror port). The default `any` captures on all
  interfaces.
- The sensor holds `CAP_NET_ADMIN` in the host's network namespace. With a
  `FIREWALL_BACKEND` other than `null` and prevention enabled, it changes **the host's**
  firewall.

## Bare-metal sensor with systemd

The following is an **example**, not a file shipped with SentinelX. Adapt paths,
users and interfaces to your host. It assumes PostgreSQL and Redis are already
available.

### Install

```sh
sudo useradd --system --home-dir /var/lib/sentinelx --shell /usr/sbin/nologin sentinelx
sudo mkdir -p /opt/sentinelx /etc/sentinelx /var/lib/sentinelx/pcaps
sudo python3 -m venv /opt/sentinelx/venv
sudo /opt/sentinelx/venv/bin/pip install /path/to/Sentinelx      # a checkout; "/path/to/Sentinelx[ml]" adds the ML extra
sudo cp -r /path/to/Sentinelx/rules /etc/sentinelx/rules          # rule files are not part of the package
sudo chown -R sentinelx:sentinelx /var/lib/sentinelx
sudo apt-get install libpcap0.8 nftables                          # BPF filters; firewall tooling if you enable prevention
```

### Environment file

`/etc/sentinelx/sentinelx.env` (readable only by root and the service user:
`sudo chmod 640 /etc/sentinelx/sentinelx.env && sudo chgrp sentinelx /etc/sentinelx/sentinelx.env`):

```sh
ENVIRONMENT=production
SENSOR_NAME=edge-sensor-1
DATABASE_URL=postgresql://sentinelx:CHANGE_ME@127.0.0.1:5432/sentinelx
REDIS_URL=redis://:CHANGE_ME@127.0.0.1:6379/0
JWT_SECRET=CHANGE_ME_TO_AT_LEAST_32_RANDOM_CHARACTERS
API_HOST=127.0.0.1
API_PORT=8000
CORS_ORIGINS=https://sentinelx.example.com
API__TRUSTED_PROXIES=["127.0.0.1/32"]
RULES_DIRECTORY=/etc/sentinelx/rules
PCAP_DIRECTORY=/var/lib/sentinelx/pcaps
CAPTURE_INTERFACE=eth1
CAPTURE__BACKEND=auto
LOG_FORMAT=json
RESPONSE_MODE=detect_only
DRY_RUN=true
FIREWALL_BACKEND=null
API__METRICS_TOKEN=CHANGE_ME
API__BOOTSTRAP_ADMIN_PASSWORD=CHANGE_ME_FIRST_ADMIN_PASSPHRASE
```

Keep comments on their own lines. systemd's `EnvironmentFile` does not remove text
after a value, so do not copy lines with trailing comments into this file.

### Unit file (example)

`/etc/systemd/system/sentinelx.service`:

```ini
# EXAMPLE unit file for a SentinelX sensor. Review before use.
[Unit]
Description=SentinelX network intrusion detection sensor and API
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=sentinelx
Group=sentinelx
WorkingDirectory=/var/lib/sentinelx
EnvironmentFile=/etc/sentinelx/sentinelx.env
ExecStartPre=/opt/sentinelx/venv/bin/sentinelx db upgrade
ExecStart=/opt/sentinelx/venv/bin/sentinelx start --capture
Restart=on-failure
RestartSec=5

# Capture needs CAP_NET_RAW. CAP_NET_ADMIN is only needed with a FIREWALL_BACKEND
# other than null; remove it otherwise.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/sentinelx

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelx
journalctl -u sentinelx -f
```

Notes:

- `ExecStartPre` applies migrations before every start; it is a no-op when the schema
  is current. Without it, the API refuses to start against a PostgreSQL schema that is
  not at the latest revision.
- Settings are also read from a `.env` file in the working directory if one exists.
  Keep `/var/lib/sentinelx` free of a stray `.env`.
- Anything the API prints to standard error, including a generated administrator
  password, is stored in the journal. Setting `API__BOOTSTRAP_ADMIN_PASSWORD` avoids
  that. It is only used while the user table is empty; remove it from the file once
  the first administrator exists and has logged in.
- With `AmbientCapabilities`, `CAP_NET_ADMIN` is already in the ambient set, so
  `sentinelx doctor` and `sentinelx capabilities`, run with the service's credentials,
  report firewall privileges as granted and `nft`/`iptables` inherit the capability.
- `API__TRUSTED_PROXIES` above assumes a reverse proxy on the same host; see
  [Reverse proxy and TLS](#reverse-proxy-and-tls).
- To run CLI commands with the service's configuration, load the same environment,
  for example:
  `sudo -u sentinelx sh -c 'set -a; . /etc/sentinelx/sentinelx.env; exec /opt/sentinelx/venv/bin/sentinelx status'`
  (this works as long as the file contains only simple `KEY=value` lines; the JSON
  value of `API__TRUSTED_PROXIES` needs quoting for `sh`).

The dashboard can run on the same or another host; see
[Dashboard configuration](#dashboard-configuration).

## Configuration reference

All configuration is defined in `packages/sentinelx/config/settings.py` and loaded once
at startup. `.env.example` lists the most common variables.

### How variables are read

- **Nested form**: `SECTION__FIELD`, for example `DETECTION__PORT_SCAN_UNIQUE_PORTS=30`
  or `API__METRICS_TOKEN=...`. Every setting has one. Names are case-insensitive.
- **Flat aliases**: sixteen short names such as `DATABASE_URL` and `DRY_RUN`, listed in
  the tables below. They are accepted both as environment variables and in `.env`, and
  are validated exactly like the nested form: `DRY_RUN=ture` is a configuration error,
  never `false`. A flat alias set to an empty string is ignored, so the default (or
  another source) applies.
- **List values** in the nested form are JSON: `API__CORS_ORIGINS='["https://a.example","https://b.example"]'`.
  The flat `CORS_ORIGINS` alias takes a comma-separated list instead:
  `CORS_ORIGINS=https://a.example,https://b.example`.
- **Sources and precedence**, highest first: explicit arguments (used by code and
  tests), nested environment variables, flat environment variables, nested entries in
  `.env`, flat entries in `.env`, defaults. A real environment variable therefore
  always beats `.env`, and the nested form wins when both spellings are set in the
  same place. `.env` is read from the current working directory. Top-level settings
  (`ENVIRONMENT`, `SENSOR_NAME`, `RULES_DIRECTORY`) have a single name.
- **Comments in `.env`**: put them on their own lines. The `.env` reader removes a
  `#` comment that follows a value after whitespace, but a `#` with no space before it
  is part of the value, and other readers of the same file (systemd `EnvironmentFile`,
  shell `source`) treat trailing text differently.
- **Runtime overrides**: settings marked "Runtime: yes"
  can also be changed while the platform runs, from the dashboard,
  `PATCH /api/v1/config/{section}` or `sentinelx config set <section> <key> <json-value>`.
  Dashboard and API changes apply immediately; `sentinelx config set` stores the
  change, which a running server picks up at its next start. Stored changes are
  re-applied at every start **on top of** the environment, so a stored override wins
  over the environment value, with one exception: when `RESPONSE_MODE`/`RESPONSE__MODE`
  or `DRY_RUN`/`RESPONSE__DRY_RUN` is set explicitly in the environment or `.env`, that
  value wins at startup and the stored value is ignored (logged as
  `stored_setting_overridden_by_environment`). This lets an operator always switch
  prevention off by editing the environment and restarting. `sentinelx config`
  (optionally `--section <name>`, `--json`) shows the effective settings.
- **Confirmation**: turning dry run off, or enabling automatic prevention, at runtime
  requires the confirmation phrase `ENABLE PREVENTION` (typed in the dashboard;
  `confirmation` in the API request; `--confirm-prevention` on the CLI). The change is
  audited.
- Invalid values stop startup; `sentinelx` commands print each problem and exit with
  status 2.

### General

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `ENVIRONMENT` | | `development` | no | `development`, `staging` or `production`. Only `production` enables [production validation](#production-validation). |
| `SENSOR_NAME` | | `sentinelx-local` | no | Sensor identifier in logs and status (1 to 64 characters). |
| `RULES_DIRECTORY` | | `rules` | no | Directory of YAML rule files; threat intel lists are read from its `intel/` subdirectory. |

### Capture (`capture`)

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `CAPTURE__INTERFACE` | `CAPTURE_INTERFACE` | `any` | yes | Interface to capture from, or `any` for every interface. |
| `CAPTURE__BACKEND` | | `auto` | no | `auto`, `af_packet` or `libpcap`. `auto` tries `af_packet` then `libpcap` on Linux, and `libpcap` elsewhere, moving on only when a backend cannot run on the host. Permission errors, unknown interfaces and invalid BPF filters are reported, not skipped. |
| `CAPTURE__BPF_FILTER` | `BPF_FILTER` | empty | yes | Optional BPF expression applied in the kernel. The characters `;` `\|` `` ` `` `$` `\` and newlines are rejected. Compiling a filter needs libpcap. |
| `CAPTURE__SNAPSHOT_LENGTH` | | `2048` | no | Bytes captured per frame (64 to 65535). |
| `CAPTURE__PROMISCUOUS` | | `true` | no | Put a named interface in promiscuous mode. |
| `CAPTURE__BUFFER_SIZE_MB` | | `16` | no | Capture buffer size (1 to 1024). |
| `CAPTURE__QUEUE_SIZE` | | `20000` | no | Bounded hand-off queue for the `libpcap` backend (at least 100). When full, packets are dropped and counted. |
| `CAPTURE__HOME_NETWORKS` | | `["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fd00::/8"]` | yes | Prefixes treated as inside; used to label packet direction. |
| `CAPTURE__PCAP_DIRECTORY` | `PCAP_DIRECTORY` | `pcaps` | no | Directory for uploaded (`uploads/`), generated and replayed capture files. |
| `CAPTURE__MAX_PCAP_SIZE_MB` | | `512` | no | Maximum capture file size (at least 1). |
| `CAPTURE__UPLOAD_QUOTA_MB` | | `2048` | no | Total space uploaded captures may use; uploads are refused once it is full. |

### Detection (`detection`)

All detection settings except `max_tracked_sources` are runtime-editable. Changing a
`*_window_seconds` value at runtime rebuilds the traffic windows, discarding current
per-source state.

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `DETECTION__MODE` | `DETECTION_MODE` | `balanced` | yes | `disabled`, `signature_only`, `balanced` or `aggressive`. |
| `DETECTION__ENABLED_DETECTORS` | | `[]` | yes | Allow-list of detector names. Empty means all detectors for the mode. |
| `DETECTION__DISABLED_DETECTORS` | | `[]` | yes | Detectors to turn off. |
| `DETECTION__PORT_SCAN_WINDOW_SECONDS` | | `15.0` | yes | Port scan observation window. |
| `DETECTION__PORT_SCAN_UNIQUE_PORTS` | | `20` | yes | Distinct destination ports from one source that trigger (at least 2). |
| `DETECTION__PORT_SCAN_MIN_SYN_RATIO` | | `0.7` | yes | Fraction of packets that must be bare SYNs (0 to 1). |
| `DETECTION__HORIZONTAL_SCAN_UNIQUE_HOSTS` | | `25` | yes | Distinct destination hosts on one port (a sweep; at least 2). |
| `DETECTION__UDP_SCAN_UNIQUE_PORTS` | | `25` | yes | Distinct UDP destination ports that trigger (at least 2). |
| `DETECTION__BRUTE_FORCE_WINDOW_SECONDS` | | `60.0` | yes | Brute force observation window. |
| `DETECTION__BRUTE_FORCE_ATTEMPTS` | | `15` | yes | Attempts within the window that trigger (at least 2). |
| `DETECTION__BRUTE_FORCE_PORTS` | | `[22,23,21,3389,445,5900,1433,3306,5432]` | yes | Services where repeated short-lived connections imply credential guessing. |
| `DETECTION__CONNECTION_RATE_WINDOW_SECONDS` | | `10.0` | yes | Connection rate window. |
| `DETECTION__CONNECTION_RATE_THRESHOLD` | | `200` | yes | New connections in the window that trigger. |
| `DETECTION__SYN_FLOOD_THRESHOLD` | | `500` | yes | SYN flood threshold. |
| `DETECTION__ICMP_FLOOD_WINDOW_SECONDS` | | `10.0` | yes | ICMP flood window. |
| `DETECTION__ICMP_FLOOD_THRESHOLD` | | `200` | yes | ICMP packets in the window that trigger. |
| `DETECTION__HTTP_FLOOD_WINDOW_SECONDS` | | `10.0` | yes | HTTP flood window. |
| `DETECTION__HTTP_FLOOD_THRESHOLD` | | `300` | yes | HTTP requests in the window that trigger. |
| `DETECTION__DNS_WINDOW_SECONDS` | | `30.0` | yes | DNS observation window. |
| `DETECTION__DNS_QUERY_THRESHOLD` | | `300` | yes | Queries from one client in the window that trigger. |
| `DETECTION__DNS_UNIQUE_DOMAIN_THRESHOLD` | | `100` | yes | Distinct names from one client suggesting tunnelling or DGA. |
| `DETECTION__DNS_LONG_LABEL_LENGTH` | | `52` | yes | Label length (10 to 63) above which a name looks like encoded data. |
| `DETECTION__DNS_HIGH_ENTROPY_THRESHOLD` | | `3.8` | yes | Shannon entropy (bits per character) suggesting an algorithmic name. |
| `DETECTION__MAX_TRACKED_SOURCES` | | `50000` | no | Upper bound on tracked source addresses (at least 100). |
| `DETECTION__DETECTION_COOLDOWN_SECONDS` | | `60.0` | yes | Suppress repeat detections of the same detector and source. |
| `DETECTION__DENYLIST_NETWORKS` | | `[]` | yes | Networks reported by the `denylist` detector when they appear in traffic. |
| `DETECTION__ALLOWLIST_NETWORKS` | | `[]` | yes | Sources never reported on; applied before any detector runs. |

### Risk scoring (`scoring`)

All scoring settings are runtime-editable. See the detection and response documents
for how the score is used.

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `SCORING__SEVERITY_WEIGHT` | | `45.0` | yes | Weight of detection severity (0 to 100). |
| `SCORING__CONFIDENCE_WEIGHT` | | `20.0` | yes | Weight of detector confidence (0 to 100). |
| `SCORING__FREQUENCY_WEIGHT` | | `10.0` | yes | Weight of repeat frequency (0 to 100). |
| `SCORING__HISTORY_WEIGHT` | | `10.0` | yes | Weight of the source's history (0 to 100). |
| `SCORING__INTEL_WEIGHT` | | `15.0` | yes | Weight of threat intelligence matches (0 to 100). |
| `SCORING__CORRELATION_WEIGHT` | | `15.0` | yes | Weight of correlation with other detectors (0 to 100). |
| `SCORING__SENSITIVE_TARGET_WEIGHT` | | `10.0` | yes | Weight for sensitive targets (0 to 100). |
| `SCORING__HISTORY_WINDOW_SECONDS` | | `3600.0` | yes | Look-back for source history. |
| `SCORING__FREQUENCY_SATURATION` | | `10` | yes | Repeat count at which the frequency factor reaches full weight. |
| `SCORING__HISTORY_SATURATION` | | `5` | yes | History count at which the history factor reaches full weight. |
| `SCORING__ALLOWLIST_PENALTY` | | `40.0` | yes | Points subtracted when an allowlisted source is still detected (0 to 100). |
| `SCORING__AUTO_BLOCK_THRESHOLD` | | `85.0` | yes | Risk at or above which an automatic block may be proposed (0 to 100). Acted on only with `RESPONSE_MODE=automatic` and `DRY_RUN=false`. |
| `SCORING__INCIDENT_THRESHOLD` | | `60.0` | yes | Defined, but not currently read by the platform. |

### Correlation (`correlation`)

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `CORRELATION__ENABLED` | | `true` | yes | Fold related detections into incidents. |
| `CORRELATION__WINDOW_SECONDS` | | `600.0` | yes | How long an incident stays open for new, related detections. |
| `CORRELATION__MIN_DETECTIONS` | | `2` | yes | Detections needed to open an incident. |
| `CORRELATION__STANDALONE_RISK_THRESHOLD` | | `85.0` | yes | A single detection at or above this risk opens an incident without corroboration. |
| `CORRELATION__MAX_OPEN_INCIDENTS` | | `1000` | yes | Cap on open incidents. |
| `CORRELATION__GROUP_BY_SOURCE` | | `true` | yes | Group detections by source address. |
| `CORRELATION__GROUP_BY_DESTINATION` | | `false` | yes | Group detections by destination address. |

### Anomaly detection (`anomaly`)

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `ANOMALY__ENABLED` | | `true` | yes | Statistical baselining detector. |
| `ANOMALY__BASELINE_ALPHA` | | `0.05` | no | EWMA decay (0 to 1). Lower adapts more slowly. |
| `ANOMALY__MIN_SAMPLES` | | `60` | yes | Observations before deviations are reported (at least 5). |
| `ANOMALY__SAMPLE_INTERVAL_SECONDS` | | `1.0` | no | Sampling interval. |
| `ANOMALY__ANOMALY_THRESHOLD` | | `0.85` | yes | Anomaly score at or above which a detection is emitted. |
| `ANOMALY__SIGMA_SATURATION` | | `6.0` | yes | Deviation (in standard deviations) at which the score saturates. |
| `ANOMALY__ML_ENABLED` | | `false` | no | Enable the Isolation Forest detector. Needs the `ml` extra and a trained model; a missing or untrusted model disables it with a logged error. |
| `ANOMALY__ML_MODEL_PATH` | | `models/isolation_forest.joblib` | no | Model file. It must not be group- or world-writable and must be owned by the user running SentinelX. |
| `ANOMALY__ML_CONTAMINATION` | | `0.02` | no | Defined, but not currently read by the platform (`sentinelx anomaly train --contamination` sets it for training). |
| `ANOMALY__ML_MIN_SCORE` | | `0.75` | yes | Minimum ML score for a detection. |

### Response (`response`)

Read [response-engine.md](response-engine.md) before changing these.

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `RESPONSE__MODE` | `RESPONSE_MODE` | `detect_only` | yes | `detect_only`, `manual_approval` or `automatic`. An explicit environment value wins over a stored runtime change at startup. |
| `RESPONSE__DRY_RUN` | `DRY_RUN` | `true` | yes | Decide, record and display responses without applying them. An explicit environment value wins over a stored runtime change at startup. |
| `RESPONSE__FIREWALL_BACKEND` | `FIREWALL_BACKEND` | `null` | no | `null`, `auto`, `nftables`, `iptables`, `pf` or `windows_firewall`. See [Firewall backends](#firewall-backends). |
| `RESPONSE__NFT_TABLE` | | `sentinelx` | no | nftables table name (1 to 32 of `A-Za-z0-9_`). |
| `RESPONSE__NFT_SET` | | `blocklist` | no | nftables set name (1 to 32 of `A-Za-z0-9_`). |
| `RESPONSE__NFT_FAMILY` | | `inet` | no | `inet`, `ip` or `ip6`. |
| `RESPONSE__PF_ANCHOR` | | `com.apple/sentinelx` | no | pf anchor for SentinelX rules: one or two `/`-separated names of 1 to 32 `A-Za-z0-9_.` characters. |
| `RESPONSE__DEFAULT_BLOCK_SECONDS` | | `900` | yes | Duration of a temporary block (30 to 86400). |
| `RESPONSE__MAX_BLOCK_SECONDS` | | `86400` | yes | Longest block allowed (60 to 2592000). |
| `RESPONSE__MAX_BLOCKED_ADDRESSES` | | `10000` | yes | Hard cap on concurrent blocks (1 to 1000000). |
| `RESPONSE__MAX_BLOCK_PREFIX_HOSTS` | | `256` | yes | Largest prefix that may be blocked, in addresses (1 to 65536; 256 is a /24). |
| `RESPONSE__ALLOWLIST_NETWORKS` | | `["127.0.0.0/8","::1/128"]` | yes | Never blocked. Loopback is re-added if removed. |
| `RESPONSE__PROTECT_MANAGEMENT_ADDRESSES` | | `true` | no | Refuse to block addresses assigned to this host and addresses of operators who signed in within the last hour. If the host's addresses cannot be listed, blocks are refused. |
| `RESPONSE__MANAGEMENT_ADDRESSES` | | `[]` | yes | Additional addresses that must never be blocked. |
| `RESPONSE__WEBHOOK_URL` | | empty | yes | HTTPS endpoint for response notifications (must start with `https://`; up to 2048 characters). Empty disables webhooks. |
| `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES` | | `false` | no | Allow the webhook host to resolve to loopback, private, link-local or reserved addresses (for an internal SIEM, for example). |
| `RESPONSE__WEBHOOK_TIMEOUT_SECONDS` | | `5.0` | yes | Webhook timeout (greater than 0, up to 30). |
| `RESPONSE__WEBHOOK_MIN_RISK` | | `60.0` | yes | Minimum risk score for webhook calls (0 to 100); also the threshold used by `GET /api/v1/alerts`. |
| `RESPONSE__RATE_LIMIT_PACKETS_PER_SECOND` | | `100` | yes | Packet rate applied by `rate_limit` actions (nftables and iptables only). |

Validation: `RESPONSE_MODE=manual_approval` or `automatic` with `DRY_RUN=false` is
rejected when `FIREWALL_BACKEND` is `null`. (`auto` passes this check even if it later
resolves to no usable backend; actions then fail with the reason.)

### Storage (`storage`)

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `STORAGE__DATABASE_URL` | `DATABASE_URL` | `sqlite+aiosqlite:///./sentinelx.db` | no | SQLAlchemy URL. `postgresql://` and `postgres://` are mapped to the asyncpg driver; `sqlite://` to aiosqlite. PostgreSQL is the production target. |
| `STORAGE__DATABASE_ECHO` | | `false` | no | Log SQL statements. |
| `STORAGE__POOL_SIZE` | | `10` | no | Connection pool size (PostgreSQL). |
| `STORAGE__MAX_OVERFLOW` | | `20` | no | Extra connections beyond the pool (PostgreSQL). |
| `STORAGE__REDIS_URL` | `REDIS_URL` | `redis://localhost:6379/0` | no | Redis URL. |
| `STORAGE__REDIS_REQUIRED` | | `false` | no | When false, Redis failures degrade to in-process state instead of failing. |
| `STORAGE__REDIS_NAMESPACE` | | `sentinelx` | no | Key prefix (1 to 64 of `A-Za-z0-9_:-`). |
| `STORAGE__RETENTION_DAYS` | `RETENTION_DAYS` | `30` | yes | Retention for detections, closed and replay incidents, response actions, inactive blocks, replay records and uploaded capture files (1 to 3650). |
| `STORAGE__AUDIT_RETENTION_DAYS` | | `365` | yes | Retention for audit events. |
| `STORAGE__METRICS_RETENTION_DAYS` | | `7` | yes | Retention for traffic summaries and system metrics. |
| `STORAGE__BATCH_SIZE` | | `200` | no | Rows flushed to the database per write. |
| `STORAGE__FLUSH_INTERVAL_SECONDS` | | `2.0` | no | Maximum delay before buffered rows are written. |

### API and authentication (`api`)

None of the API settings are runtime-editable.

| Env var | Flat alias | Default | Description |
|---|---|---|---|
| `API__HOST` | `API_HOST` | `127.0.0.1` | Listen address (`sentinelx start --host` overrides). |
| `API__PORT` | `API_PORT` | `8000` | Listen port (`--port` overrides). |
| `API__ROOT_PATH` | | empty | ASGI root path, for a proxy that mounts the API under a prefix. Cookie paths (`/api`, `/api/v1/auth`) are fixed, so browser sessions expect the API at `/api` on the dashboard's origin. |
| `API__CORS_ORIGINS` | `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed browser origins; also used by the WebSocket origin check. Each must include a scheme. `*` is ignored by the CORS middleware and rejected in production. |
| `API__JWT_SECRET` | `JWT_SECRET` | empty | Token signing key, at least 32 characters. Outside production an empty value is replaced by a random per-process secret. |
| `API__JWT_ALGORITHM` | | `HS256` | `HS256`, `HS384` or `HS512`. |
| `API__ACCESS_TOKEN_TTL_SECONDS` | | `900` | Access token lifetime (60 to 86400). |
| `API__REFRESH_TOKEN_TTL_SECONDS` | | `604800` | Refresh token lifetime (at least 300). |
| `API__JWT_ISSUER` | | `sentinelx` | `iss` claim. |
| `API__COOKIE_SECURE` | | `false` | Mark auth cookies `Secure` and send HSTS. Forced on in production. |
| `API__PASSWORD_MIN_LENGTH` | | `12` | Minimum password length (8 to 128). |
| `API__LOCKOUT_THRESHOLD` | | `5` | Consecutive failed logins before an account locks. |
| `API__LOCKOUT_SECONDS` | | `900` | Lock duration (at least 30). |
| `API__AUTH_ENABLED` | | `true` | Development only; rejected as `false` in production. |
| `API__BOOTSTRAP_ADMIN_USERNAME` | | `admin` | Name of the first administrator (3 to 64 characters). |
| `API__BOOTSTRAP_ADMIN_PASSWORD` | | empty | Password for the first administrator, used only when the user table is empty. If empty, one is generated and printed once. |
| `API__RATE_LIMIT_REQUESTS` | | `300` | Requests per client IP per window. |
| `API__RATE_LIMIT_WINDOW_SECONDS` | | `60` | Rate limit window. |
| `API__LOGIN_RATE_LIMIT_ATTEMPTS` | | `8` | Login attempts per client IP per window. |
| `API__LOGIN_RATE_LIMIT_WINDOW_SECONDS` | | `300` | Login throttle window. |
| `API__WEBSOCKET_MAX_QUEUE` | | `500` | Per-connection outbound event buffer (at least 10). |
| `API__MAX_UPLOAD_MB` | | `200` | Upload limit; the effective limit is the smaller of this, `CAPTURE__MAX_PCAP_SIZE_MB` and the space left in `CAPTURE__UPLOAD_QUOTA_MB`. |
| `API__TRUSTED_PROXIES` | | `[]` | CIDRs of reverse proxies whose `X-Forwarded-For` is believed. |
| `API__METRICS_TOKEN` | | empty | Bearer token for `/api/v1/metrics`. Empty: loopback clients only, and never a request carrying a forwarding header. |
| `API__DOCS_ENABLED` | | `true` | Serve `/api/docs`, `/api/redoc` and `/api/v1/openapi.json`. Forced off in production. |

### Telemetry (`telemetry`)

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `TELEMETRY__LOG_LEVEL` | `LOG_LEVEL` | `INFO` | yes | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. |
| `TELEMETRY__LOG_FORMAT` | `LOG_FORMAT` | `console` | no | `console` or `json`. |
| `TELEMETRY__LOG_FILE` | | unset | no | Also write logs to this file (rotated at 50 MB, 5 backups). |
| `TELEMETRY__METRICS_ENABLED` | | `true` | no | Defined, but not currently read; the metrics endpoint is always registered. |
| `TELEMETRY__METRICS_PATH` | | `/metrics` | no | Defined, but not currently read; the endpoint is always `/api/v1/metrics`. |
| `TELEMETRY__PROFILE_PIPELINE` | | `false` | no | Defined, but not currently read. |

### Variables outside the settings model

| Variable | Read by | Purpose |
|---|---|---|
| `SENTINELX_API_URL` | dashboard `next.config.ts`; `sentinelx metrics --url` | Where the dashboard server forwards `/api`; the API base URL for `sentinelx metrics`. |
| `SENTINELX_PUBLIC_WS_URL` | dashboard `/runtime-config` | Optional WebSocket base URL for the browser. |
| `SENTINELX_METRICS_TOKEN` | `sentinelx metrics --token` | Metrics token for the CLI. |
| `SENTINELX_DASHBOARD_URL` | `sentinelx doctor` | Default dashboard address to probe. |

### Production validation

With `ENVIRONMENT=production`, settings validation (`Settings._validate_production`)
changes and checks the following. Any failed check stops startup with a single error
listing every problem.

| Rule | Effect |
|---|---|
| `api.cookie_secure` | Forced to `true` (cookies `Secure`, HSTS header sent). |
| `api.docs_enabled` | Forced to `false`. |
| `JWT_SECRET` | Must be at least 32 characters. |
| `api.auth_enabled` | Must be `true`. |
| `CORS_ORIGINS` | Must not contain `*`. |
| `DATABASE_URL` | Must not be SQLite. |

`staging` behaves like `development` for these rules. Independently of the
environment, the API refuses to start with a JWT secret shorter than 32 characters.

## Database migrations

Schema changes are managed with Alembic; migrations live in
`packages/sentinelx/storage/migrations`.

```sh
sentinelx db upgrade                 # apply migrations up to head (--revision to target another)
sentinelx db current                 # applied and latest revision, and whether an upgrade is needed
sentinelx db purge                   # apply retention policies now
```

What happens at startup depends on the database:

- **SQLite files** are migrated to the latest revision automatically. A SQLite
  database created before migrations were tracked (it has tables but no
  `alembic_version`) is first stamped at the initial revision (`540eb200aacd`) and
  then upgraded, so upgrading SentinelX does not leave an existing file missing a
  column. SQLite is for development and evaluation.
- **PostgreSQL** is never changed automatically. If the schema is not at the latest
  revision, startup stops with
  `database schema is at revision <applied> but this version of SentinelX needs <head>; run: sentinelx db upgrade`.
  Run `sentinelx db upgrade` before the first start and after every upgrade. The
  Compose `migrate` service and the example `ExecStartPre` do this. `sentinelx doctor`
  reports the migrations check as FAIL when a PostgreSQL schema is behind, and as WARN
  for a SQLite file that is behind (it is migrated at the next start). `doctor` does not
  migrate either database.

Revisions:

| Revision | Change |
|---|---|
| `540eb200aacd` | Initial schema. |
| `a8829c9a233e` | Adds `response_actions.replay_id` (indexed), so response decisions from replays stay out of the live firewall log, and an index on `detections (status, timestamp)` for triage and analytics filters. |

`sentinelx db` configures Alembic programmatically from `DATABASE_URL`. `alembic.ini`
at the repository root exists for developers running Alembic directly from a
checkout (for example `.venv/bin/python -m alembic current`); it takes the database
URL from SentinelX settings and must never contain credentials.

## Retention

A background task in the API applies retention 60 seconds after startup and then
every 6 hours. `sentinelx db purge` runs the same policy on demand and prints what was
removed.

| Data | Removed when older than | Setting |
|---|---|---|
| Live detections (by detection time) | `retention_days` | `RETENTION_DAYS` (30) |
| Live incidents with status `resolved` or `false_positive` (by last-seen time) | `retention_days` | |
| Live response actions (by decision time) | `retention_days` | |
| Replay records (by when the replay ran, `replays.created_at`), together with every detection, incident and response action of that replay | `retention_days` | |
| Inactive block records | `retention_days` | |
| Uploaded capture files in `PCAP_DIRECTORY/uploads` (by file modification time) | `retention_days` | |
| Traffic summaries, system metrics | `metrics_retention_days` | `STORAGE__METRICS_RETENTION_DAYS` (7) |
| Audit events | `audit_retention_days` | `STORAGE__AUDIT_RETENTION_DAYS` (365) |
| Refresh tokens | when expired | |

Open live incidents are never removed by retention. Replay results are not expired by
their packet timestamps, so a replay of an old capture is kept for the full
`retention_days` after it ran. Only regular files in the
`uploads` subdirectory are deleted; generated fixtures and files you place elsewhere in
the PCAP directory are left alone. All three retention values can be changed at
runtime.

## Redis and degraded mode

Redis holds state shared between processes: API rate-limit and login-throttle
counters, WebSocket tickets, event fan-out and short-lived caches. Per-packet
detection state never uses Redis. Nothing in Redis needs to survive a restart; the
Compose stack disables Redis persistence.

When Redis is unreachable and `STORAGE__REDIS_REQUIRED=false` (the default):

- SentinelX logs `redis_unavailable_degraded_mode` once and continues with in-process
  equivalents.
- Rate limits, login throttling and WebSocket tickets apply per process rather than
  globally.
- `GET /api/v1/system/health` and `/system/status` report `"status": "degraded"`, and
  `sentinelx doctor` shows a warning.
- Reconnection is attempted every 30 seconds; `redis_recovered` is logged when it
  succeeds.

With `STORAGE__REDIS_REQUIRED=true`, an unreachable Redis stops startup, and a Redis
failure during operation raises an error instead of degrading, so affected requests
fail (with a 5xx response) until Redis is back.

## Reverse proxy and TLS

SentinelX does not terminate TLS. For any access beyond the local host, keep the API
and dashboard on loopback (the defaults) and terminate TLS in a reverse proxy. With
`ENVIRONMENT=production`, authentication cookies are `Secure` and the API sends
`Strict-Transport-Security`, so browsers on other machines need HTTPS.

### Client addresses: `trusted_proxies`

The API uses the client address for rate limiting, login throttling, audit records,
the operator-address safety check and the metrics loopback check. By default it uses
the TCP peer address and ignores `X-Forwarded-For`, so clients cannot spoof their
address. Behind a proxy every request would then appear to come from the proxy, and
one client could exhaust the rate limit for everyone.

List your proxies' addresses:

```sh
API__TRUSTED_PROXIES='["10.0.0.5/32"]'
```

`sentinelx start` then enables uvicorn's proxy header handling for those addresses,
and the API reads `X-Forwarded-For` from right to left, taking the first address that
is not a trusted proxy. Configure the outermost proxy to set `X-Forwarded-For` to the
client address rather than pass through a client-supplied value.

The metrics endpoint without a token rejects any request that carries
`X-Forwarded-For`, `Forwarded` or `X-Real-IP`, so proxied requests always need
`API__METRICS_TOKEN`.

### With Docker Compose

The Compose `proxy` already serves the dashboard, REST API and WebSocket on one
origin at `127.0.0.1:${DASHBOARD_PORT:-3000}` (see [The front proxy](#the-front-proxy)).
Terminate TLS in a proxy on the host that forwards to that address, or add a TLS
server block to `docker/proxy/default.conf.template`. The outer proxy must:

- preserve `Host` (the WebSocket origin check accepts an `Origin` that matches the
  forwarded `Host`, or one listed in `CORS_ORIGINS`);
- forward WebSocket upgrades for `/api/v1/ws/`;
- replace `X-Forwarded-For` with the client address (the Compose proxy appends to it,
  and the API trusts the Compose network, as described above);
- allow request bodies as large as `SENTINELX_MAX_UPLOAD_MB` for PCAP uploads.

Set `CORS_ORIGINS` to the public origin, for example `https://sentinelx.example.com`.
Keep `/api/v1/metrics` off the public proxy; Prometheus scrapes
`127.0.0.1:${API_PORT:-8000}` with `API__METRICS_TOKEN`.

### Without Docker

Route `/api/` and `/api/v1/ws/` to the API and everything else to the dashboard,
as the Compose proxy does. Example nginx server block (an **example**; adapt
certificates, addresses and names):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    server_name sentinelx.example.com;
    ssl_certificate     /etc/ssl/certs/sentinelx.example.com.pem;
    ssl_certificate_key /etc/ssl/private/sentinelx.example.com.key;

    client_max_body_size 200m;   # match API__MAX_UPLOAD_MB for PCAP uploads

    proxy_set_header Host            $host;
    proxy_set_header X-Forwarded-For $remote_addr;

    location = /api/v1/metrics {
        return 404;
    }

    location /api/v1/ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 1h;   # the server pings after 25 idle seconds
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_request_buffering off;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
    }
}
```

with `API__TRUSTED_PROXIES='["127.0.0.1/32"]'` (nginx on the same host) and
`CORS_ORIGINS=https://sentinelx.example.com`. The dashboard then uses the same origin
for the WebSocket; `SENTINELX_PUBLIC_WS_URL` is not needed.

## Dashboard configuration

The dashboard (`apps/dashboard`, Next.js) has two environment variables:

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `SENTINELX_API_URL` | `next.config.ts` (rewrite of `/api/:path*`) | `http://127.0.0.1:8000` | Where the dashboard server forwards `/api/*` requests when the browser reaches the dashboard directly (development, or a deployment without a front proxy). |
| `SENTINELX_PUBLIC_WS_URL` | `src/app/runtime-config/route.ts` | unset | Optional base URL for the WebSocket, for example `wss://sentinelx.example.com`. |

`GET /runtime-config` on the dashboard returns
`{"app": "sentinelx-dashboard", "wsUrl": <SENTINELX_PUBLIC_WS_URL or null>}`, read from
the server environment on every request (`Cache-Control: no-store`). `app` lets
`sentinelx doctor` recognise the dashboard. When `wsUrl` is `null`, the browser opens
the WebSocket on the page's own origin (`ws://` or `wss://` to match the page), which
the dashboard server in development, the Compose proxy, or your reverse proxy forwards
to the API.

In Docker Compose the dashboard container has no environment of its own: the `proxy`
routes `/api/` to the API before requests reach the dashboard.

### Known limitation: dashboard API address in a build

Next.js resolves `rewrites()` in `next.config.ts` when the application is **built**, and
writes the destination into `.next/routes-manifest.json` (and the standalone
`server.js`). `SENTINELX_API_URL` therefore takes effect when set during
`npm run build` (or when running `npm run dev`), not when set only on an already built
server. `docker/Dockerfile.dashboard` does not set it during the build, so the image's
own rewrite forwards to `http://127.0.0.1:8000`; this does not matter in Compose,
where the proxy handles `/api/`. If you run a built dashboard without a front proxy,
set `SENTINELX_API_URL` at build time.

### Running the dashboard outside Docker

The image build is the reference (`docker/Dockerfile.dashboard`):

```sh
cd apps/dashboard
npm ci
SENTINELX_API_URL=http://127.0.0.1:8000 npm run build
cp -r .next/static .next/standalone/.next/static
cp -r public .next/standalone/public
cd .next/standalone
NODE_ENV=production PORT=3000 HOSTNAME=127.0.0.1 node server.js
```

## Backups

| What | Where | How |
|---|---|---|
| Database (detections, incidents, audit log, users, API-created rules, runtime setting overrides, active block deadlines) | PostgreSQL | `pg_dump`. With Compose: `docker compose exec -T postgres pg_dump -U sentinelx -Fc sentinelx > sentinelx-$(date +%F).dump` |
| Secrets and configuration | `.env`, or `/etc/sentinelx/sentinelx.env` | Back up securely; it contains database, Redis and JWT secrets. |
| File-based rules and threat intel lists | `RULES_DIRECTORY` (`rules/`, `rules/intel/`) | Version control or file backup. |
| Capture files | `PCAP_DIRECTORY` (Compose volume `pcaps`) | File backup, if you need to keep them. Uploads older than `RETENTION_DAYS` are deleted by retention. |
| Redis | | Nothing to back up. |

Losing the JWT secret only invalidates existing sessions. The SQLite development
database is the single file named in `DATABASE_URL` (default `./sentinelx.db`, with
`-wal` and `-shm` companion files while running).

Test restores periodically: restore a dump into an empty database, run
`sentinelx db current`, and start an API against it.

## Upgrades

1. Read the release notes for configuration changes.
2. Back up the database.
3. Update the code.
4. Apply migrations (PostgreSQL) and restart. SQLite files are migrated at startup.

Docker Compose:

```sh
git pull
docker compose up -d --build     # rebuilds images; `migrate` runs before `api` starts
docker compose logs -f api
```

With the `capture` profile, repeat the command you started it with
(`SENTINELX_API_UPSTREAM=... docker compose --profile capture up -d --build --scale api=0`).

Bare metal:

```sh
sudo systemctl stop sentinelx
sudo /opt/sentinelx/venv/bin/pip install /path/to/Sentinelx
sudo cp -r /path/to/Sentinelx/rules/. /etc/sentinelx/rules/   # if you use the bundled rules
sudo systemctl start sentinelx                                 # ExecStartPre runs `sentinelx db upgrade`
```

Afterwards, confirm with `sentinelx db current` (run with the service's environment),
`GET /api/v1/system/health`, and `sentinelx doctor`.

Runtime overrides stored in the database survive upgrades and are re-validated at
startup; an override that is no longer valid is skipped and logged as
`stored_setting_invalid`.

## Production hardening checklist

Configuration:

- [ ] `ENVIRONMENT=production` (the Compose default).
- [ ] `JWT_SECRET` of at least 32 random characters, stored outside version control.
- [ ] PostgreSQL `DATABASE_URL` with a dedicated user and strong password; migrations
      applied (`sentinelx db current` shows up to date).
- [ ] Redis protected with a password and not exposed beyond the hosts that need it.
- [ ] `CORS_ORIGINS` lists exactly the dashboard's public origin(s), with `https://`.
- [ ] `API__TRUSTED_PROXIES` lists exactly the proxies in front of the API: the Compose
      `FRONTEND_SUBNET`, or your reverse proxy's address. The outermost proxy replaces
      `X-Forwarded-For` with the client address.
- [ ] `API__METRICS_TOKEN` set whenever Prometheus is not a loopback client of the API
      (always, with Compose); `/api/v1/metrics` not reachable through the public proxy.
- [ ] `RESPONSE__WEBHOOK_URL`, if used, points at a trusted HTTPS endpoint;
      `RESPONSE__WEBHOOK_ALLOW_PRIVATE_ADDRESSES` left `false` unless the receiver is
      internal.
- [ ] `API__BOOTSTRAP_ADMIN_PASSWORD` removed after the first administrator exists, or
      never set and the generated password changed at first login.
- [ ] Effective values confirmed with `sentinelx config` or `GET /api/v1/config`
      (environment variables override `.env`; stored runtime overrides win over both,
      except an explicitly set response mode or dry run).

Network and transport:

- [ ] API, dashboard and Compose proxy bound to loopback or a private interface; TLS
      terminated at a reverse proxy for all remote access, so `Secure` cookies are
      sent.
- [ ] The reverse proxy preserves `Host` and forwards WebSocket upgrades for
      `/api/v1/ws/`.
- [ ] With the Compose `capture` profile, `FRONTEND_GATEWAY` left at (or set to) the
      `frontend` network's gateway, so the sensor listens only there and not on
      `0.0.0.0`.
- [ ] PostgreSQL and Redis ports not reachable from untrusted networks.

Accounts:

- [ ] Individual accounts for each person; `admin` role only for those who change
      firewall state, rules or settings; `viewer` for read-only users.
- [ ] Scripts use dedicated accounts with the least role they need.
- [ ] Periodic review of `GET /api/v1/users` and the audit log.

Prevention and capture:

- [ ] Run with `RESPONSE_MODE=detect_only` or `manual_approval` and `DRY_RUN=true`
      until detections have been tuned on your traffic.
- [ ] `RESPONSE__ALLOWLIST_NETWORKS` and `RESPONSE__MANAGEMENT_ADDRESSES` include
      gateways, DNS servers, monitoring and administrator networks before enabling
      prevention. See [response-engine.md](response-engine.md).
- [ ] The firewall backend is one that has been verified on your platform (see
      [Platform support](#platform-support)); `sentinelx capabilities` shows it as
      available.
- [ ] Only `CAP_NET_RAW` (and `CAP_NET_ADMIN` only with a firewall backend) granted to
      the sensor; the service runs as a non-root user.
- [ ] `sentinelx doctor` reports no `FAIL` on the sensor host.

Operations:

- [ ] Database backups scheduled and a restore tested.
- [ ] Retention values reviewed against your storage and compliance requirements.
- [ ] Logs shipped with `LOG_FORMAT=json`; alerts on `status` other than `ok` from
      `/api/v1/system/health`.
- [ ] PCAP directory size monitored (retention deletes only uploads older than
      `RETENTION_DAYS`).

See [security.md](security.md) for the threat model and residual risks.
