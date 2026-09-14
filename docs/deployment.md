# Deployment

This document covers the three supported ways to run SentinelX, the complete
configuration reference, and the operational tasks around a deployment: database
migrations, retention, Redis, reverse proxies and TLS, the dashboard, backups and
upgrades. It ends with a production hardening checklist.

Related documents: [architecture.md](architecture.md) (components),
[packet-capture.md](packet-capture.md) (capture backends and privileges),
[response-engine.md](response-engine.md) (prevention and the safety guard),
[security.md](security.md) (threat model), [api.md](api.md) (REST and WebSocket API),
[benchmarking.md](benchmarking.md).

## Contents

- [Choosing a deployment](#choosing-a-deployment)
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

## Choosing a deployment

| Option | Database | Live capture of real traffic | Use for |
|---|---|---|---|
| Local development (`make dev`) | SQLite (default) | Yes, if the Python interpreter has `CAP_NET_RAW` | Development, evaluation, PCAP replay |
| Docker Compose, default stack | PostgreSQL | **No**: containers on a bridge network see only their own traffic | Replay, investigation, a demo of the full stack |
| Docker Compose, `capture` profile | PostgreSQL | Yes: the `sensor` service uses the host network (Linux only) | A single Linux host that runs everything in containers |
| Bare metal with systemd | PostgreSQL | Yes | A dedicated sensor on a SPAN/mirror port or gateway |

`sentinelx start` runs one API process (uvicorn with a single worker) that hosts the
REST API, the WebSocket stream, the detection pipeline and, with `--capture`, live
capture. One process is one sensor.

## Local development

Requirements: Python 3.12 or newer (`requires-python = ">=3.12"`), Node.js 20.9 or
newer with npm (`apps/dashboard/package.json` engines), and `make`. Redis and
PostgreSQL are optional.

```sh
make install   # .venv, editable backend install with dev tools, dashboard npm ci, .env from .env.example
make dev       # API on :8000 and dashboard on :3000, both with reload; Ctrl-C stops both
```

What the targets do (from the `Makefile`):

| Target | Effect |
|---|---|
| `make install` | `python3 -m venv .venv`; `.venv/bin/pip install -e ".[dev]"`; `npm ci` in `apps/dashboard`; copies `.env.example` to `.env` if `.env` does not exist. |
| `make dev` | `.venv/bin/sentinelx start --reload` and, in `apps/dashboard`, `SENTINELX_API_URL=http://127.0.0.1:8000 npm run dev`. |
| `make api` | Only the API, with reload. |
| `make dashboard` | Only the dashboard dev server. |
| `make fixtures` | `sentinelx fixtures generate --output pcaps/fixtures`: writes synthetic scenario captures (nothing is transmitted). |
| `make replay PCAP=path/to/file.pcap` | `sentinelx replay <file>`; generates fixtures first if the file is missing. Default `PCAP` is `pcaps/fixtures/mixed_intrusion.pcap`. |
| `make seed` | Fills the development database with detections from synthetic scenarios (`scripts/seed_demo.py`). |
| `make test` | Test suite on SQLite; no external services. |
| `make test-integration` | Tests against throwaway PostgreSQL and Redis containers. |
| `make check` | Lint, type checks, tests, rule validation and a dashboard build. |

On first start with an empty user table the API creates the administrator `admin`
and prints a one-time password to the terminal (unless
`API__BOOTSTRAP_ADMIN_PASSWORD` is set). You must change it at first login. Open
`http://localhost:3000`. Interactive API docs are at `http://127.0.0.1:8000/api/docs`
outside production.

Defaults in development:

- SQLite at `./sentinelx.db`; tables are created automatically at startup.
- Redis at `redis://localhost:6379/0`; if it is not running, SentinelX logs a warning
  and continues in [degraded mode](#redis-and-degraded-mode).
- `JWT_SECRET` unset: a random per-process secret is used, so sessions end when the
  API restarts.
- `RESPONSE_MODE=detect_only`, `DRY_RUN=true`, `FIREWALL_BACKEND=null`: nothing on the
  host firewall is ever changed.

Check the host and configuration at any time:

```sh
.venv/bin/sentinelx doctor
```

`doctor` checks configuration validity, safety posture, capture privileges, the capture
interface, firewall binaries, rules, the PCAP directory, the JWT secret, database
connectivity and migration state (PostgreSQL), and Redis. It exits with status 1 if
any check fails.

Live capture in development needs `CAP_NET_RAW`. `doctor` prints the command it
suggests when the capability is missing:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

This grants the capabilities to every script run by that interpreter binary; prefer a
dedicated virtual environment's interpreter, and see [packet-capture.md](packet-capture.md).
Then start with capture:

```sh
.venv/bin/sentinelx start --capture --interface eth0
```

## Docker Compose

`docker-compose.yml` defines five services, plus a `sensor` service in the optional
`capture` profile.

| Service | Image | Role | Published port (host) |
|---|---|---|---|
| `postgres` | `postgres:17-alpine` | Database; data in the `postgres-data` volume | `127.0.0.1:${POSTGRES_HOST_PORT:-5433}` |
| `redis` | `redis:7-alpine` | Rate-limit counters, WebSocket tickets, caches; password protected, persistence disabled | `127.0.0.1:${REDIS_HOST_PORT:-6381}` |
| `migrate` | `sentinelx-api:local` (built from `docker/Dockerfile.api`) | Runs `sentinelx db upgrade` once and exits | none |
| `api` | `sentinelx-api:local` | `sentinelx start`; PCAP files in the `pcaps` volume at `/data/pcaps` | `127.0.0.1:${API_PORT:-8000}` |
| `dashboard` | `sentinelx-dashboard:local` (built from `docker/Dockerfile.dashboard`) | Next.js standalone server | `127.0.0.1:${DASHBOARD_PORT:-3000}` |
| `sensor` (profile `capture`) | `sentinelx-api:local` | `sentinelx start --capture` on the host network | host network, port 8001 |

Start order: `postgres` becomes healthy, `migrate` completes successfully, then `api`
starts once `redis` is healthy. The dashboard waits for `api` to be healthy (the
dependency is marked `required: false` so the dashboard can run with the `capture`
profile when `api` is scaled to zero).

All ports are published on the loopback interface only. For access from other
machines, put a TLS-terminating reverse proxy in front (see
[Reverse proxy and TLS](#reverse-proxy-and-tls)). PostgreSQL and Redis are published
on loopback (host ports 5433 and 6381 by default) because the host-network `sensor`
cannot resolve Compose service names.

### Secrets and environment

```sh
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, REDIS_PASSWORD and JWT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(48))"   # generates a JWT_SECRET
make docker-up        # or: docker compose up -d --build
make docker-logs      # follow API logs; shows the one-time admin password on first start
```

Compose reads `.env` for variable substitution. Three variables are mandatory and use
the `${VAR:?message}` form, so `docker compose` refuses to start with an explicit
message when any of them is empty:

| Variable | Used for |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL superuser password and the API's `DATABASE_URL` |
| `REDIS_PASSWORD` | `redis-server --requirepass` and the API's `REDIS_URL` |
| `JWT_SECRET` | Token signing; must be at least 32 characters (enforced in production) |

Other Compose variables and what they become inside the API containers (the
`x-api-env` block):

| Compose variable | Default | Passed to the API as |
|---|---|---|
| `ENVIRONMENT` | `production` | `ENVIRONMENT` |
| `POSTGRES_USER`, `POSTGRES_DB` | `sentinelx`, `sentinelx` | part of `DATABASE_URL` |
| `ADMIN_PASSWORD` | empty | `API__BOOTSTRAP_ADMIN_PASSWORD` |
| `METRICS_TOKEN` | empty | `API__METRICS_TOKEN` |
| `CORS_ORIGINS` | `http://localhost:3000` | `CORS_ORIGINS` |
| `DETECTION_MODE` | `balanced` | `DETECTION_MODE` |
| `RESPONSE_MODE` | `detect_only` | `RESPONSE_MODE` |
| `DRY_RUN` | `true` | `DRY_RUN` |
| `FIREWALL_BACKEND` | `null` | `FIREWALL_BACKEND` |
| `CAPTURE_INTERFACE` | `any` | `CAPTURE_INTERFACE` |
| `LOG_LEVEL` | `INFO` | `LOG_LEVEL` |
| `RETENTION_DAYS` | `30` | `RETENTION_DAYS` |
| `SENSOR_NAME` | `sentinelx` | `SENSOR_NAME` |
| `API_PORT`, `DASHBOARD_PORT`, `POSTGRES_HOST_PORT`, `REDIS_HOST_PORT` | `8000`, `3000`, `5433`, `6381` | host port mappings only |
| `DASHBOARD_API_URL` | `http://api:8000` | `SENTINELX_API_URL` in the dashboard container |
| `PUBLIC_WS_URL` | `ws://localhost:8000` | `SENTINELX_PUBLIC_WS_URL` in the dashboard container |

The API image also sets `RULES_DIRECTORY=/app/rules`, `PCAP_DIRECTORY=/data/pcaps`,
`API_HOST=0.0.0.0`, `API_PORT=8000` and `LOG_FORMAT=json`. Only variables listed in
`docker-compose.yml` reach the containers; to set any other setting (for example
`API__TRUSTED_PROXIES`), add it to the `x-api-env` block.

Because the stack defaults to `ENVIRONMENT=production`, the production rules in
[Production validation](#production-validation) apply: authentication cookies are
`Secure`, interactive API docs are disabled (`make docker-up` still prints an
`/api/docs` URL, which returns 404 in production), and a short `JWT_SECRET` stops the
API from starting. Browsers only send `Secure` cookies over HTTPS, with an exception
most browsers make for `localhost`; to use the dashboard from another machine, serve
it over HTTPS.

### Container hardening in the default stack

`api` and `dashboard` run with a read-only root filesystem, a tmpfs `/tmp`,
`no-new-privileges`, and all Linux capabilities dropped. Both images run as the
non-root user `sentinelx` (uid 10001) and include a `HEALTHCHECK`
(`/api/v1/system/health` for the API, `/login` for the dashboard). The dashboard is
attached only to the `frontend` network; PostgreSQL and Redis only to `backend`.

### What the default stack can see

Containers on a Docker bridge network see only traffic addressed to or from
themselves, never the host's other traffic. In the default stack SentinelX therefore
analyses PCAP replays (uploaded or generated in the PCAP lab) and traffic sent to the
stack itself. It is not a network sensor. For real traffic use the `capture` profile
or a [bare-metal install](#bare-metal-sensor-with-systemd).

### The `capture` profile

The `sensor` service replaces `api` for live capture on a Linux host:

- `network_mode: host`: it sees the host's interfaces.
- `cap_drop: [ALL]`, `cap_add: [NET_RAW, NET_ADMIN]`. `NET_RAW` is needed for capture;
  `NET_ADMIN` is used only if you configure a firewall backend. The image grants these
  capabilities to the Python interpreter as file capabilities, which is why
  `no-new-privileges` is set to `false` for this service.
- It connects to PostgreSQL and Redis through their loopback-published ports
  (`127.0.0.1:5433` and `127.0.0.1:6381` by default).
- It runs `sentinelx start --capture` with `API_HOST=0.0.0.0` and `API_PORT=8001`.

Start it as documented at the top of `docker-compose.yml`:

```sh
DASHBOARD_API_URL=http://host.docker.internal:8001 PUBLIC_WS_URL=ws://localhost:8001 \
  docker compose --profile capture up -d --build --scale api=0
```

`--scale api=0` stops the bridge-network `api` so only one pipeline writes to the
database. The dashboard reaches the sensor through `host.docker.internal`, which the
dashboard service maps to the host gateway.

Notes:

- With host networking the sensor's API listens on port 8001 on **all host
  interfaces**, not just loopback. Restrict it with the host firewall or a reverse
  proxy.
- Set `CAPTURE_INTERFACE` in `.env` to the interface that carries the traffic you
  want to monitor (for example a mirror port). The default `any` captures on all
  interfaces.
- See [known limitation: dashboard API address](#known-limitation-dashboard-api-address).

## Bare-metal sensor with systemd

The following is an **example**, not a file shipped with SentinelX. Adapt paths,
users and interfaces to your host. It assumes PostgreSQL and Redis are already
available.

### Install

```sh
sudo useradd --system --home-dir /var/lib/sentinelx --shell /usr/sbin/nologin sentinelx
sudo mkdir -p /opt/sentinelx /etc/sentinelx /var/lib/sentinelx/pcaps
sudo python3 -m venv /opt/sentinelx/venv
sudo /opt/sentinelx/venv/bin/pip install /path/to/Sentinelx      # a checkout of this repository
sudo cp -r /path/to/Sentinelx/rules /etc/sentinelx/rules          # rule files are not part of the package
sudo chown -R sentinelx:sentinelx /var/lib/sentinelx
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
RULES_DIRECTORY=/etc/sentinelx/rules
PCAP_DIRECTORY=/var/lib/sentinelx/pcaps
CAPTURE_INTERFACE=eth1
LOG_FORMAT=json
RESPONSE_MODE=detect_only
DRY_RUN=true
FIREWALL_BACKEND=null
API__METRICS_TOKEN=CHANGE_ME
API__BOOTSTRAP_ADMIN_PASSWORD=CHANGE_ME_FIRST_ADMIN_PASSPHRASE
```

systemd's `EnvironmentFile` does not strip trailing `# comments` on a line, so do not
copy `.env.example` verbatim; its inline comments would become part of the values.

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

# Capture needs CAP_NET_RAW. CAP_NET_ADMIN is only needed with FIREWALL_BACKEND
# set to nftables or iptables; remove it otherwise.
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
  is current.
- Settings are also read from a `.env` file in the working directory if one exists.
  Keep `/var/lib/sentinelx` free of a stray `.env`.
- Anything the API prints to standard error, including a generated administrator
  password, is stored in the journal. Setting `API__BOOTSTRAP_ADMIN_PASSWORD` avoids
  that. It is only used while the user table is empty; remove it from the file once
  the first administrator exists and has logged in.
- `sentinelx doctor` run as the service user reports capture privileges by actually
  opening a raw socket. Its "firewall privileges" check only looks for root, so it
  warns under `AmbientCapabilities` even when `CAP_NET_ADMIN` is present.
- To run CLI commands with the service's configuration, load the same environment,
  for example:
  `sudo -u sentinelx sh -c 'set -a; . /etc/sentinelx/sentinelx.env; exec /opt/sentinelx/venv/bin/sentinelx status'`
  (this works as long as the file contains only simple `KEY=value` lines).

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
  are validated exactly like the nested form (for example `DRY_RUN=ture` is a
  configuration error). A flat alias set to an empty string is ignored, so the default
  (or another source) applies.
- **List values** in the nested form are JSON: `API__CORS_ORIGINS='["https://a.example","https://b.example"]'`.
  The flat `CORS_ORIGINS` alias takes a comma-separated list instead:
  `CORS_ORIGINS=https://a.example,https://b.example`.
- **Sources and precedence**, highest first: nested environment variables, flat
  environment variables, nested entries in `.env`, flat entries in `.env`, defaults.
  A real environment variable therefore always beats `.env`, and the nested form wins
  when both spellings are set in the same place. `.env` is read from the current
  working directory. Top-level settings (`ENVIRONMENT`, `SENSOR_NAME`,
  `RULES_DIRECTORY`) have a single name.
- **Runtime overrides**: settings marked "Runtime: yes" can also be changed while the
  platform runs, from the dashboard, `PATCH /api/v1/config/{section}` or
  `sentinelx config set <section> <key> <json-value>`. These changes are stored in the
  database and re-applied at every start **on top of** the environment, so a stored
  override wins over the environment value. `sentinelx config` shows the effective
  settings.
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
| `CAPTURE__INTERFACE` | `CAPTURE_INTERFACE` | `any` | yes | Interface to capture from. `any` uses the Linux cooked-capture device. |
| `CAPTURE__BPF_FILTER` | `BPF_FILTER` | empty | yes | Optional BPF expression applied in the kernel. The characters `;` `\|` `` ` `` `$` `\` and newlines are rejected. |
| `CAPTURE__SNAPSHOT_LENGTH` | | `2048` | no | Bytes captured per frame (64 to 65535). |
| `CAPTURE__PROMISCUOUS` | | `true` | no | Put the interface in promiscuous mode. |
| `CAPTURE__BUFFER_SIZE_MB` | | `16` | no | Capture buffer size (1 to 1024). |
| `CAPTURE__QUEUE_SIZE` | | `20000` | no | Bounded queue between capture and the pipeline (at least 100). When full, packets are dropped and counted. |
| `CAPTURE__HOME_NETWORKS` | | `["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fd00::/8"]` | yes | Prefixes treated as inside; used to label packet direction. |
| `CAPTURE__PCAP_DIRECTORY` | `PCAP_DIRECTORY` | `pcaps` | no | Directory for uploaded, generated and replayed capture files. |
| `CAPTURE__MAX_PCAP_SIZE_MB` | | `512` | no | Maximum capture file size. |

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
| `DETECTION__HORIZONTAL_SCAN_UNIQUE_HOSTS` | | `25` | yes | Distinct destination hosts on one port (a sweep). |
| `DETECTION__UDP_SCAN_UNIQUE_PORTS` | | `25` | yes | Distinct UDP destination ports that trigger. |
| `DETECTION__BRUTE_FORCE_WINDOW_SECONDS` | | `60.0` | yes | Brute force observation window. |
| `DETECTION__BRUTE_FORCE_ATTEMPTS` | | `15` | yes | Attempts within the window that trigger. |
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
| `SCORING__CONFIDENCE_WEIGHT` | | `20.0` | yes | Weight of detector confidence. |
| `SCORING__FREQUENCY_WEIGHT` | | `10.0` | yes | Weight of repeat frequency. |
| `SCORING__HISTORY_WEIGHT` | | `10.0` | yes | Weight of the source's history. |
| `SCORING__INTEL_WEIGHT` | | `15.0` | yes | Weight of threat intelligence matches. |
| `SCORING__CORRELATION_WEIGHT` | | `15.0` | yes | Weight of correlation with other detectors. |
| `SCORING__SENSITIVE_TARGET_WEIGHT` | | `10.0` | yes | Weight for sensitive targets. |
| `SCORING__HISTORY_WINDOW_SECONDS` | | `3600.0` | yes | Look-back for source history. |
| `SCORING__FREQUENCY_SATURATION` | | `10` | yes | Repeat count at which the frequency factor reaches full weight. |
| `SCORING__HISTORY_SATURATION` | | `5` | yes | History count at which the history factor reaches full weight. |
| `SCORING__ALLOWLIST_PENALTY` | | `40.0` | yes | Points subtracted when an allowlisted source is still detected. |
| `SCORING__AUTO_BLOCK_THRESHOLD` | | `85.0` | yes | Risk at or above which an automatic block may be proposed. Acted on only with `RESPONSE_MODE=automatic` and `DRY_RUN=false`. |
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
| `ANOMALY__ML_ENABLED` | | `false` | no | Enable the IsolationForest detector. Needs a trained model; a missing model disables it with a logged error. |
| `ANOMALY__ML_MODEL_PATH` | | `models/isolation_forest.joblib` | no | Model file. |
| `ANOMALY__ML_CONTAMINATION` | | `0.02` | no | Defined, but not currently read by the platform. |
| `ANOMALY__ML_MIN_SCORE` | | `0.75` | yes | Minimum ML score for a detection. |

### Response (`response`)

Read [response-engine.md](response-engine.md) before changing these.

| Env var | Flat alias | Default | Runtime | Description |
|---|---|---|---|---|
| `RESPONSE__MODE` | `RESPONSE_MODE` | `detect_only` | yes | `detect_only`, `manual_approval` or `automatic`. |
| `RESPONSE__DRY_RUN` | `DRY_RUN` | `true` | yes | Decide, record and display responses without applying them. |
| `RESPONSE__FIREWALL_BACKEND` | `FIREWALL_BACKEND` | `null` | no | `null`, `nftables` or `iptables`. |
| `RESPONSE__NFT_TABLE` | | `sentinelx` | no | nftables table name (1 to 32 of `A-Za-z0-9_`). |
| `RESPONSE__NFT_SET` | | `blocklist` | no | nftables set name. |
| `RESPONSE__NFT_FAMILY` | | `inet` | no | `inet`, `ip` or `ip6`. |
| `RESPONSE__DEFAULT_BLOCK_SECONDS` | | `900` | yes | Duration of a temporary block (30 to 86400). |
| `RESPONSE__MAX_BLOCK_SECONDS` | | `86400` | yes | Longest block allowed (at least 60). |
| `RESPONSE__MAX_BLOCKED_ADDRESSES` | | `10000` | yes | Hard cap on concurrent blocks. |
| `RESPONSE__MAX_BLOCK_PREFIX_HOSTS` | | `256` | yes | Largest prefix that may be blocked, in addresses (256 is a /24). |
| `RESPONSE__ALLOWLIST_NETWORKS` | | `["127.0.0.0/8","::1/128"]` | yes | Never blocked. Loopback is re-added if removed. |
| `RESPONSE__PROTECT_MANAGEMENT_ADDRESSES` | | `true` | no | Refuse to block addresses assigned to local interfaces and addresses with an established connection to the API port. |
| `RESPONSE__MANAGEMENT_ADDRESSES` | | `[]` | yes | Additional addresses that must never be blocked. |
| `RESPONSE__WEBHOOK_URL` | | empty | yes | Webhook for response notifications. |
| `RESPONSE__WEBHOOK_TIMEOUT_SECONDS` | | `5.0` | yes | Webhook timeout (up to 60). |
| `RESPONSE__WEBHOOK_MIN_RISK` | | `60.0` | yes | Minimum risk score for webhook calls; also the threshold used by `GET /api/v1/alerts`. |
| `RESPONSE__RATE_LIMIT_PACKETS_PER_SECOND` | | `100` | yes | Packet rate applied by `rate_limit` actions. |

Validation: `RESPONSE_MODE=automatic` with `DRY_RUN=false` is rejected unless
`FIREWALL_BACKEND` is `nftables` or `iptables`. Enabling prevention at runtime also
requires the confirmation phrase `ENABLE PREVENTION`
(`sentinelx config set ... --confirm-prevention` on the CLI).

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
| `STORAGE__RETENTION_DAYS` | `RETENTION_DAYS` | `30` | yes | Retention for detections, closed incidents, response actions, inactive blocks and replay records (1 to 3650). |
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
| `API__MAX_UPLOAD_MB` | | `200` | Upload limit; the effective limit is the smaller of this and `CAPTURE__MAX_PCAP_SIZE_MB`. |
| `API__TRUSTED_PROXIES` | | `[]` | CIDRs of reverse proxies whose `X-Forwarded-For` is believed. |
| `API__METRICS_TOKEN` | | empty | Bearer token for `/api/v1/metrics`. Empty: loopback clients only. |
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

- **PostgreSQL**: run `sentinelx db upgrade` before the first start and after every
  upgrade. The API does not create or migrate the PostgreSQL schema itself. The
  Compose `migrate` service and the example `ExecStartPre` do this automatically.
  `sentinelx doctor` fails its "migrations" check when the database is behind.
- **SQLite**: missing tables are created from the models at startup. SQLite is for
  development and evaluation.

`sentinelx db` configures Alembic programmatically from `DATABASE_URL`. `alembic.ini`
at the repository root exists for developers running Alembic directly from a
checkout (for example `.venv/bin/python -m alembic current`); it takes the database
URL from SentinelX settings and must never contain credentials.

## Retention

A background task in the API applies retention 60 seconds after startup and then
every 6 hours. `sentinelx db purge` runs the same policy on demand and prints the rows
removed per table.

| Data | Removed when older than | Setting |
|---|---|---|
| Detections | `retention_days` | `RETENTION_DAYS` (30) |
| Incidents with status `resolved` or `false_positive` (by last-seen time) | `retention_days` | |
| Response actions | `retention_days` | |
| Inactive block records | `retention_days` | |
| Replay records | `retention_days` | |
| Traffic summaries, system metrics | `metrics_retention_days` | `STORAGE__METRICS_RETENTION_DAYS` (7) |
| Audit events | `audit_retention_days` | `STORAGE__AUDIT_RETENTION_DAYS` (365) |

Open incidents are never removed by retention. Capture files in the PCAP directory
are not removed by retention; manage that directory separately. All three retention
values can be changed at runtime.

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

SentinelX does not terminate TLS. For any access beyond the local host, run the API and
dashboard on loopback (the defaults) and put a TLS-terminating reverse proxy in front.

Set `ENVIRONMENT=production`: authentication cookies become `Secure` and the API sends
`Strict-Transport-Security`.

### Client addresses: `trusted_proxies`

The API uses the client address for rate limiting, login throttling, audit records and
the metrics loopback check. By default it uses the TCP peer address and ignores
`X-Forwarded-For`, so clients cannot spoof their address. Behind a proxy every
request would then appear to come from the proxy, and one client could exhaust the
rate limit for everyone.

List your proxies' addresses:

```sh
API__TRUSTED_PROXIES='["10.0.0.5/32"]'
```

`sentinelx start` then enables uvicorn's proxy header handling for those addresses, and
the API believes `X-Forwarded-For` only from peers in the list. Configure the proxy
to set `X-Forwarded-For` itself rather than pass through a client-supplied value.

When trusting a proxy on loopback (`127.0.0.1/32`), remember that the metrics
endpoint's loopback exception then applies to the forwarded client address, not to
the proxy.

### Routing

The dashboard proxies `/api/*` to the API server-side, so a browser only needs to
reach the dashboard for REST calls. The WebSocket connects from the browser directly
to the URL in `SENTINELX_PUBLIC_WS_URL` (see
[Dashboard configuration](#dashboard-configuration)). A typical single-hostname layout:

| Public path on `https://sentinelx.example.com` | Upstream |
|---|---|
| `/api/v1/ws/events` | API (`127.0.0.1:8000`), with WebSocket upgrade headers forwarded |
| everything else | Dashboard (`127.0.0.1:3000`) |

with `SENTINELX_PUBLIC_WS_URL=wss://sentinelx.example.com` and
`CORS_ORIGINS=https://sentinelx.example.com`. The WebSocket origin check accepts an
`Origin` listed in `CORS_ORIGINS`, or one that matches the request's `Host` header, so
the proxy should preserve `Host`.

Example nginx server block (an **example**; adapt certificates, addresses and names):

```nginx
server {
    listen 443 ssl;
    server_name sentinelx.example.com;
    ssl_certificate     /etc/ssl/certs/sentinelx.example.com.pem;
    ssl_certificate_key /etc/ssl/private/sentinelx.example.com.key;

    client_max_body_size 200m;   # match API__MAX_UPLOAD_MB for PCAP uploads

    location /api/v1/ws/events {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 120s;   # the server pings every 25 s
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

In this layout the API sees REST requests from the dashboard server, not from the
proxy. Add the dashboard host's address to `API__TRUSTED_PROXIES` only if it forwards a
trustworthy `X-Forwarded-For`; otherwise REST rate limits are shared by all dashboard
users. Scripts and integrations can also be routed to the API directly (for example a
`location /api/` block pointing at the API), in which case the nginx host is the proxy
to trust.

Prometheus should scrape the API directly on a private network or through the proxy
with `API__METRICS_TOKEN` set.

## Dashboard configuration

The dashboard (`apps/dashboard`, Next.js) has no settings of its own beyond two
environment variables:

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `SENTINELX_API_URL` | `next.config.ts` (rewrite of `/api/:path*`) | `http://127.0.0.1:8000` | Where the dashboard server forwards `/api/*` requests. In Compose it is set from `DASHBOARD_API_URL`. |
| `SENTINELX_PUBLIC_WS_URL` | `src/app/runtime-config/route.ts` | unset | Base URL the browser uses for the WebSocket, for example `wss://sentinelx.example.com`. In Compose it is set from `PUBLIC_WS_URL`. |

`GET /runtime-config` on the dashboard returns `{"wsUrl": <SENTINELX_PUBLIC_WS_URL or null>}`,
read from the server environment on every request (`Cache-Control: no-store`), so the
same build works in any deployment. When it is `null`, the browser connects to
`ws://<page hostname>:8000` (or `wss://` on an HTTPS page). The browser's origin must
then be allowed by the API's `CORS_ORIGINS` or match the API's `Host`.

### Known limitation: dashboard API address

Next.js resolves `rewrites()` in `next.config.ts` when the application is **built**, and
writes the destination into `.next/routes-manifest.json` (and the standalone
`server.js`). `SENTINELX_API_URL` therefore takes effect when set during
`npm run build` (or when running `npm run dev`), not when set only on an already built
server. `docker/Dockerfile.dashboard` does not set it during the build, so the image
forwards to `http://127.0.0.1:8000`, and the runtime `SENTINELX_API_URL`
(`DASHBOARD_API_URL`) set in `docker-compose.yml` may have no effect. If dashboard API
calls fail in a container deployment, check the destination in
`/app/.next/routes-manifest.json` inside the dashboard container.

### Running the dashboard outside Docker

The image build is the reference (`docker/Dockerfile.dashboard`):

```sh
cd apps/dashboard
npm ci
SENTINELX_API_URL=http://127.0.0.1:8000 npm run build
cp -r .next/static .next/standalone/.next/static
cp -r public .next/standalone/public
cd .next/standalone
NODE_ENV=production PORT=3000 HOSTNAME=127.0.0.1 SENTINELX_PUBLIC_WS_URL=wss://sentinelx.example.com node server.js
```

## Backups

| What | Where | How |
|---|---|---|
| Database (detections, incidents, audit log, users, API-created rules, runtime setting overrides) | PostgreSQL | `pg_dump`. With Compose: `docker compose exec -T postgres pg_dump -U sentinelx -Fc sentinelx > sentinelx-$(date +%F).dump` |
| Secrets and configuration | `.env`, or `/etc/sentinelx/sentinelx.env` | Back up securely; it contains database, Redis and JWT secrets. |
| File-based rules and threat intel lists | `RULES_DIRECTORY` (`rules/`, `rules/intel/`) | Version control or file backup. |
| Capture files | `PCAP_DIRECTORY` (Compose volume `pcaps`) | File backup, if you need to keep them. |
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
4. Apply migrations and restart.

Docker Compose:

```sh
git pull
docker compose up -d --build     # rebuilds images; `migrate` runs before `api` starts
docker compose logs -f api
```

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

- [ ] `ENVIRONMENT=production`.
- [ ] `JWT_SECRET` of at least 32 random characters, stored outside version control.
- [ ] PostgreSQL `DATABASE_URL` with a dedicated user and strong password; migrations
      applied (`sentinelx db current` shows up to date).
- [ ] Redis protected with a password and not exposed beyond the hosts that need it.
- [ ] `CORS_ORIGINS` lists exactly the dashboard's public origin(s).
- [ ] If a reverse proxy is used, `API__TRUSTED_PROXIES` lists exactly its addresses.
- [ ] `API__METRICS_TOKEN` set if Prometheus scrapes from another host.
- [ ] `API__BOOTSTRAP_ADMIN_PASSWORD` removed after the first administrator exists, or
      never set and the generated password changed at first login.
- [ ] Effective values confirmed with `sentinelx config` or `GET /api/v1/config`
      (environment variables override `.env`, and stored runtime overrides win over both).

Network and transport:

- [ ] API and dashboard bound to loopback or a private interface; TLS terminated at a
      reverse proxy for all remote access.
- [ ] With the Compose `capture` profile, port 8001 restricted by the host firewall.
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
- [ ] Only `CAP_NET_RAW` (and `CAP_NET_ADMIN` only with a firewall backend) granted to
      the sensor; the service runs as a non-root user.
- [ ] `sentinelx doctor` passes on the sensor host.

Operations:

- [ ] Database backups scheduled and a restore tested.
- [ ] Retention values reviewed against your storage and compliance requirements.
- [ ] Logs shipped with `LOG_FORMAT=json`; alerts on `status` other than `ok` from
      `/api/v1/system/health`.
- [ ] PCAP directory size monitored (retention does not delete capture files).

See [security.md](security.md) for the threat model and residual risks.
