# REST and WebSocket API

SentinelX exposes a JSON REST API under `/api/v1`, a real-time event stream at
`/api/v1/ws/events`, and a Prometheus endpoint at `/api/v1/metrics`. The dashboard,
the CLI and third-party integrations all use the same services behind this API.

Routes are thin: they validate input, check the caller's role, call a service and
return its result. Detection, scoring and response logic are described in
[architecture.md](architecture.md) and [response-engine.md](response-engine.md); the
threat model behind the authentication design is in [security.md](security.md).

All examples assume the API listens on `http://127.0.0.1:8000` (the default
`API_HOST`/`API_PORT`). Response bodies shown below were captured from the
application running in-process against SQLite; tokens and ids are shortened.

## Contents

- [OpenAPI document and interactive docs](#openapi-document-and-interactive-docs)
- [Authentication](#authentication)
- [Roles](#roles)
- [Endpoint reference](#endpoint-reference)
- [Errors](#errors)
- [Pagination and filters](#pagination-and-filters)
- [Rate limiting](#rate-limiting)
- [WebSocket event stream](#websocket-event-stream)
- [Prometheus metrics](#prometheus-metrics)
- [Examples](#examples)

## OpenAPI document and interactive docs

| Path | Content |
|---|---|
| `/api/v1/openapi.json` | OpenAPI document |
| `/api/docs` | Swagger UI |
| `/api/redoc` | ReDoc |

All three are served only when `api.docs_enabled` is true (`API__DOCS_ENABLED`,
default `true`). When `ENVIRONMENT=production` the setting is forced to `false`
regardless of what you configure, and the three paths return 404
(`packages/sentinelx/api/app.py`, `packages/sentinelx/config/settings.py`). The
Docker Compose stack defaults to `ENVIRONMENT=production`, so its API does not serve
docs.

A copy of the document is committed at `apps/dashboard/src/lib/openapi.json`; the
dashboard's TypeScript types are generated from it. Regenerate both with:

```sh
make openapi
```

which runs `scripts/export_openapi.py` (writes the committed file) and
`npm run generate:api` in `apps/dashboard`. The script takes an optional output path
as its only argument; it has no `--help` flag. CI fails if the committed files
differ from a fresh export. At the time of writing the committed document matches
the code (55 paths).

The WebSocket endpoint does not appear in the OpenAPI document; it is documented
[below](#websocket-event-stream).

## Authentication

Implemented in `packages/sentinelx/api/security.py`,
`packages/sentinelx/services/auth.py` and `packages/sentinelx/api/routes/auth.py`.

### Two client modes

| | Scripts, CLI, integrations | Browser (the dashboard) |
|---|---|---|
| Signalled by | no special header | `X-SentinelX-Client: dashboard` on login and refresh |
| Access token | `access_token` in the login response body; send `Authorization: Bearer <token>` | also set as the `sx_access` cookie |
| Refresh token | `refresh_token` in the response body | only as the `sx_refresh` cookie; the body field is `null` |
| CSRF | not required | `X-CSRF-Token` header must equal the `sx_csrf` cookie on every non-GET/HEAD/OPTIONS request authenticated by cookie |

If a request carries an `Authorization: Bearer` header, that token is used and the
cookie is ignored. Bearer requests are exempt from the CSRF check.

Cookies set for a dashboard login:

| Cookie | Contents | Attributes |
|---|---|---|
| `sx_access` | access token | `HttpOnly`, `SameSite=Strict`, `Path=/api`, `Max-Age` = token lifetime |
| `sx_refresh` | refresh token | `HttpOnly`, `SameSite=Strict`, `Path=/api/v1/auth`, `Max-Age` = refresh lifetime |
| `sx_csrf` | random CSRF token (also returned as `csrf_token` in the body) | readable by JavaScript, `SameSite=Strict`, `Path=/` |

All three are marked `Secure` when `api.cookie_secure` is true, which is forced on in
production. A cookie-authenticated state-changing request without a matching
`X-CSRF-Token` gets `403 {"detail": "CSRF token missing or invalid"}`.

The dashboard reaches the API through its own origin (Next.js rewrites `/api/*` to
the API), which is what makes the `SameSite=Strict` cookies usable without CORS.

### Tokens

- Access tokens are JWTs signed with `api.jwt_secret` using `api.jwt_algorithm`
  (`HS256` by default; `HS384` and `HS512` are accepted). Claims: `sub` (user id),
  `iss` (`api.jwt_issuer`, default `sentinelx`), `iat`, `exp`, `jti`, `type`
  (`access`), `username`, `role`, `pwd_change`.
- Access token lifetime: `api.access_token_ttl_seconds`, default **900 seconds**
  (15 minutes), allowed range 60 to 86400. The absolute expiry is returned as
  `expires_at`.
- Refresh token lifetime: `api.refresh_token_ttl_seconds`, default **604800 seconds**
  (7 days).
- Every authenticated request re-reads the user from the database, so a deactivated
  user or a changed role takes effect on the next request rather than at token
  expiry.
- The JWT secret must be at least 32 characters. Outside production an unset secret is
  replaced by a random per-process value, so tokens do not survive a restart.

### Refresh rotation and reuse detection

`POST /api/v1/auth/refresh` accepts the refresh token from the `sx_refresh` cookie
or, if there is no cookie, from a JSON body `{"refresh_token": "..."}`.

- Each refresh token id is stored server-side. A successful refresh marks the
  presented token revoked and issues a new access and refresh token pair.
- Presenting a refresh token that has already been rotated is treated as theft: every
  refresh token for that user is revoked and the call returns
  `401 {"detail": "invalid token"}`. The legitimate client's newest refresh token then
  also fails, forcing a new login.
- A failed refresh clears the auth cookies.
- `POST /api/v1/auth/logout` revokes all of the user's refresh tokens and clears the
  cookies. Access tokens that were already issued remain valid until they expire.

### Login throttling and account lockout

Two independent controls apply to `POST /api/v1/auth/login`:

| Control | Scope | Default | Response |
|---|---|---|---|
| Login throttle | client IP | `api.login_rate_limit_attempts` = 8 attempts per `api.login_rate_limit_window_seconds` = 300 s; reset by a successful login | `429 {"detail": "too many login attempts; try again later"}` with `Retry-After` |
| Account lockout | user account | `api.lockout_threshold` = 5 consecutive failures lock the account for `api.lockout_seconds` = 900 s | `423 {"detail": "account temporarily locked after repeated failures"}` with `Retry-After` (seconds remaining) |

While an account is locked, even the correct password returns 423. Credential
failures always return `401 {"detail": "invalid username or password"}`, whether or
not the username exists, and unknown usernames are verified against a dummy hash so
timing does not reveal valid names. An administrator's password reset clears the
lock.

### Forced password change

Accounts with `must_change_password` set (the bootstrap administrator when its
password was generated, and any user whose password an administrator reset) can
log in, but every endpoint except these three returns
`403 {"detail": "password change required before continuing"}`:

- `POST /api/v1/auth/change-password`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/logout`

The login response's `user.must_change_password` tells the client to prompt for a
new password. A successful change clears the flag (the current access token is then
no longer gated) and revokes all of the user's refresh tokens, which signs out every
other session once its access token expires.

### Password policy

Enforced on user creation, password change, administrative reset and the bootstrap
administrator password (`validate_password` in `services/auth.py`):

- at least `api.password_min_length` characters (default 12, allowed 8 to 128);
- at most 256 characters;
- must not contain the username (case-insensitive);
- must not be one of a small built-in list of common passwords;
- must contain at least 5 distinct characters.

There are no character-class composition rules. Violations return 422 with every
problem joined in one message, for example
`{"detail": "password must be at least 12 characters; must not contain the username"}`.
Changing a password to the current one returns
`422 {"detail": "new password must differ from the current one"}`; a wrong current
password returns `403 {"detail": "current password is incorrect"}`.

Usernames are 3 to 64 characters of letters, digits, `.`, `_` or `-`.

### First administrator

When the user table is empty at startup, SentinelX creates an administrator named
`api.bootstrap_admin_username` (default `admin`). If
`API__BOOTSTRAP_ADMIN_PASSWORD` is set it is used (and must meet the policy);
otherwise a password is generated, printed once to the server's standard error, and
the account must change it at first login. `GET /api/v1/system/status` reports
`bootstrap_admin_pending: true` when the running process generated such a password at
startup.

### Authentication disabled

`api.auth_enabled=false` (`API__AUTH_ENABLED`) makes every request act as an
administrator named `anonymous` and removes the WebSocket ticket requirement. It is
intended only for local development and is rejected when `ENVIRONMENT=production`.

## Roles

Roles are hierarchical: `admin` includes everything `analyst` can do, and `analyst`
includes everything `viewer` can do.

| Role | Can |
|---|---|
| `viewer` | Read detections, incidents, alerts, threats, firewall state, rules, detectors, statistics, sensors, replays. |
| `analyst` | Viewer, plus: triage detections, update incidents, read the audit log and effective configuration, preview the safety guard, validate and test rules, upload captures, generate fixtures, start and cancel replays. Receives `audit.event` and `config.changed` on the WebSocket. |
| `admin` | Analyst, plus: users, sensors start/stop, blocking and unblocking, approvals, the allowlist, creating/editing/enabling/deleting rules, enabling/disabling detectors, changing configuration. |

A caller without the required role receives `403 {"detail": "requires the <role> role"}`.

## Endpoint reference

All paths are relative to `/api/v1`. "Role" is the minimum role. "Public" means no
authentication; "Any" means any authenticated user.

### Auth (`routes/auth.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/auth/login` | Public | Exchange `{"username", "password"}` for tokens. |
| POST | `/auth/refresh` | Public (refresh token) | Rotate a refresh token; returns a new token pair. |
| POST | `/auth/logout` | Any | Revoke all refresh tokens for the user and clear cookies. 204. |
| GET | `/auth/me` | Any | The current user. |
| POST | `/auth/change-password` | Any | `{"current_password", "new_password"}`. 204. |
| POST | `/auth/ws-ticket` | Any | Issue a single-use, 30-second WebSocket ticket. |
| GET | `/users` | admin | List users. |
| POST | `/users` | admin | Create a user: `{"username", "password", "role"}` (`role` defaults to `viewer`). 201. |
| PATCH | `/users/{user_id}` | admin | Change `role` and/or `is_active`. Deactivation revokes the user's refresh tokens. You cannot demote or deactivate yourself, or demote the last active administrator. |
| POST | `/users/{user_id}/reset-password` | admin | `{"new_password"}`. Forces a change at next login, clears lockout, revokes sessions. 204. |
| DELETE | `/users/{user_id}` | admin | Delete a user. Not yourself, not the last active administrator. 204. |

### System, sensors, metrics and audit (`routes/system.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/system/health` | Public | Liveness probe: `{"status": "ok" \| "degraded" \| "error", "version"}`. Not rate limited. |
| GET | `/system/status` | viewer | Full health report: components (database, Redis, firewall, event bus, persister, sensor, rules), process metrics, pipeline status, safety posture. |
| GET | `/sensors` | viewer | Sensor status (a single-element list). |
| GET | `/interfaces` | viewer | Network interfaces available for capture. |
| POST | `/sensors/start` | admin | Start live capture: `{"interface"?, "bpf_filter"?}`; defaults to `CAPTURE_INTERFACE`. |
| POST | `/sensors/stop` | admin | Stop live capture. |
| GET | `/metrics` | metrics token or loopback | Prometheus exposition format. See [Prometheus metrics](#prometheus-metrics). |
| GET | `/metrics/summary` | viewer | JSON summary of decoder, feature, detection, capture and event bus counters. |
| GET | `/audit` | analyst | Audit log, paginated. Filters: `actor`, `action`, `target`, `since`. |

### Detections, incidents, alerts and threats (`routes/detections.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/detections` | viewer | Detections, paginated and filtered. |
| GET | `/detections/{detection_id}` | viewer | One detection with its evidence, risk breakdown and response actions. |
| PATCH | `/detections/{detection_id}` | analyst | Triage: `{"status": "new" \| "acknowledged" \| "false_positive" \| "resolved"}`. |
| GET | `/incidents` | viewer | Correlated incidents, paginated and filtered. |
| GET | `/incidents/{incident_id}` | viewer | One incident with its detections and actions. |
| PATCH | `/incidents/{incident_id}` | analyst | Any of `status`, `assigned_to`, `notes`. |
| GET | `/alerts` | viewer | Untriaged detections at or above `response.webhook_min_risk` in the last `hours` (default 24, max 720), plus pending approvals. |
| GET | `/threats` | viewer | Detections grouped by source address. Query: `hours` (1 to 720, default 24), `limit` (1 to 500, default 100). |

### Firewall, blocking and approvals (`routes/firewall.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/firewall` | viewer | Firewall overview. |
| GET | `/firewall/blocked` | viewer | Currently blocked addresses (refreshed from the backend). |
| GET | `/firewall/actions` | viewer | Response action history, paginated. Filters: `target`, `outcome` (repeatable). |
| POST | `/firewall/check` | analyst | `{"target"}`: preview whether the safety guard would permit acting on it. |
| POST | `/firewall/block` | admin | Block or rate limit an address or prefix. Honours `DRY_RUN` and the safety guard. |
| POST | `/firewall/unblock` | admin | `{"target", "reason"}`: remove a block. |
| GET | `/firewall/approvals` | viewer | Actions waiting for approval (`RESPONSE_MODE=manual_approval`). |
| POST | `/firewall/approvals/{action_id}/approve` | admin | Approve and carry out a pending action (still subject to the guard and dry run). |
| POST | `/firewall/approvals/{action_id}/reject` | admin | `{"reason"?}`: discard a pending action. |
| GET | `/firewall/allowlist` | viewer | Response allowlist, detection allowlist and management addresses. |
| PUT | `/firewall/allowlist` | admin | `{"networks": [...]}`: replace the never-block allowlist. Loopback is always retained. |

`POST /firewall/block` body:

| Field | Type | Notes |
|---|---|---|
| `target` | string, 2 to 64 chars | IP address or CIDR prefix. |
| `reason` | string, 3 to 500 chars | Recorded in the audit log. |
| `duration_seconds` | integer, 30 to 604800, optional | Present: `temporary_block`. Omitted: permanent `block_ip`. Capped at `response.max_block_seconds`. |
| `rate_limit` | boolean, default `false` | `true` requests a `rate_limit` action instead of a block. |

A block the safety guard refuses is **not** an HTTP error. The request was valid, so
the API returns 200 with `executed: false`, `outcome: "failed"`, a non-null `error`
and an `http_note` field; see the [example](#block-an-address). Clients must check
`error` and `executed`, not just the status code. See
[response-engine.md](response-engine.md) for the guard's rules.

### Rules and detectors (`routes/rules.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/rules` | viewer | All rules with live counters, plus `load_problems` for invalid rule files. |
| GET | `/rules/fields` | viewer | Fields and operators usable in rule conditions, and available scenario names. |
| GET | `/rules/{rule_id}` | viewer | One rule. |
| POST | `/rules/validate` | analyst | `{"definition": "<YAML>"}`: validate without saving. |
| POST | `/rules/test` | analyst | `{"definition", "scenario"?, "pcap_path"?}`: run a rule in isolation against a scenario, a capture file or its embedded tests. |
| POST | `/rules` | admin | Create a rule from `{"definition"}`. 201. |
| PUT | `/rules/{rule_id}` | admin | Replace a rule's definition. |
| PATCH | `/rules/{rule_id}/enabled` | admin | `{"enabled": bool}`. |
| DELETE | `/rules/{rule_id}` | admin | Delete a rule. 204. |
| GET | `/detectors` | viewer | Built-in and rule detectors with their counters. |
| PATCH | `/detectors/{name}/enabled` | admin | `{"enabled": bool}` for a built-in detector; persisted to `detection.disabled_detectors`. Rule detectors (`rule:*`) must use `/rules/{rule_id}/enabled`. |

An invalid rule returns `422 {"detail": "rule is invalid", "problems": [...]}`.

### Configuration and statistics (`routes/stats.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/config` | analyst | Effective settings with secrets removed, the runtime-editable fields per section, and the safety posture (including the confirmation phrase). |
| PATCH | `/config/{section}` | admin | `{"changes": {...}, "confirmation"?}`: change runtime-editable settings in one section. |
| GET | `/stats/overview` | viewer | Dashboard overview, sensor status, safety banner and health. |
| GET | `/stats/network` | viewer | Traffic statistics and interfaces. |
| GET | `/stats/analytics` | viewer | Time-series analytics. Query: `hours` (1 to 2160, default 24). |

Runtime configuration changes are validated with the same models used at startup,
applied immediately, stored in the database, audited, and broadcast as
`config.changed`. Stored changes are re-applied at every start, on top of the
environment. The editable fields are listed in
[deployment.md](deployment.md#configuration-reference). Changing a field that is not
runtime-editable returns 422.

Enabling prevention (`response.mode` = `automatic` with `response.dry_run` = `false`)
requires `"confirmation": "ENABLE PREVENTION"`; without it the API returns 422.

### PCAP lab and replay (`routes/replay.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/replay/files` | viewer | Capture files in the PCAP directory. |
| GET | `/replay/files/inspect` | viewer | Query `path` (required): summary of one capture file. |
| POST | `/replay/upload` | analyst | Multipart upload, form field `file`. Size limit is the smaller of `api.max_upload_mb` and `capture.max_pcap_size_mb`. 201. |
| GET | `/replay/scenarios` | viewer | Synthetic traffic scenarios available for generation. |
| POST | `/replay/scenarios/{name}` | analyst | `{"params": {...}}`: write a scenario to `fixtures/<name>.pcap`. Nothing is transmitted. 201. |
| POST | `/replay` | analyst | `{"path", "speed"?, "limit"?}`: start a replay through the live pipeline. `speed` 0 (as fast as possible) to 100. 202. |
| GET | `/replay` | viewer | Recent replays. Query: `limit` (1 to 200, default 50). |
| GET | `/replay/{replay_id}` | viewer | Replay status, progress and final report. |
| POST | `/replay/{replay_id}/cancel` | analyst | Cancel a running replay; 409 if it is not running. |

Replay responses are always simulated; a replay never changes the firewall.

### WebSocket (`api/websocket.py`)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET (upgrade) | `/ws/events` | ticket from `POST /auth/ws-ticket` | Real-time event stream. |

## Errors

Error bodies are JSON with a `detail` field. Handlers are installed in
`packages/sentinelx/api/errors.py`; authentication and authorisation errors come from
`api/security.py`.

| Status | Cause | Body |
|---|---|---|
| 401 | Missing, invalid or expired token; bad credentials; refresh failure | `{"detail": "authentication required"}`, `"token expired"`, `"invalid token"`, `"invalid username or password"`, `"account disabled"`. Token failures on protected endpoints include `WWW-Authenticate: Bearer`. |
| 403 | Insufficient role; CSRF failure; forced password change; wrong current password | `{"detail": "requires the admin role"}` and similar |
| 404 | Unknown resource | `{"detail": "detection not found"}` and similar |
| 404 | Capture interface does not exist | `{"detail": "...", "available": [...]}` |
| 409 | Operation conflicts with current state (capture errors, missing OS permission, replay not running, duplicate username) | `{"detail": "..."}` |
| 422 | Request validation (FastAPI) | `{"detail": [{"type", "loc", "msg", "input", ...}]}` |
| 422 | Invalid rule | `{"detail": "rule is invalid", "problems": [...]}` |
| 422 | Safety guard refusal raised by a service | `{"detail": "refused by safety guard: <reason>", "target": "..."}` |
| 422 | Configuration or PCAP error, password policy, business rule | `{"detail": "..."}` |
| 423 | Account locked | `{"detail": "account temporarily locked after repeated failures"}` + `Retry-After` |
| 429 | API or login rate limit | `{"detail": "rate limit exceeded"}` or `{"detail": "too many login attempts; try again later"}` + `Retry-After` |
| 502 | Firewall command failed | `{"detail": "firewall operation failed: ..."}` |
| 503 | Database unavailable | `{"detail": "storage unavailable", "error_id": "<12 hex chars>"}` |
| 500 | Unexpected error | `{"detail": "internal error", "error_id": "<12 hex chars>"}` |

For 500 and 503 the exception detail is written to the server log under the same
`error_id` and never returned to the client.

Request bodies are strict: unknown fields are rejected with 422 (`extra_forbidden`),
and string whitespace is stripped.

## Pagination and filters

Paginated endpoints (`/detections`, `/incidents`, `/audit`, `/firewall/actions`)
accept `limit` and `offset` and return:

```json
{ "items": [ ... ], "total": 5, "limit": 1, "offset": 0 }
```

`total` is the number of matching rows before `limit`/`offset`.

| Endpoint | `limit` default / max | Filters |
|---|---|---|
| `GET /detections` | 50 / 500 | `severity`, `detector`, `category`, `status` (all repeatable); `source_ip`, `destination_ip`, `protocol`, `incident_id`, `replay_id`, `since`, `until`, `min_risk` (0 to 100), `q` (free text over title, description, source IP and detector, max 200 chars), `order` = `newest` (default) \| `oldest` \| `risk` |
| `GET /incidents` | 50 / 500 | `status`, `severity` (repeatable); `min_risk`, `replay_id`, `since` |
| `GET /audit` | 100 / 500 | `actor`, `action`, `target`, `since` |
| `GET /firewall/actions` | 100 / 500 | `target`, `outcome` (repeatable, max 10) |

- Repeatable parameters are passed multiple times: `?severity=high&severity=critical`.
- `severity` values: `info`, `low`, `medium`, `high`, `critical`.
- `category` values: `reconnaissance`, `brute_force`, `denial_of_service`,
  `exfiltration`, `protocol_anomaly`, `policy_violation`, `malicious_reputation`,
  `anomaly`, `lateral_movement`, `other`.
- Incident `status` values: `open`, `investigating`, `contained`, `resolved`,
  `false_positive`.
- `since` and `until` are ISO 8601 date-times, for example `2026-09-14T00:00:00Z`.
  For incidents, `since` compares against the incident's last-seen time.
- Detections and incidents produced by replays are excluded unless you pass
  `replay_id`.

## Rate limiting

`RateLimitMiddleware` (`api/security.py`) applies a sliding-window limit per client IP
to every path under `/api/` except `/api/v1/system/health`.

| Setting | Env var | Default |
|---|---|---|
| `api.rate_limit_requests` | `API__RATE_LIMIT_REQUESTS` | 300 |
| `api.rate_limit_window_seconds` | `API__RATE_LIMIT_WINDOW_SECONDS` | 60 |

Every limited response that is allowed carries:

```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 299
```

When the limit is exceeded the API returns `429 {"detail": "rate limit exceeded"}` with
`Retry-After: <seconds>`. Browsers on other origins can read `Retry-After` and
`X-RateLimit-Remaining` (exposed through CORS).

Counters live in Redis so that the limit holds across processes. If Redis is
unreachable and `storage.redis_required` is false, counters fall back to in-process
memory and limits apply per process. The client IP is the TCP peer address unless the
peer is listed in `api.trusted_proxies`, in which case `X-Forwarded-For` is used; see
[deployment.md](deployment.md#reverse-proxy-and-tls).

The login throttle described in
[Login throttling and account lockout](#login-throttling-and-account-lockout) is a
separate, stricter counter.

## WebSocket event stream

Endpoint: `/api/v1/ws/events`.

### Connecting

1. Obtain a ticket with an authenticated request:

   ```http
   POST /api/v1/auth/ws-ticket
   ```

   ```json
   { "ticket": "Ef9WWbh_aiSWOk5qHPuSJfA2mEWIsQAvDwEkqn-9djY", "expires_in": 30 }
   ```

2. Open the socket within 30 seconds:

   ```
   ws://127.0.0.1:8000/api/v1/ws/events?ticket=<ticket>[&types=detection.created,incident.opened]
   ```

Tickets are random, single use and expire after 30 seconds, so a long-lived
credential never appears in a URL. They are stored in Redis when available (so any
API process can redeem them) and in process memory otherwise. A ticket is consumed
on its first redemption attempt.

### Origin check

Browsers send an `Origin` header on WebSocket upgrades. The connection is allowed when:

- there is no `Origin` header (typical for non-browser clients), or
- the origin is listed in `api.cors_origins`, or
- the origin is `http://<Host>` or `https://<Host>`, where `<Host>` is the request's
  `Host` header.

Otherwise the server closes the connection before accepting it, with code **1008**
and reason `origin not allowed`. Because the close happens before the handshake is
accepted, a client connected through a real ASGI server normally sees this as a
rejected handshake (HTTP 403) rather than a close frame.

### Close codes

| Code | When | Client action |
|---|---|---|
| 4401 | Ticket missing, invalid, expired or already used (sent after accepting the handshake), or the account is disabled | Request a new ticket and reconnect. |
| 1008 | Origin not allowed, or an unknown event type in `types` (sent before accepting, see above) | Fix the configuration or request; do not retry blindly. |

A client whose single send stalls for 10 seconds is disconnected.

### Type filters

`types` is an optional comma-separated list of event types (at most the first 32
are considered). An unknown type closes the connection with 1008 and reason
`unknown event type`. Without `types` the client receives every type its role allows.
Viewers never receive `audit.event` or `config.changed`; requesting them as a viewer
silently drops them from the subscription.

### Messages

The first message after connecting is a greeting:

```json
{
  "type": "hello",
  "payload": {
    "user": "admin",
    "role": "admin",
    "subscribed": ["detection.created", "incident.opened"],
    "safety": "DETECTION ONLY - no traffic will be modified"
  }
}
```

Every event after that uses the envelope:

```json
{
  "id": "<event id>",
  "type": "detection.created",
  "timestamp": "2026-09-14T21:55:50.219835+00:00",
  "payload": { }
}
```

If no event is delivered for 25 seconds the server sends `{"type": "ping"}`. Messages
from the client are read (to notice disconnects) and otherwise ignored; there are no
client commands.

Each connection has a bounded outbound queue of `api.websocket_max_queue` events
(default 500). When a client cannot keep up, events are dropped for that client so a
slow consumer never slows detection. After reconnecting, use the REST API to catch up.

Event types (`EventType` in `packages/sentinelx/events/bus.py`):

| Type | Visible to |
|---|---|
| `detection.created` | all roles |
| `incident.opened` | all roles |
| `incident.updated` | all roles |
| `incident.closed` | all roles |
| `severity.changed` | all roles |
| `ip.blocked` | all roles |
| `ip.unblocked` | all roles |
| `response.decided` | all roles |
| `response.pending_approval` | all roles |
| `sensor.status` | all roles |
| `packet.stats` | all roles |
| `system.health` | all roles (published every 5 seconds) |
| `replay.progress` | all roles |
| `replay.completed` | all roles |
| `rule.changed` | all roles |
| `audit.event` | analyst and admin |
| `config.changed` | analyst and admin |

Detection and incident payloads are built with the shared serialisers in
`sentinelx.events.serialize`, so their core fields match the REST representation.
Stored-record fields such as triage `status` and `reviewed_by` are only available from
the REST API. Events from replays are also published on the stream; their payloads
carry a non-null `replay_id`.

## Prometheus metrics

`GET /api/v1/metrics` returns the Prometheus text exposition format
(`text/plain; version=0.0.4`). Metric names are prefixed `sentinelx_`, for example
`sentinelx_packets_captured_total`.

Access depends on `api.metrics_token` (`API__METRICS_TOKEN`):

| `API__METRICS_TOKEN` | Access |
|---|---|
| empty (default) | Loopback clients only. Others get `403 {"detail": "set API__METRICS_TOKEN to expose metrics to remote scrapers"}`. |
| set | Requests must send `Authorization: Bearer <token>`; otherwise `401 {"detail": "metrics token required"}`. The loopback exception no longer applies. |

The endpoint does not use user accounts, and it counts against the API rate limit.
The client address used for the loopback check honours `api.trusted_proxies`.

Example Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: sentinelx
    metrics_path: /api/v1/metrics
    authorization:
      type: Bearer
      credentials: <API__METRICS_TOKEN value>
    static_configs:
      - targets: ["sentinelx.internal:8000"]
```

`sentinelx metrics --url <base URL> --token <token>` prints key values from a running
server (`--url` defaults to `http://127.0.0.1:8000`, also read from
`SENTINELX_API_URL`; `--token` is also read from `SENTINELX_METRICS_TOKEN`).

The JSON `GET /api/v1/metrics/summary` endpoint is separate and requires the viewer
role.

## Examples

The examples use `jq` to extract fields.

### Log in

```sh
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "Correct-Horse-Battery-2026"}'
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_at": "2026-09-14T22:10:18.818280+00:00",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "is_active": true,
    "must_change_password": false,
    "last_login_at": null,
    "created_at": null
  },
  "csrf_token": null
}
```

Keep the token in a shell variable for the following examples. Avoid putting passwords
on the command line on shared hosts; they are visible in the process list and shell
history.

```sh
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "Correct-Horse-Battery-2026"}' | jq -r .access_token)
```

Refresh (script client):

```sh
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token": "<refresh_token>"}'
```

### List detections

```sh
curl -s -G http://127.0.0.1:8000/api/v1/detections \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'severity=high' --data-urlencode 'severity=critical' \
  --data-urlencode 'since=2026-09-14T00:00:00Z' \
  --data-urlencode 'order=risk' --data-urlencode 'limit=1'
```

A response (captured from a replay of the `tcp_port_scan` scenario, queried with
`replay_id`):

```json
{
  "items": [
    {
      "detection_id": "3f10aced4be34fb2bfde8de860c5bddd",
      "timestamp": "2026-09-14T21:55:50.219835+00:00",
      "detector": "connection_rate",
      "rule_name": null,
      "category": "denial_of_service",
      "severity": "medium",
      "confidence": 0.55,
      "title": "Abnormal connection rate",
      "description": "203.0.113.45 opened 200 connections in 10s.",
      "source_ip": "203.0.113.45",
      "destination_ip": "192.168.10.50",
      "source_port": 44199,
      "destination_port": 294,
      "protocol": "tcp",
      "evidence": [
        {
          "key": "connection_attempts",
          "value": 200,
          "description": "200 new connections in 10s (threshold 200)",
          "threshold": 200,
          "weight": 1.0
        }
      ],
      "recommended_action": "rate_limit",
      "risk": {
        "score": 47.5,
        "band": "medium",
        "contributions": { "severity": 22.5, "confidence": 11.0, "history": 4.0, "correlation": 10.0 },
        "rationale": [
          "+22.5 severity medium (2/4)",
          "+11.0 detector confidence 55%",
          "+4.0 source history: previously triggered rule:rapid_syn_scan, tcp_port_scan",
          "+10.0 correlated with 2 other detector(s) in an open incident"
        ],
        "assessed_at": "2026-09-14T21:55:50.220817+00:00"
      },
      "observation_window_seconds": 10.0,
      "packet_count": 200,
      "tags": ["rate"],
      "incident_id": "df0bc6accabb42539295ff93e5550153",
      "status": "new",
      "reviewed_by": null,
      "reviewed_at": null,
      "replay_id": "fe566b1349144c04ab08aa10f0d7433b"
    }
  ],
  "total": 5,
  "limit": 1,
  "offset": 0
}
```

(The `evidence` array is shortened.)

### Block an address

Preview first (analyst):

```sh
curl -s -X POST http://127.0.0.1:8000/api/v1/firewall/check \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target": "127.0.0.1"}'
```

```json
{
  "target": "127.0.0.1",
  "allowed": false,
  "network": null,
  "reason": "127.0.0.1 is loopback, link-local, multicast or reserved",
  "dry_run": true
}
```

Block (admin). A refusal by the safety guard returns **HTTP 200**:

```sh
curl -s -X POST http://127.0.0.1:8000/api/v1/firewall/block \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target": "127.0.0.1", "reason": "test refusal"}'
```

```json
{
  "decision_id": "428c1ac3f5bb4e3c8d0b281b60ad2860",
  "action": "block_ip",
  "target": "127.0.0.1",
  "reason": "test refusal",
  "outcome": "failed",
  "executed": false,
  "dry_run": true,
  "requires_approval": false,
  "duration_seconds": null,
  "detection_id": null,
  "incident_id": null,
  "error": "safety guard: 127.0.0.1 is loopback, link-local, multicast or reserved",
  "decided_at": "2026-09-14T21:55:20.399671+00:00",
  "http_note": "the request was valid but the action was not carried out; see 'error'"
}
```

A permitted temporary block with `DRY_RUN=true` (the default) is recorded but not
applied:

```sh
curl -s -X POST http://127.0.0.1:8000/api/v1/firewall/block \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target": "203.0.113.50", "reason": "scanner", "duration_seconds": 3600}'
```

```json
{
  "decision_id": "cda84762e7c949faa2b6af3ca6151a8f",
  "action": "temporary_block",
  "target": "203.0.113.50",
  "reason": "scanner [DRY RUN - not applied]",
  "outcome": "simulated",
  "executed": false,
  "dry_run": true,
  "requires_approval": false,
  "duration_seconds": 3600,
  "detection_id": null,
  "incident_id": null,
  "error": null,
  "decided_at": "2026-09-14T21:55:20.409231+00:00"
}
```

A viewer or analyst attempting the same call receives
`403 {"detail": "requires the admin role"}`.

### WebSocket ticket

```sh
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/ws-ticket \
  -H "Authorization: Bearer $TOKEN"
```

```json
{ "ticket": "Ef9WWbh_aiSWOk5qHPuSJfA2mEWIsQAvDwEkqn-9djY", "expires_in": 30 }
```

Then connect with any WebSocket client, for example:

```
ws://127.0.0.1:8000/api/v1/ws/events?ticket=Ef9WWbh_aiSWOk5qHPuSJfA2mEWIsQAvDwEkqn-9djY&types=detection.created
```

### Browser-style session (for testing CSRF handling)

```sh
curl -s -c jar.txt -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' -H 'X-SentinelX-Client: dashboard' \
  -d '{"username": "admin", "password": "Correct-Horse-Battery-2026"}' | jq -r .csrf_token
# state-changing request authenticated by cookie: must echo the CSRF token
curl -s -b jar.txt -X POST http://127.0.0.1:8000/api/v1/auth/ws-ticket \
  -H 'X-CSRF-Token: <csrf_token>'
```

Without the `X-CSRF-Token` header the second request returns
`403 {"detail": "CSRF token missing or invalid"}`. With `ENVIRONMENT=production` the
cookies are `Secure` and curl will only send them over HTTPS.
