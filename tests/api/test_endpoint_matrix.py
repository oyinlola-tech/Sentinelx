"""Endpoint verification matrix.

Every HTTP operation the live application exposes is listed once in ``OPS`` with its
intended access level and a sample request. The tests then check, for every
operation:

* the table matches the routes and their role dependencies (a new route, or a
  changed dependency, fails ``test_policy_table_matches_the_live_routes``);
* unauthenticated callers get 401, except the documented public endpoints;
* each role is allowed or refused exactly as the table says;
* malformed JSON, missing fields, wrong types and oversized strings are 4xx, not 500;
* hostile or non-existent path parameters are 4xx, not 500;
* no response carries a traceback, a server file path, a password hash or a secret.

It also covers pagination and filter validation, rate limiting, a database outage
and the WebSocket stream.

The matrix shares one platform per module (Argon2 logins make a platform per case
too slow); cases that end sessions log in afresh.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute

from sentinelx.api.app import create_app
from sentinelx.common.enums import UserRole
from sentinelx.firewall import MemoryFirewall
from sentinelx.services.platform import Platform
from tests.api.conftest import ADMIN_PASSWORD, REPO_RULES, make_settings

API = "/api/v1"
ROLES = ("viewer", "analyst", "admin")
RANK = {"public": 0, "metrics": 0, "any": 0, "viewer": 1, "analyst": 2, "admin": 3}
PASSWORDS = {
    "admin": ADMIN_PASSWORD,
    "analyst": "Analyst-Matrix-Passphrase-2026",
    "viewer": "Viewer-Matrix-Passphrase-2026",
}
JWT_SECRET = "matrix-jwt-signing-secret-0f3c9a71d2b84e6a"
VALID_RULE = "rule:\n  name: Matrix Rule\n  condition: ttl > 1\n"
NO_BODY: Any = object()

#: Endpoints reachable without a user session, and why that is intended.
PUBLIC_JUSTIFICATION = {
    ("POST", "/auth/login"): "credential exchange",
    ("POST", "/auth/refresh"): "authenticated by the refresh token itself",
    ("GET", "/system/health"): "liveness probe; returns only status and version",
    ("GET", "/metrics"): "own guard: metrics token, or a direct loopback request",
}

#: Authenticated responses allowed to contain absolute server paths.
PATH_DISCLOSURE_ALLOWED = {
    ("GET", "/rules"): "rule source_path, shown by the dashboard's rules page",
    ("GET", "/rules/{rule_id}"): "rule source_path",
    ("GET", "/config"): "effective settings (analyst): pcap_directory, rules_directory",
    ("GET", "/system/status"): "database URL with the password hidden (SQLite file path)",
}


@dataclass(frozen=True)
class Op:
    method: str
    template: str
    access: str
    path: str | None = None
    json: Any = NO_BODY
    content: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    allowed: int = 200
    fresh_session: bool = False
    #: body validation samples (JSON operations only)
    required: bool = True
    wrong_type: dict[str, Any] | None = None
    oversized: dict[str, Any] | None = None
    #: status for invalid bodies when the endpoint parses its own body
    invalid_body_status: int = 422

    @property
    def id(self) -> str:
        return f"{self.method} {self.template}"

    @property
    def concrete(self) -> str:
        return self.path or self.template


OPS: list[Op] = [
    # ------------------------------------------------------------------ auth
    Op(
        "POST",
        "/auth/login",
        "public",
        json={"username": "admin", "password": ADMIN_PASSWORD},
        wrong_type={"username": ["admin"], "password": 5},
        oversized={"username": "u" * 65, "password": "p" * 10},
    ),
    Op(
        "POST",
        "/auth/refresh",
        "public",
        json={},
        allowed=401,
        required=False,
        wrong_type={"refresh_token": 5},
        oversized={"refresh_token": "t" * 20_000},
        invalid_body_status=401,
    ),
    Op("POST", "/auth/logout", "any", allowed=204, fresh_session=True),
    Op("GET", "/auth/me", "any"),
    Op(
        "POST",
        "/auth/change-password",
        "any",
        # A wrong current password reaches the handler (403 from the service, not RBAC).
        json={"current_password": "not-the-current-one", "new_password": "Another-Pass-2026x"},
        allowed=403,
        wrong_type={"current_password": 1, "new_password": 2},
        oversized={"current_password": "c", "new_password": "n" * 257},
    ),
    Op("POST", "/auth/ws-ticket", "any"),
    # ----------------------------------------------------------------- users
    Op("GET", "/users", "admin"),
    Op(
        "POST",
        "/users",
        "admin",
        json={"username": "matrix-created", "password": "Created-Passphrase-2026", "role": "viewer"},
        allowed=201,
        wrong_type={"username": "valid-name", "password": "Created-Pass-2026", "role": "root"},
        oversized={"username": "u" * 65, "password": "Created-Pass-2026"},
    ),
    Op(
        "PATCH",
        "/users/{user_id}",
        "admin",
        path="/users/999999",
        json={"is_active": True},
        allowed=404,
        required=False,
        wrong_type={"is_active": "perhaps", "role": 7},
    ),
    Op(
        "POST",
        "/users/{user_id}/reset-password",
        "admin",
        path="/users/999999/reset-password",
        json={"new_password": "Reset-Passphrase-2026"},
        allowed=404,
        wrong_type={"new_password": ["x"]},
        oversized={"new_password": "n" * 257},
    ),
    Op("DELETE", "/users/{user_id}", "admin", path="/users/999999", allowed=404),
    # ---------------------------------------------------------------- system
    Op("GET", "/system/health", "public"),
    Op("GET", "/system/status", "viewer"),
    Op("GET", "/system/capabilities", "viewer"),
    Op("GET", "/sensors", "viewer"),
    Op("GET", "/interfaces", "viewer"),
    Op(
        "POST",
        "/sensors/start",
        "admin",
        json={"interface": "sxmatrix0"},
        allowed=404,
        required=False,  # {} would start capture on the default interface; never sent
        wrong_type={"interface": 5},
        oversized={"interface": "i" * 33},
    ),
    Op("POST", "/sensors/stop", "admin"),
    Op("GET", "/metrics", "metrics"),
    Op("GET", "/metrics/summary", "viewer"),
    Op("GET", "/audit", "analyst"),
    # ------------------------------------------------------------ detections
    Op("GET", "/detections", "viewer"),
    Op(
        "GET",
        "/detections/{detection_id}",
        "viewer",
        path="/detections/does-not-exist",
        allowed=404,
    ),
    Op(
        "PATCH",
        "/detections/{detection_id}",
        "analyst",
        path="/detections/does-not-exist",
        json={"status": "acknowledged"},
        allowed=404,
        wrong_type={"status": "deleted"},
    ),
    Op("GET", "/incidents", "viewer"),
    Op("GET", "/incidents/{incident_id}", "viewer", path="/incidents/does-not-exist", allowed=404),
    Op(
        "PATCH",
        "/incidents/{incident_id}",
        "analyst",
        path="/incidents/does-not-exist",
        json={"status": "investigating"},
        allowed=404,
        wrong_type={"status": 3},
        oversized={"notes": "n" * 10_001, "assigned_to": "a" * 65},
    ),
    Op("GET", "/alerts", "viewer"),
    Op("GET", "/threats", "viewer"),
    # -------------------------------------------------------------- firewall
    Op("GET", "/firewall", "viewer"),
    Op("GET", "/firewall/blocked", "viewer"),
    Op("GET", "/firewall/actions", "viewer"),
    Op(
        "POST",
        "/firewall/check",
        "analyst",
        json={"target": "203.0.113.7"},
        wrong_type={"target": ["203.0.113.7"]},
        oversized={"target": "1" * 65},
    ),
    Op(
        "POST",
        "/firewall/block",
        "admin",
        json={"target": "203.0.113.50", "reason": "matrix test"},
        wrong_type={"target": "203.0.113.50", "reason": "matrix", "duration_seconds": "long"},
        oversized={"target": "203.0.113.50", "reason": "r" * 501},
    ),
    Op(
        "POST",
        "/firewall/unblock",
        "admin",
        json={"target": "203.0.113.50", "reason": "matrix test"},
        wrong_type={"target": 203, "reason": "matrix"},
        oversized={"target": "t" * 65, "reason": "matrix"},
    ),
    Op("GET", "/firewall/approvals", "viewer"),
    Op(
        "POST",
        "/firewall/approvals/{action_id}/approve",
        "admin",
        path="/firewall/approvals/does-not-exist/approve",
        allowed=404,
    ),
    Op(
        "POST",
        "/firewall/approvals/{action_id}/reject",
        "admin",
        path="/firewall/approvals/does-not-exist/reject",
        json={"reason": "matrix"},
        allowed=404,
        required=False,
        wrong_type={"reason": 5},
        oversized={"reason": "r" * 501},
    ),
    Op("GET", "/firewall/allowlist", "viewer"),
    Op(
        "PUT",
        "/firewall/allowlist",
        "admin",
        json={"networks": ["198.51.100.0/24"]},
        wrong_type={"networks": "198.51.100.0/24"},
        oversized={"networks": ["198.51.100.0/24"] * 1001},
    ),
    # ----------------------------------------------------------------- rules
    Op("GET", "/rules", "viewer"),
    Op("GET", "/rules/fields", "viewer"),
    Op("GET", "/rules/{rule_id}", "viewer", path="/rules/ssh_brute_force"),
    Op(
        "POST",
        "/rules/validate",
        "analyst",
        json={"definition": VALID_RULE},
        wrong_type={"definition": 42},
        oversized={"definition": "d" * 20_001},
    ),
    Op(
        "POST",
        "/rules/test",
        "analyst",
        json={"definition": VALID_RULE, "scenario": "normal_traffic"},
        wrong_type={"definition": VALID_RULE, "scenario": ["normal_traffic"]},
        oversized={"definition": VALID_RULE, "pcap_path": "p" * 513},
    ),
    Op(
        "POST",
        "/rules",
        "admin",
        json={"definition": VALID_RULE},
        allowed=201,
        wrong_type={"definition": {"rule": 1}},
        oversized={"definition": "d" * 20_001},
    ),
    Op(
        "PUT",
        "/rules/{rule_id}",
        "admin",
        path="/rules/no_such_rule",
        json={"definition": VALID_RULE},
        allowed=404,
        wrong_type={"definition": 42},
        oversized={"definition": "d" * 20_001},
    ),
    Op(
        "PATCH",
        "/rules/{rule_id}/enabled",
        "admin",
        path="/rules/no_such_rule/enabled",
        json={"enabled": False},
        allowed=404,
        wrong_type={"enabled": "perhaps"},
    ),
    Op("DELETE", "/rules/{rule_id}", "admin", path="/rules/no_such_rule", allowed=404),
    Op("GET", "/detectors", "viewer"),
    Op(
        "PATCH",
        "/detectors/{name}/enabled",
        "admin",
        path="/detectors/no_such_detector/enabled",
        json={"enabled": True},
        allowed=404,
        wrong_type={"enabled": [True]},
    ),
    # ---------------------------------------------------------- config/stats
    Op("GET", "/config", "analyst"),
    Op(
        "PATCH",
        "/config/{section}",
        "admin",
        path="/config/detection",
        json={"changes": {"port_scan_unique_ports": 30}},
        wrong_type={"changes": ["port_scan_unique_ports"]},
        oversized={"changes": {"port_scan_unique_ports": 30}, "confirmation": "c" * 65},
    ),
    Op("GET", "/stats/overview", "viewer"),
    Op("GET", "/stats/network", "viewer"),
    Op("GET", "/stats/analytics", "viewer"),
    # ---------------------------------------------------------------- replay
    Op("GET", "/replay/files", "viewer"),
    Op("GET", "/replay/files/inspect", "viewer", params={"path": "missing.pcap"}, allowed=422),
    Op(
        "POST",
        "/replay/upload",
        "analyst",
        content=b"definitely not a capture file",
        headers={"content-type": "application/octet-stream"},
        allowed=422,
    ),
    Op("GET", "/replay/scenarios", "viewer"),
    Op(
        "POST",
        "/replay/scenarios/{name}",
        "analyst",
        path="/replay/scenarios/normal_traffic",
        json={"params": {}},
        allowed=201,
        required=False,
        wrong_type={"params": {"packet_count": [1]}},
        oversized={"params": {f"p{i}": 1 for i in range(11)}},
    ),
    Op(
        "POST",
        "/replay",
        "analyst",
        json={"path": "missing.pcap"},
        allowed=422,
        wrong_type={"path": "missing.pcap", "speed": "fast"},
        oversized={"path": "p" * 513},
    ),
    Op("GET", "/replay", "viewer"),
    Op("GET", "/replay/{replay_id}", "viewer", path="/replay/does-not-exist", allowed=404),
    Op(
        "POST",
        "/replay/{replay_id}/cancel",
        "analyst",
        path="/replay/does-not-exist/cancel",
        allowed=409,  # documented: 409 when the replay is not running
    ),
]

JSON_OPS = [op for op in OPS if op.json is not NO_BODY]
TEMPLATED_OPS = [op for op in OPS if "{" in op.template]


# ------------------------------------------------------------------ helpers


@dataclass
class Env:
    platform: Platform
    app: FastAPI
    client: httpx.AsyncClient
    headers: dict[str, dict[str, str]]
    tmp: Path

    async def login(self, role: str) -> dict[str, str]:
        username = "admin" if role == "admin" else f"{role}1"
        response = await self.client.post(
            "/auth/login", json={"username": username, "password": PASSWORDS[role]}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def call(
        self,
        op: Op,
        headers: dict[str, str],
        *,
        path: str | None = None,
        body: Any = NO_BODY,
        content: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        kwargs: dict[str, Any] = {
            "headers": {**op.headers, **headers, **(extra_headers or {})},
            "params": op.params,
        }
        payload = op.json if body is NO_BODY else body
        if content is not None:
            kwargs["content"] = content
        elif op.content is not None:
            kwargs["content"] = op.content
        elif payload is not NO_BODY:
            kwargs["json"] = payload
        return await self.client.request(op.method, path or op.concrete, **kwargs)


def server_secrets(env_tmp: Path, platform: Platform) -> list[str]:
    return [
        platform.settings.api.jwt_secret,
        *PASSWORDS.values(),
        "$argon2",
        "password_hash",
    ]


def assert_clean(
    response: httpx.Response, platform: Platform, tmp: Path, op: Op | None = None
) -> None:
    """No traceback, server path, hash or secret in a response body."""
    text = response.text
    context = f"{op.id if op else ''} -> {response.status_code}: {text[:300]}"
    assert response.status_code < 500 or response.status_code == 503, context
    assert "Traceback" not in text and 'File "/' not in text, context
    for secret in server_secrets(tmp, platform):
        assert secret not in text, f"secret {secret[:6]}... leaked: {context}"
    disclosure_ok = op is not None and (op.method, op.template) in PATH_DISCLOSURE_ALLOWED
    if not disclosure_ok or response.status_code >= 400:
        for server_path in (str(tmp), str(REPO_RULES.parent), "site-packages", "dist-packages"):
            assert server_path not in text, f"server path leaked: {context}"


def derived_access(route: APIRoute) -> str:
    names = {dependency.call.__name__ for dependency in route.dependant.dependencies}
    for role in ("admin", "analyst", "viewer"):
        if f"require_{role}" in names:
            return role
    return "any" if "current_principal" in names else "public"


@asynccontextmanager
async def build_env(tmp: Path, **api: Any) -> AsyncIterator[Env]:
    settings = make_settings(tmp, jwt_secret=JWT_SECRET, **api)
    platform = Platform(settings, firewall=MemoryFirewall())
    await platform.start()
    if platform.pipeline is None:
        raise RuntimeError("platform failed to start")
    platform.pipeline.response.guard._local_addresses = lambda: set()
    app = create_app(platform.settings, platform=platform)
    # raise_app_exceptions=False: a server error must be observed as a 500 response.
    transport = httpx.ASGITransport(
        app=app, client=("127.0.0.1", 50000), raise_app_exceptions=False
    )
    try:
        async with httpx.AsyncClient(transport=transport, base_url=f"http://testserver{API}") as http:
            env = Env(platform, app, http, {}, tmp)
            for role in (UserRole.ANALYST, UserRole.VIEWER):
                await platform.auth.create_user(f"{role.value}1", PASSWORDS[role.value], role)
            for role in ROLES:
                env.headers[role] = await env.login(role)
            yield env
    finally:
        await platform.stop()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Env]:
    async with build_env(tmp_path_factory.mktemp("matrix")) as instance:
        yield instance


@pytest_asyncio.fixture
async def solo(tmp_path: Path) -> AsyncIterator[Env]:
    """A private platform for tests that change limits or break the database."""
    async with build_env(tmp_path) as instance:
        yield instance


# ------------------------------------------------------------ policy table


def test_policy_table_matches_the_live_routes(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, jwt_secret=JWT_SECRET))
    live: dict[tuple[str, str], str] = {}
    websockets: list[str] = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            assert route.path.startswith(API), route.path
            for method in route.methods:
                live[(method, route.path.removeprefix(API))] = derived_access(route)
        elif isinstance(route, APIWebSocketRoute):
            websockets.append(route.path)
    table = {(op.method, op.template): op.access for op in OPS}
    assert len(table) == len(OPS), "duplicate operation in OPS"
    assert set(live) == set(table), {
        "routes missing from the table": sorted(set(live) - set(table)),
        "table entries with no route": sorted(set(table) - set(live)),
    }
    mismatched = {
        key: {"route dependency": live[key], "table": access}
        for key, access in table.items()
        if live[key] != ("public" if access == "metrics" else access)
    }
    assert not mismatched
    public = {key for key, access in table.items() if access in ("public", "metrics")}
    assert public == set(PUBLIC_JUSTIFICATION)
    assert websockets == [f"{API}/ws/events"]


@pytest.mark.asyncio(loop_scope="module")
class TestMatrix:
    # ---------------------------------------------------- (a) authentication

    @pytest.mark.parametrize("op", OPS, ids=lambda op: op.id)
    async def test_unauthenticated(self, env: Env, op: Op) -> None:
        response = await env.call(op, {})
        assert_clean(response, env.platform, env.tmp, op)
        if op.access in ("any", "viewer", "analyst", "admin"):
            assert response.status_code == 401, response.text
            assert response.json() == {"detail": "authentication required"}
            assert response.headers.get("www-authenticate") == "Bearer"
            # A garbage token and a body-less request are refused the same way.
            garbage = await env.call(op, {"Authorization": "Bearer not.a.token"})
            assert garbage.status_code == 401 and garbage.json() == {"detail": "invalid token"}
            if op.json is not NO_BODY or op.content is not None:
                bare = await env.client.request(op.method, op.concrete, params=op.params)
                assert bare.status_code == 401, bare.text
        elif op.access == "metrics":
            assert response.status_code == 200  # direct loopback scrape
            proxied = await env.call(op, {}, extra_headers={"X-Forwarded-For": "203.0.113.9"})
            assert proxied.status_code == 403
        else:
            assert (op.method, op.template) in PUBLIC_JUSTIFICATION
            assert response.status_code == op.allowed, response.text
            if op.template == "/system/health":
                assert set(response.json()) == {"status", "version"}

    # ------------------------------------------------------ (b) roles

    @pytest.mark.parametrize("op", OPS, ids=lambda op: op.id)
    async def test_role_policy(self, env: Env, op: Op) -> None:
        for role in ROLES:
            headers = await env.login(role) if op.fresh_session else env.headers[role]
            response = await env.call(op, headers)
            assert_clean(response, env.platform, env.tmp, op)
            outcome = f"{role} {op.id}: {response.status_code} {response.text[:200]}"
            if RANK[role] >= RANK[op.access]:
                assert response.status_code == op.allowed, outcome
                if response.status_code == 403:
                    assert not response.json()["detail"].startswith("requires the"), outcome
            else:
                assert response.status_code == 403, outcome
                assert response.json() == {"detail": f"requires the {op.access} role"}, outcome

    # ------------------------------------------------ (c) request validation

    @pytest.mark.parametrize("op", JSON_OPS, ids=lambda op: op.id)
    async def test_invalid_bodies_are_rejected_cleanly(self, env: Env, op: Op) -> None:
        headers = env.headers["admin"]
        json_type = {"content-type": "application/json"}
        cases: list[tuple[str, dict[str, Any], int]] = [
            ("malformed", {"content": b'{"unterminated": ', "extra_headers": json_type}, 422),
            ("not utf-8", {"content": b"\xff\xfe\xfd", "extra_headers": json_type}, 422),
            ("array", {"body": []}, op.invalid_body_status),
            ("scalar", {"body": "just a string"}, op.invalid_body_status),
        ]
        if isinstance(op.json, dict) and op.template != "/auth/refresh":
            cases.append(("unknown field", {"body": {**op.json, "exec": "id"}}, 422))
        if op.required:
            cases.append(("missing required", {"body": {}}, 422))
        if op.wrong_type is not None:
            cases.append(("wrong type", {"body": op.wrong_type}, op.invalid_body_status))
        if op.oversized is not None:
            cases.append(("oversized", {"body": op.oversized}, op.invalid_body_status))
        for label, kwargs, expected in cases:
            response = await env.call(op, headers, **kwargs)
            assert_clean(response, env.platform, env.tmp, op)
            assert response.status_code == expected, f"{label}: {response.text[:300]}"

    async def test_upload_body_checks(self, env: Env) -> None:
        headers = env.headers["analyst"]
        wrong_type = await env.client.post(
            "/replay/upload", headers={**headers, "content-type": "text/plain"}, content=b"x"
        )
        assert wrong_type.status_code == 415
        multipart = await env.client.post(
            "/replay/upload", headers=headers, files={"file": ("a.pcap", b"\xd4\xc3\xb2\xa1")}
        )
        assert multipart.status_code == 415
        bad_length = await env.client.post(
            "/replay/upload",
            headers={**headers, "content-type": "application/octet-stream", "content-length": "1e9"},
            content=b"",
        )
        assert bad_length.status_code == 400
        too_large = await env.client.post(
            "/replay/upload",
            headers={
                **headers,
                "content-type": "application/octet-stream",
                "content-length": str(10**12),
            },
            content=b"",
        )
        assert too_large.status_code == 413
        long_name = await env.client.post(
            "/replay/upload",
            params={"filename": "f" * 201},
            headers={**headers, "content-type": "application/octet-stream"},
            content=b"x",
        )
        assert long_name.status_code == 422
        for response in (wrong_type, multipart, bad_length, too_large, long_name):
            assert_clean(response, env.platform, env.tmp)

    # --------------------------------------------------- (d) path parameters

    @pytest.mark.parametrize("op", TEMPLATED_OPS, ids=lambda op: op.id)
    async def test_hostile_and_unknown_path_parameters(self, env: Env, op: Op) -> None:
        headers = env.headers["admin"]
        if "{user_id}" in op.template:
            values = {"0": 422, "-1": 422, "abc": 422, "1.5": 422, "2147483648": 422}
            values |= {"999999": 404, "9" * 40: 422}
        else:
            values = {"does-not-exist-anywhere": op.allowed if op.allowed != 200 else 404}
            values |= {"z" * 2048: None, "%00": None, "..%2F..%2Fetc%2Fpasswd": None}
            values |= {"%F0%9F%92%A5": None, "' OR 1=1 --": None}
        body = op.json if op.json is not NO_BODY else NO_BODY
        if op.template == "/config/{section}":
            body = {"changes": {"anything": 1}}
            values["does-not-exist-anywhere"] = 422  # documented: section not editable
        for value, expected in values.items():
            path = re.sub(r"\{[^}]+\}", value, op.template)
            response = await env.call(op, headers, path=path, body=body)
            assert_clean(response, env.platform, env.tmp, op)
            outcome = f"{op.method} {path[:80]}: {response.status_code} {response.text[:200]}"
            if expected is not None:
                assert response.status_code == expected, outcome
            else:
                assert response.status_code in (404, 405, 409, 422), outcome

    # ----------------------------------------------- pagination and filters

    @pytest.mark.parametrize(
        ("path", "maximum"),
        [("/detections", 500), ("/incidents", 500), ("/audit", 500), ("/firewall/actions", 500)],
    )
    async def test_pagination_bounds(self, env: Env, path: str, maximum: int) -> None:
        headers = env.headers["admin"]
        for params in (
            {"limit": 0},
            {"limit": maximum + 1},
            {"limit": -1},
            {"limit": "ten"},
            {"offset": -1},
            {"offset": 1_000_001},
            {"offset": "1e3"},
        ):
            response = await env.client.get(path, headers=headers, params=params)
            assert response.status_code == 422, (params, response.text)
            assert_clean(response, env.platform, env.tmp)
        edge = await env.client.get(
            path, headers=headers, params={"limit": maximum, "offset": 1_000_000}
        )
        assert edge.status_code == 200
        body = edge.json()
        assert body["items"] == [] and body["limit"] == maximum and body["offset"] == 1_000_000
        assert isinstance(body["total"], int) and body["total"] >= 0

    @pytest.mark.parametrize(
        ("path", "params"),
        [
            ("/detections", {"severity": "apocalyptic"}),
            ("/detections", {"category": "mischief"}),
            ("/detections", {"status": "deleted"}),
            ("/detections", {"order": "random"}),
            ("/detections", {"since": "yesterday"}),
            ("/detections", {"until": "2026-13-45T00:00:00Z"}),
            ("/detections", {"min_risk": 101}),
            ("/detections", {"min_risk": "high"}),
            ("/detections", {"q": "q" * 201}),
            ("/detections", {"source_ip": "s" * 65}),
            ("/detections", [("detector", f"d{i}") for i in range(51)]),
            ("/incidents", {"status": "closed-ish"}),
            ("/incidents", {"severity": "loud"}),
            ("/incidents", {"since": "not-a-date"}),
            ("/audit", {"since": "not-a-date"}),
            ("/audit", {"target": "t" * 513}),
            ("/firewall/actions", [("outcome", f"o{i}") for i in range(11)]),
            ("/firewall/actions", {"include_alerts": "sometimes"}),
            ("/alerts", {"hours": 0}),
            ("/alerts", {"hours": 721}),
            ("/threats", {"limit": 501}),
            ("/stats/analytics", {"hours": 24 * 90 + 1}),
            ("/replay", {"limit": 201}),
            ("/replay/files/inspect", {"path": ""}),
            ("/replay/files/inspect", {"path": "p" * 513}),
        ],
    )
    async def test_filter_parameters_are_validated(
        self, env: Env, path: str, params: Any
    ) -> None:
        response = await env.client.get(path, headers=env.headers["admin"], params=params)
        assert response.status_code == 422, response.text
        assert_clean(response, env.platform, env.tmp)

    async def test_pages_add_up_to_the_total(self, env: Env) -> None:
        headers = env.headers["admin"]
        platform = env.platform
        for index in range(5):
            blocked = await env.client.post(
                "/firewall/block",
                headers=headers,
                json={"target": f"203.0.113.{120 + index}", "reason": "pagination"},
            )
            assert blocked.status_code == 200
        generated = await env.client.post(
            "/replay/scenarios/mixed_intrusion", headers=headers, json={}
        )
        replay = (
            await env.client.post("/replay", headers=headers, json={"path": generated.json()["path"]})
        ).json()
        assert platform.replay is not None
        await platform.replay.wait(replay["replay_id"])

        async def walk(path: str, params: dict[str, Any], key: str) -> None:
            deadline = time.monotonic() + 15
            while True:  # response actions are written by the persister
                first = (await env.client.get(path, headers=headers, params=params)).json()
                if first["total"] >= 3 or time.monotonic() > deadline:
                    break
                await asyncio.sleep(0.05)
            total, seen, offset = first["total"], [], 0
            assert total >= 3, (path, first)
            while offset < total:
                page = (
                    await env.client.get(
                        path, headers=headers, params={**params, "limit": 2, "offset": offset}
                    )
                ).json()
                assert page["total"] == total and page["limit"] == 2 and page["offset"] == offset
                assert len(page["items"]) == min(2, total - offset)
                seen.extend(item[key] for item in page["items"])
                offset += 2
            assert len(seen) == total and len(set(seen)) == total, path

        scoped = {"replay_id": replay["replay_id"]}
        await walk("/audit", {}, "id")
        await walk("/firewall/actions", {}, "id")
        await walk("/detections", scoped, "detection_id")
        # A filter narrows the total, and every returned item satisfies it.
        logins = (await env.client.get("/audit", headers=headers, params={"action": "LOGIN"})).json()
        assert logins["total"] >= 3 and all(i["action"] == "LOGIN" for i in logins["items"])
        everything = (await env.client.get("/detections", headers=headers, params=scoped)).json()
        for severity in {d["severity"] for d in everything["items"]}:
            narrowed = (
                await env.client.get(
                    "/detections", headers=headers, params={**scoped, "severity": severity}
                )
            ).json()
            assert 0 < narrowed["total"] <= everything["total"]
            assert all(d["severity"] == severity for d in narrowed["items"])
        incidents = (await env.client.get("/incidents", headers=headers, params=scoped)).json()
        assert incidents["total"] == len(incidents["items"]) == 1


# ------------------------------------------------------------ rate limiting


async def test_api_rate_limit_returns_429_with_retry_after(solo: Env) -> None:
    solo.platform.settings.api.rate_limit_requests = 5
    solo.platform.settings.api.rate_limit_window_seconds = 60
    await solo.platform.state.reset("api", "127.0.0.1")
    allowed = await solo.client.get("/detections")
    assert allowed.status_code == 401 and allowed.headers["x-ratelimit-remaining"] == "4"
    codes = [(await solo.client.get("/detections")).status_code for _ in range(6)]
    assert codes == [401] * 4 + [429] * 2
    limited = await solo.client.get("/auth/me", headers=solo.headers["admin"])
    assert limited.status_code == 429 and limited.json() == {"detail": "rate limit exceeded"}
    assert 1 <= int(limited.headers["retry-after"]) <= 60
    # The liveness probe is exempt, so an orchestrator never sees a throttled probe.
    assert (await solo.client.get("/system/health")).status_code == 200
    # Limits are per client address.
    transport = httpx.ASGITransport(app=solo.app, client=("192.0.2.77", 50000))
    async with httpx.AsyncClient(transport=transport, base_url=f"http://testserver{API}") as other:
        assert (await other.get("/detections")).status_code == 401


async def test_login_throttle_returns_429_with_retry_after(solo: Env) -> None:
    settings = solo.platform.settings.api
    settings.login_rate_limit_attempts = 3
    await solo.platform.state.reset("login", "127.0.0.1")
    # Distinct usernames, so the per-account lockout (423) is not what trips.
    for index in range(3):
        failed = await solo.client.post(
            "/auth/login", json={"username": f"nobody{index}", "password": "wrong-password-1"}
        )
        assert failed.status_code == 401
    throttled = await solo.client.post(
        "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    assert throttled.status_code == 429
    assert throttled.json() == {"detail": "too many login attempts; try again later"}
    assert 1 <= int(throttled.headers["retry-after"]) <= settings.login_rate_limit_window_seconds


# --------------------------------------------------------- database outage


@contextmanager
def database_unavailable(platform: Platform, tmp: Path) -> Iterator[None]:
    """Point the platform at a database file that cannot be opened, then restore it.

    Every session and health check then fails inside SQLAlchemy with
    ``OperationalError``, exactly as when the database server goes away.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    database = platform.database
    engine, sessions = database._engine, database._sessions
    broken = create_async_engine(f"sqlite+aiosqlite:///{tmp}/no-such-directory/secret-db.sqlite")
    database._engine, database._sessions = broken, async_sessionmaker(broken)
    platform._health_cache = None  # health is cached for 3 seconds
    try:
        yield
    finally:
        database._engine, database._sessions = engine, sessions
        platform._health_cache = None


def assert_incident_body(response: httpx.Response, status: int, detail: str) -> None:
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"detail", "error_id"} and body["detail"] == detail
    assert re.fullmatch(r"[0-9a-f]{12}", body["error_id"])
    for leak in ("OperationalError", "sqlite", "secret-db", "no-such-directory", "Traceback"):
        assert leak not in response.text


async def test_database_outage_is_a_clean_503_and_recovers(solo: Env) -> None:
    client, platform = solo.client, solo.platform
    admin = solo.headers["admin"]
    protected = [op for op in OPS if op.access in ("any", "viewer", "analyst", "admin")]
    with database_unavailable(platform, solo.tmp):
        health = await client.get("/system/health")
        assert health.status_code == 200 and health.json()["status"] == "error"
        assert set(health.json()) == {"status", "version"}
        for op in protected:
            if op.fresh_session:
                continue
            response = await solo.call(op, admin)
            assert_clean(response, platform, solo.tmp, op)
            assert_incident_body(response, 503, "storage unavailable")
        login = await client.post(
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert_incident_body(login, 503, "storage unavailable")
    # The engine is back: health recovers and the same session keeps working.
    recovered = await client.get("/system/health")
    assert recovered.json()["status"] != "error"
    assert (await client.get("/auth/me", headers=admin)).status_code == 200
    assert (await client.get("/detections", headers=admin)).status_code == 200


async def test_database_error_inside_a_handler_is_503_without_detail(
    solo: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.exc import OperationalError

    assert solo.platform.queries is not None

    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise OperationalError(
            "SELECT * FROM detections", {}, Exception("could not connect to db.internal:5432")
        )

    monkeypatch.setattr(solo.platform.queries, "detections", fail)
    response = await solo.client.get("/detections", headers=solo.headers["viewer"])
    assert_incident_body(response, 503, "storage unavailable")
    assert "db.internal" not in response.text and "SELECT" not in response.text


async def test_unexpected_error_is_a_generic_500(
    solo: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert solo.platform.queries is not None

    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(f"boom in {solo.tmp} with secret {JWT_SECRET}")

    monkeypatch.setattr(solo.platform.queries, "incidents", fail)
    response = await solo.client.get("/incidents", headers=solo.headers["viewer"])
    assert_incident_body(response, 500, "internal error")
    assert_clean(response, solo.platform, solo.tmp)


# ----------------------------------------------------------------- WebSocket


def _ws_app(tmp_path: Path) -> FastAPI:
    return create_app(make_settings(tmp_path, jwt_secret=JWT_SECRET))


def _next_event(ws: Any) -> dict[str, Any]:
    while (message := ws.receive_json())["type"] == "ping":
        pass
    return message  # type: ignore[no-any-return]


class _WsUsers:
    def __init__(self, http: Any) -> None:
        self.http = http
        self.platform: Platform = http.app.state.platform
        for role in (UserRole.ANALYST, UserRole.VIEWER):
            http.portal.call(
                self.platform.auth.create_user, f"{role.value}1", PASSWORDS[role.value], role
            )
        self.headers = {}
        for role in ROLES:
            username = "admin" if role == "admin" else f"{role}1"
            token = http.post(
                f"{API}/auth/login", json={"username": username, "password": PASSWORDS[role]}
            ).json()["access_token"]
            self.headers[role] = {"Authorization": f"Bearer {token}"}

    def ticket(self, role: str) -> str:
        response = self.http.post(f"{API}/auth/ws-ticket", headers=self.headers[role])
        assert response.status_code == 200
        return str(response.json()["ticket"])

    def url(self, role: str, **params: str) -> str:
        query = "&".join(f"{k}={v}" for k, v in {"ticket": self.ticket(role), **params}.items())
        return f"{API}/ws/events?{query}"


def _close_code(http: Any, url: str, **kwargs: Any) -> int:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as closed, http.websocket_connect(url, **kwargs) as ws:
        ws.receive_json()
    return int(closed.value.code)


def test_websocket_refusals(tmp_path: Path) -> None:
    from starlette.testclient import TestClient

    with TestClient(_ws_app(tmp_path)) as http:
        users = _WsUsers(http)
        assert _close_code(http, f"{API}/ws/events") == 4401
        assert _close_code(http, f"{API}/ws/events?ticket=forged-ticket") == 4401
        assert _close_code(http, f"{API}/ws/events?ticket={'t' * 129}") == 4401
        # An access token is not a ticket.
        token = users.headers["admin"]["Authorization"].removeprefix("Bearer ")
        assert _close_code(http, f"{API}/ws/events?ticket={token}") == 4401
        evil = {"origin": "https://evil.example"}
        assert _close_code(http, users.url("admin"), headers=evil) == 1008
        assert _close_code(http, users.url("admin", types="no.such.type")) == 1008
        # An expired ticket (30 second lifetime) is refused.
        stale = users.ticket("admin")
        state = users.platform.state
        real_clock = state._clock
        state._clock = lambda: real_clock() + 31
        try:
            assert _close_code(http, f"{API}/ws/events?ticket={stale}") == 4401
        finally:
            state._clock = real_clock
        # Allowed origins: the configured dashboard origin and the API's own host.
        for origin in ("http://localhost:3000", "http://testserver"):
            with http.websocket_connect(users.url("viewer"), headers={"origin": origin}) as ws:
                assert ws.receive_json()["type"] == "hello"


def test_websocket_fan_out_role_filtering_and_reconnect(tmp_path: Path) -> None:
    from starlette.testclient import TestClient

    from sentinelx.events.bus import EventType

    with TestClient(_ws_app(tmp_path)) as http:
        users = _WsUsers(http)
        bus = users.platform.bus
        tickets = {role: users.url(role) for role in ROLES}
        with (
            http.websocket_connect(tickets["admin"]) as admin_ws,
            http.websocket_connect(users.url("admin")) as admin_ws2,
            http.websocket_connect(tickets["analyst"]) as analyst_ws,
            http.websocket_connect(tickets["viewer"]) as viewer_ws,
        ):
            sockets = {"admin": admin_ws, "admin2": admin_ws2, "analyst": analyst_ws}
            sockets["viewer"] = viewer_ws
            hellos = {name: ws.receive_json() for name, ws in sockets.items()}
            assert "audit.event" not in hellos["viewer"]["payload"]["subscribed"]
            assert "config.changed" not in hellos["viewer"]["payload"]["subscribed"]
            assert "audit.event" in hellos["analyst"]["payload"]["subscribed"]

            http.portal.call(bus.publish, EventType.DETECTION_CREATED, {"detection_id": "d-1"})
            first = {name: _next_event(ws) for name, ws in sockets.items()}
            assert {m["type"] for m in first.values()} == {"detection.created"}
            assert len({m["id"] for m in first.values()}) == 1  # the same event everywhere

            http.portal.call(bus.publish, EventType.AUDIT_EVENT, {"action": "LOGIN"})
            http.portal.call(bus.publish, EventType.CONFIG_CHANGED, {"section": "response"})
            http.portal.call(bus.publish, EventType.DETECTION_CREATED, {"detection_id": "d-2"})
            for name in ("admin", "admin2", "analyst"):
                received = [_next_event(sockets[name])["type"] for _ in range(3)]
                assert received == ["audit.event", "config.changed", "detection.created"]
            after = _next_event(viewer_ws)
            assert after["type"] == "detection.created"
            assert after["payload"]["detection_id"] == "d-2"

        # Reconnect after a disconnect: a new ticket works, the old one does not.
        reused = tickets["viewer"]
        assert _close_code(http, reused) == 4401
        with http.websocket_connect(users.url("viewer")) as ws:
            assert ws.receive_json()["type"] == "hello"
            http.portal.call(bus.publish, EventType.INCIDENT_OPENED, {"incident_id": "i-1"})
            assert _next_event(ws)["payload"] == {"incident_id": "i-1"}


def test_websocket_viewer_cannot_subscribe_to_analyst_only_events(tmp_path: Path) -> None:
    """Regression: requesting only analyst-only types left an empty filter, and the bus
    treats an empty filter as "everything", so a viewer received audit events."""
    from starlette.testclient import TestClient

    from sentinelx.events.bus import EventType

    with TestClient(_ws_app(tmp_path)) as http:
        users = _WsUsers(http)
        bus = users.platform.bus
        assert _close_code(http, users.url("viewer", types="audit.event,config.changed")) == 1008
        mixed = users.url("viewer", types="audit.event,detection.created")
        with http.websocket_connect(mixed) as ws:
            assert ws.receive_json()["payload"]["subscribed"] == ["detection.created"]
            http.portal.call(bus.publish, EventType.AUDIT_EVENT, {"action": "secret"})
            http.portal.call(bus.publish, EventType.DETECTION_CREATED, {"detection_id": "d"})
            assert _next_event(ws)["type"] == "detection.created"
        with http.websocket_connect(users.url("analyst", types="audit.event")) as ws:
            assert ws.receive_json()["payload"]["subscribed"] == ["audit.event"]
            http.portal.call(bus.publish, EventType.AUDIT_EVENT, {"action": "visible"})
            assert _next_event(ws)["payload"] == {"action": "visible"}


def test_websocket_per_user_connection_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from starlette.testclient import TestClient

    import sentinelx.api.websocket as ws_module

    assert ws_module._MAX_CONNECTIONS_PER_USER == 10  # documented limit
    monkeypatch.setattr(ws_module, "_MAX_CONNECTIONS_PER_USER", 3)
    with TestClient(_ws_app(tmp_path)) as http:
        users = _WsUsers(http)
        with (
            http.websocket_connect(users.url("analyst")) as one,
            http.websocket_connect(users.url("analyst")) as two,
        ):
            with http.websocket_connect(users.url("analyst")) as three:
                for ws in (one, two, three):
                    assert ws.receive_json()["type"] == "hello"
                assert _close_code(http, users.url("analyst")) == 4429
                # Another user is unaffected by this user's streams.
                with http.websocket_connect(users.url("viewer")) as viewer:
                    assert viewer.receive_json()["type"] == "hello"
            # Closing a stream frees its slot.
            deadline = time.monotonic() + 5
            while ws_module._connections.get("analyst1", 0) >= 3 and time.monotonic() < deadline:
                time.sleep(0.01)
            with http.websocket_connect(users.url("analyst")) as again:
                assert again.receive_json()["type"] == "hello"
    assert "analyst1" not in ws_module._connections
