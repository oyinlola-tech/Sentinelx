"""Authentication and authorisation matrix.

Login and lockout, disabled accounts, forced password changes, token expiry and
forgery, refresh rotation, logout, cookie sessions with CSRF, the password policy,
secrets in logs, and role enforcement on every state-changing area (firewall, rules,
configuration, users) including the last-administrator guard.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import pytest_asyncio
import structlog

from sentinelx.api.app import create_app
from sentinelx.common.enums import UserRole
from sentinelx.firewall import MemoryFirewall
from sentinelx.services.platform import Platform
from tests.api.conftest import ADMIN_PASSWORD, make_settings

API = "/api/v1"
VIEWER_PASSWORD = "Viewer-Auth-Passphrase-2026"
ANALYST_PASSWORD = "Analyst-Auth-Passphrase-2026"
GENERIC_FAILURE = {"detail": "invalid username or password"}


@asynccontextmanager
async def client_from(
    platform: Platform, address: str = "127.0.0.1"
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(platform.settings, platform=platform)
    # Server errors must surface as 500 responses, not as exceptions in the test.
    transport = httpx.ASGITransport(app=app, client=(address, 50000), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url=f"http://testserver{API}") as http:
        yield http


@pytest_asyncio.fixture
async def http(platform: Platform) -> AsyncIterator[httpx.AsyncClient]:
    async with client_from(platform) as client:
        yield client


async def login_pair(
    http: httpx.AsyncClient, username: str, password: str, **kwargs: Any
) -> dict[str, Any]:
    response = await http.post(
        "/auth/login", json={"username": username, "password": password}, **kwargs
    )
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def people(platform: Platform, http: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
    """Tokens and ids for one user of each role."""
    await platform.auth.create_user("analyst1", ANALYST_PASSWORD, UserRole.ANALYST)
    await platform.auth.create_user("viewer1", VIEWER_PASSWORD, UserRole.VIEWER)
    result: dict[str, dict[str, Any]] = {}
    for role, username, password in (
        ("admin", "admin", ADMIN_PASSWORD),
        ("analyst", "analyst1", ANALYST_PASSWORD),
        ("viewer", "viewer1", VIEWER_PASSWORD),
    ):
        pair = await login_pair(http, username, password)
        result[role] = {
            "headers": bearer(pair["access_token"]),
            "pair": pair,
            "id": pair["user"]["id"],
            "username": username,
            "password": password,
        }
    return result


def claims_for(platform: Platform, **overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": "1",
        "iss": platform.settings.api.jwt_issuer,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": "a" * 32,
        "type": "access",
        "username": "admin",
        "role": "admin",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def sign(platform: Platform, claims: dict[str, Any], **kwargs: Any) -> str:
    return jwt.encode(claims, platform.settings.api.jwt_secret, algorithm="HS256", **kwargs)


# ------------------------------------------------------------------- login


class TestLogin:
    async def test_success_returns_a_complete_token_pair(
        self, platform: Platform, http: httpx.AsyncClient
    ) -> None:
        body = await login_pair(http, "admin", ADMIN_PASSWORD)
        assert (
            body["token_type"] == "bearer" and body["refresh_token"] and body["csrf_token"] is None
        )
        assert body["user"]["username"] == "admin" and body["user"]["role"] == "admin"
        claims = jwt.decode(
            body["access_token"], platform.settings.api.jwt_secret, algorithms=["HS256"]
        )
        assert claims["type"] == "access" and claims["sub"] == str(body["user"]["id"])
        assert not {"password", "password_hash", "hash"} & set(claims)
        assert ADMIN_PASSWORD not in str(body)

    async def test_failures_do_not_reveal_whether_the_account_exists(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        await platform.auth.create_user("dormant", "Sleeping-Passphrase-2026", UserRole.VIEWER)
        dormant = await http.get("/users", headers=people["admin"]["headers"])
        dormant_id = next(u["id"] for u in dormant.json() if u["username"] == "dormant")
        await http.patch(
            f"/users/{dormant_id}", headers=people["admin"]["headers"], json={"is_active": False}
        )
        attempts = {
            "unknown user": ("nobody-here", "Some-Password-2026"),
            "wrong password": ("admin", "Some-Password-2026"),
            "disabled user, right password": ("dormant", "Sleeping-Passphrase-2026"),
            "case-mangled unknown": ("ADMIN ", "Some-Password-2026"),
        }
        responses = {}
        for label, (username, password) in attempts.items():
            responses[label] = await http.post(
                "/auth/login", json={"username": username, "password": password}
            )
        for label, response in responses.items():
            assert response.status_code == 401, label
            assert response.json() == GENERIC_FAILURE, label
        header_sets = {frozenset(k for k in r.headers if k != "date") for r in responses.values()}
        assert len(header_sets) == 1

    async def test_lockout_is_uniform_and_expires(self, platform: Platform) -> None:
        threshold = platform.settings.api.lockout_threshold
        lockout = platform.settings.api.lockout_seconds
        locked: dict[str, httpx.Response] = {}
        for address, username in (("198.51.100.1", "admin"), ("198.51.100.2", "ghost-user")):
            async with client_from(platform, address) as attacker:
                for _ in range(threshold):
                    failed = await attacker.post(
                        "/auth/login", json={"username": username, "password": "Wrong-Guess-2026"}
                    )
                    assert failed.status_code == 401
                locked[username] = await attacker.post(
                    "/auth/login", json={"username": username, "password": ADMIN_PASSWORD}
                )
        for response in locked.values():
            assert response.status_code == 423
            assert response.json() == {
                "detail": "account temporarily locked after repeated failures"
            }
            assert 1 <= int(response.headers["retry-after"]) <= lockout
        # Once the window passes, the right password works again from that address.
        real_clock = platform.state._clock
        platform.state._clock = lambda: real_clock() + lockout + 1
        try:
            async with client_from(platform, "198.51.100.1") as owner:
                await login_pair(owner, "admin", ADMIN_PASSWORD)
        finally:
            platform.state._clock = real_clock

    async def test_disabled_user_loses_tokens_refresh_and_tickets(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        viewer = people["viewer"]
        ticket = (await http.post("/auth/ws-ticket", headers=viewer["headers"])).json()["ticket"]
        disabled = await http.patch(
            f"/users/{viewer['id']}", headers=people["admin"]["headers"], json={"is_active": False}
        )
        assert disabled.status_code == 200
        me = await http.get("/auth/me", headers=viewer["headers"])
        assert me.status_code == 401 and me.json() == {"detail": "account disabled"}
        refresh = await http.post(
            "/auth/refresh", json={"refresh_token": viewer["pair"]["refresh_token"]}
        )
        assert refresh.status_code == 401
        from sentinelx.services.auth import AuthError

        with pytest.raises(AuthError):
            await platform.auth.redeem_ws_ticket(ticket)
        relogin = await http.post(
            "/auth/login", json={"username": "viewer1", "password": VIEWER_PASSWORD}
        )
        assert relogin.status_code == 401 and relogin.json() == GENERIC_FAILURE
        await http.patch(
            f"/users/{viewer['id']}", headers=people["admin"]["headers"], json={"is_active": True}
        )
        await login_pair(http, "viewer1", VIEWER_PASSWORD)


# ------------------------------------------------------------------ tokens


class TestTokens:
    async def test_expired_access_and_refresh_tokens_are_401(
        self, platform: Platform, http: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sentinelx.services.auth as auth_module

        ttl = platform.settings.api.refresh_token_ttl_seconds

        class IssuedLongAgo(datetime):
            @classmethod
            def now(cls, tz: Any = None) -> IssuedLongAgo:
                return super().now(tz) - timedelta(seconds=ttl + 60)

        with monkeypatch.context() as patch:
            patch.setattr(auth_module, "datetime", IssuedLongAgo)
            pair = await login_pair(http, "admin", ADMIN_PASSWORD)
        expired = await http.get("/auth/me", headers=bearer(pair["access_token"]))
        assert expired.status_code == 401 and expired.json() == {"detail": "token expired"}
        assert expired.headers["www-authenticate"] == "Bearer"
        refreshed = await http.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert refreshed.status_code == 401 and refreshed.json() == {"detail": "token expired"}

    async def test_forged_tampered_and_wrong_type_tokens_are_401(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        admin = people["admin"]
        access, refresh = admin["pair"]["access_token"], admin["pair"]["refresh_token"]
        head, payload, signature = access.split(".")
        elevated_payload = jwt.utils.base64url_encode(
            b'{"sub":"1","type":"access","role":"admin","exp":9999999999}'
        ).decode()
        ticket = (await http.post("/auth/ws-ticket", headers=admin["headers"])).json()["ticket"]
        variants = {
            "signature altered": f"{head}.{payload}.{signature[:-4]}AAAA",
            "payload altered": f"{head}.{elevated_payload}.{signature}",
            "wrong secret": jwt.encode(claims_for(platform), "another-secret-" * 4, "HS256"),
            "alg none": jwt.encode(claims_for(platform), "", algorithm="none"),
            "HS512 with the real secret": jwt.encode(
                claims_for(platform), platform.settings.api.jwt_secret, algorithm="HS512"
            ),
            "wrong issuer": sign(platform, claims_for(platform, iss="someone-else")),
            "no jti": sign(platform, claims_for(platform, jti=None)),
            "no exp": sign(platform, claims_for(platform, exp=None)),
            "no type": sign(platform, claims_for(platform, type=None)),
            "refresh used as access": refresh,
            "websocket ticket": ticket,
            "non-integer subject": sign(platform, claims_for(platform, sub="admin")),
            "huge subject": sign(platform, claims_for(platform, sub="9" * 40)),
            "negative subject": sign(platform, claims_for(platform, sub="-1")),
            "unknown user": sign(platform, claims_for(platform, sub="424242")),
            "empty": "",
            "garbage": "e30.e30.e30",
        }
        for label, token in variants.items():
            response = await http.get("/auth/me", headers=bearer(token))
            assert response.status_code == 401, f"{label}: {response.status_code} {response.text}"
            assert "error_id" not in response.json(), label
        for scheme in (f"Basic {access}", f"Token {access}", access):
            assert (
                await http.get("/auth/me", headers={"Authorization": scheme})
            ).status_code == 401
        # An access token is not a refresh token either.
        wrong = await http.post("/auth/refresh", json={"refresh_token": access})
        assert wrong.status_code == 401
        for subject in ("x", "9" * 40):
            forged_refresh = sign(platform, claims_for(platform, type="refresh", sub=subject))
            response = await http.post("/auth/refresh", json={"refresh_token": forged_refresh})
            assert response.status_code == 401, f"refresh sub={subject[:8]}: {response.text}"

    async def test_role_comes_from_the_database_not_the_token(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        viewer = people["viewer"]
        # Even a correctly signed token cannot grant a role the account does not have.
        elevated = sign(
            platform, claims_for(platform, sub=str(viewer["id"]), username="viewer1", role="admin")
        )
        response = await http.get("/users", headers=bearer(elevated))
        assert response.status_code == 403 and response.json() == {
            "detail": "requires the admin role"
        }

    async def test_refresh_rotation_and_reuse(
        self, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        first = people["analyst"]["pair"]
        rotated = await http.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert rotated.status_code == 200
        second = rotated.json()
        assert second["refresh_token"] != first["refresh_token"]
        assert second["access_token"] != first["access_token"]
        assert (
            await http.get("/auth/me", headers=bearer(second["access_token"]))
        ).status_code == 200
        reused = await http.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert reused.status_code == 401
        family = await http.post("/auth/refresh", json={"refresh_token": second["refresh_token"]})
        assert family.status_code == 401  # reuse revoked the whole family

    async def test_refresh_request_body_errors_are_clean(self, http: httpx.AsyncClient) -> None:
        """Regression: a malformed JSON body on /auth/refresh was an unhandled 500."""
        json_type = {"content-type": "application/json"}
        for content in (b'{"refresh_token": ', b"\xff\xfe\x00", b"[1, 2"):
            response = await http.post("/auth/refresh", content=content, headers=json_type)
            assert response.status_code == 422, (content, response.text)
            assert response.json() == {"detail": "request body is not valid JSON"}
        missing = await http.post("/auth/refresh", content=b"", headers=json_type)
        assert missing.status_code in (401, 422)
        not_json = await http.post(
            "/auth/refresh", content=b"refresh_token=x", headers={"content-type": "text/plain"}
        )
        assert not_json.status_code == 401 and not_json.json() == {
            "detail": "refresh token required"
        }

    async def test_logout_ends_access_and_refresh_tokens(
        self, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        analyst = people["analyst"]
        assert (await http.post("/auth/logout", headers=analyst["headers"])).status_code == 204
        assert (await http.get("/auth/me", headers=analyst["headers"])).status_code == 401
        refresh = await http.post(
            "/auth/refresh", json={"refresh_token": analyst["pair"]["refresh_token"]}
        )
        assert refresh.status_code == 401
        # Other users' sessions are untouched.
        assert (await http.get("/auth/me", headers=people["viewer"]["headers"])).status_code == 200


# ------------------------------------------------------------ cookie mode


class TestCookieSessions:
    async def test_cookie_refresh_requires_the_dashboard_client_header(
        self, platform: Platform
    ) -> None:
        """Regression: the refresh cookie alone rotated a session; only SameSite=Strict
        kept it off cross-site requests."""
        dashboard = {"X-SentinelX-Client": "dashboard"}
        async with client_from(platform) as browser:
            login = await browser.post(
                "/auth/login",
                json={"username": "admin", "password": ADMIN_PASSWORD},
                headers=dashboard,
            )
            assert login.status_code == 200 and browser.cookies.get("sx_refresh")
            for headers in ({}, {"X-SentinelX-Client": "someone-else"}):
                refused = await browser.post("/auth/refresh", headers=headers)
                assert refused.status_code == 403, headers
                assert refused.json() == {
                    "detail": "refreshing from the session cookie requires the dashboard client header"
                }
                assert not refused.headers.get_list("set-cookie")  # the session is untouched
            # The refused attempts did not consume the token: the dashboard still refreshes.
            rotated = await browser.post("/auth/refresh", headers=dashboard)
            assert rotated.status_code == 200 and rotated.json()["csrf_token"]

    async def test_refresh_token_in_the_body_works_without_the_header(
        self, platform: Platform, http: httpx.AsyncClient
    ) -> None:
        pair = await login_pair(http, "admin", ADMIN_PASSWORD)
        rotated = await http.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert rotated.status_code == 200 and rotated.json()["refresh_token"]
        # A body token is used even when a (stale) cookie is also present.
        async with client_from(platform) as mixed:
            mixed.cookies.set("sx_refresh", "stale-cookie-value", path="/api/v1/auth")
            body = await mixed.post(
                "/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}
            )
            assert body.status_code == 200, body.text

    async def test_cookie_login_refresh_csrf_and_logout(self, platform: Platform) -> None:
        dashboard = {"X-SentinelX-Client": "dashboard"}
        async with client_from(platform) as browser:
            response = await browser.post(
                "/auth/login",
                json={"username": "admin", "password": ADMIN_PASSWORD},
                headers=dashboard,
            )
            assert response.status_code == 200
            body = response.json()
            assert body["refresh_token"] is None and body["csrf_token"]
            cookies = {c.split("=", 1)[0]: c for c in response.headers.get_list("set-cookie")}
            for name, path in (("sx_access", "/api"), ("sx_refresh", "/api/v1/auth")):
                assert "HttpOnly" in cookies[name] and "samesite=strict" in cookies[name].lower()
                assert f"Path={path}" in cookies[name]
            assert "HttpOnly" not in cookies["sx_csrf"]
            assert browser.cookies["sx_csrf"] == body["csrf_token"]
            csrf = body["csrf_token"]

            assert (await browser.get("/auth/me")).status_code == 200
            for headers in ({}, {"X-CSRF-Token": "forged"}, {"X-CSRF-Token": ""}):
                refused = await browser.post("/auth/ws-ticket", headers=headers)
                assert refused.status_code == 403 and refused.json() == {
                    "detail": "CSRF token missing or invalid"
                }
            assert (
                await browser.post("/auth/ws-ticket", headers={"X-CSRF-Token": csrf})
            ).status_code == 200

            rotated = await browser.post("/auth/refresh", headers=dashboard)
            assert rotated.status_code == 200 and rotated.json()["refresh_token"] is None
            csrf = rotated.json()["csrf_token"]
            assert (await browser.get("/auth/me")).status_code == 200

            old_access = browser.cookies["sx_access"]
            # Access cookie without the csrf cookie: a matching header alone is not enough.
            # Checked while that cookie is still valid, so the refusal comes from the CSRF
            # check and not from the session cut-off (which has one-second resolution).
            async with client_from(platform) as other:
                raw = {"Cookie": f"sx_access={old_access}", "X-CSRF-Token": csrf}
                assert (await other.post("/auth/ws-ticket", headers=raw)).status_code == 403
            out = await browser.post("/auth/logout", headers={"X-CSRF-Token": csrf})
            assert out.status_code == 204
            cleared = [c for c in out.headers.get_list("set-cookie") if c.startswith("sx_")]
            assert {c.split("=", 1)[0] for c in cleared} == {"sx_access", "sx_refresh", "sx_csrf"}
            assert all("Max-Age=0" in c or "expires=" in c.lower() for c in cleared)
        async with client_from(platform) as other:
            # After logout the old cookie no longer authenticates.
            stale = {"Cookie": f"sx_access={old_access}"}
            assert (await other.get("/auth/me", headers=stale)).status_code == 401

    async def test_bearer_requests_need_no_csrf_token(
        self, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        response = await http.post("/auth/ws-ticket", headers=people["viewer"]["headers"])
        assert response.status_code == 200


# ------------------------------------------------- forced password changes


class TestPasswords:
    async def test_must_change_password_restricts_the_session(
        self, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        admin, viewer = people["admin"], people["viewer"]
        reset = await http.post(
            f"/users/{viewer['id']}/reset-password",
            headers=admin["headers"],
            json={"new_password": "Temporary-Reset-2026x"},
        )
        assert reset.status_code == 204
        pair = await login_pair(http, "viewer1", "Temporary-Reset-2026x")
        assert pair["user"]["must_change_password"] is True
        headers = bearer(pair["access_token"])
        me = await http.get("/auth/me", headers=headers)
        assert me.status_code == 200 and me.json()["must_change_password"] is True
        for method, path in (
            ("GET", "/detections"),
            ("GET", "/system/status"),
            ("POST", "/auth/ws-ticket"),
            ("GET", "/users"),
        ):
            refused = await http.request(method, path, headers=headers)
            assert refused.status_code == 403, path
            assert refused.json() == {"detail": "password change required before continuing"}
        # A refreshed session is still restricted: the flag lives in the database.
        refreshed = await http.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert (
            await http.get("/detections", headers=bearer(refreshed.json()["access_token"]))
        ).status_code == 403
        changed = await http.post(
            "/auth/change-password",
            headers=headers,
            json={"current_password": "Temporary-Reset-2026x", "new_password": "Chosen-By-Me-2026"},
        )
        assert changed.status_code == 200
        fresh = bearer(changed.json()["access_token"])
        assert changed.json()["user"]["must_change_password"] is False
        assert (await http.get("/detections", headers=fresh)).status_code == 200

    async def test_password_policy(self, http: httpx.AsyncClient, people: dict[str, Any]) -> None:
        admin = people["admin"]["headers"]
        rejected = {
            "too short": "Short-2026",
            "contains username": "policy-user-Passphrase",
            "common": "changeme1234",
            "few distinct characters": "abababababababab",
        }
        for label, password in rejected.items():
            response = await http.post(
                "/users",
                headers=admin,
                json={"username": "policy-user", "password": password, "role": "viewer"},
            )
            assert response.status_code == 422, label
            assert password not in response.text, label
        too_long = await http.post(
            "/users", headers=admin, json={"username": "policy-user", "password": "L" * 257}
        )
        assert too_long.status_code == 422
        created = await http.post(
            "/users",
            headers=admin,
            json={"username": "policy-user", "password": "Acceptable-Passphrase-2026"},
        )
        assert created.status_code == 201 and created.json()["role"] == "viewer"
        duplicate = await http.post(
            "/users",
            headers=admin,
            json={"username": "policy-user", "password": "Acceptable-Passphrase-2026"},
        )
        assert duplicate.status_code == 409
        viewer = people["viewer"]
        wrong_current = await http.post(
            "/auth/change-password",
            headers=viewer["headers"],
            json={"current_password": "not-my-password", "new_password": "Brand-New-Pass-2026"},
        )
        assert wrong_current.status_code == 403
        same = await http.post(
            "/auth/change-password",
            headers=viewer["headers"],
            json={"current_password": VIEWER_PASSWORD, "new_password": VIEWER_PASSWORD},
        )
        assert same.status_code == 422
        weak_reset = await http.post(
            f"/users/{viewer['id']}/reset-password", headers=admin, json={"new_password": "weak"}
        )
        assert weak_reset.status_code == 422

    async def test_logs_and_audit_never_contain_passwords_or_tokens(
        self,
        platform: Platform,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from sentinelx.config.settings import TelemetrySettings
        from sentinelx.telemetry.logging import configure_logging

        configure_logging(TelemetrySettings(log_format="json", log_level="INFO"))
        # configure_logging caches loggers on first use, so a module logger first used
        # under an earlier test's configuration (the suite silences logging) would
        # ignore this one. Fresh proxies make the capture independent of test order.
        import sys

        from sentinelx.telemetry.logging import get_logger

        for name, module in list(sys.modules.items()):
            if name.startswith("sentinelx.") and isinstance(
                getattr(module, "log", None), structlog._config.BoundLoggerLazyProxy
            ):
                monkeypatch.setattr(module, "log", get_logger(name))
        secrets: list[str] = [platform.settings.api.jwt_secret, ADMIN_PASSWORD]
        try:
            async with client_from(platform) as http:
                pair = await login_pair(http, "admin", ADMIN_PASSWORD)
                admin = bearer(pair["access_token"])
                secrets += [pair["access_token"], pair["refresh_token"]]
                for username in ("admin", "no-such-user"):
                    await http.post(
                        "/auth/login",
                        json={"username": username, "password": "Guessed-Password-2026"},
                    )
                secrets.append("Guessed-Password-2026")
                created = await http.post(
                    "/users",
                    headers=admin,
                    json={"username": "logged-user", "password": "Logged-Passphrase-2026"},
                )
                secrets.append("Logged-Passphrase-2026")
                user_pair = await login_pair(http, "logged-user", "Logged-Passphrase-2026")
                secrets += [user_pair["access_token"], user_pair["refresh_token"]]
                rotated = await http.post(
                    "/auth/refresh", json={"refresh_token": user_pair["refresh_token"]}
                )
                secrets += [rotated.json()["access_token"], rotated.json()["refresh_token"]]
                user = bearer(rotated.json()["access_token"])
                ticket = (await http.post("/auth/ws-ticket", headers=user)).json()["ticket"]
                secrets.append(ticket)
                changed = await http.post(
                    "/auth/change-password",
                    headers=user,
                    json={
                        "current_password": "Logged-Passphrase-2026",
                        "new_password": "Changed-Passphrase-2026",
                    },
                )
                secrets += ["Changed-Passphrase-2026", changed.json()["access_token"]]
                await http.post(
                    f"/users/{created.json()['id']}/reset-password",
                    headers=admin,
                    json={"new_password": "Reset-By-Admin-2026"},
                )
                secrets.append("Reset-By-Admin-2026")
                cookie = await http.post(
                    "/auth/login",
                    json={"username": "admin", "password": ADMIN_PASSWORD},
                    headers={"X-SentinelX-Client": "dashboard"},
                )
                secrets.append(cookie.json()["csrf_token"])
                await http.get("/auth/me", headers=bearer(pair["access_token"] + "tampered"))
                await http.post(
                    "/auth/refresh",
                    content=f'{{"refresh_token": "{pair["refresh_token"]}"'.encode(),
                    headers={"content-type": "application/json"},
                )
                assert platform.queries is not None

                async def explode(*args: Any, **kwargs: Any) -> Any:
                    raise RuntimeError("query failed")

                monkeypatch.setattr(platform.queries, "detections", explode)
                crashed = await http.get("/detections", headers=admin)
                assert crashed.status_code == 500
                audit = await http.get("/audit", headers=admin, params={"limit": 500})
                audit_text = audit.text
        finally:
            captured = capsys.readouterr()
            root = logging.getLogger()
            for handler in root.handlers[:]:
                root.removeHandler(handler)
            structlog.configure(
                wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL)
            )
        logs = captured.out + captured.err
        # The capture really saw the flows, so the absence checks below mean something.
        for event in ("login_succeeded", "login_failed", "unhandled_error", "audit"):
            assert event in logs, event
        assert "LOGIN_FAILED" in audit_text and "RESET_PASSWORD" in audit_text
        for secret in secrets:
            assert secret, "empty secret collected"
            assert secret not in logs, f"{secret[:8]}... appeared in the logs"
            assert secret not in audit_text, f"{secret[:8]}... appeared in the audit log"
        assert "$argon2" not in logs and "$argon2" not in audit_text


# ------------------------------------------------------------ authorisation


FORBIDDEN_CHANGES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("POST", "/firewall/block", {"target": "203.0.113.66", "reason": "not allowed"}),
    ("POST", "/firewall/unblock", {"target": "203.0.113.66", "reason": "not allowed"}),
    ("POST", "/firewall/approvals/any-id/approve", None),
    ("POST", "/firewall/approvals/any-id/reject", {"reason": "no"}),
    ("PUT", "/firewall/allowlist", {"networks": ["0.0.0.0/0"]}),
    ("POST", "/rules", {"definition": "rule:\n  name: Sneaky Rule\n  condition: ttl > 1\n"}),
    (
        "PUT",
        "/rules/ssh_brute_force",
        {"definition": "rule:\n  name: X Rule\n  condition: ttl > 1\n"},
    ),
    ("PATCH", "/rules/ssh_brute_force/enabled", {"enabled": False}),
    ("DELETE", "/rules/ssh_brute_force", None),
    ("PATCH", "/detectors/port_scan/enabled", {"enabled": False}),
    (
        "PATCH",
        "/config/response",
        {"changes": {"mode": "automatic", "dry_run": False}, "confirmation": "ENABLE PREVENTION"},
    ),
    ("PATCH", "/config/detection", {"changes": {"port_scan_unique_ports": 999}}),
    ("POST", "/sensors/start", {"interface": "lo"}),
    ("POST", "/sensors/stop", None),
    ("GET", "/users", None),
    (
        "POST",
        "/users",
        {"username": "intruder", "password": "Intruder-Passphrase-2026", "role": "admin"},
    ),
    ("PATCH", "/users/{self}", {"role": "admin"}),
    ("PATCH", "/users/1", {"is_active": False}),
    ("POST", "/users/1/reset-password", {"new_password": "Taken-Over-Pass-2026"}),
    ("DELETE", "/users/1", None),
]


class TestAuthorization:
    async def snapshot(self, platform: Platform, http: httpx.AsyncClient, admin: Any) -> Any:
        rules = (await http.get("/rules", headers=admin)).json()["rules"]
        return {
            "blocked": (await http.get("/firewall/blocked", headers=admin)).json(),
            "actions": (await http.get("/firewall/actions", headers=admin)).json()["total"],
            "allowlist": (await http.get("/firewall/allowlist", headers=admin)).json(),
            "rules": sorted((r["rule_id"], r["enabled"], r["definition"]) for r in rules),
            "detectors": sorted(
                (d["name"], d.get("enabled"))
                for d in (await http.get("/detectors", headers=admin)).json()
            ),
            "config": (await http.get("/config", headers=admin)).json(),
            "users": (await http.get("/users", headers=admin)).json(),
            "sensor": platform.sensor.state if platform.sensor else None,
            "prevention": platform.settings.prevention_active,
        }

    @pytest.mark.parametrize("role", ["viewer", "analyst"])
    async def test_lower_roles_cannot_change_protected_state(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any], role: str
    ) -> None:
        admin = people["admin"]["headers"]
        before = await self.snapshot(platform, http, admin)
        for method, path, body in FORBIDDEN_CHANGES:
            path = path.replace("{self}", str(people[role]["id"]))
            # A browser-looking request gets no special treatment: the check is server-side.
            headers = {
                **people[role]["headers"],
                "X-SentinelX-Client": "dashboard",
                "Origin": "http://localhost:3000",
            }
            kwargs: dict[str, Any] = {"headers": headers}
            if body is not None:
                kwargs["json"] = body
            response = await http.request(method, path, **kwargs)
            assert response.status_code == 403, f"{role} {method} {path}: {response.text}"
            assert response.json() == {"detail": "requires the admin role"}
        after = await self.snapshot(platform, http, admin)
        # Users' last_login_at does not change on refusals either.
        assert after == before

    async def test_read_restrictions(self, http: httpx.AsyncClient, people: dict[str, Any]) -> None:
        expected = {
            "viewer": {"/audit": 403, "/config": 403, "/users": 403, "/detections": 200},
            "analyst": {"/audit": 200, "/config": 200, "/users": 403, "/detections": 200},
            "admin": {"/audit": 200, "/config": 200, "/users": 200, "/detections": 200},
        }
        for role, paths in expected.items():
            for path, status in paths.items():
                response = await http.get(path, headers=people[role]["headers"])
                assert response.status_code == status, (role, path, response.text)

    async def test_role_change_takes_effect_on_the_next_request(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        admin, analyst = people["admin"], people["analyst"]
        promoted = await http.patch(
            f"/users/{analyst['id']}", headers=admin["headers"], json={"role": "admin"}
        )
        assert promoted.status_code == 200
        assert (await http.get("/users", headers=analyst["headers"])).status_code == 200
        demoted = await http.patch(
            f"/users/{analyst['id']}", headers=admin["headers"], json={"role": "viewer"}
        )
        assert demoted.status_code == 200
        assert (await http.get("/users", headers=analyst["headers"])).status_code == 403
        assert (await http.get("/audit", headers=analyst["headers"])).status_code == 403

    async def test_admin_cannot_remove_themselves_or_the_last_admin(
        self, http: httpx.AsyncClient, people: dict[str, Any]
    ) -> None:
        admin = people["admin"]
        me = f"/users/{admin['id']}"
        for body in ({"role": "viewer"}, {"role": "analyst"}, {"is_active": False}):
            response = await http.patch(me, headers=admin["headers"], json=body)
            assert response.status_code == 422, body
        assert (await http.delete(me, headers=admin["headers"])).status_code == 422
        assert (await http.get("/users", headers=admin["headers"])).status_code == 200

    @pytest.mark.parametrize("change", ["deactivate", "demote", "delete"])
    async def test_concurrent_changes_cannot_leave_no_active_admin(
        self, platform: Platform, http: httpx.AsyncClient, people: dict[str, Any], change: str
    ) -> None:
        """Regression: two administrators removing each other at the same moment both
        passed the last-administrator check, leaving no one able to administer."""
        await platform.auth.create_user("admin2", "Second-Admin-Pass-2026", UserRole.ADMIN)
        second = await login_pair(http, "admin2", "Second-Admin-Pass-2026")
        first_id, second_id = people["admin"]["id"], second["user"]["id"]

        def request(headers: dict[str, str], target: int) -> Any:
            if change == "delete":
                return http.delete(f"/users/{target}", headers=headers)
            body = {"is_active": False} if change == "deactivate" else {"role": "viewer"}
            return http.patch(f"/users/{target}", headers=headers, json=body)

        results = await asyncio.gather(
            request(people["admin"]["headers"], second_id),
            request(bearer(second["access_token"]), first_id),
        )
        statuses = sorted(r.status_code for r in results)
        assert 500 not in statuses and 503 not in statuses, [r.text for r in results]
        async with platform.database.session() as session:
            from sentinelx.storage.repositories import UserRepository

            active_admins = [
                u.username
                for u in await UserRepository(session).all()
                if u.role == UserRole.ADMIN.value and u.is_active
            ]
        assert active_admins, f"no active administrator left: {[r.text for r in results]}"
        assert statuses[0] in (200, 204), statuses  # one of the two changes went through


# ----------------------------------------------------------------- root path


class TestRootPath:
    async def test_prefixed_requests_keep_auth_exemptions_and_rate_limits(
        self, tmp_path: Path
    ) -> None:
        """Regression: with ``api.root_path`` set, requests carrying the prefix skipped
        the API rate limiter and could not reach the forced password-change endpoints."""
        platform = Platform(
            make_settings(tmp_path, root_path="/sx", rate_limit_requests=50),
            firewall=MemoryFirewall(),
        )
        await platform.start()
        try:
            user = await platform.auth.create_user("viewer1", VIEWER_PASSWORD, UserRole.VIEWER)
            await platform.auth.set_password(user.id, "Temporary-Reset-2026x")
            app = create_app(platform.settings, platform=platform)
            transport = httpx.ASGITransport(
                app=app, client=("127.0.0.1", 50000), raise_app_exceptions=False
            )
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver/sx/api/v1"
            ) as prefixed:
                pair = await login_pair(prefixed, "viewer1", "Temporary-Reset-2026x")
                headers = bearer(pair["access_token"])
                me = await prefixed.get("/auth/me", headers=headers)
                assert me.status_code == 200, me.text
                assert "x-ratelimit-remaining" in me.headers
                assert me.headers.get("content-security-policy")
                changed = await prefixed.post(
                    "/auth/change-password",
                    headers=headers,
                    json={
                        "current_password": "Temporary-Reset-2026x",
                        "new_password": "Chosen-After-Reset-2026",
                    },
                )
                assert changed.status_code == 200, changed.text
                assert (await prefixed.get("/detections", headers=headers)).status_code in (
                    401,
                    403,
                )
                platform.settings.api.rate_limit_requests = 3
                await platform.state.reset("api", "127.0.0.1")
                codes = [(await prefixed.get("/detections")).status_code for _ in range(5)]
                assert codes[-1] == 429, codes
                health = await prefixed.get("/system/health")
                assert health.status_code == 200
        finally:
            await platform.stop()
