from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from sentinelx.services.platform import Platform
from tests.api.conftest import ADMIN_PASSWORD, make_settings


class TestAuthentication:
    async def test_protected_endpoints_require_authentication(
        self, client: httpx.AsyncClient
    ) -> None:
        for path in (
            "/system/status",
            "/detections",
            "/incidents",
            "/rules",
            "/firewall",
            "/audit",
            "/config",
        ):
            assert (await client.get(path)).status_code == 401, path

    async def test_health_is_public_and_minimal(self, client: httpx.AsyncClient) -> None:
        body = (await client.get("/system/health")).json()
        assert set(body) == {"status", "version"}

    async def test_login_failure_is_uniform_for_unknown_and_known_users(
        self, client: httpx.AsyncClient
    ) -> None:
        unknown = await client.post(
            "/auth/login", json={"username": "ghost", "password": "whatever-123456"}
        )
        wrong = await client.post(
            "/auth/login", json={"username": "admin", "password": "whatever-123456"}
        )
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() == wrong.json()

    async def test_account_locks_after_repeated_failures(
        self, client: httpx.AsyncClient, platform: Platform
    ) -> None:
        for _ in range(platform.settings.api.lockout_threshold):
            await client.post(
                "/auth/login", json={"username": "admin", "password": "not-the-password-1"}
            )
        locked = await client.post(
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert locked.status_code == 423
        assert "retry-after" in locked.headers

    async def test_tampered_forged_and_wrong_type_tokens_rejected(
        self, client: httpx.AsyncClient
    ) -> None:
        import jwt

        good = await client.post(
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        access, refresh = good.json()["access_token"], good.json()["refresh_token"]
        head, payload, signature = access.split(".")
        tampered = f"{head}.{payload}.{signature[::-1]}"
        forged = jwt.encode(
            {
                "sub": "1",
                "type": "access",
                "jti": "x",
                "iat": 1,
                "exp": 9_999_999_999,
                "iss": "sentinelx",
                "role": "admin",
            },
            "not-the-server-secret-not-the-server-secret",
            algorithm="HS256",
        )
        unsigned = jwt.encode(
            {"sub": "1", "type": "access", "jti": "x", "iat": 1, "exp": 9_999_999_999},
            None,
            algorithm="none",
        )
        for token in (tampered, refresh, forged, unsigned):
            assert (
                await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
            ).status_code == 401

    async def test_refresh_rotation_and_reuse_detection(self, client: httpx.AsyncClient) -> None:
        first = (
            await client.post("/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        ).json()
        rotated = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert rotated.status_code == 200
        assert (
            await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        ).status_code == 401
        # Reuse revoked the whole family, including the token the rotation issued.
        replay = await client.post(
            "/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}
        )
        assert replay.status_code == 401

    async def test_browser_login_uses_httponly_cookies_and_enforces_csrf(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.post(
            "/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD},
            headers={"X-SentinelX-Client": "dashboard"},
        )
        assert response.json()["refresh_token"] is None
        cookies = response.headers.get_list("set-cookie")
        assert any(
            c.startswith("sx_access=") and "HttpOnly" in c and "samesite=strict" in c.lower()
            for c in cookies
        )
        csrf = response.json()["csrf_token"]
        assert (await client.get("/auth/me")).status_code == 200  # safe method via cookie
        body = {"target": "203.0.113.9", "reason": "csrf test"}
        assert (await client.post("/firewall/block", json=body)).status_code == 403
        assert (
            await client.post("/firewall/block", json=body, headers={"X-CSRF-Token": "forged"})
        ).status_code == 403
        assert (
            await client.post("/firewall/block", json=body, headers={"X-CSRF-Token": csrf})
        ).status_code == 200

    async def test_password_change_policy(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        weak = await client.post(
            "/auth/change-password",
            headers=admin,
            json={"current_password": ADMIN_PASSWORD, "new_password": "short"},
        )
        assert weak.status_code == 422
        ok = await client.post(
            "/auth/change-password",
            headers=admin,
            json={
                "current_password": ADMIN_PASSWORD,
                "new_password": "A-much-better-passphrase-77",
            },
        )
        assert ok.status_code == 200 and ok.json()["access_token"]
        # The session that changed the password continues with its new token; the old
        # access token is revoked.
        fresh = {"Authorization": f"Bearer {ok.json()['access_token']}"}
        assert (await client.get("/auth/me", headers=fresh)).status_code == 200
        assert (await client.get("/auth/me", headers=admin)).status_code == 401
        relogin = await client.post(
            "/auth/login", json={"username": "admin", "password": "A-much-better-passphrase-77"}
        )
        assert relogin.status_code == 200


MATRIX: list[tuple[str, str, dict[str, Any] | None, dict[str, int]]] = [
    ("get", "/detections", None, {"viewer": 200, "analyst": 200, "admin": 200}),
    ("get", "/audit", None, {"viewer": 403, "analyst": 200, "admin": 200}),
    ("get", "/config", None, {"viewer": 403, "analyst": 200, "admin": 200}),
    (
        "post",
        "/rules/validate",
        {"definition": "rule:\n  name: Test Rule\n  condition: ttl > 1\n"},
        {"viewer": 403, "analyst": 200, "admin": 200},
    ),
    (
        "post",
        "/firewall/block",
        {"target": "203.0.113.50", "reason": "rbac test"},
        {"viewer": 403, "analyst": 403, "admin": 200},
    ),
    (
        "patch",
        "/config/detection",
        {"changes": {"port_scan_unique_ports": 30}},
        {"viewer": 403, "analyst": 403, "admin": 200},
    ),
    (
        "post",
        "/rules",
        {"definition": "rule:\n  name: Rbac Rule\n  condition: ttl > 1\n"},
        {"viewer": 403, "analyst": 403, "admin": 201},
    ),
    ("get", "/users", None, {"viewer": 403, "analyst": 403, "admin": 200}),
    ("post", "/sensors/stop", None, {"viewer": 403, "analyst": 403, "admin": 200}),
]


class TestAuthorization:
    @pytest.mark.parametrize(
        ("method", "path", "body", "expected"), MATRIX, ids=[f"{m} {p}" for m, p, _, _ in MATRIX]
    )
    async def test_role_matrix(
        self,
        client: httpx.AsyncClient,
        roles: dict[str, dict[str, str]],
        method: str,
        path: str,
        body: dict[str, Any] | None,
        expected: dict[str, int],
    ) -> None:
        for role in ("viewer", "analyst", "admin"):
            kwargs: dict[str, Any] = {"headers": roles[role]}
            if body is not None:
                kwargs["json"] = body
            response = await getattr(client, method)(path, **kwargs)
            assert response.status_code == expected[role], (
                f"{role} {method} {path}: {response.status_code} {response.text}"
            )

    async def test_last_admin_cannot_be_demoted_or_deleted(
        self, client: httpx.AsyncClient, roles: dict[str, dict[str, str]]
    ) -> None:
        users = (await client.get("/users", headers=roles["admin"])).json()
        admin_id = next(u["id"] for u in users if u["username"] == "admin")
        assert (
            await client.patch(
                f"/users/{admin_id}", headers=roles["admin"], json={"role": "viewer"}
            )
        ).status_code == 422
        assert (
            await client.delete(f"/users/{admin_id}", headers=roles["admin"])
        ).status_code == 422

    async def test_deactivated_user_loses_access_immediately(
        self, client: httpx.AsyncClient, roles: dict[str, dict[str, str]]
    ) -> None:
        users = (await client.get("/users", headers=roles["admin"])).json()
        viewer_id = next(u["id"] for u in users if u["username"] == "viewer1")
        assert (
            await client.patch(
                f"/users/{viewer_id}", headers=roles["admin"], json={"is_active": False}
            )
        ).status_code == 200
        assert (await client.get("/detections", headers=roles["viewer"])).status_code == 401


class TestValidationAndSafety:
    async def test_unknown_fields_and_bad_values_rejected(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        extra = await client.post(
            "/firewall/block",
            headers=admin,
            json={"target": "1.2.3.4", "reason": "abcde", "exec": "id"},
        )
        assert extra.status_code == 422
        assert (
            await client.get("/detections", headers=admin, params={"limit": 100000})
        ).status_code == 422
        assert (
            await client.get("/detections", headers=admin, params={"severity": "apocalyptic"})
        ).status_code == 422

    async def test_safety_guard_refuses_and_audits(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        response = await client.post(
            "/firewall/block", headers=admin, json={"target": "127.0.0.1", "reason": "should fail"}
        )
        assert response.json()["outcome"] == "failed" and "safety guard" in response.json()["error"]
        audit = (await client.get("/audit", headers=admin, params={"action": "BLOCK_IP"})).json()
        assert audit["items"][0]["outcome"] == "failed"

    async def test_dry_run_default_and_prevention_confirmation(
        self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform
    ) -> None:
        block = await client.post(
            "/firewall/block",
            headers=admin,
            json={"target": "203.0.113.7", "reason": "dry run check"},
        )
        assert block.json()["outcome"] == "simulated"
        platform.settings.response.firewall_backend = (
            "nftables"  # a real backend configured via environment
        )
        changes = {"mode": "automatic", "dry_run": False}
        refused = await client.patch("/config/response", headers=admin, json={"changes": changes})
        assert refused.status_code == 422 and "ENABLE PREVENTION" in refused.json()["detail"]
        accepted = await client.patch(
            "/config/response",
            headers=admin,
            json={"changes": changes, "confirmation": "ENABLE PREVENTION"},
        )
        assert (
            accepted.status_code == 200 and accepted.json()["safety"]["prevention_active"] is True
        )
        executed = await client.post(
            "/firewall/block", headers=admin, json={"target": "203.0.113.8", "reason": "real block"}
        )
        assert executed.json()["outcome"] == "executed"
        assert (
            await client.get("/audit", headers=admin, params={"action": "ENABLE_PREVENTION"})
        ).json()["total"] == 1

    async def test_non_editable_settings_and_secret_redaction(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        response = await client.patch(
            "/config/storage", headers=admin, json={"changes": {"database_url": "sqlite://"}}
        )
        assert response.status_code == 422
        platform = client._transport.app.state.platform  # type: ignore[attr-defined]
        platform.settings.api.metrics_token = "metrics-token-value-0123456789abcdef"
        platform.settings.response.webhook_url = (
            "https://user:hunter2@hooks.example.com/services/T000/B000/SECRETPATH?sig=abc"
        )
        view = (await client.get("/config", headers=admin)).json()
        text = str(view)
        for secret in (
            "x" * 48,
            "Correct-Horse-Battery-2026",
            "metrics-token-value",
            "hunter2",
            "SECRETPATH",
            "sig=abc",
        ):
            assert secret not in text, secret
        assert view["settings"]["api"]["jwt_secret"] == "[redacted]"
        assert view["settings"]["response"]["webhook_url"] == "https://hooks.example.com/…"

    async def test_webhook_secret_never_reaches_the_audit_log(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        url = "https://hooks.example.com/services/T000/B000/SECRETPATH?sig=abc"
        response = await client.patch(
            "/config/response", headers=admin, json={"changes": {"webhook_url": url}}
        )
        assert response.status_code == 200, response.text
        audit = await client.get("/audit", headers=admin, params={"action": "UPDATE_SETTINGS"})
        assert audit.status_code == 200, audit.text
        # Nothing of the secret path or query anywhere in the response.
        assert "SECRETPATH" not in audit.text and "sig=abc" not in audit.text
        # The change itself is recorded with the URL reduced to scheme and host. Parse it
        # and compare each part: a substring match on the host would also accept a URL
        # that merely mentions it (``https://evil.test/hooks.example.com``).
        entries = [e for e in audit.json()["items"] if e["target"] == "response"]
        assert len(entries) == 1, entries
        recorded = urlsplit(entries[0]["details"]["changes"]["webhook_url"]["to"])
        assert (recorded.scheme, recorded.hostname, recorded.port) == (
            "https",
            "hooks.example.com",
            None,
        )
        assert (recorded.path, recorded.query, recorded.fragment) == ("/…", "", "")

    async def test_path_traversal_refused(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        for path in ("../../etc/passwd", "/etc/passwd", "fixtures/../../x.pcap"):
            assert (
                await client.get("/replay/files/inspect", headers=admin, params={"path": path})
            ).status_code == 422

    async def test_upload_streams_raw_body_after_auth_with_limits(
        self,
        client: httpx.AsyncClient,
        admin: dict[str, str],
        platform: Platform,
        tmp_path: Path,
    ) -> None:
        from sentinelx.testing import get_scenario, write_pcap

        capture = tmp_path / "scan.pcap"
        write_pcap(capture, get_scenario("tcp_port_scan", ports=30).frames)
        body = capture.read_bytes()
        octet = {"Content-Type": "application/octet-stream"}
        uploads = Path(platform.settings.capture.pcap_directory) / "uploads"

        # Unauthenticated: refused before the body is stored anywhere.
        anonymous = await client.post("/replay/upload", headers=octet, content=body)
        assert anonymous.status_code == 401
        assert not uploads.exists() or not any(uploads.iterdir())

        # Declared size over the limit: refused from the header alone.
        too_big = {**admin, **octet, "Content-Length": str(1024 * 1024 * 1024)}
        assert (
            await client.post("/replay/upload", headers=too_big, content=b"x")
        ).status_code == 413

        # Multipart (or any other type) is not accepted.
        files = {"file": ("scan.pcap", body, "application/octet-stream")}
        assert (await client.post("/replay/upload", headers=admin, files=files)).status_code == 415

        # Not a capture: rejected and removed.
        evil = await client.post(
            "/replay/upload",
            headers={**admin, **octet},
            params={"filename": "evil.pcap"},
            content=b"<?php system($_GET[1]); ?>",
        )
        assert evil.status_code == 422
        assert not any(uploads.iterdir())

        stored = await client.post(
            "/replay/upload",
            headers={**admin, **octet},
            params={"filename": "../../scan.pcap"},
            content=body,
        )
        assert stored.status_code == 201, stored.text
        result = stored.json()
        assert result["path"].startswith("uploads/") and ".." not in result["path"]
        assert not Path(result["path"]).is_absolute()
        assert str(tmp_path) not in stored.text  # no server paths leak
        assert result["packet_count"] == len(get_scenario("tcp_port_scan", ports=30).frames)

    async def test_upload_quota_is_enforced(
        self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform
    ) -> None:
        platform.settings.capture.upload_quota_mb = 1
        uploads = Path(platform.settings.capture.pcap_directory) / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        (uploads / "old.pcap").write_bytes(b"\0" * (1024 * 1024))
        full = await client.post(
            "/replay/upload",
            headers={**admin, "Content-Type": "application/octet-stream"},
            content=b"\xd4\xc3\xb2\xa1" + b"\0" * 20,
        )
        assert full.status_code == 507 and "full" in full.json()["detail"]

        # Streamed without Content-Length, larger than the space left: 413 while reading.
        platform.settings.capture.upload_quota_mb = 2

        async def stream() -> Any:
            yield b"\xd4\xc3\xb2\xa1" + b"\0" * 20
            for _ in range(24):
                yield b"\0" * 65536

        over = await client.post(
            "/replay/upload",
            headers={**admin, "Content-Type": "application/octet-stream"},
            content=stream(),
        )
        assert over.status_code == 413, over.text
        assert [p.name for p in uploads.iterdir()] == ["old.pcap"]  # partial file removed

    async def test_security_headers(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        headers = (await client.get("/detections", headers=admin)).headers
        assert (
            headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
        )
        assert "default-src 'none'" in headers["content-security-policy"]

    async def test_cors_only_for_configured_origins(self, client: httpx.AsyncClient) -> None:
        preflight = {"Access-Control-Request-Method": "GET"}
        allowed = await client.options(
            "/detections", headers={"Origin": "http://localhost:3000", **preflight}
        )
        denied = await client.options(
            "/detections", headers={"Origin": "https://evil.example", **preflight}
        )
        assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert "access-control-allow-origin" not in denied.headers


async def test_rate_limit(tmp_path: Path) -> None:
    from sentinelx.api.app import create_app

    platform = Platform(make_settings(tmp_path, rate_limit_requests=5))
    await platform.start()
    try:
        transport = httpx.ASGITransport(app=create_app(platform.settings, platform=platform))
        async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as http:
            codes = [(await http.get("/detections")).status_code for _ in range(8)]
        assert codes[:5] == [401] * 5 and codes[5:] == [429] * 3
    finally:
        await platform.stop()


class TestWorkflows:
    async def test_fixture_replay_incident_and_isolation(
        self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform
    ) -> None:
        generated = (
            await client.post("/replay/scenarios/mixed_intrusion", headers=admin, json={})
        ).json()
        replay = (
            await client.post("/replay", headers=admin, json={"path": generated["path"]})
        ).json()
        if platform.replay is None:
            raise RuntimeError("replay service missing")
        await platform.replay.wait(replay["replay_id"])
        record = (await client.get(f"/replay/{replay['replay_id']}", headers=admin)).json()
        assert record["status"] == "completed" and record["report"]["incident_count"] == 1
        assert all(d["outcome"] in ("skipped", "simulated") for d in record["report"]["decisions"])
        # A completed replay's results are already stored: no waiting for the persister.
        incidents = (
            await client.get("/incidents", headers=admin, params={"replay_id": replay["replay_id"]})
        ).json()
        detail = (
            await client.get(f"/incidents/{incidents['items'][0]['incident_id']}", headers=admin)
        ).json()
        assert detail["title"] == "Potential host compromise attempt" and detail["detections"]
        assert detail["detections"][0]["evidence"] and detail["risk"]["rationale"]
        assert (await client.get("/incidents", headers=admin)).json()["total"] == 0

    async def test_rule_lifecycle(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        definition = (
            "rule:\n  name: Api Brute Rule\n  condition: destination_port == 22 and short_sessions >= 20\n"
            "  within: 60s\n  severity: high\n  action: alert\n"
        )
        tested = (
            await client.post(
                "/rules/test",
                headers=admin,
                json={"definition": definition, "scenario": "ssh_brute_force"},
            )
        ).json()
        assert tested["matched"] and tested["evidence"]
        assert (
            await client.post("/rules", headers=admin, json={"definition": definition})
        ).status_code == 201
        toggled = await client.patch(
            "/rules/api_brute_rule/enabled", headers=admin, json={"enabled": False}
        )
        assert toggled.json()["enabled"] is False
        unsafe = definition.replace("action: alert", "action: block_ip").replace(
            " and short_sessions >= 20", ""
        )
        rejected = await client.put(
            "/rules/api_brute_rule", headers=admin, json={"definition": unsafe}
        )
        assert rejected.status_code == 422 and any(
            "count threshold" in p for p in rejected.json()["problems"]
        )
        assert (
            await client.delete("/rules/ssh_brute_force", headers=admin)
        ).status_code == 422  # file rule
        assert (await client.delete("/rules/api_brute_rule", headers=admin)).status_code == 204

    async def test_triage_threats_and_analytics(
        self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform
    ) -> None:
        from sentinelx.capture import MockCapture
        from sentinelx.testing import get_scenario, shift_to

        if platform.pipeline is None:
            raise RuntimeError("pipeline missing")
        frames = shift_to(get_scenario("mixed_intrusion").frames, time.time())
        await platform.pipeline.run(MockCapture(frames))
        detections = await eventually(
            lambda: client.get("/detections", headers=admin), lambda body: body["total"] >= 3
        )
        detection_id = detections["items"][0]["detection_id"]
        triaged = await client.patch(
            f"/detections/{detection_id}", headers=admin, json={"status": "false_positive"}
        )
        assert triaged.status_code == 200
        incident = (await client.get("/incidents", headers=admin)).json()["items"][0]
        updated = await client.patch(
            f"/incidents/{incident['incident_id']}",
            headers=admin,
            json={"status": "investigating", "assigned_to": "admin"},
        )
        assert updated.json()["status"] == "investigating"
        threats = (await client.get("/threats", headers=admin)).json()
        assert threats[0]["source_ip"] == "203.0.113.200" and threats[0]["detections"] >= 3
        analytics = (await client.get("/stats/analytics", headers=admin)).json()
        assert analytics["false_positives"] == 1 and analytics["timeline"]

    async def test_resolving_an_incident_stops_live_correlation_into_it(
        self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform
    ) -> None:
        from sentinelx.capture import MockCapture
        from sentinelx.testing import get_scenario, shift_to

        if platform.pipeline is None:
            raise RuntimeError("pipeline missing")
        await platform.pipeline.run(
            MockCapture(shift_to(get_scenario("mixed_intrusion").frames, time.time() - 30))
        )
        listed = await eventually(
            lambda: client.get("/incidents", headers=admin), lambda body: body["total"] >= 1
        )
        incident_id = listed["items"][0]["incident_id"]
        resolved = await client.patch(
            f"/incidents/{incident_id}", headers=admin, json={"status": "resolved"}
        )
        assert resolved.status_code == 200
        assert incident_id not in {
            i.incident_id for i in platform.pipeline.correlation.open_incidents()
        }
        # The same attacker again (cooldown off, so it is reported again): a new
        # incident, and the resolved one stays resolved.
        platform.settings.detection.detection_cooldown_seconds = 0
        await platform.pipeline.run(
            MockCapture(shift_to(get_scenario("mixed_intrusion", seed=44).frames, time.time()))
        )
        again = await eventually(
            lambda: client.get("/incidents", headers=admin), lambda body: body["total"] >= 2
        )
        assert again["total"] == 2
        old = (await client.get(f"/incidents/{incident_id}", headers=admin)).json()
        assert old["status"] == "resolved"


async def eventually(
    request: Callable[[], Awaitable[httpx.Response]],
    ready: Callable[[Any], bool],
    *,
    wait_seconds: float = 15.0,
) -> Any:
    """Poll until the persister has flushed; slow machines (emulated ARM64) need longer."""
    deadline = time.monotonic() + wait_seconds
    while True:
        body = (await request()).json()
        if ready(body) or time.monotonic() > deadline:
            return body
        await asyncio.sleep(0.05)


def test_websocket_ticket_flow(tmp_path: Path) -> None:
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from sentinelx.api.app import create_app
    from sentinelx.events.bus import EventType

    app = create_app(make_settings(tmp_path))
    with TestClient(app) as http:
        token = http.post(
            "/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        def ticket() -> str:
            return str(http.post("/api/v1/auth/ws-ticket", headers=headers).json()["ticket"])

        with (
            pytest.raises(WebSocketDisconnect) as bad_ticket,
            http.websocket_connect("/api/v1/ws/events?ticket=bogus") as ws,
        ):
            ws.receive_json()
        assert bad_ticket.value.code == 4401

        with (
            pytest.raises(WebSocketDisconnect) as bad_origin,
            http.websocket_connect(
                f"/api/v1/ws/events?ticket={ticket()}", headers={"origin": "https://evil.example"}
            ) as ws,
        ):
            ws.receive_json()
        assert bad_origin.value.code == 1008

        issued = ticket()
        with http.websocket_connect(
            f"/api/v1/ws/events?ticket={issued}&types=detection.created"
        ) as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello" and hello["payload"]["subscribed"] == [
                "detection.created"
            ]
            bus = app.state.platform.bus
            http.portal.call(bus.publish, EventType.PACKET_STATS, {"frames": 1})  # filtered out
            http.portal.call(bus.publish, EventType.DETECTION_CREATED, {"detection_id": "abc"})
            message = ws.receive_json()
            assert (
                message["type"] == "detection.created"
                and message["payload"]["detection_id"] == "abc"
            )

        with (
            pytest.raises(WebSocketDisconnect) as reused,
            http.websocket_connect(f"/api/v1/ws/events?ticket={issued}") as ws,
        ):
            ws.receive_json()
        assert reused.value.code == 4401


def test_websocket_survives_idle_pings_and_drops_deactivated_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a read cancelled at each ping interval closed the event stream."""
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    import sentinelx.api.websocket as ws_module
    from sentinelx.api.app import create_app
    from sentinelx.events.bus import EventType
    from sentinelx.storage.repositories import UserRepository

    monkeypatch.setattr(ws_module, "_PING_INTERVAL", 0.2)
    app = create_app(make_settings(tmp_path))
    with TestClient(app) as http:
        token = http.post(
            "/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        issued = http.post("/api/v1/auth/ws-ticket", headers=headers).json()["ticket"]
        platform = app.state.platform
        with http.websocket_connect(f"/api/v1/ws/events?ticket={issued}") as ws:
            assert ws.receive_json()["type"] == "hello"
            assert ws.receive_json()["type"] == "ping"
            assert ws.receive_json()["type"] == "ping"
            http.portal.call(platform.bus.publish, EventType.DETECTION_CREATED, {"n": 1})
            while (message := ws.receive_json())["type"] == "ping":
                pass
            assert message["type"] == "detection.created"

            async def deactivate() -> None:
                async with platform.database.session() as session:
                    user = await UserRepository(session).by_username("admin")
                    assert user is not None
                    user.is_active = False

            http.portal.call(deactivate)
            with pytest.raises(WebSocketDisconnect) as closed:
                while True:
                    ws.receive_json()
            assert closed.value.code == 4401


def test_websocket_busy_stream_still_rechecks_the_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stream that never goes idle must not escape the deactivation check."""
    import asyncio

    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    import sentinelx.api.websocket as ws_module
    from sentinelx.api.app import create_app
    from sentinelx.events.bus import EventType
    from sentinelx.storage.repositories import UserRepository

    monkeypatch.setattr(ws_module, "_PING_INTERVAL", 0.3)
    app = create_app(make_settings(tmp_path))
    with TestClient(app) as http:
        token = http.post(
            "/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        issued = http.post("/api/v1/auth/ws-ticket", headers=headers).json()["ticket"]
        platform = app.state.platform

        async def publish_forever() -> None:
            while True:
                await platform.bus.publish(EventType.DETECTION_CREATED, {"n": 1})
                await asyncio.sleep(0.02)

        async def deactivate() -> None:
            async with platform.database.session() as session:
                user = await UserRepository(session).by_username("admin")
                assert user is not None
                user.is_active = False

        with http.websocket_connect(f"/api/v1/ws/events?ticket={issued}") as ws:
            assert ws.receive_json()["type"] == "hello"
            publisher = http.portal.start_task_soon(publish_forever)
            try:
                http.portal.call(deactivate)
                pings = 0
                with pytest.raises(WebSocketDisconnect) as closed:
                    for _ in range(2000):
                        pings += ws.receive_json()["type"] == "ping"
                assert closed.value.code == 4401
                assert pings == 0  # the stream was busy the whole time
            finally:
                publisher.cancel()
