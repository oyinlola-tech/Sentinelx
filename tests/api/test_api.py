from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinelx.services.platform import Platform
from tests.api.conftest import ADMIN_PASSWORD, make_settings


class TestAuthentication:
    async def test_protected_endpoints_require_authentication(self, client: httpx.AsyncClient) -> None:
        for path in ("/system/status", "/detections", "/incidents", "/rules", "/firewall", "/audit", "/config"):
            assert (await client.get(path)).status_code == 401, path

    async def test_health_is_public_and_minimal(self, client: httpx.AsyncClient) -> None:
        body = (await client.get("/system/health")).json()
        assert set(body) == {"status", "version"}

    async def test_login_failure_is_uniform_for_unknown_and_known_users(self, client: httpx.AsyncClient) -> None:
        unknown = await client.post("/auth/login", json={"username": "ghost", "password": "whatever-123456"})
        wrong = await client.post("/auth/login", json={"username": "admin", "password": "whatever-123456"})
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() == wrong.json()

    async def test_account_locks_after_repeated_failures(self, client: httpx.AsyncClient, platform: Platform) -> None:
        for _ in range(platform.settings.api.lockout_threshold):
            await client.post("/auth/login", json={"username": "admin", "password": "not-the-password-1"})
        locked = await client.post("/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert locked.status_code == 423
        assert "retry-after" in locked.headers

    async def test_tampered_forged_and_wrong_type_tokens_rejected(self, client: httpx.AsyncClient) -> None:
        import jwt

        good = await client.post("/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        access, refresh = good.json()["access_token"], good.json()["refresh_token"]
        head, payload, signature = access.split(".")
        tampered = f"{head}.{payload}.{signature[::-1]}"
        forged = jwt.encode(
            {"sub": "1", "type": "access", "jti": "x", "iat": 1, "exp": 9_999_999_999, "iss": "sentinelx", "role": "admin"},
            "not-the-server-secret-not-the-server-secret",
            algorithm="HS256",
        )
        unsigned = jwt.encode({"sub": "1", "type": "access", "jti": "x", "iat": 1, "exp": 9_999_999_999}, None, algorithm="none")
        for token in (tampered, refresh, forged, unsigned):
            assert (await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})).status_code == 401

    async def test_refresh_rotation_and_reuse_detection(self, client: httpx.AsyncClient) -> None:
        first = (await client.post("/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})).json()
        rotated = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert rotated.status_code == 200
        assert (await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})).status_code == 401
        # Reuse revoked the whole family, including the token the rotation issued.
        replay = await client.post("/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]})
        assert replay.status_code == 401

    async def test_browser_login_uses_httponly_cookies_and_enforces_csrf(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}, headers={"X-SentinelX-Client": "dashboard"}
        )
        assert response.json()["refresh_token"] is None
        cookies = response.headers.get_list("set-cookie")
        assert any(c.startswith("sx_access=") and "HttpOnly" in c and "samesite=strict" in c.lower() for c in cookies)
        csrf = response.json()["csrf_token"]
        assert (await client.get("/auth/me")).status_code == 200  # safe method via cookie
        body = {"target": "203.0.113.9", "reason": "csrf test"}
        assert (await client.post("/firewall/block", json=body)).status_code == 403
        assert (await client.post("/firewall/block", json=body, headers={"X-CSRF-Token": "forged"})).status_code == 403
        assert (await client.post("/firewall/block", json=body, headers={"X-CSRF-Token": csrf})).status_code == 200

    async def test_password_change_policy(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        weak = await client.post(
            "/auth/change-password", headers=admin, json={"current_password": ADMIN_PASSWORD, "new_password": "short"}
        )
        assert weak.status_code == 422
        ok = await client.post(
            "/auth/change-password",
            headers=admin,
            json={"current_password": ADMIN_PASSWORD, "new_password": "A-much-better-passphrase-77"},
        )
        assert ok.status_code == 204
        relogin = await client.post("/auth/login", json={"username": "admin", "password": "A-much-better-passphrase-77"})
        assert relogin.status_code == 200


MATRIX: list[tuple[str, str, dict[str, Any] | None, dict[str, int]]] = [
    ("get", "/detections", None, {"viewer": 200, "analyst": 200, "admin": 200}),
    ("get", "/audit", None, {"viewer": 403, "analyst": 200, "admin": 200}),
    ("get", "/config", None, {"viewer": 403, "analyst": 200, "admin": 200}),
    ("post", "/rules/validate", {"definition": "rule:\n  name: Test Rule\n  condition: ttl > 1\n"},
     {"viewer": 403, "analyst": 200, "admin": 200}),
    ("post", "/firewall/block", {"target": "203.0.113.50", "reason": "rbac test"},
     {"viewer": 403, "analyst": 403, "admin": 200}),
    ("patch", "/config/detection", {"changes": {"port_scan_unique_ports": 30}},
     {"viewer": 403, "analyst": 403, "admin": 200}),
    ("post", "/rules", {"definition": "rule:\n  name: Rbac Rule\n  condition: ttl > 1\n"},
     {"viewer": 403, "analyst": 403, "admin": 201}),
    ("get", "/users", None, {"viewer": 403, "analyst": 403, "admin": 200}),
    ("post", "/sensors/stop", None, {"viewer": 403, "analyst": 403, "admin": 200}),
]


class TestAuthorization:
    @pytest.mark.parametrize(("method", "path", "body", "expected"), MATRIX, ids=[f"{m} {p}" for m, p, _, _ in MATRIX])
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
            assert response.status_code == expected[role], f"{role} {method} {path}: {response.status_code} {response.text}"

    async def test_last_admin_cannot_be_demoted_or_deleted(self, client: httpx.AsyncClient, roles: dict[str, dict[str, str]]) -> None:
        users = (await client.get("/users", headers=roles["admin"])).json()
        admin_id = next(u["id"] for u in users if u["username"] == "admin")
        assert (await client.patch(f"/users/{admin_id}", headers=roles["admin"], json={"role": "viewer"})).status_code == 422
        assert (await client.delete(f"/users/{admin_id}", headers=roles["admin"])).status_code == 422

    async def test_deactivated_user_loses_access_immediately(self, client: httpx.AsyncClient, roles: dict[str, dict[str, str]]) -> None:
        users = (await client.get("/users", headers=roles["admin"])).json()
        viewer_id = next(u["id"] for u in users if u["username"] == "viewer1")
        assert (await client.patch(f"/users/{viewer_id}", headers=roles["admin"], json={"is_active": False})).status_code == 200
        assert (await client.get("/detections", headers=roles["viewer"])).status_code == 401


class TestValidationAndSafety:
    async def test_unknown_fields_and_bad_values_rejected(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        extra = await client.post("/firewall/block", headers=admin, json={"target": "1.2.3.4", "reason": "abcde", "exec": "id"})
        assert extra.status_code == 422
        assert (await client.get("/detections", headers=admin, params={"limit": 100000})).status_code == 422
        assert (await client.get("/detections", headers=admin, params={"severity": "apocalyptic"})).status_code == 422

    async def test_safety_guard_refuses_and_audits(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        response = await client.post("/firewall/block", headers=admin, json={"target": "127.0.0.1", "reason": "should fail"})
        assert response.json()["outcome"] == "failed" and "safety guard" in response.json()["error"]
        audit = (await client.get("/audit", headers=admin, params={"action": "BLOCK_IP"})).json()
        assert audit["items"][0]["outcome"] == "failed"

    async def test_dry_run_default_and_prevention_confirmation(
        self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform
    ) -> None:
        block = await client.post("/firewall/block", headers=admin, json={"target": "203.0.113.7", "reason": "dry run check"})
        assert block.json()["outcome"] == "simulated"
        platform.settings.response.firewall_backend = "nftables"  # a real backend configured via environment
        changes = {"mode": "automatic", "dry_run": False}
        refused = await client.patch("/config/response", headers=admin, json={"changes": changes})
        assert refused.status_code == 422 and "ENABLE PREVENTION" in refused.json()["detail"]
        accepted = await client.patch(
            "/config/response", headers=admin, json={"changes": changes, "confirmation": "ENABLE PREVENTION"}
        )
        assert accepted.status_code == 200 and accepted.json()["safety"]["prevention_active"] is True
        executed = await client.post("/firewall/block", headers=admin, json={"target": "203.0.113.8", "reason": "real block"})
        assert executed.json()["outcome"] == "executed"
        assert (await client.get("/audit", headers=admin, params={"action": "ENABLE_PREVENTION"})).json()["total"] == 1

    async def test_non_editable_settings_and_secret_redaction(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        response = await client.patch("/config/storage", headers=admin, json={"changes": {"database_url": "sqlite://"}})
        assert response.status_code == 422
        view = (await client.get("/config", headers=admin)).json()
        assert "jwt_secret" not in view["settings"]["api"]
        assert "bootstrap_admin_password" not in view["settings"]["api"]

    async def test_path_traversal_refused(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        for path in ("../../etc/passwd", "/etc/passwd", "fixtures/../../x.pcap"):
            assert (await client.get("/replay/files/inspect", headers=admin, params={"path": path})).status_code == 422

    async def test_upload_rejects_non_pcap(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        files = {"file": ("evil.pcap", b"<?php system($_GET[1]); ?>", "application/octet-stream")}
        assert (await client.post("/replay/upload", headers=admin, files=files)).status_code == 422

    async def test_security_headers(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        headers = (await client.get("/detections", headers=admin)).headers
        assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in headers["content-security-policy"]

    async def test_cors_only_for_configured_origins(self, client: httpx.AsyncClient) -> None:
        preflight = {"Access-Control-Request-Method": "GET"}
        allowed = await client.options("/detections", headers={"Origin": "http://localhost:3000", **preflight})
        denied = await client.options("/detections", headers={"Origin": "https://evil.example", **preflight})
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
        generated = (await client.post("/replay/scenarios/mixed_intrusion", headers=admin, json={})).json()
        replay = (await client.post("/replay", headers=admin, json={"path": generated["path"]})).json()
        if platform.replay is None:
            raise RuntimeError("replay service missing")
        await platform.replay.wait(replay["replay_id"])
        record = (await client.get(f"/replay/{replay['replay_id']}", headers=admin)).json()
        assert record["status"] == "completed" and record["report"]["incident_count"] == 1
        assert all(d["outcome"] in ("skipped", "simulated") for d in record["report"]["decisions"])
        await asyncio.sleep(0.3)
        incidents = (await client.get("/incidents", headers=admin, params={"replay_id": replay["replay_id"]})).json()
        detail = (await client.get(f"/incidents/{incidents['items'][0]['incident_id']}", headers=admin)).json()
        assert detail["title"] == "Potential host compromise attempt" and detail["detections"]
        assert detail["detections"][0]["evidence"] and detail["risk"]["rationale"]
        assert (await client.get("/incidents", headers=admin)).json()["total"] == 0

    async def test_rule_lifecycle(self, client: httpx.AsyncClient, admin: dict[str, str]) -> None:
        definition = (
            "rule:\n  name: Api Brute Rule\n  condition: destination_port == 22 and short_sessions >= 20\n"
            "  within: 60s\n  severity: high\n  action: alert\n"
        )
        tested = (await client.post("/rules/test", headers=admin, json={"definition": definition, "scenario": "ssh_brute_force"})).json()
        assert tested["matched"] and tested["evidence"]
        assert (await client.post("/rules", headers=admin, json={"definition": definition})).status_code == 201
        toggled = await client.patch("/rules/api_brute_rule/enabled", headers=admin, json={"enabled": False})
        assert toggled.json()["enabled"] is False
        unsafe = definition.replace("action: alert", "action: block_ip").replace(" and short_sessions >= 20", "")
        rejected = await client.put("/rules/api_brute_rule", headers=admin, json={"definition": unsafe})
        assert rejected.status_code == 422 and any("count threshold" in p for p in rejected.json()["problems"])
        assert (await client.delete("/rules/ssh_brute_force", headers=admin)).status_code == 422  # file rule
        assert (await client.delete("/rules/api_brute_rule", headers=admin)).status_code == 204

    async def test_triage_threats_and_analytics(self, client: httpx.AsyncClient, admin: dict[str, str], platform: Platform) -> None:
        from sentinelx.capture import MockCapture
        from sentinelx.testing import get_scenario

        if platform.pipeline is None:
            raise RuntimeError("pipeline missing")
        await platform.pipeline.run(MockCapture(get_scenario("mixed_intrusion").frames))
        await asyncio.sleep(0.3)
        detections = (await client.get("/detections", headers=admin)).json()
        assert detections["total"] >= 3
        detection_id = detections["items"][0]["detection_id"]
        triaged = await client.patch(f"/detections/{detection_id}", headers=admin, json={"status": "false_positive"})
        assert triaged.status_code == 200
        incident = (await client.get("/incidents", headers=admin)).json()["items"][0]
        updated = await client.patch(
            f"/incidents/{incident['incident_id']}", headers=admin, json={"status": "investigating", "assigned_to": "admin"}
        )
        assert updated.json()["status"] == "investigating"
        threats = (await client.get("/threats", headers=admin)).json()
        assert threats[0]["source_ip"] == "203.0.113.200" and threats[0]["detections"] >= 3
        analytics = (await client.get("/stats/analytics", headers=admin)).json()
        assert analytics["false_positives"] == 1 and analytics["timeline"]


def test_websocket_ticket_flow(tmp_path: Path) -> None:
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from sentinelx.api.app import create_app
    from sentinelx.events.bus import EventType

    app = create_app(make_settings(tmp_path))
    with TestClient(app) as http:
        token = http.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        def ticket() -> str:
            return str(http.post("/api/v1/auth/ws-ticket", headers=headers).json()["ticket"])

        with pytest.raises(WebSocketDisconnect) as bad_ticket, http.websocket_connect("/api/v1/ws/events?ticket=bogus") as ws:
            ws.receive_json()
        assert bad_ticket.value.code == 4401

        with pytest.raises(WebSocketDisconnect) as bad_origin, http.websocket_connect(
            f"/api/v1/ws/events?ticket={ticket()}", headers={"origin": "https://evil.example"}
        ) as ws:
            ws.receive_json()
        assert bad_origin.value.code == 1008

        issued = ticket()
        with http.websocket_connect(f"/api/v1/ws/events?ticket={issued}&types=detection.created") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello" and hello["payload"]["subscribed"] == ["detection.created"]
            bus = app.state.platform.bus
            http.portal.call(bus.publish, EventType.PACKET_STATS, {"frames": 1})  # filtered out
            http.portal.call(bus.publish, EventType.DETECTION_CREATED, {"detection_id": "abc"})
            message = ws.receive_json()
            assert message["type"] == "detection.created" and message["payload"]["detection_id"] == "abc"

        with pytest.raises(WebSocketDisconnect) as reused, http.websocket_connect(f"/api/v1/ws/events?ticket={issued}") as ws:
            ws.receive_json()
        assert reused.value.code == 4401
