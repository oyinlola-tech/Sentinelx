"""Regression tests for the security audit: races, lockout abuse, token revocation,
proxy address handling and input that used to exhaust memory."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from sentinelx.api.app import create_app
from sentinelx.services.platform import Platform
from tests.api.conftest import ADMIN_PASSWORD, login


@asynccontextmanager
async def client_from(platform: Platform, address: str) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(platform.settings, platform=platform)
    transport = httpx.ASGITransport(app=app, client=(address, 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver/api/v1") as http:
        yield http


class TestTokenRaces:
    async def test_concurrent_refreshes_with_one_token_yield_one_session(
        self, client: httpx.AsyncClient
    ) -> None:
        tokens = (
            await client.post("/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        ).json()
        results = await asyncio.gather(
            *(
                client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
                for _ in range(5)
            )
        )
        assert sum(r.status_code == 200 for r in results) <= 1
        # Whatever won, the family is revoked once reuse was seen.
        for response in results:
            if response.status_code == 200:
                again = await client.post(
                    "/auth/refresh", json={"refresh_token": response.json()["refresh_token"]}
                )
                assert again.status_code == 401

    async def test_websocket_ticket_redeems_once_under_concurrency(
        self, platform: Platform, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        ticket = (await client.post("/auth/ws-ticket", headers=admin)).json()["ticket"]
        outcomes = await asyncio.gather(
            *(platform.auth.redeem_ws_ticket(ticket) for _ in range(5)), return_exceptions=True
        )
        assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1

    async def test_logout_revokes_the_access_token_immediately(
        self, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        assert (await client.post("/auth/logout", headers=admin)).status_code == 204
        assert (await client.get("/auth/me", headers=admin)).status_code == 401

    async def test_password_change_ends_other_sessions_but_not_the_callers_new_one(
        self, client: httpx.AsyncClient
    ) -> None:
        other = (
            await client.post("/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        ).json()
        await asyncio.sleep(1.1)  # access-token cut-off has one-second resolution
        caller = await login(client)
        changed = await client.post(
            "/auth/change-password",
            headers=caller,
            json={
                "current_password": ADMIN_PASSWORD,
                "new_password": "A-much-better-passphrase-77",
            },
        )
        assert changed.status_code == 200
        new_session = changed.json()
        # The other session's access token stops working now, not when it expires.
        stale = {"Authorization": f"Bearer {other['access_token']}"}
        assert (await client.get("/auth/me", headers=stale)).status_code == 401
        # Its refresh token is refused without being treated as theft...
        assert (
            await client.post("/auth/refresh", json={"refresh_token": other["refresh_token"]})
        ).status_code == 401
        # ...so the session the password was changed from keeps working.
        refreshed = await client.post(
            "/auth/refresh", json={"refresh_token": new_session["refresh_token"]}
        )
        assert refreshed.status_code == 200


class TestLockout:
    async def test_failures_from_one_address_do_not_lock_the_owner_elsewhere(
        self, platform: Platform
    ) -> None:
        threshold = platform.settings.api.lockout_threshold
        async with client_from(platform, "198.51.100.66") as attacker:
            for _ in range(threshold):
                await attacker.post(
                    "/auth/login", json={"username": "admin", "password": "wrong-password-xx"}
                )
            locked = await attacker.post(
                "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
            )
            assert locked.status_code == 423
        async with client_from(platform, "192.0.2.10") as owner:
            assert (await login(owner))["Authorization"].startswith("Bearer ")

    async def test_distributed_guessing_locks_the_account(self, platform: Platform) -> None:
        from sentinelx.services.auth import ACCOUNT_LOCK_MULTIPLIER

        threshold = platform.settings.api.lockout_threshold
        for index in range(threshold * ACCOUNT_LOCK_MULTIPLIER):
            async with client_from(platform, f"203.0.113.{index + 1}") as guesser:
                response = await guesser.post(
                    "/auth/login", json={"username": "admin", "password": "wrong-password-xx"}
                )
                assert response.status_code == 401
        async with client_from(platform, "192.0.2.10") as owner:
            response = await owner.post(
                "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
            )
            assert response.status_code == 423


class TestProxyAddresses:
    async def test_forged_leftmost_forwarded_address_is_not_believed(
        self, platform: Platform
    ) -> None:
        from types import SimpleNamespace

        from starlette.requests import Request

        from sentinelx.api.security import client_ip

        platform.settings.api.trusted_proxies = ["127.0.0.1/32", "10.0.0.0/24"]

        def resolve(peer: str, forwarded: str) -> str:
            scope = {
                "type": "http",
                "client": (peer, 1234),
                "headers": [(b"x-forwarded-for", forwarded.encode())],
                "app": SimpleNamespace(state=SimpleNamespace(platform=platform)),
            }
            return client_ip(Request(scope))

        # The client claims 10.9.9.9; the trusted proxy appended the real peer.
        assert resolve("127.0.0.1", "10.9.9.9, 198.51.100.7") == "198.51.100.7"
        # Two trusted hops: skip both, take the first untrusted address from the right.
        assert resolve("127.0.0.1", "6.6.6.6, 198.51.100.8, 10.0.0.5") == "198.51.100.8"
        # From an untrusted peer the header is ignored entirely.
        assert resolve("203.0.113.1", "127.0.0.1") == "203.0.113.1"

    async def test_metrics_are_not_served_to_proxied_requests_without_a_token(
        self, client: httpx.AsyncClient
    ) -> None:
        direct = await client.get("/metrics")
        assert direct.status_code == 200
        proxied = await client.get("/metrics", headers={"X-Forwarded-For": "203.0.113.9"})
        assert proxied.status_code == 403

    async def test_non_ascii_metrics_token_is_rejected_not_a_server_error(
        self, platform: Platform, client: httpx.AsyncClient
    ) -> None:
        platform.settings.api.metrics_token = "m" * 32
        response = await client.get(
            "/metrics", headers={"Authorization": "Bearer é".encode("latin-1")}
        )
        assert response.status_code == 401
        # A non-ASCII token sent correctly (UTF-8 on the wire) must still match.
        platform.settings.api.metrics_token = "métriques-" + "m" * 32
        correct = await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {platform.settings.api.metrics_token}".encode()},
        )
        assert correct.status_code == 200


class TestResourceExhaustion:
    async def test_yaml_alias_expansion_is_rejected(
        self, client: httpx.AsyncClient, roles: dict[str, dict[str, str]]
    ) -> None:
        bomb = (
            "rule:\n  name: Bomb Rule\n  condition: ttl > 1\n  tests:\n"
            "    - scenario: normal_traffic\n      expect: no_match\n"
            "      params: {a: &a [1,1,1,1,1,1,1,1,1], b: [*a,*a,*a,*a,*a,*a,*a,*a,*a]}\n"
        )
        response = await client.post(
            "/rules/validate", headers=roles["analyst"], json={"definition": bomb}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is False and any("aliases" in p for p in body["problems"])
        assert len(response.content) < 10_000

    async def test_oversized_scenario_parameters_are_refused_before_generation(
        self, client: httpx.AsyncClient, roles: dict[str, dict[str, str]]
    ) -> None:
        for params in (
            {"packet_count": 10**12},
            {"target": "not-an-ip"},
            {"unknown": 1},
            {"packet_count": -5},
        ):
            name = "tcp_port_scan" if "target" in params else "normal_traffic"
            response = await client.post(
                f"/replay/scenarios/{name}", headers=roles["analyst"], json={"params": params}
            )
            assert response.status_code == 422, (params, response.text)


class TestPreventionSettings:
    async def test_allowlist_can_be_extended_while_prevention_is_active(
        self, platform: Platform, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        platform.settings.response.firewall_backend = "nftables"
        enabled = await client.patch(
            "/config/response",
            headers=admin,
            json={
                "changes": {"mode": "automatic", "dry_run": False},
                "confirmation": "ENABLE PREVENTION",
            },
        )
        assert enabled.status_code == 200, enabled.text
        extended = await client.put(
            "/firewall/allowlist", headers=admin, json={"networks": ["198.51.100.0/24"]}
        )
        assert extended.status_code == 200, extended.text
        assert platform.settings.prevention_active

    async def test_environment_safety_posture_beats_stored_override(
        self, tmp_path: object, platform: Platform
    ) -> None:
        from sentinelx.config.settings import ResponseSettings
        from sentinelx.services.config import ConfigService
        from sentinelx.storage.repositories import SettingRepository

        async with platform.database.session() as session:
            await SettingRepository(session).set(
                "response", {"mode": "automatic", "dry_run": False}, "admin"
            )
        # The environment explicitly asks for dry run: that must win on restart.
        platform.settings.response = ResponseSettings(dry_run=True, firewall_backend="nftables")
        service = ConfigService(platform.settings, platform.database, platform.audit, platform.bus)
        await service.load_overrides()
        assert platform.settings.response.dry_run is True
        assert not platform.settings.prevention_active

    async def test_turning_dry_run_off_requires_confirmation_and_changes_the_banner(
        self, platform: Platform, client: httpx.AsyncClient, admin: dict[str, str]
    ) -> None:
        platform.settings.response.firewall_backend = "nftables"
        refused = await client.patch(
            "/config/response", headers=admin, json={"changes": {"dry_run": False}}
        )
        assert refused.status_code == 422 and "ENABLE PREVENTION" in refused.json()["detail"]
        assert platform.settings.response.dry_run is True
        accepted = await client.patch(
            "/config/response",
            headers=admin,
            json={"changes": {"dry_run": False}, "confirmation": "ENABLE PREVENTION"},
        )
        assert accepted.status_code == 200
        banner = platform.settings.safety_banner()
        # Still detect_only, but manual blocks are real: the banner must say so.
        assert banner.startswith("MANUAL BLOCKS ENFORCED") and "nftables" in banner


class TestReplayParity:
    async def test_replay_pipeline_runs_the_same_detectors_as_live(
        self, platform: Platform
    ) -> None:
        platform.settings.anomaly.enabled = True
        from sentinelx.assembly import attach_anomaly_detectors

        live = platform.require()[0]
        attach_anomaly_detectors(live, platform.settings)  # fixture disables anomaly
        _, _, replay, _ = platform.require()
        replayed = replay._isolated_pipeline("parity")
        platform.rules.attach(replayed.detection)
        await platform.rules.apply()
        names = lambda pipeline: sorted(d.name for d in pipeline.detection.detectors)  # noqa: E731
        assert names(replayed) == names(live)
        assert "statistical_anomaly" in names(replayed)
        assert replayed.intel is platform.intel
        platform.rules.engines.remove(replayed.detection)


class TestOperatorProtection:
    async def test_admin_cannot_block_their_own_workstation(self, platform: Platform) -> None:
        async with client_from(platform, "198.51.100.23") as workstation:
            headers = await login(workstation)
            refused = await workstation.post(
                "/firewall/block",
                headers=headers,
                json={"target": "198.51.100.23", "reason": "oops"},
            )
            body = refused.json()
            assert body["outcome"] == "failed" and "operator" in body["error"]
            other = await workstation.post(
                "/firewall/block",
                headers=headers,
                json={"target": "203.0.113.99", "reason": "unrelated scanner"},
            )
            assert other.status_code == 200, other.text
            assert other.json()["outcome"] == "simulated"  # dry run default
