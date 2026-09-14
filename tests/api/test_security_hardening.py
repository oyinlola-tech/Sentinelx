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
