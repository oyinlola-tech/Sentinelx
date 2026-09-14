from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinelx.api.app import create_app
from sentinelx.common.enums import UserRole
from sentinelx.config.settings import Settings
from sentinelx.firewall import MemoryFirewall
from sentinelx.services.platform import Platform

ADMIN_PASSWORD = "Correct-Horse-Battery-2026"
REPO_RULES = Path(__file__).resolve().parents[2] / "rules"


def make_settings(tmp_path: Path, **api: Any) -> Settings:
    """Isolated settings: a file SQLite database, and an unreachable Redis so the
    degraded in-process path is what gets exercised (deterministic, no services)."""
    return Settings(
        storage={
            "database_url": f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
            "redis_url": "redis://127.0.0.1:1/0",
            "flush_interval_seconds": 0.05,
        },
        api={
            "bootstrap_admin_password": ADMIN_PASSWORD,
            "jwt_secret": "x" * 48,
            "rate_limit_requests": 10_000,
            "cors_origins": ["http://localhost:3000"],
            **api,
        },
        capture={"pcap_directory": tmp_path / "pcaps"},
        rules_directory=REPO_RULES,
        anomaly={"enabled": False},
    )


@pytest.fixture
async def platform(tmp_path: Path) -> AsyncIterator[Platform]:
    instance = Platform(make_settings(tmp_path), firewall=MemoryFirewall())
    await instance.start()
    if instance.pipeline is None:
        raise RuntimeError("platform failed to start")
    instance.pipeline.response.guard._local_addresses = lambda: set()
    yield instance
    await instance.stop()


@pytest.fixture
async def client(platform: Platform) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(platform.settings, platform=platform)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver/api/v1") as http:
        yield http


async def login(
    client: httpx.AsyncClient, username: str = "admin", password: str = ADMIN_PASSWORD
) -> dict[str, str]:
    response = await client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
async def admin(client: httpx.AsyncClient) -> dict[str, str]:
    return await login(client)


@pytest.fixture
async def roles(
    client: httpx.AsyncClient, platform: Platform, admin: dict[str, str]
) -> dict[str, dict[str, str]]:
    headers = {"admin": admin}
    for role in (UserRole.ANALYST, UserRole.VIEWER):
        await platform.auth.create_user(f"{role.value}1", f"{role.value}-Passphrase-2026", role)
        headers[role.value] = await login(client, f"{role.value}1", f"{role.value}-Passphrase-2026")
    return headers
