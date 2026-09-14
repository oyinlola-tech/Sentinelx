"""Firewall enforcement against real netfilter, verified with real traffic."""

from __future__ import annotations

import asyncio
import socket
import subprocess

import pytest

from sentinelx.common.enums import ActionType, ResponseMode
from sentinelx.config.settings import ResponseSettings, ScoringSettings
from sentinelx.firewall import create_firewall
from sentinelx.response.engine import ResponseEngine
from sentinelx.response.safety import SafetyGuard
from tests.kernel.conftest import ATTACKER, VICTIM


def delivered(count: int = 5, port: int = 7000) -> int:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client,
    ):
        server.bind((VICTIM, port))
        server.settimeout(0.5)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        client.bind((ATTACKER, 0))
        for _ in range(count):
            client.sendto(b"probe", (VICTIM, port))
        received = 0
        try:
            while received < count:
                server.recvfrom(64)
                received += 1
        except TimeoutError:
            pass
        return received


async def engine_for(backend: str) -> ResponseEngine:
    settings = ResponseSettings(
        mode=ResponseMode.MANUAL_APPROVAL,
        dry_run=False,
        firewall_backend=backend,  # type: ignore[arg-type]
        rate_limit_packets_per_second=20,
    )
    # The test addresses are assigned to this (namespaced) host on purpose.
    guard = SafetyGuard(settings, local_addresses=lambda: set())
    engine = ResponseEngine(
        settings, create_firewall(settings), scoring=ScoringSettings(), guard=guard
    )
    await engine.start()
    return engine


@pytest.mark.parametrize("backend", ["nftables", "iptables"])
async def test_block_unblock_expiry_reblock_rate_limit_teardown(backend: str) -> None:
    engine = await engine_for(backend)
    act = engine.manual_action
    try:
        assert delivered() == 5

        assert (
            await act(ActionType.BLOCK_IP, ATTACKER, actor="t", reason="t")
        ).outcome == "executed"
        assert [e.network for e in await engine.firewall.list_blocked()] == [f"{ATTACKER}/32"]
        assert delivered() == 0

        assert (
            await act(ActionType.UNBLOCK_IP, ATTACKER, actor="t", reason="t")
        ).outcome == "executed"
        assert delivered() == 5  # restoration

        await act(ActionType.TEMPORARY_BLOCK, ATTACKER, actor="t", reason="t", duration=2)
        assert delivered() == 0
        await asyncio.sleep(3)
        await engine.expire_due()  # iptables needs the reaper; nftables expired in the kernel
        assert delivered() == 5

        # Regression: a permanent block over a temporary one kept the old expiry.
        await act(ActionType.TEMPORARY_BLOCK, ATTACKER, actor="t", reason="t", duration=2)
        await act(ActionType.BLOCK_IP, ATTACKER, actor="t", reason="t")
        await asyncio.sleep(3)
        await engine.expire_due()
        assert delivered() == 0
        await act(ActionType.UNBLOCK_IP, ATTACKER, actor="t", reason="t")

        await act(ActionType.RATE_LIMIT, ATTACKER, actor="t", reason="t", duration=60)
        assert delivered(400, port=7001) < 100
        await act(ActionType.UNBLOCK_IP, ATTACKER, actor="t", reason="t")
        assert delivered(400, port=7001) == 400
    finally:
        await engine.stop()
        await engine.firewall.teardown()
    tables, chains = await asyncio.to_thread(_ruleset)
    assert "sentinelx" not in tables and "SENTINELX" not in chains


def _ruleset() -> tuple[str, str]:
    tables = subprocess.run(["nft", "list", "tables"], capture_output=True, text=True, check=False)  # noqa: S607
    chains = subprocess.run(["iptables", "-S"], capture_output=True, text=True, check=False)  # noqa: S607
    return tables.stdout, chains.stdout
