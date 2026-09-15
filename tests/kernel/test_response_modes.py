"""Automatic response against real netfilter: duplicates, rate limits and escalation.

Runs only inside ``make test-kernel`` (a private network namespace); see conftest.
"""

from __future__ import annotations

import pytest

from sentinelx.common.enums import ActionType, ResponseMode, RiskBand, Severity, ThreatCategory
from sentinelx.common.models import Detection, RiskAssessment
from sentinelx.config.settings import ResponseSettings, ScoringSettings
from sentinelx.firewall import create_firewall
from sentinelx.response.engine import ResponseEngine
from sentinelx.response.safety import SafetyGuard
from tests.kernel.conftest import ATTACKER
from tests.kernel.test_firewall import delivered

HIGH_RISK = RiskAssessment(score=99, band=RiskBand.CRITICAL, contributions={}, rationale=[])


def detection(action: ActionType) -> Detection:
    return Detection(
        detector="kernel_test",
        category=ThreatCategory.DENIAL_OF_SERVICE,
        severity=Severity.CRITICAL,
        confidence=0.9,
        title="kernel test",
        description="",
        source_ip=ATTACKER,
        recommended_action=action,
        recommended_duration_seconds=120,
    )


@pytest.mark.parametrize("backend", ["nftables", "iptables"])
async def test_automatic_duplicates_rate_limit_and_escalation(backend: str) -> None:
    settings = ResponseSettings(
        mode=ResponseMode.AUTOMATIC,
        dry_run=False,
        firewall_backend=backend,
        rate_limit_packets_per_second=20,
    )
    engine = ResponseEngine(
        settings,
        create_firewall(settings),
        scoring=ScoringSettings(),
        guard=SafetyGuard(settings, local_addresses=lambda: set()),
    )
    await engine.start()

    async def respond(action: ActionType) -> str:
        decisions = await engine.handle_detection(detection(action), HIGH_RISK)
        return next(d for d in decisions if d.action is action).outcome

    try:
        assert await respond(ActionType.TEMPORARY_BLOCK) == "executed"
        assert await respond(ActionType.TEMPORARY_BLOCK) == "skipped"  # duplicate
        assert delivered() == 0
        assert len(await engine.firewall.list_blocked()) == 1

        # Regression: a rate limit replaced the block (iptables delivered all 5 probes).
        assert await respond(ActionType.RATE_LIMIT) == "skipped"
        assert delivered() == 0
        (entry,) = await engine.blocked(refresh=True)
        assert not entry.rate_limited

        await engine.manual_action(ActionType.UNBLOCK_IP, ATTACKER, actor="t", reason="t")
        assert delivered() == 5

        assert await respond(ActionType.RATE_LIMIT) == "executed"
        assert delivered(400, port=7002) < 100
        assert await respond(ActionType.RATE_LIMIT) == "skipped"

        # Regression: a rate-limited source could never be escalated to a block.
        assert await respond(ActionType.TEMPORARY_BLOCK) == "executed"
        assert delivered() == 0

        await engine.manual_action(ActionType.UNBLOCK_IP, ATTACKER, actor="t", reason="t")
        assert delivered(400, port=7003) == 400  # neither block nor rate limit remains
    finally:
        await engine.stop()
        await engine.firewall.teardown()
