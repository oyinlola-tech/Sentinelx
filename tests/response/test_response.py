from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from sentinelx.common.enums import ActionType, ResponseMode, RiskBand, Severity, ThreatCategory
from sentinelx.common.errors import FirewallError, SafetyViolationError
from sentinelx.common.models import Detection, Evidence, RiskAssessment
from sentinelx.common.netutils import parse_network
from sentinelx.config.settings import ResponseSettings, ScoringSettings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.firewall import MemoryFirewall
from sentinelx.firewall.base import CommandResult
from sentinelx.firewall.iptables import IptablesAdapter
from sentinelx.firewall.nftables import NftablesAdapter
from sentinelx.response.engine import ResponseEngine
from sentinelx.response.safety import SafetyGuard


def guard(
    settings: ResponseSettings, local: set[str] | None = None, active: int = 0
) -> SafetyGuard:
    return SafetyGuard(
        settings, local_addresses=lambda: local or set(), active_block_count=lambda: active
    )


class TestSafetyGuard:
    @pytest.mark.parametrize(
        "target",
        [
            "127.0.0.1",
            "::1",
            "169.254.10.10",
            "224.0.0.1",
            "0.0.0.0/0",
            "::/0",
            "10.0.0.0/8",
            "not-an-ip",
            "1.2.3.4; nft flush ruleset",
            "",
            "1.2.3.4\n",
        ],
    )
    def test_refuses_dangerous_targets(self, target: str) -> None:
        with pytest.raises(SafetyViolationError):
            guard(ResponseSettings()).check(target)

    def test_allows_ordinary_external_host_and_small_prefix(self) -> None:
        g = guard(ResponseSettings())
        assert str(g.check("203.0.113.5")) == "203.0.113.5/32"
        assert str(g.check("203.0.113.0/28")) == "203.0.113.0/28"

    def test_refuses_prefix_containing_this_host(self) -> None:
        with pytest.raises(SafetyViolationError, match="address of this host"):
            guard(ResponseSettings(), local={"192.0.2.10"}).check("192.0.2.0/28")

    def test_refuses_allowlist_and_management_overlap(self) -> None:
        g = guard(
            ResponseSettings(
                allowlist_networks=["198.51.100.0/24"], management_addresses=["192.0.2.50"]
            )
        )
        with pytest.raises(SafetyViolationError, match="allowlisted"):
            g.check("198.51.100.0/30")
        with pytest.raises(SafetyViolationError, match="management"):
            g.check("192.0.2.50")

    def test_refuses_when_block_limit_reached(self) -> None:
        with pytest.raises(SafetyViolationError, match="already active"):
            guard(ResponseSettings(max_blocked_addresses=5), active=5).check("203.0.113.5")

    def test_prefix_limit_is_configurable(self) -> None:
        with pytest.raises(SafetyViolationError, match="exceeds"):
            guard(ResponseSettings(max_block_prefix_hosts=1)).check("203.0.113.0/31")

    def test_evaluate_previews_without_raising_or_counting(self) -> None:
        g = guard(ResponseSettings())
        assert not g.evaluate("127.0.0.1").allowed and g.refusals == 0
        assert g.evaluate("203.0.113.9").allowed

    def test_allowlist_update_always_keeps_loopback(self) -> None:
        g = guard(ResponseSettings())
        g.update_allowlist(["198.51.100.0/24"])
        assert "127.0.0.0/8" in g.allowlist


def detection(
    action: ActionType = ActionType.TEMPORARY_BLOCK, source: str = "203.0.113.5"
) -> Detection:
    return Detection(
        detector="tcp_port_scan",
        category=ThreatCategory.RECONNAISSANCE,
        severity=Severity.CRITICAL,
        confidence=0.95,
        title="TCP port scan",
        description="d",
        source_ip=source,
        evidence=[Evidence("ports", 94, "94 ports")],
        recommended_action=action,
    )


def risk(score: float) -> RiskAssessment:
    return RiskAssessment(
        score=score,
        band=RiskBand.from_score(score),
        contributions={"severity": score},
        rationale=["x"],
    )


async def engine_for(
    mode: ResponseMode, dry_run: bool, **extra: object
) -> tuple[ResponseEngine, MemoryFirewall, list[dict[str, object]], EventBus]:
    settings = ResponseSettings(
        mode=mode, dry_run=dry_run, firewall_backend="null" if dry_run else "nftables", **extra
    )  # type: ignore[arg-type]
    firewall = MemoryFirewall()
    audit: list[dict[str, object]] = []

    async def sink(record: dict[str, object]) -> None:
        audit.append(record)

    bus = EventBus()
    engine = ResponseEngine(
        settings,
        firewall,
        scoring=ScoringSettings(auto_block_threshold=85),
        bus=bus,
        audit=sink,
        guard=guard(settings),
    )
    return engine, firewall, audit, bus


def outcome(decisions: list, action: ActionType) -> str:  # type: ignore[type-arg]
    return next(d.outcome for d in decisions if d.action is action)


class TestResponseModes:
    async def test_detect_only_never_touches_firewall(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=False)
        decisions = await engine.handle_detection(detection(), risk(99))
        assert outcome(decisions, ActionType.TEMPORARY_BLOCK) == "skipped"
        assert firewall.operations == [] and audit[0]["outcome"] == "skipped"

    async def test_automatic_dry_run_simulates(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.AUTOMATIC, dry_run=True)
        decisions = await engine.handle_detection(detection(), risk(99))
        assert outcome(decisions, ActionType.TEMPORARY_BLOCK) == "simulated"
        assert firewall.operations == [] and "DRY RUN" in audit[0]["reason"]  # type: ignore[operator]

    async def test_automatic_enforcing_blocks_and_publishes(self) -> None:
        engine, firewall, audit, bus = await engine_for(ResponseMode.AUTOMATIC, dry_run=False)
        events: list[str] = []
        async with bus.subscribe("t") as stream:
            decisions = await engine.handle_detection(detection(), risk(99))
            while len(events) < 2:
                events.append((await anext(stream)).type.value)
        assert outcome(decisions, ActionType.TEMPORARY_BLOCK) == "executed"
        assert firewall.operations == [("block", "203.0.113.5/32")]
        assert EventType.IP_BLOCKED.value in events and audit[0]["outcome"] == "executed"
        assert (await engine.blocked())[0].temporary

    async def test_below_threshold_is_not_applied_or_audited(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.AUTOMATIC, dry_run=False)
        decisions = await engine.handle_detection(detection(), risk(50))
        assert outcome(decisions, ActionType.TEMPORARY_BLOCK) == "skipped"
        assert firewall.operations == [] and audit == []

    async def test_automatic_refuses_unsafe_target_and_audits_refusal(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.AUTOMATIC, dry_run=False)
        decisions = await engine.handle_detection(detection(source="127.0.0.1"), risk(99))
        assert outcome(decisions, ActionType.TEMPORARY_BLOCK) == "failed"
        assert firewall.operations == [] and audit[0]["outcome"] == "failed"

    async def test_manual_approval_queues_then_executes_on_approve(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.MANUAL_APPROVAL, dry_run=False)
        decisions = await engine.handle_detection(detection(), risk(99))
        assert outcome(decisions, ActionType.TEMPORARY_BLOCK) == "pending_approval"
        assert firewall.operations == [] and len(engine.pending) == 1
        await engine.handle_detection(detection(), risk(99))
        assert len(engine.pending) == 1  # not queued twice
        action_id = next(iter(engine.pending))
        approved = await engine.approve(action_id, actor="admin")
        assert approved.outcome == "executed" and firewall.operations == [
            ("block", "203.0.113.5/32")
        ]
        assert audit[-1]["actor"] == "admin"

    async def test_expired_approval_request_cannot_be_approved(self) -> None:
        from dataclasses import replace as replace_field
        from datetime import UTC, datetime, timedelta

        from sentinelx.response.engine import PENDING_APPROVAL_TTL

        engine, firewall, _, _ = await engine_for(ResponseMode.MANUAL_APPROVAL, dry_run=False)
        await engine.handle_detection(detection(), risk(99))
        action_id, pending = next(iter(engine.pending.items()))
        stale = datetime.now(UTC) - PENDING_APPROVAL_TTL - timedelta(minutes=1)
        engine.pending[action_id] = replace_field(pending, created_at=stale)
        assert engine.pending_actions() == []
        with pytest.raises(KeyError):
            await engine.approve(action_id, actor="admin")
        assert firewall.operations == []

    async def test_reject_removes_pending_and_audits(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.MANUAL_APPROVAL, dry_run=False)
        await engine.handle_detection(detection(), risk(99))
        await engine.reject(next(iter(engine.pending)), actor="admin", reason="false positive")
        assert (
            engine.pending == {}
            and audit[-1]["action"] == "REJECT_RESPONSE"
            and firewall.operations == []
        )

    async def test_manual_block_honours_dry_run_and_safety(self) -> None:
        engine, firewall, _, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=True)
        simulated = await engine.manual_action(
            ActionType.BLOCK_IP, "203.0.113.7", actor="admin", reason="test"
        )
        assert simulated.outcome == "simulated" and firewall.operations == []
        refused = await engine.manual_action(
            ActionType.BLOCK_IP, "127.0.0.1", actor="admin", reason="oops"
        )
        assert refused.outcome == "failed" and "safety" in (refused.error or "")

    async def test_manual_block_and_unblock_when_enforcing(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=False)
        await engine.manual_action(ActionType.BLOCK_IP, "203.0.113.7", actor="admin", reason="scan")
        await engine.manual_action(
            ActionType.UNBLOCK_IP, "203.0.113.7", actor="admin", reason="cleared"
        )
        assert firewall.operations == [("block", "203.0.113.7/32"), ("unblock", "203.0.113.7/32")]
        assert [a["action"] for a in audit] == ["BLOCK_IP", "UNBLOCK_IP"]
        assert await engine.blocked() == []

    async def test_manual_duration_is_clamped_to_maximum(self) -> None:
        engine, _, _, _ = await engine_for(
            ResponseMode.DETECT_ONLY, dry_run=False, max_block_seconds=600
        )
        decision = await engine.manual_action(
            ActionType.TEMPORARY_BLOCK, "203.0.113.8", actor="a", reason="r", duration=99999
        )
        assert decision.duration_seconds == 600

    async def test_firewall_failure_is_reported_not_raised(self) -> None:
        engine, firewall, _audit, _ = await engine_for(ResponseMode.AUTOMATIC, dry_run=False)

        async def broken(*args: object, **kwargs: object) -> None:
            raise FirewallError("nft: permission denied")

        firewall.block = broken  # type: ignore[method-assign]
        decisions = await engine.handle_detection(detection(), risk(99))
        failed = next(d for d in decisions if d.action is ActionType.TEMPORARY_BLOCK)
        assert failed.outcome == "failed" and "permission denied" in (failed.error or "")


class FakeRunner:
    """Records argv instead of executing, so adapter command construction is testable."""

    def __init__(self, fail_on: tuple[str, ...] = ()) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_on = fail_on
        self.stdout = ""

    async def run(self, *args: str, check: bool = True) -> CommandResult:
        self.calls.append(args)
        failed = any(token in args for token in self.fail_on)
        if failed and check:
            raise FirewallError("failed", command=" ".join(args))
        return CommandResult(
            argv=args, returncode=1 if failed else 0, stdout=self.stdout, stderr="", duration=0.0
        )


class TestNftablesAdapter:
    async def test_setup_uses_accept_policy_and_is_idempotent(self) -> None:
        runner = FakeRunner()
        adapter = NftablesAdapter(runner=runner)  # type: ignore[arg-type]
        await adapter.setup()
        joined = [" ".join(call) for call in runner.calls]
        assert any("policy accept" in line for line in joined)
        assert not any("policy drop" in line for line in joined)
        assert sum("flush chain" in line for line in joined) == 2

    async def test_block_replaces_element_atomically_with_new_timeout(self) -> None:
        runner = FakeRunner()
        adapter = NftablesAdapter(runner=runner)  # type: ignore[arg-type]
        await adapter.block(parse_network("203.0.113.5"), duration=900)
        call = runner.calls[-1]
        # One nft invocation (one kernel transaction): add, delete, add-with-timeout.
        statements = " ".join(call).split(" ; ")
        assert statements == [
            "add element inet sentinelx blocklist_v4 { 203.0.113.5 }",
            "delete element inet sentinelx blocklist_v4 { 203.0.113.5 }",
            "add element inet sentinelx blocklist_v4 { 203.0.113.5 timeout 900s }",
        ]
        await adapter.block(parse_network("2001:db8::/64"))
        assert "blocklist_v6" in runner.calls[-1] and "2001:db8::/64" in runner.calls[-1]
        assert "timeout" not in runner.calls[-1]

    async def test_unblock_reports_failures_instead_of_not_blocked(self) -> None:
        runner = FakeRunner()

        async def denied(*args: str, check: bool = True) -> CommandResult:
            return CommandResult(
                argv=args, returncode=1, stdout="", stderr="Operation not permitted", duration=0.0
            )

        runner.run = denied  # type: ignore[method-assign]
        with pytest.raises(FirewallError, match="not permitted"):
            await NftablesAdapter(runner=runner).unblock(parse_network("203.0.113.5"))  # type: ignore[arg-type]
        with pytest.raises(FirewallError, match="not permitted"):
            await NftablesAdapter(runner=runner).list_blocked()  # type: ignore[arg-type]

    async def test_unblock_of_absent_element_is_false_not_error(self) -> None:
        runner = FakeRunner()

        async def missing(*args: str, check: bool = True) -> CommandResult:
            return CommandResult(
                argv=args,
                returncode=1,
                stdout="",
                stderr="Error: Could not process rule: No such file or directory",
                duration=0.0,
            )

        runner.run = missing  # type: ignore[method-assign]
        assert await NftablesAdapter(runner=runner).unblock(parse_network("203.0.113.5")) is False  # type: ignore[arg-type]

    def test_rejects_unsafe_table_names(self) -> None:
        with pytest.raises(FirewallError):
            NftablesAdapter(table="x; flush ruleset", runner=FakeRunner())  # type: ignore[arg-type]

    async def test_list_parses_json_elements(self) -> None:
        runner = FakeRunner()
        runner.stdout = '{"nftables":[{"metainfo":{}},{"set":{"name":"blocklist_v4","elem":["203.0.113.5",{"prefix":{"addr":"198.51.100.0","len":28}},{"elem":{"val":"192.0.2.9","timeout":900,"expires":812}}]}}]}'
        entries = await NftablesAdapter(runner=runner).list_blocked()  # type: ignore[arg-type]
        networks = {e.network for e in entries}
        assert {"203.0.113.5/32", "198.51.100.0/28", "192.0.2.9/32"} <= networks
        assert any(e.expires_at is not None for e in entries)

    async def test_teardown_deletes_only_own_table(self) -> None:
        runner = FakeRunner()
        await NftablesAdapter(runner=runner).teardown()  # type: ignore[arg-type]
        assert runner.calls == [("delete", "table", "inet", "sentinelx")]


class TestIptablesAdapter:
    async def test_block_checks_then_inserts_drop_rule(self) -> None:
        v4 = FakeRunner(fail_on=("-C",))
        adapter = IptablesAdapter(runner_v4=v4, runner_v6=FakeRunner())  # type: ignore[arg-type]
        await adapter.block(parse_network("203.0.113.5"))
        assert v4.calls[-1][:4] == ("-w", "-I", "SENTINELX", "1") and "DROP" in v4.calls[-1]

    async def test_list_parses_rules(self) -> None:
        v4 = FakeRunner()
        v4.stdout = (
            "-N SENTINELX\n-A SENTINELX -s 203.0.113.5/32 -m comment --comment sentinelx -j DROP\n"
        )
        entries = await IptablesAdapter(runner_v4=v4, runner_v6=FakeRunner()).list_blocked()  # type: ignore[arg-type]
        assert [e.network for e in entries] == ["203.0.113.5/32"]


async def test_command_runner_rejects_control_characters_and_missing_binary() -> None:
    from sentinelx.firewall.base import CommandRunner

    with pytest.raises(FirewallError):
        CommandRunner("definitely-not-a-real-binary-xyz")
    runner = CommandRunner("true")
    with pytest.raises(FirewallError, match="control characters"):
        await runner.run("a\nb")
    assert (await runner.run("anything")).ok


def test_block_entry_serialises() -> None:
    from sentinelx.firewall.base import BlockEntry

    entry = BlockEntry(network="203.0.113.5/32", expires_at=datetime.now(UTC))
    assert entry.as_dict()["temporary"] is True


class TestWebhookSafety:
    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]:8443/hook",
            "https://10.1.2.3/hook",
            "https://localhost/hook",
        ],
    )
    async def test_internal_destinations_are_refused_by_default(self, url: str) -> None:
        from sentinelx.response.engine import WebhookRejectedError, check_webhook_destination

        with pytest.raises(WebhookRejectedError):
            await check_webhook_destination(url, allow_private=False)
        await check_webhook_destination(url, allow_private=True)

    @pytest.mark.parametrize(
        "url", ["http://hooks.example.com/x", "gopher://x", "file:///etc/passwd", "not a url"]
    )
    def test_settings_require_https(self, url: str) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ResponseSettings(webhook_url=url)

    def test_display_hides_credentials_path_and_query(self) -> None:
        from sentinelx.response.engine import webhook_display

        shown = webhook_display("https://u:pw@hooks.example.com:8443/T0/B0/SECRET?sig=1")
        assert shown == "https://hooks.example.com:8443/…"


class TestExpiryAndFailures:
    async def test_expired_temporary_block_is_removed_and_audited(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=False)
        await engine.manual_action(
            ActionType.TEMPORARY_BLOCK, "203.0.113.7", actor="admin", reason="r", duration=30
        )
        entry = (await engine.blocked())[0]
        engine._blocks[entry.network] = replace(entry, expires_at=datetime.now(UTC))
        assert await engine.expire_due() == 1
        assert await engine.blocked() == []
        assert firewall.operations[-1] == ("unblock", "203.0.113.7/32")
        assert audit[-1]["outcome"] == "executed" and audit[-1]["action"] == "UNBLOCK_IP"

    async def test_failed_expiry_keeps_the_block_and_audits_failure(self) -> None:
        engine, firewall, audit, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=False)
        await engine.manual_action(
            ActionType.TEMPORARY_BLOCK, "203.0.113.8", actor="admin", reason="r", duration=30
        )
        entry = (await engine.blocked())[0]
        engine._blocks[entry.network] = replace(entry, expires_at=datetime.now(UTC))

        async def denied(network: object) -> bool:
            raise FirewallError("nft: Operation not permitted")

        firewall.unblock = denied  # type: ignore[method-assign]
        assert await engine.expire_due() == 0
        assert [e.network for e in await engine.blocked()] == ["203.0.113.8/32"]
        assert audit[-1]["outcome"] == "failed" and audit[-1]["details"]["will_retry"]  # type: ignore[index]

    async def test_null_backend_never_reports_a_block_as_executed(self) -> None:
        from sentinelx.firewall import NullFirewall

        settings = ResponseSettings(mode=ResponseMode.DETECT_ONLY, dry_run=False)
        engine = ResponseEngine(
            settings, NullFirewall(), scoring=ScoringSettings(), guard=guard(settings)
        )
        decision = await engine.manual_action(
            ActionType.BLOCK_IP, "203.0.113.9", actor="admin", reason="r"
        )
        assert decision.outcome == "failed" and "FIREWALL_BACKEND=null" in (decision.error or "")

    def test_manual_approval_without_dry_run_needs_a_real_backend(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="FIREWALL_BACKEND"):
            ResponseSettings(
                mode=ResponseMode.MANUAL_APPROVAL, dry_run=False, firewall_backend="null"
            )

    async def test_duplicate_block_of_bare_address_is_recognised(self) -> None:
        engine, firewall, _, _ = await engine_for(ResponseMode.AUTOMATIC, dry_run=False)
        await engine.handle_detection(detection(), risk(99))
        second = await engine.handle_detection(detection(), risk(99))
        assert "already blocked" in next(
            d.reason for d in second if d.action is ActionType.TEMPORARY_BLOCK
        )
        assert firewall.operations == [("block", "203.0.113.5/32")]

    async def test_rule_duration_is_used_for_automatic_blocks(self) -> None:
        engine, _, _, _ = await engine_for(ResponseMode.AUTOMATIC, dry_run=False)
        ruled = replace(detection(), recommended_duration_seconds=3600)
        decisions = await engine.handle_detection(ruled, risk(99))
        block = next(d for d in decisions if d.action is ActionType.TEMPORARY_BLOCK)
        assert block.duration_seconds == 3600


class TestIptablesExpiry:
    async def test_temporary_block_deadline_survives_a_restart(self) -> None:
        v4 = FakeRunner()
        adapter = IptablesAdapter(runner_v4=v4, runner_v6=FakeRunner())  # type: ignore[arg-type]
        await adapter.block(parse_network("203.0.113.5"), duration=600)
        inserted = v4.calls[-1]
        comment = inserted[inserted.index("--comment") + 1]
        assert comment.startswith("sentinelx:exp=")
        # A fresh adapter (a restarted server) reads the deadline back from iptables.
        restarted_runner = FakeRunner()
        restarted_runner.stdout = (
            f"-N SENTINELX\n-A SENTINELX -s 203.0.113.5/32 -m comment --comment {comment} -j DROP\n"
        )
        entries = await IptablesAdapter(
            runner_v4=restarted_runner, runner_v6=FakeRunner()
        ).list_blocked()  # type: ignore[arg-type]
        assert entries[0].expires_at is not None and entries[0].temporary


async def test_dry_run_unblock_of_an_invalid_target_is_refused_not_simulated() -> None:
    engine, firewall, audit, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=True)
    for target in ("notanip", "1.2.3.4; rm -rf /", "2001:db8::1%eth0", "10.0.0.0/33"):
        decision = await engine.manual_action(
            ActionType.UNBLOCK_IP, target, actor="admin", reason="cleanup"
        )
        assert decision.outcome == "failed" and "invalid target" in (decision.error or "")
    assert firewall.operations == []
    ok = await engine.manual_action(ActionType.UNBLOCK_IP, "203.0.113.9", actor="admin", reason="x")
    assert ok.outcome == "simulated"


async def test_manual_rate_limit_never_downgrades_an_existing_block() -> None:
    engine, firewall, _, _ = await engine_for(ResponseMode.DETECT_ONLY, dry_run=False)
    blocked = await engine.manual_action(
        ActionType.BLOCK_IP, "203.0.113.5", actor="admin", reason="attacker"
    )
    assert blocked.outcome == "executed"
    weaker = await engine.manual_action(
        ActionType.RATE_LIMIT, "203.0.113.5", actor="admin", reason="soften", duration=600
    )
    assert weaker.outcome == "failed" and "unblock it first" in (weaker.error or "")
    assert firewall.operations == [("block", "203.0.113.5/32")]
    assert not (await engine.blocked())[0].rate_limited
