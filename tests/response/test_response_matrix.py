"""Response engine matrix: modes, approvals, expiry, duplicates, webhooks, failures, safety.

Firewall commands are observed at the lowest level available without touching the
host: a recording runner behind the real nftables adapter, or the real
:class:`CommandRunner` executing fake ``nft``/``iptables`` scripts in ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import ssl
import stat
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import sentinelx.response.engine as engine_module
from sentinelx.common.enums import ActionType, ResponseMode, RiskBand, Severity, ThreatCategory
from sentinelx.common.errors import FirewallError
from sentinelx.common.models import Detection, Evidence, Incident, RiskAssessment
from sentinelx.config.settings import ResponseSettings, ScoringSettings, Settings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.firewall import MemoryFirewall
from sentinelx.firewall.base import BlockEntry, CommandResult, CommandRunner, FirewallAdapter
from sentinelx.firewall.iptables import IptablesAdapter
from sentinelx.firewall.nftables import NftablesAdapter
from sentinelx.firewall.pf import PfAdapter
from sentinelx.firewall.windows import WindowsFirewallAdapter
from sentinelx.response.engine import ResponseEngine
from sentinelx.response.safety import SafetyGuard
from sentinelx.telemetry.metrics import metrics

ATTACKER = "203.0.113.5"
LOCAL_V4, LOCAL_V6 = "192.0.2.10", "2001:db8::10"
MANAGEMENT = "198.51.100.7"
OPERATOR = "203.0.113.200"
ALLOWLISTED = "10.20.30.0/24"


# ================================================================== helpers


class RecordingRunner:
    """Stands in for ``CommandRunner``: records argv, succeeds with empty output."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def run(self, *args: str, check: bool = True) -> CommandResult:
        self.calls.append(args)
        return CommandResult(argv=args, returncode=0, stdout="", stderr="", duration=0.0)

    def mutating(self) -> list[tuple[str, ...]]:
        """Every call except read-only listings (nft ``-j list``/``list``, ``-S``)."""
        return [
            c for c in self.calls if c[:2] != ("-j", "list") and c[0] != "list" and "-S" not in c
        ]


def detection(
    action: ActionType = ActionType.TEMPORARY_BLOCK,
    source: str = ATTACKER,
    *,
    duration: int | None = None,
) -> Detection:
    return Detection(
        detector="ssh_brute_force",
        category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.CRITICAL,
        confidence=0.95,
        title="SSH brute force",
        description="d",
        source_ip=source,
        destination_ip="203.0.113.6",
        destination_port=22,
        evidence=[Evidence("short_sessions", 40, "40 short sessions")],
        recommended_action=action,
        recommended_duration_seconds=duration,
    )


def risk(score: float) -> RiskAssessment:
    return RiskAssessment(
        score=score, band=RiskBand.from_score(score), contributions={"x": score}, rationale=["why"]
    )


def incident(score: float, *sources: str) -> Incident:
    return Incident(
        incident_id="inc-1",
        title="Potential host compromise attempt",
        summary="s",
        severity=Severity.CRITICAL,
        risk=risk(score),
        detection_ids=["d1"],
        affected_sources=set(sources),
        affected_destinations=set(),
        affected_services=set(),
        categories={ThreatCategory.BRUTE_FORCE},
    )


@dataclass
class Harness:
    engine: ResponseEngine
    firewall: FirewallAdapter
    audit: list[dict[str, Any]]
    bus: EventBus
    events: list[tuple[EventType, dict[str, Any]]] = field(default_factory=list)
    responses: list[str] = field(default_factory=list)

    def outcome(self, decisions: list[Any], action: ActionType) -> Any:
        return next(d for d in decisions if d.action is action)


def build(
    *,
    mode: ResponseMode = ResponseMode.AUTOMATIC,
    dry_run: bool = False,
    firewall: FirewallAdapter | None = None,
    threshold: float = 85.0,
    **overrides: Any,
) -> Harness:
    settings = ResponseSettings(
        mode=mode,
        dry_run=dry_run,
        firewall_backend="nftables",
        allowlist_networks=[ALLOWLISTED],
        management_addresses=[MANAGEMENT],
        **overrides,
    )
    audit: list[dict[str, Any]] = []

    async def sink(record: dict[str, Any]) -> None:
        audit.append(record)

    bus = EventBus()
    responses: list[str] = []
    fw = firewall or MemoryFirewall()
    harness_engine = ResponseEngine(
        settings,
        fw,
        scoring=ScoringSettings(auto_block_threshold=threshold),
        bus=bus,
        audit=sink,
        guard=None,
        on_response=responses.append,
    )
    harness_engine.guard = SafetyGuard(
        settings,
        local_addresses=lambda: {LOCAL_V4, LOCAL_V6, "fe80::1%eth0"},
        active_block_count=lambda: len(harness_engine._blocks),
        operator_addresses=lambda: [OPERATOR],
    )
    harness = Harness(harness_engine, fw, audit, bus, responses=responses)

    async def record(event_type: EventType, payload: dict[str, Any]) -> Any:
        harness.events.append((event_type, payload))
        return await EventBus.publish(bus, event_type, payload)

    bus.publish = record  # type: ignore[method-assign]
    return harness


def nft_harness(**kwargs: Any) -> tuple[Harness, RecordingRunner]:
    runner = RecordingRunner()
    return build(firewall=NftablesAdapter(runner=runner), **kwargs), runner  # type: ignore[arg-type]


def event_types(harness: Harness) -> list[EventType]:
    return [t for t, _ in harness.events]


# ========================================================= defaults and modes


class TestDefaults:
    def test_automatic_prevention_is_off_by_default(self) -> None:
        response = Settings().response
        assert response.mode is ResponseMode.DETECT_ONLY
        assert response.dry_run is True and response.prevention_active is False
        assert response.firewall_backend == "null"
        assert ResponseSettings().prevention_active is False
        assert ResponseSettings(mode=ResponseMode.AUTOMATIC).prevention_active is False  # dry run
        assert ScoringSettings().auto_block_threshold == 85.0

    async def test_default_settings_never_touch_the_firewall(self) -> None:
        runner = RecordingRunner()
        settings = Settings().response
        engine = ResponseEngine(
            settings,
            NftablesAdapter(runner=runner),  # type: ignore[arg-type]
            guard=SafetyGuard(settings, local_addresses=set),
        )
        await engine.start()
        try:
            decisions = await engine.handle_detection(detection(ActionType.BLOCK_IP), risk(100))
            decisions += await engine.handle_incident(incident(100, ATTACKER))
        finally:
            await engine.stop()
        assert {d.outcome for d in decisions if d.action is not ActionType.ALERT} == {"skipped"}
        assert runner.mutating() == []


class TestDetectOnly:
    async def test_alerts_and_logs_only(self) -> None:
        harness, runner = nft_harness(mode=ResponseMode.DETECT_ONLY)
        decisions = await harness.engine.handle_detection(detection(), risk(100))
        decisions += await harness.engine.handle_incident(incident(100, ATTACKER, "203.0.113.9"))
        alert = harness.outcome(decisions, ActionType.ALERT)
        assert alert.outcome == "executed"
        preventive = [d for d in decisions if d.action.is_preventive]
        assert len(preventive) == 3 and {d.outcome for d in preventive} == {"skipped"}
        assert all("RESPONSE_MODE=detect_only" in d.reason for d in preventive)
        assert runner.calls == [] and harness.responses == []
        assert {r["outcome"] for r in harness.audit} == {"skipped"}
        assert EventType.IP_BLOCKED not in event_types(harness)

    @pytest.mark.parametrize(
        "action", [ActionType.ALERT, ActionType.LOG, ActionType.WEBHOOK, ActionType.NONE]
    )
    async def test_non_preventive_recommendations_never_reach_the_firewall(
        self, action: ActionType
    ) -> None:
        harness, runner = nft_harness(mode=ResponseMode.AUTOMATIC)
        decisions = await harness.engine.handle_detection(detection(action), risk(100))
        assert [d.action for d in decisions] == [ActionType.ALERT] and runner.calls == []


class TestDryRun:
    @pytest.mark.parametrize(
        "mode", [ResponseMode.DETECT_ONLY, ResponseMode.MANUAL_APPROVAL, ResponseMode.AUTOMATIC]
    )
    async def test_dry_run_sends_no_mutating_firewall_command_in_any_path(
        self, mode: ResponseMode
    ) -> None:
        """Regression (manual_approval): start() created the nft table in dry run."""
        harness, runner = nft_harness(mode=mode, dry_run=True)
        engine = harness.engine
        await engine.start()
        try:
            decisions = await engine.handle_detection(detection(), risk(100))
            decisions += await engine.handle_detection(
                detection(ActionType.RATE_LIMIT, "203.0.113.8"), risk(100)
            )
            decisions += await engine.handle_incident(incident(100, "203.0.113.9"))
            for action in (
                ActionType.BLOCK_IP,
                ActionType.TEMPORARY_BLOCK,
                ActionType.RATE_LIMIT,
                ActionType.QUARANTINE,
                ActionType.UNBLOCK_IP,
            ):
                decisions.append(
                    await engine.manual_action(action, "203.0.113.77", actor="admin", reason="dry")
                )
            for pending in engine.pending_actions():
                decisions.append(await engine.approve(pending.action_id, actor="admin"))
            await engine.expire_due()
        finally:
            await engine.stop()
        assert runner.mutating() == [], runner.mutating()
        assert not any(d.executed for d in decisions if d.action is not ActionType.ALERT)
        assert await engine.blocked() == [] and harness.responses == []
        manual = [d for d in decisions if d.target == "203.0.113.77"]
        assert {d.outcome for d in manual} == {"simulated"}
        assert all("[DRY RUN - not applied]" in d.reason for d in manual)
        if mode is ResponseMode.MANUAL_APPROVAL:
            approved = [d for d in decisions if d.reason.startswith("approved:")]
            assert len(approved) == 3 and {d.outcome for d in approved} == {"simulated"}


class TestManualAndApproval:
    async def test_manual_actions_execute_and_are_attributed(self) -> None:
        harness = build(mode=ResponseMode.DETECT_ONLY)
        block = await harness.engine.manual_action(
            ActionType.QUARANTINE, "203.0.113.40", actor="alice", reason="contain", source="cli"
        )
        assert block.outcome == "executed" and block.executed
        assert harness.firewall.operations == [("block", "203.0.113.40/32")]  # type: ignore[attr-defined]
        assert harness.audit[-1] | {"details": None} == {
            "action": "QUARANTINE",
            "actor": "alice",
            "target": "203.0.113.40",
            "reason": "contain",
            "source": "cli",
            "outcome": "executed",
            "details": None,
        }
        assert EventType.IP_BLOCKED in event_types(harness) and harness.responses == [
            "203.0.113.40"
        ]

    async def test_unblock_of_an_address_that_is_not_blocked_is_not_reported_as_done(self) -> None:
        harness = build(mode=ResponseMode.DETECT_ONLY)
        decision = await harness.engine.manual_action(
            ActionType.UNBLOCK_IP, "203.0.113.41", actor="alice", reason="cleanup"
        )
        assert decision.outcome == "skipped" and not decision.executed
        assert harness.audit[-1]["outcome"] == "skipped"

    async def test_approval_queue_publishes_and_approval_rechecks_safety(self) -> None:
        harness = build(mode=ResponseMode.MANUAL_APPROVAL)
        engine = harness.engine
        queued = await engine.handle_detection(detection(source="203.0.113.50"), risk(99))
        assert harness.outcome(queued, ActionType.TEMPORARY_BLOCK).outcome == "pending_approval"
        assert EventType.RESPONSE_PENDING_APPROVAL in event_types(harness)
        (pending,) = engine.pending_actions()
        assert pending.target == "203.0.113.50" and pending.evidence == ["40 short sessions"]

        engine.guard.update_allowlist([ALLOWLISTED, "203.0.113.50/32"])  # allowlisted meanwhile
        decision = await engine.approve(pending.action_id, actor="bob")
        assert decision.outcome == "failed" and "allowlisted" in (decision.error or "")
        assert harness.firewall.operations == []  # type: ignore[attr-defined]
        assert engine.pending == {}

    async def test_unknown_and_expired_approvals_raise(self) -> None:
        harness = build(mode=ResponseMode.MANUAL_APPROVAL)
        engine = harness.engine
        with pytest.raises(KeyError):
            await engine.approve("nope", actor="bob")
        with pytest.raises(KeyError):
            await engine.reject("nope", actor="bob")
        await engine.handle_detection(detection(), risk(99))
        action_id, pending = next(iter(engine.pending.items()))
        engine.pending[action_id] = replace(
            pending,
            created_at=pending.created_at
            - engine_module.PENDING_APPROVAL_TTL
            - dt.timedelta(seconds=1),
        )
        with pytest.raises(KeyError):
            await engine.reject(action_id, actor="bob")
        assert harness.firewall.operations == []  # type: ignore[attr-defined]

    async def test_approval_queue_is_bounded_and_evicts_the_oldest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(engine_module, "MAX_PENDING_APPROVALS", 3)
        harness = build(mode=ResponseMode.MANUAL_APPROVAL)
        for index in range(5):
            await harness.engine.handle_detection(
                detection(source=f"203.0.113.{60 + index}"), risk(99)
            )
        assert [p.target for p in harness.engine.pending_actions()] == [
            "203.0.113.62",
            "203.0.113.63",
            "203.0.113.64",
        ]

    async def test_manual_approval_never_applies_on_its_own(self) -> None:
        harness = build(mode=ResponseMode.MANUAL_APPROVAL)
        for _ in range(3):
            await harness.engine.handle_detection(detection(), risk(100))
            await harness.engine.handle_incident(incident(100, ATTACKER))
        assert harness.firewall.operations == [] and len(harness.engine.pending) == 1  # type: ignore[attr-defined]


class TestAutomaticThreshold:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [(0, "skipped"), (84.9, "skipped"), (85, "executed"), (100, "executed")],
    )
    async def test_threshold_is_inclusive(self, score: float, expected: str) -> None:
        harness = build()
        decisions = await harness.engine.handle_detection(detection(), risk(score))
        assert harness.outcome(decisions, ActionType.TEMPORARY_BLOCK).outcome == expected
        assert bool(harness.firewall.operations) is (expected == "executed")  # type: ignore[attr-defined]

    async def test_configured_threshold_and_durations(self) -> None:
        harness = build(threshold=50, default_block_seconds=600, max_block_seconds=1200)
        decisions = await harness.engine.handle_detection(detection(duration=99_999), risk(51))
        block = harness.outcome(decisions, ActionType.TEMPORARY_BLOCK)
        assert block.outcome == "executed" and block.duration_seconds == 1200
        (entry,) = await harness.engine.blocked()
        assert entry.temporary and 1100 < (entry.remaining_seconds() or 0) <= 1200

    async def test_incident_response_blocks_every_safe_source_once(self) -> None:
        harness = build()
        assert await harness.engine.handle_incident(incident(84, ATTACKER)) == []
        decisions = await harness.engine.handle_incident(
            incident(90, ATTACKER, "127.0.0.1", "203.0.113.9")
        )
        outcomes = {d.target: d.outcome for d in decisions}
        assert outcomes == {"127.0.0.1": "failed", ATTACKER: "executed", "203.0.113.9": "executed"}
        assert all(d.duration_seconds == 900 and d.incident_id == "inc-1" for d in decisions)
        assert await harness.engine.handle_incident(incident(95, ATTACKER, "203.0.113.9")) == []


class TestExpiryAndReaper:
    async def test_reaper_unblocks_expired_temporary_blocks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_sleep = asyncio.sleep

        async def fast_sleep(delay: float, *args: Any) -> Any:
            return await real_sleep(min(delay, 0.01), *args)

        harness = build(mode=ResponseMode.DETECT_ONLY)
        engine = harness.engine
        await engine.manual_action(
            ActionType.TEMPORARY_BLOCK, ATTACKER, actor="a", reason="r", duration=60
        )
        await engine.manual_action(
            ActionType.BLOCK_IP, "203.0.113.9", actor="a", reason="permanent"
        )
        key = f"{ATTACKER}/32"
        monkeypatch.setattr(asyncio, "sleep", fast_sleep)  # the reaper looks it up at call time
        await engine.start()  # re-reads the firewall's own entries
        engine._blocks[key] = replace(engine._blocks[key], expires_at=dt.datetime.now(dt.UTC))
        try:
            deadline = time.monotonic() + 3
            while key in engine._blocks and time.monotonic() < deadline:
                await real_sleep(0.01)
        finally:
            await engine.stop()
        assert [e.network for e in await engine.blocked()] == ["203.0.113.9/32"]
        assert ("unblock", key) in harness.firewall.operations  # type: ignore[attr-defined]
        assert harness.audit[-1] == {
            "action": "UNBLOCK_IP",
            "actor": "system",
            "target": key,
            "reason": "temporary block expired",
            "source": "engine",
            "outcome": "executed",
        }
        assert EventType.IP_UNBLOCKED in event_types(harness)

    async def test_start_restores_expiries_the_backend_cannot_store(self) -> None:
        firewall = MemoryFirewall()
        await firewall.block(ipaddress.ip_network(ATTACKER))
        harness = build(firewall=firewall, mode=ResponseMode.DETECT_ONLY)
        past = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        await harness.engine.start({f"{ATTACKER}/32": past})
        try:
            assert (await harness.engine.blocked())[0].expires_at == past
            assert await harness.engine.expire_due() == 1
        finally:
            await harness.engine.stop()
        assert await firewall.list_blocked() == []


class TestDuplicatesAndRateLimits:
    async def test_manual_reblock_replaces_rather_than_duplicates(self) -> None:
        harness = build(mode=ResponseMode.DETECT_ONLY)
        await harness.engine.manual_action(
            ActionType.TEMPORARY_BLOCK, ATTACKER, actor="a", reason="r", duration=60
        )
        await harness.engine.manual_action(
            ActionType.BLOCK_IP, f"{ATTACKER}/32", actor="a", reason="r"
        )
        (entry,) = await harness.engine.blocked()
        assert entry.network == f"{ATTACKER}/32" and not entry.temporary

    async def test_automatic_rate_limit_is_applied_to_the_rate_limit_set(self) -> None:
        harness, runner = nft_harness(rate_limit_packets_per_second=100)
        decisions = await harness.engine.handle_detection(
            detection(ActionType.RATE_LIMIT), risk(95)
        )
        limit = harness.outcome(decisions, ActionType.RATE_LIMIT)
        assert limit.outcome == "executed" and limit.duration_seconds == 900
        (entry,) = await harness.engine.blocked()
        assert entry.rate_limited and entry.temporary
        assert "ratelimit_v4" in runner.calls[-1] and "timeout" in runner.calls[-1]
        again = await harness.engine.handle_detection(detection(ActionType.RATE_LIMIT), risk(95))
        assert "already rate limited" in harness.outcome(again, ActionType.RATE_LIMIT).reason

    async def test_rate_limit_never_downgrades_an_existing_block(self) -> None:
        """Regression: an automatic rate limit replaced a permanent block in the registry
        (and on iptables in the firewall), and its expiry then removed the block."""
        harness = build()
        await harness.engine.manual_action(
            ActionType.BLOCK_IP, ATTACKER, actor="admin", reason="keep"
        )
        decisions = await harness.engine.handle_detection(
            detection(ActionType.RATE_LIMIT), risk(99)
        )
        limit = harness.outcome(decisions, ActionType.RATE_LIMIT)
        assert limit.outcome == "skipped" and "already blocked" in limit.reason
        (entry,) = await harness.engine.blocked()
        assert not entry.rate_limited and not entry.temporary
        assert harness.firewall.operations == [("block", f"{ATTACKER}/32")]  # type: ignore[attr-defined]

    async def test_block_escalates_over_an_existing_rate_limit(self) -> None:
        """Regression: a rate-limited source counted as 'already blocked', so neither a
        stronger detection nor an incident could ever escalate it to a block."""
        harness = build()
        await harness.engine.handle_detection(detection(ActionType.RATE_LIMIT), risk(90))
        decisions = await harness.engine.handle_detection(
            detection(ActionType.TEMPORARY_BLOCK), risk(99)
        )
        assert harness.outcome(decisions, ActionType.TEMPORARY_BLOCK).outcome == "executed"
        (entry,) = await harness.engine.blocked()
        assert not entry.rate_limited

        second = build()
        await second.engine.handle_detection(detection(ActionType.RATE_LIMIT), risk(90))
        (escalated,) = await second.engine.handle_incident(incident(99, ATTACKER))
        assert escalated.outcome == "executed" and escalated.action is ActionType.TEMPORARY_BLOCK
        assert not (await second.engine.blocked())[0].rate_limited

    async def test_block_limit_counts_active_blocks(self) -> None:
        harness = build(mode=ResponseMode.DETECT_ONLY, max_blocked_addresses=2)
        results = [
            await harness.engine.manual_action(
                ActionType.BLOCK_IP, f"203.0.113.{i}", actor="a", reason="r"
            )
            for i in (20, 21, 22)
        ]
        assert [r.outcome for r in results] == ["executed", "executed", "failed"]
        assert "already active" in (results[-1].error or "")


# ================================================================== webhooks


@dataclass
class HookServer:
    url: str
    requests: list[dict[str, Any]]
    status: int = 200
    delay: float = 0.0
    location: str | None = None


@pytest.fixture
async def hook_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[HookServer]:
    """A local HTTPS receiver with a self-signed certificate trusted via SSL_CERT_FILE."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "hook.crt", tmp_path / "hook.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))

    state = HookServer(url="", requests=[])

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode().split("\r\n")
            headers = {
                k.lower(): v.strip()
                for k, v in (line.split(":", 1) for line in lines[1:] if ":" in line)
            }
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            state.requests.append({"request_line": lines[0], "headers": headers, "body": body})
            if state.delay:
                await asyncio.sleep(state.delay)
            extra = f"Location: {state.location}\r\n" if state.location else ""
            writer.write(
                f"HTTP/1.1 {state.status} X\r\nContent-Length: 0\r\n{extra}Connection: close\r\n\r\n".encode()
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    state.url = f"https://127.0.0.1:{port}/hooks/T0/SECRET-TOKEN?sig=abc"
    try:
        yield state
    finally:
        server.close()


def failures() -> float:
    return float(metrics.webhook_failures._value.get())


async def deliver(harness: Harness, score: float = 90.0) -> list[Any]:
    """Queue a detection's webhook and wait for the worker's final decision."""
    before = len(harness.engine.decisions)
    decisions = await harness.engine.handle_detection(detection(ActionType.ALERT), risk(score))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        done = [
            d
            for d in harness.engine.decisions[before:]
            if d.action is ActionType.WEBHOOK
            and (d.executed or d.error)
            and "queued" not in d.reason
        ]
        if done or not any(d.action is ActionType.WEBHOOK for d in decisions):
            return decisions + done
        await asyncio.sleep(0.02)
    raise AssertionError("webhook worker produced no decision")


class TestWebhooks:
    async def test_payload_is_delivered_over_https_without_leaking_the_secret(
        self, hook_server: HookServer
    ) -> None:
        harness = build(
            mode=ResponseMode.DETECT_ONLY,
            webhook_url=hook_server.url,
            webhook_allow_private_addresses=True,
        )
        await harness.engine.start()
        try:
            decisions = await deliver(harness)
        finally:
            await harness.engine.stop()
        queued = next(
            d for d in decisions if d.action is ActionType.WEBHOOK and "queued" in d.reason
        )
        delivered = decisions[-1]
        assert delivered.executed and delivered.error is None
        for decision in (queued, delivered):
            assert (
                decision.target
                == f"https://127.0.0.1:{hook_server.url.split(':')[2].split('/')[0]}/…"
            )
            assert "SECRET" not in decision.target
        (request,) = hook_server.requests
        assert request["request_line"] == "POST /hooks/T0/SECRET-TOKEN?sig=abc HTTP/1.1"
        assert request["headers"]["content-type"] == "application/json"
        body = json.loads(request["body"])
        assert body == {
            "type": "sentinelx.detection",
            "title": "SSH brute force",
            "detector": "ssh_brute_force",
            "severity": "critical",
            "risk": 90.0,
            "risk_band": RiskBand.from_score(90.0).value,
            "source_ip": ATTACKER,
            "destination_ip": "203.0.113.6",
            "evidence": ["40 short sessions"],
            "timestamp": body["timestamp"],
        }
        assert not any(r.get("action") == "WEBHOOK" for r in harness.audit)

    async def test_below_minimum_risk_sends_nothing(self, hook_server: HookServer) -> None:
        harness = build(
            webhook_url=hook_server.url, webhook_allow_private_addresses=True, webhook_min_risk=95
        )
        await harness.engine.start()
        try:
            decisions = await deliver(harness, score=94.9)
            await asyncio.sleep(0.1)
        finally:
            await harness.engine.stop()
        assert (
            not any(d.action is ActionType.WEBHOOK for d in decisions)
            and hook_server.requests == []
        )

    @pytest.mark.parametrize(
        ("status", "delay", "location", "fragment"),
        [
            (500, 0.0, None, "HTTPStatusError"),
            (404, 0.0, None, "HTTPStatusError"),
            (
                302,
                0.0,
                "https://169.254.169.254/latest",
                "HTTPStatusError",
            ),  # redirects not followed
            (200, 2.0, None, "ReadTimeout"),
        ],
    )
    async def test_failures_are_counted_and_reported(
        self,
        hook_server: HookServer,
        status: int,
        delay: float,
        location: str | None,
        fragment: str,
    ) -> None:
        hook_server.status, hook_server.delay, hook_server.location = status, delay, location
        harness = build(
            webhook_url=hook_server.url,
            webhook_allow_private_addresses=True,
            webhook_timeout_seconds=0.3,
        )
        before = failures()
        await harness.engine.start()
        started = time.monotonic()
        try:
            decisions = await deliver(harness)
        finally:
            await harness.engine.stop()
        final = decisions[-1]
        assert not final.executed and final.error == f"webhook failed: {fragment}"
        assert failures() == before + 1 and len(hook_server.requests) == 1
        assert time.monotonic() - started < 1.9  # the timeout, not the server, ended it

    async def test_private_destination_is_refused_without_the_flag(
        self, hook_server: HookServer
    ) -> None:
        harness = build(webhook_url=hook_server.url, webhook_allow_private_addresses=False)
        before = failures()
        await harness.engine.start()
        try:
            decisions = await deliver(harness)
        finally:
            await harness.engine.stop()
        final = decisions[-1]
        assert final.outcome == "failed" and "non-public address 127.0.0.1" in (final.error or "")
        assert "WEBHOOK_ALLOW_PRIVATE_ADDRESSES" in (final.error or "")
        assert hook_server.requests == [] and failures() == before + 1

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8443/hook",
            "HTTP://example.com/x",
            "https:///no-host",
            "https://exa mple.com/x",
            "ftp://example.com",
        ],
    )
    def test_non_https_or_malformed_urls_are_rejected_even_with_the_private_flag(
        self, url: str
    ) -> None:
        with pytest.raises(ValidationError):
            ResponseSettings(webhook_url=url, webhook_allow_private_addresses=True)

    async def test_full_queue_drops_and_counts_without_blocking_detection(self) -> None:
        harness = build(webhook_url="https://hooks.example.com/x", mode=ResponseMode.DETECT_ONLY)
        before = failures()
        for _ in range(engine_module.WEBHOOK_QUEUE_SIZE):
            await harness.engine.handle_detection(detection(ActionType.ALERT), risk(90))
        decisions = await harness.engine.handle_detection(detection(ActionType.ALERT), risk(90))
        dropped = next(d for d in decisions if d.action is ActionType.WEBHOOK)
        assert dropped.error == "webhook queue full; delivery skipped" and failures() == before + 1


# ======================================================== firewall failures


def fake_binary(directory: Path, name: str, script: str) -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


NONZERO = 'echo "Error: Could not process rule: Operation not permitted" >&2; exit 1\n'
#: setup and listing succeed; changing an element or rule fails.
ELEMENT_DENIED = (
    'case "$*" in *element*|*" -I SENTINELX "*|*" -A SENTINELX "*) '
    'echo "iptables v1.8.10: can\'t initialize: Permission denied (you must be root)" >&2; exit 4;; esac\n'
    'case "$*" in *"-S SENTINELX"*) echo "-N SENTINELX";; esac\nexit 0\n'
)
SLOW = 'case "$*" in *element*|*"-I SENTINELX"*|*"-A SENTINELX"*) sleep 5;; esac\nexit 0\n'


def adapter_for(kind: str, binary: Path, timeout: float = 10.0) -> FirewallAdapter:
    runner = CommandRunner(str(binary), timeout=timeout)
    if kind == "nftables":
        return NftablesAdapter(runner=runner)
    return IptablesAdapter(runner_v4=runner, runner_v6=runner)


FailureSetup = Callable[[Path], Awaitable[tuple[Path, float, str]]]


class TestFirewallFailures:
    @pytest.mark.parametrize("kind", ["nftables", "iptables"])
    @pytest.mark.parametrize(
        ("case", "script", "limit", "fragment"),
        [
            ("nonzero_exit", NONZERO, 10.0, "Operation not permitted"),
            ("permission_denied", ELEMENT_DENIED, 10.0, "Permission denied (you must be root)"),
            ("timeout", SLOW, 0.3, "timed out after 0.3s"),
            ("binary_removed", "exit 0\n", 10.0, "could not execute firewall command"),
            ("not_executable", "exit 0\n", 10.0, "Permission denied"),
        ],
    )
    async def test_failure_is_reported_with_the_real_error_and_never_as_blocked(
        self, tmp_path: Path, kind: str, case: str, script: str, limit: float, fragment: str
    ) -> None:
        binary = fake_binary(tmp_path, "nft" if kind == "nftables" else "iptables", script)
        firewall = adapter_for(kind, binary, limit)
        if case == "binary_removed":
            binary.unlink()
        elif case == "not_executable":
            binary.chmod(0o644)
        harness = build(firewall=firewall)
        await harness.engine.start()  # regression: a setup failure here crashed start-up
        try:
            automatic = await harness.engine.handle_detection(detection(), risk(99))
            manual = await harness.engine.manual_action(
                ActionType.RATE_LIMIT, "203.0.113.30", actor="admin", reason="r", duration=60
            )
        finally:
            await harness.engine.stop()
        for decision in (harness.outcome(automatic, ActionType.TEMPORARY_BLOCK), manual):
            assert decision.outcome == "failed" and not decision.executed and not decision.dry_run
            assert fragment in (decision.error or ""), decision.error
        assert [r["outcome"] for r in harness.audit] == ["failed", "failed"]
        assert all(fragment in (r["details"]["error"] or "") for r in harness.audit)
        assert harness.engine._blocks == {} and harness.responses == []
        assert EventType.IP_BLOCKED not in event_types(harness)

    async def test_failed_unblock_keeps_the_block_registered(self, tmp_path: Path) -> None:
        binary = fake_binary(
            tmp_path,
            "nft",
            'case "$1" in delete) echo "Error: Operation not permitted" >&2; exit 1;; esac\nexit 0\n',
        )
        harness = build(firewall=adapter_for("nftables", binary), mode=ResponseMode.DETECT_ONLY)
        assert (
            await harness.engine.manual_action(ActionType.BLOCK_IP, ATTACKER, actor="a", reason="r")
        ).executed
        decision = await harness.engine.manual_action(
            ActionType.UNBLOCK_IP, ATTACKER, actor="a", reason="r"
        )
        assert decision.outcome == "failed" and "Operation not permitted" in (decision.error or "")
        assert [e.network for e in await harness.engine.blocked()] == [f"{ATTACKER}/32"]
        assert harness.audit[-1]["outcome"] == "failed"

    async def test_setup_is_retried_after_a_transient_failure(self, tmp_path: Path) -> None:
        flag = tmp_path / "broken"
        flag.touch()
        binary = fake_binary(
            tmp_path, "nft", f'[ -e "{flag}" ] && {{ echo "Error: busy" >&2; exit 1; }}\nexit 0\n'
        )
        harness = build(firewall=adapter_for("nftables", binary))
        await harness.engine.start()
        try:
            first = await harness.engine.handle_detection(detection(), risk(99))
            flag.unlink()
            second = await harness.engine.handle_detection(detection(), risk(99))
        finally:
            await harness.engine.stop()
        assert (
            harness.outcome(first, ActionType.TEMPORARY_BLOCK).error
            == "firewall command failed (1): Error: busy"
        )
        assert harness.outcome(second, ActionType.TEMPORARY_BLOCK).outcome == "executed"


class ChainRunner:
    """Stands in for ``iptables``: keeps the SENTINELX chain as a real rule list.

    ``fail_deletes`` makes that many rule deletions fail; ``vanish`` makes the rule
    disappear just before its deletion runs (someone else removed it), so the delete
    fails with iptables' "Bad rule" error.
    """

    def __init__(self, *, fail_deletes: int = 0, vanish: bool = False) -> None:
        self.rules: list[tuple[str, ...]] = []
        self.fail_deletes = fail_deletes
        self.vanish = vanish

    async def run(self, *args: str, check: bool = True) -> CommandResult:
        import shlex

        argv = args[1:] if args[:1] == ("-w",) else args
        code, stdout, stderr = 0, "", ""
        if argv[:2] == ("-S", "SENTINELX"):
            stdout = "-N SENTINELX\n" + "".join(
                shlex.join(("-A", "SENTINELX", *rule)) + "\n" for rule in self.rules
            )
        elif argv[:3] == ("-I", "SENTINELX", "1"):
            self.rules.insert(0, tuple(argv[3:]))
        elif argv[:2] == ("-A", "SENTINELX"):
            self.rules.append(tuple(argv[2:]))
        elif argv[:2] == ("-D", "SENTINELX"):
            rule = tuple(argv[2:])
            if self.vanish and rule in self.rules:
                self.vanish = False
                self.rules.remove(rule)  # gone before our delete reaches the kernel
                code, stderr = 1, "iptables: Bad rule (does a matching rule exist in that chain?)."
            elif self.fail_deletes:
                self.fail_deletes -= 1
                code, stderr = 4, "iptables: Resource temporarily unavailable."
            elif rule in self.rules:
                self.rules.remove(rule)
            else:
                code, stderr = 1, "iptables: Bad rule (does a matching rule exist in that chain?)."
        if check and code:
            raise FirewallError(stderr, command=shlex.join(args), stderr=stderr)
        return CommandResult(argv=args, returncode=code, stdout=stdout, stderr=stderr, duration=0.0)

    def kinds(self) -> list[str]:
        return ["rate_limit" if "hashlimit" in rule else "block" for rule in self.rules]


async def iptables_harness(**runner: Any) -> tuple[Harness, ChainRunner]:
    chain = ChainRunner(**runner)
    harness = build(
        mode=ResponseMode.DETECT_ONLY,
        firewall=IptablesAdapter(runner_v4=chain, runner_v6=chain),  # type: ignore[arg-type]
    )
    return harness, chain


async def registry_matches_kernel(harness: Harness) -> None:
    registry = {e.network: e.rate_limited for e in await harness.engine.blocked()}
    kernel = {e.network: e.rate_limited for e in await harness.firewall.list_blocked()}
    assert registry == kernel


class TestIptablesReplacement:
    """Replacing a rule inserts the new one before deleting the old one. When that delete
    failed, the decision was reported failed while the new rule stayed in the kernel,
    missing from the registry."""

    async def test_failed_delete_withdraws_the_new_rule_and_reports_failure(self) -> None:
        harness, chain = await iptables_harness()
        act = harness.engine.manual_action
        limited = await act(ActionType.RATE_LIMIT, ATTACKER, actor="a", reason="r", duration=600)
        assert limited.outcome == "executed" and chain.kinds() == ["rate_limit"]

        chain.fail_deletes = 1
        block = await act(ActionType.BLOCK_IP, ATTACKER, actor="a", reason="escalate")
        assert block.outcome == "failed" and not block.executed
        assert "Resource temporarily unavailable" in (block.error or "")
        assert "existing rule stays in force" in (block.error or "")
        assert chain.kinds() == ["rate_limit"]  # exactly the state before the attempt
        await registry_matches_kernel(harness)
        assert (await harness.engine.blocked())[0].rate_limited

        chain.fail_deletes = 1
        renewed = await act(ActionType.RATE_LIMIT, ATTACKER, actor="a", reason="r", duration=60)
        assert renewed.outcome == "failed" and chain.kinds() == ["rate_limit"]
        await registry_matches_kernel(harness)

    async def test_rule_already_removed_by_someone_else_counts_as_replaced(self) -> None:
        harness, chain = await iptables_harness()
        act = harness.engine.manual_action
        await act(ActionType.RATE_LIMIT, ATTACKER, actor="a", reason="r", duration=600)
        chain.vanish = True
        block = await act(ActionType.BLOCK_IP, ATTACKER, actor="a", reason="escalate")
        assert block.outcome == "executed" and chain.kinds() == ["block"]
        await registry_matches_kernel(harness)
        assert not (await harness.engine.blocked())[0].rate_limited

    async def test_new_rule_that_cannot_be_withdrawn_is_reported_applied(self) -> None:
        import logging

        import structlog
        from structlog.testing import capture_logs

        harness, chain = await iptables_harness()
        act = harness.engine.manual_action
        await act(ActionType.RATE_LIMIT, ATTACKER, actor="a", reason="r", duration=600)
        chain.fail_deletes = 2  # the old rule's delete and the new rule's withdrawal
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG))
        try:
            with capture_logs() as logs:
                block = await act(ActionType.BLOCK_IP, ATTACKER, actor="a", reason="escalate")
        finally:
            structlog.configure(
                wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL)
            )
        # The block is in force (first in the chain), so it is reported and recorded as
        # applied; the leftover rate limit is reported separately.
        assert block.outcome == "executed" and chain.kinds() == ["block", "rate_limit"]
        await registry_matches_kernel(harness)
        assert not (await harness.engine.blocked())[0].rate_limited
        leftover = [log for log in logs if log["event"] == "iptables_replaced_rule_left_in_place"]
        assert (
            leftover
            and leftover[0]["log_level"] == "error"
            and "hashlimit" in leftover[0]["leftover"][0]
        )
        # Unblocking removes the leftover too.
        unblock = await act(ActionType.UNBLOCK_IP, ATTACKER, actor="a", reason="r")
        assert unblock.outcome == "executed" and chain.rules == []
        await registry_matches_kernel(harness)

    async def test_reblocking_with_an_identical_rule_is_not_mistaken_for_a_leftover(self) -> None:
        harness, chain = await iptables_harness()
        act = harness.engine.manual_action
        await act(ActionType.BLOCK_IP, ATTACKER, actor="a", reason="r")
        adapter = harness.firewall
        assert isinstance(adapter, IptablesAdapter)
        chain.vanish = True  # the delete removes one copy, then reports failure
        await adapter.block(ipaddress.ip_network(ATTACKER))
        assert chain.kinds() == ["block"]


# =============================================================== safety guard

REFUSED: list[tuple[str, str]] = [
    ("127.0.0.1", "loopback"),
    ("127.10.20.30", "loopback"),
    ("::1", "loopback"),
    ("::ffff:127.0.0.1", "loopback"),
    ("::ffff:7f00:1", "loopback"),
    ("169.254.169.254", "link-local"),
    ("fe80::1", "link-local"),
    ("224.0.0.251", "multicast"),
    ("ff02::1", "multicast"),
    ("239.255.255.250", "multicast"),
    ("240.0.0.1", "reserved"),
    ("255.255.255.255", "reserved"),
    ("0.0.0.0", "reserved"),
    ("::", "reserved"),
    ("0.0.0.0/0", "/0 prefix"),
    ("::/0", "/0 prefix"),
    (LOCAL_V4, "address of this host"),
    (LOCAL_V6, "address of this host"),
    ("192.0.2.0/28", "address of this host"),
    (MANAGEMENT, "management address"),
    ("198.51.100.0/29", "management address"),
    (OPERATOR, "operator signed in"),
    ("10.20.30.40", "allowlisted"),
    ("10.20.30.0/25", "allowlisted"),
    ("10.0.0.0/8", "exceeds the maximum"),
    ("203.0.113.0/23", "exceeds the maximum"),
    ("2001:db8::/64", "exceeds the maximum"),
    ("", "whitespace or control"),
    (" ", "whitespace or control"),
    ("1.2.3.4; rm -rf /", "whitespace or control"),
    ("1.2.3.4\n", "whitespace or control"),
    ("\t1.2.3.4", "whitespace or control"),
    ("1.2.3.4\x00", "whitespace or control"),
    ("1.2.3.4\N{ZERO WIDTH SPACE}", "whitespace or control"),
    ("1.2.3.4\N{NO-BREAK SPACE}", "whitespace or control"),
    ("-A INPUT", "whitespace or control"),
    ("--flush", "not a valid IP network"),
    ("$(reboot)", "not a valid IP network"),
    ("1.2.3.4;reboot", "not a valid IP network"),
    (
        "\N{FULLWIDTH DIGIT ONE}.\N{FULLWIDTH DIGIT TWO}.\N{FULLWIDTH DIGIT THREE}.\N{FULLWIDTH DIGIT FOUR}",
        "not a valid IP network",
    ),
    (
        "\N{ARABIC-INDIC DIGIT ONE}.\N{ARABIC-INDIC DIGIT TWO}.\N{ARABIC-INDIC DIGIT THREE}.\N{ARABIC-INDIC DIGIT FOUR}",
        "not a valid IP network",
    ),
    ("1.2.3.4/33", "not a valid IP network"),
    ("999.1.1.1", "not a valid IP network"),
    ("1.2.3", "not a valid IP network"),
    ("01.2.3.4", "not a valid IP network"),
    ("2001:db8::g", "not a valid IP network"),
    # IPv6 zone identifiers (regression: accepted, and passed verbatim to adapters)
    ("2001:db8::1%eth0", "zone identifiers"),
    ("fe80::1%eth0", "zone identifiers"),
    ("2001:db8::1%'+$(calc)+'", "zone identifiers"),
    # IPv4 embedded in IPv6 (regression: 6to4/Teredo/mapped forms of protected addresses)
    ("2002:7f00:1::1", "embedded 6to4 IPv4 127.0.0.1/32"),
    ("2002:c000:20a::1", "embedded 6to4 IPv4 192.0.2.10/32"),
    ("2001:0:4136:e378:8000:63bf:80ff:fffe", "embedded Teredo client IPv4 127.0.0.1/32"),
    ("2001:0:c000:20a::1", "embedded Teredo server IPv4 192.0.2.10/32"),
    ("::ffff:198.51.100.7", "embedded IPv4-mapped IPv4 198.51.100.7/32"),
    ("::ffff:10.20.30.1", "allowlisted"),
    ("::ffff:203.0.113.200", "operator signed in"),
    ("64:ff9b::7f00:1", "reserved"),
]

ALLOWED = [
    "203.0.113.5",
    "203.0.113.0/25",
    "2001:db8:1::5",
    "::ffff:203.0.113.5",
    "2002:cb00:7105::1",
    "2001:db8:1::/120",
]


class TestSafetyGuardMatrix:
    @pytest.mark.parametrize(("target", "fragment"), REFUSED)
    async def test_refused_with_a_reason_and_no_command(self, target: str, fragment: str) -> None:
        harness, runner = nft_harness(mode=ResponseMode.DETECT_ONLY, max_block_prefix_hosts=256)
        report = harness.engine.guard.evaluate(target)
        assert not report.allowed and fragment in report.reason, report.reason
        for action in (
            ActionType.BLOCK_IP,
            ActionType.TEMPORARY_BLOCK,
            ActionType.RATE_LIMIT,
            ActionType.QUARANTINE,
        ):
            decision = await harness.engine.manual_action(
                action, target, actor="admin", reason="try"
            )
            assert decision.outcome == "failed" and not decision.executed
            assert (decision.error or "").startswith("safety guard:") and fragment in (
                decision.error or ""
            )
        automatic = build()
        decisions = await automatic.engine.handle_detection(
            detection(source=target or "x"), risk(100)
        )
        assert harness.outcome(decisions, ActionType.TEMPORARY_BLOCK).outcome == "failed"
        assert automatic.firewall.operations == []  # type: ignore[attr-defined]
        assert runner.calls == [] and harness.engine.guard.refusals == 4
        assert [r["outcome"] for r in harness.audit] == ["failed"] * 4

    @pytest.mark.parametrize("target", ALLOWED)
    def test_ordinary_targets_are_permitted(self, target: str) -> None:
        report = build(max_block_prefix_hosts=256).engine.guard.evaluate(target)
        assert report.allowed, report.reason

    def test_every_refusal_reason_is_exercised_by_the_matrix(self) -> None:
        reasons = " ".join(fragment for _, fragment in REFUSED)
        for phrase in (
            "loopback",
            "/0 prefix",
            "exceeds",
            "allowlisted",
            "management",
            "this host",
            "operator",
            "whitespace",
            "valid IP",
            "zone",
            "embedded",
        ):
            assert phrase in reasons

    async def test_unblock_with_a_zone_identifier_runs_no_command(self) -> None:
        harness, runner = nft_harness(mode=ResponseMode.DETECT_ONLY)
        decision = await harness.engine.manual_action(
            ActionType.UNBLOCK_IP, "2001:db8::1%;x", actor="a", reason="r"
        )
        assert decision.outcome == "failed" and "zone identifiers" in (decision.error or "")
        assert runner.calls == []

    @pytest.mark.parametrize("kind", ["nftables", "iptables", "pf", "windows_firewall"])
    async def test_adapters_refuse_scoped_networks_before_building_commands(
        self, kind: str
    ) -> None:
        """Regression: ``ipaddress`` accepts any text after '%', which reached pfctl and, on
        Windows, a PowerShell script as ``-RemoteAddress '2001:db8::1%'+$(calc)+'/128'``."""
        runner = RecordingRunner()
        adapters: dict[str, Callable[[], FirewallAdapter]] = {
            "nftables": lambda: NftablesAdapter(runner=runner),  # type: ignore[arg-type]
            "iptables": lambda: IptablesAdapter(runner_v4=runner, runner_v6=runner),  # type: ignore[arg-type]
            "pf": lambda: PfAdapter(runner=runner),  # type: ignore[arg-type]
            "windows_firewall": lambda: WindowsFirewallAdapter(runner=runner),  # type: ignore[arg-type]
        }
        adapter = adapters[kind]()
        scoped = ipaddress.ip_network("2001:db8::1%'+$(calc)+'")
        with pytest.raises(FirewallError, match="zone identifier"):
            await adapter.block(scoped, comment="x")
        if kind in ("nftables", "iptables"):
            with pytest.raises(FirewallError, match="zone identifier"):
                await adapter.rate_limit(scoped, packets_per_second=10)
        if kind != "windows_firewall":  # its unblock uses only a hash of the network
            with pytest.raises(FirewallError, match="zone identifier"):
                await adapter.unblock(scoped)
        assert runner.calls == []
        entry = await adapter.block(ipaddress.ip_network("2001:db8::1"))
        assert isinstance(entry, BlockEntry) and runner.calls
