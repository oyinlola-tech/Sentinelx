"""pf and Windows Firewall adapters, and backend selection.

These adapters cannot run on the Linux CI host, so their command construction, output
parsing and error mapping are tested against recorded command results. Real enforcement
on macOS and Windows is not covered here and is documented as unverified.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

import sentinelx.firewall as firewall_module
from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import parse_network
from sentinelx.config.settings import ResponseSettings
from sentinelx.firewall import (
    NullFirewall,
    UnavailableFirewall,
    create_firewall,
    firewall_capabilities,
)
from sentinelx.firewall.base import CommandResult
from sentinelx.firewall.pf import PfAdapter
from sentinelx.firewall.windows import WindowsFirewallAdapter


class ScriptedRunner:
    """Returns queued results and records every argv."""

    def __init__(self, *results: tuple[int, str, str]) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, ...]] = []

    async def run(self, *args: str, check: bool = True) -> CommandResult:
        self.calls.append(args)
        code, stdout, stderr = self.results.pop(0) if self.results else (0, "", "")
        if check and code != 0:
            raise FirewallError("failed")
        return CommandResult(argv=args, returncode=code, stdout=stdout, stderr=stderr, duration=0.0)


class TestPf:
    async def test_block_adds_to_anchor_table_and_kills_states(self) -> None:
        runner = ScriptedRunner((0, "", "1/1 addresses added.\n"), (0, "", ""))
        adapter = PfAdapter(runner=runner)  # type: ignore[arg-type]
        entry = await adapter.block(parse_network("203.0.113.5"), duration=600)
        assert runner.calls[0] == (
            "-a",
            "com.apple/sentinelx",
            "-t",
            "sentinelx_block",
            "-T",
            "add",
            "203.0.113.5/32",
        )
        assert runner.calls[1] == ("-k", "203.0.113.5")
        assert entry.temporary

    async def test_unblock_parses_deleted_count(self) -> None:
        present = ScriptedRunner((0, "", "1/1 addresses deleted.\n"))
        absent = ScriptedRunner((0, "", "0/1 addresses deleted.\n"))
        assert await PfAdapter(runner=present).unblock(parse_network("203.0.113.5")) is True  # type: ignore[arg-type]
        assert await PfAdapter(runner=absent).unblock(parse_network("203.0.113.5")) is False  # type: ignore[arg-type]

    async def test_permission_denied_is_an_error_not_success(self) -> None:
        runner = ScriptedRunner((1, "", "pfctl: /dev/pf: Permission denied\n"))
        with pytest.raises(FirewallError, match="root"):
            await PfAdapter(runner=runner).block(parse_network("203.0.113.5"))  # type: ignore[arg-type]

    async def test_list_parses_table_and_rate_limit_is_refused(self) -> None:
        runner = ScriptedRunner((0, "   203.0.113.5\n   198.51.100.0/28\n", ""))
        adapter = PfAdapter(runner=runner)  # type: ignore[arg-type]
        assert {e.network for e in await adapter.list_blocked()} == {
            "203.0.113.5/32",
            "198.51.100.0/28",
        }
        with pytest.raises(FirewallError, match="rate-limit"):
            await adapter.rate_limit(parse_network("203.0.113.5"), packets_per_second=10)

    def test_rejects_unsafe_anchor_names(self) -> None:
        with pytest.raises(FirewallError):
            PfAdapter(anchor="x; pfctl -d", runner=ScriptedRunner())  # type: ignore[arg-type]


class TestWindowsFirewall:
    async def test_block_script_contains_only_generated_values(self) -> None:
        runner = ScriptedRunner((0, "", ""))
        adapter = WindowsFirewallAdapter(runner=runner)  # type: ignore[arg-type]
        await adapter.block(
            parse_network("203.0.113.5"), duration=60, comment="x'; Remove-Item C:\\ -Recurse"
        )
        script = runner.calls[0][-1]
        assert "Remove-Item" not in script  # operator text is never interpolated
        assert "-RemoteAddress '203.0.113.5/32'" in script
        assert "-Direction Inbound" in script and "-Direction Outbound" in script
        assert "-Description 'exp=" in script and "-Group 'SentinelX'" in script
        assert runner.calls[0][:6] == (
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        )

    async def test_access_denied_explains_elevation(self) -> None:
        runner = ScriptedRunner((1, "", "New-NetFirewallRule : Access is denied.\n"))
        with pytest.raises(FirewallError, match="elevated"):
            await WindowsFirewallAdapter(runner=runner).block(parse_network("203.0.113.5"))  # type: ignore[arg-type]

    async def test_list_restores_expiry_from_description(self) -> None:
        expires = int(datetime(2030, 1, 1, tzinfo=UTC).timestamp())
        listing = json.dumps(
            [
                {
                    "Name": "SentinelX-abc-inbound",
                    "Description": f"exp={expires}",
                    "Remote": ["203.0.113.5"],
                }
            ]
        )
        runner = ScriptedRunner((0, listing, ""))
        entries = await WindowsFirewallAdapter(runner=runner).list_blocked()  # type: ignore[arg-type]
        assert entries[0].network == "203.0.113.5/32"
        assert entries[0].expires_at == datetime(2030, 1, 1, tzinfo=UTC)

    async def test_unblock_reports_whether_rules_existed(self) -> None:
        assert (
            await WindowsFirewallAdapter(runner=ScriptedRunner((0, "2\n", ""))).unblock(
                parse_network("203.0.113.5")
            )
            is True
        )  # type: ignore[arg-type]
        assert (
            await WindowsFirewallAdapter(runner=ScriptedRunner((0, "0\n", ""))).unblock(
                parse_network("203.0.113.5")
            )
            is False
        )  # type: ignore[arg-type]


class TestBackendSelection:
    @pytest.mark.parametrize(
        ("platform", "backend", "available_somewhere"),
        [
            ("win32", "nftables", False),
            ("darwin", "windows_firewall", False),
            ("linux", "pf", False),
        ],
    )
    def test_backend_for_another_platform_is_reported_unavailable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        platform: str,
        backend: str,
        available_somewhere: bool,
    ) -> None:
        monkeypatch.setattr(firewall_module, "PLATFORM", platform)
        report = firewall_capabilities(backend)
        assert report.available is available_somewhere and "not available on" in report.reason

    def test_missing_binary_yields_unavailable_adapter_not_crash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(firewall_module, "PLATFORM", "linux")
        monkeypatch.setattr("shutil.which", lambda name: None)
        adapter = create_firewall(ResponseSettings(firewall_backend="nftables"))
        assert isinstance(adapter, UnavailableFirewall) and adapter.backend == "nftables"

    async def test_auto_without_a_usable_backend_is_null_with_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(firewall_module, "PLATFORM", "sunos5")
        adapter = create_firewall(ResponseSettings(firewall_backend="auto"))
        assert isinstance(adapter, NullFirewall)
        with pytest.raises(FirewallError, match="no firewall backend exists"):
            await adapter.block(parse_network("203.0.113.5"))
