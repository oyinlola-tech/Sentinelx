"""Windows Firewall adapter (Windows Defender Firewall with Advanced Security).

Each block is a pair of rules - inbound and outbound - in the ``SentinelX`` rule
group, created and removed with the NetSecurity PowerShell cmdlets. Windows Firewall
has no per-rule expiry, so a temporary block's deadline is stored in the rule's
description (``exp=<unix seconds>``) and enforced by the response engine's reaper,
including after a restart. Rate limiting is not available on this platform.

Requires an elevated (Administrator) process. Group Policy can override local rules,
and rules have no effect on a profile whose firewall is turned off; :meth:`health`
reports both conditions.

Only values SentinelX generated are placed in the PowerShell scripts: network
addresses that passed :mod:`ipaddress` and the safety guard, hexadecimal rule names,
and integers. Operator-supplied text (block reasons) is never interpolated.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT, parse_network
from sentinelx.firewall.base import BlockEntry, CommandRunner, FirewallAdapter
from sentinelx.telemetry.logging import get_logger

__all__ = ["WindowsFirewallAdapter", "powershell_path"]

log = get_logger(__name__)

PLATFORM: str = sys.platform
GROUP = "SentinelX"
_PREFIX = "SentinelX-"


def powershell_path() -> str | None:
    """Absolute path to Windows PowerShell, resolved without trusting ``PATH``."""
    root = os.environ.get("SYSTEMROOT", r"C:\Windows")  # case-insensitive on Windows
    candidate = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(candidate) if candidate.is_file() else None


def _rule_name(network: IPNetworkT) -> str:
    digest = hashlib.sha256(str(network).encode("ascii")).hexdigest()[:16]
    return f"{_PREFIX}{digest}"


class WindowsFirewallAdapter(FirewallAdapter):
    backend = "windows_firewall"

    def __init__(self, *, runner: CommandRunner | None = None) -> None:
        if runner is None:
            executable = powershell_path()
            if executable is None:
                raise FirewallError(
                    "Windows PowerShell was not found; Windows Firewall control is unavailable"
                )
            runner = CommandRunner(executable, timeout=30.0)
        self._runner = runner
        self._comments: dict[str, str] = {}

    async def _script(self, body: str, *, check: bool = True) -> str:
        """Run a PowerShell script. ``body`` must contain only generated values."""
        preamble = (
            "$ErrorActionPreference='Stop';"
            "$ProgressPreference='SilentlyContinue';"
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        )
        result = await self._runner.run(
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            preamble + body,
            check=False,
        )
        if check and not result.ok:
            detail = (result.stderr or result.stdout).strip()
            if "access is denied" in detail.lower() or "0x80070005" in detail:
                raise FirewallError(
                    "Windows Firewall refused the change: run SentinelX from an elevated "
                    "(Administrator) terminal",
                    command="powershell NetSecurity",
                    stderr=result.stderr,
                )
            raise FirewallError(
                f"Windows Firewall command failed: {detail[:300]}",
                command="powershell NetSecurity",
                stderr=result.stderr,
            )
        return result.stdout

    async def setup(self) -> None:
        # Rules are self-contained; there is no table or chain to create.
        return None

    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        name = _rule_name(network)
        expires = datetime.now(UTC) + timedelta(seconds=duration) if duration else None
        description = f"exp={int(expires.timestamp())}" if expires else "exp=never"
        address = str(parse_network(str(network)))  # re-validated: goes into a script
        rules = ";".join(
            f"New-NetFirewallRule -Name '{name}-{direction.lower()}' "
            f"-DisplayName 'SentinelX block {address} ({direction.lower()})' "
            f"-Group '{GROUP}' -Description '{description}' -Direction {direction} "
            f"-Action Block -RemoteAddress '{address}' -Profile Any -Enabled True | Out-Null"
            for direction in ("Inbound", "Outbound")
        )
        script = (
            f"Remove-NetFirewallRule -Name '{name}-inbound','{name}-outbound' "
            f"-ErrorAction SilentlyContinue;{rules}"
        )
        try:
            await self._script(script)
        except FirewallError:
            self._record("block", self.backend, False)
            raise
        self._record("block", self.backend, True)
        self._comments[str(network)] = comment
        return BlockEntry(network=str(network), expires_at=expires, comment=comment)

    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        self._record("rate_limit", self.backend, False)
        raise FirewallError(
            "Windows Firewall cannot rate-limit traffic; use a block or a temporary block"
        )

    async def unblock(self, network: IPNetworkT) -> bool:
        name = _rule_name(network)
        script = (
            f"$r=@(Get-NetFirewallRule -Name '{name}-inbound','{name}-outbound' "
            "-ErrorAction SilentlyContinue);"
            "if($r.Count -gt 0){$r | Remove-NetFirewallRule};"
            "Write-Output $r.Count"
        )
        try:
            output = await self._script(script)
        except FirewallError:
            self._record("unblock", self.backend, False)
            raise
        lines = output.strip().splitlines()
        try:
            removed = int(lines[-1]) > 0 if lines else False
        except ValueError as exc:
            raise FirewallError("unexpected output from Remove-NetFirewallRule") from exc
        self._comments.pop(str(network), None)
        self._record("unblock", self.backend, True)
        return removed

    async def list_blocked(self) -> list[BlockEntry]:
        script = (
            f"ConvertTo-Json -Compress -InputObject @(Get-NetFirewallRule -Group '{GROUP}' "
            "-Direction Inbound -ErrorAction SilentlyContinue | ForEach-Object {"
            "[pscustomobject]@{Name=$_.Name;Description=$_.Description;"
            "Remote=@(($_ | Get-NetFirewallAddressFilter).RemoteAddress)}})"
        )
        return self._parse_rules(await self._script(script))

    def _parse_rules(self, payload: str) -> list[BlockEntry]:
        text = payload.strip()
        if not text:
            return []
        try:
            document: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FirewallError("could not parse Windows Firewall rule listing") from exc
        rules = document if isinstance(document, list) else [document]
        entries: list[BlockEntry] = []
        for rule in rules:
            if not isinstance(rule, dict) or not str(rule.get("Name", "")).startswith(_PREFIX):
                continue
            remotes = rule.get("Remote") or []
            if isinstance(remotes, str):
                remotes = [remotes]
            for remote in remotes:
                try:
                    network = str(parse_network(str(remote)))
                except ValueError:
                    continue
                entries.append(
                    BlockEntry(
                        network=network,
                        expires_at=_expiry(str(rule.get("Description", ""))),
                        comment=self._comments.get(network, ""),
                    )
                )
        return entries

    async def teardown(self) -> None:
        await self._script(
            f"Remove-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue", check=False
        )
        self._comments.clear()

    async def health(self) -> dict[str, object]:
        script = (
            "ConvertTo-Json -Compress -InputObject @{"
            "Profiles=@(Get-NetFirewallProfile | ForEach-Object {"
            "[pscustomobject]@{Name=$_.Name;Enabled=[bool]$_.Enabled}});"
            f"Rules=@(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue).Count}}"
        )
        try:
            document = json.loads(await self._script(script))
        except (FirewallError, json.JSONDecodeError) as exc:
            return {
                "backend": self.backend,
                "ok": False,
                "enforcing": False,
                "error": str(exc)[:300],
            }
        profiles = document.get("Profiles") or []
        disabled = [p.get("Name") for p in profiles if isinstance(p, dict) and not p.get("Enabled")]
        return {
            "backend": self.backend,
            "ok": not disabled,
            "enforcing": not disabled,
            "rules": document.get("Rules", 0),
            "disabled_profiles": disabled,
            "error": f"firewall is off for profile(s): {', '.join(map(str, disabled))}"
            if disabled
            else None,
        }


def _expiry(description: str) -> datetime | None:
    if not description.startswith("exp=") or description == "exp=never":
        return None
    try:
        return datetime.fromtimestamp(int(description[4:]), UTC)
    except ValueError:
        return None
