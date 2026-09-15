"""Capability detection and diagnostics must describe the host as it is."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

import sentinelx.system.environment as environment_module
from sentinelx.config.settings import ResponseSettings, Settings
from sentinelx.services import diagnostics
from sentinelx.system.capabilities import detect_capabilities


def test_report_contains_every_documented_field() -> None:
    report = detect_capabilities(Settings()).as_dict()
    for key in (
        "operating_system",
        "architecture",
        "privileged_access",
        "interface_enumeration_available",
        "packet_capture_available",
        "live_capture_available",
        "pcap_replay_available",
        "firewall_available",
        "automatic_blocking_available",
    ):
        assert key in report
    # PCAP replay is the universal fallback and must work wherever the tests run.
    assert report["pcap_replay_available"] is True


def test_null_firewall_is_never_reported_as_able_to_block() -> None:
    report = detect_capabilities(Settings())
    assert not report.firewall.available and not report.automatic_blocking.available


def test_unprivileged_live_capture_explains_how_to_enable_it() -> None:
    report = detect_capabilities(Settings())
    if not report.live_capture.available:
        assert report.live_capture.remedy


@pytest.mark.parametrize(
    ("osrelease", "expected"),
    [
        ("5.15.153.1-microsoft-standard-WSL2", 2),
        ("4.4.0-19041-Microsoft", 1),
        ("6.8.0-45-generic", None),
    ],
)
def test_wsl_detection_from_kernel_release(
    monkeypatch: pytest.MonkeyPatch, osrelease: str, expected: int | None
) -> None:
    monkeypatch.setattr(environment_module, "PLATFORM", "linux")
    monkeypatch.setattr(environment_module, "_read", lambda path: osrelease)
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.delenv("WSL_INTEROP", raising=False)
    assert environment_module._wsl_version() == expected


async def test_doctor_does_not_pass_a_service_that_is_not_sentinelx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"hello": "some other app"})

    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        return original(transport=transport)

    monkeypatch.setattr(diagnostics.httpx, "AsyncClient", client)
    check = await diagnostics._probe("http://127.0.0.1:9/x", "dashboard", "dashboard", "dashboard")
    assert check.status == "WARN" and "not as SentinelX" in check.detail


async def test_doctor_fails_when_rules_directory_is_missing(tmp_path: Path) -> None:
    checks = diagnostics._local_checks(Settings(rules_directory=tmp_path / "missing"))
    rules = next(c for c in checks if c.name == "rules")
    assert rules.status == "FAIL"


def test_interface_addresses_survive_a_refused_stats_ioctl(monkeypatch: pytest.MonkeyPatch) -> None:
    # QEMU user-mode emulation (and some sandboxed kernels) refuse SIOCETHTOOL, which
    # psutil.net_if_stats needs. Addresses must still be readable: the firewall
    # safety guard depends on them.
    import psutil

    from sentinelx.system import interfaces

    def refused() -> None:
        raise OSError(25, "Inappropriate ioctl for device")

    monkeypatch.setattr(psutil, "net_if_stats", refused)
    listed = interfaces.list_interfaces()
    assert listed and all(entry["is_up"] is False for entry in listed)
    assert "127.0.0.1" in interfaces.local_addresses()


def test_refused_address_enumeration_is_still_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import psutil

    from sentinelx.system import interfaces

    def refused() -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(psutil, "net_if_addrs", refused)
    with pytest.raises(OSError):
        interfaces.local_addresses()


class TestFirewallFunctionalProbe:
    """A firewall used to count as available when its tool was installed and privileges
    were held, even if the kernel side did not work (no nf_tables, netlink refused)."""

    @pytest.fixture
    def host(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        import shutil

        import sentinelx.firewall as firewall_module
        from sentinelx.system.privileges import PrivilegeCheck

        tools = tmp_path / "bin"
        tools.mkdir()
        real_which = shutil.which

        def which(name: str, *args: object, **kwargs: object) -> str | None:
            candidate = tools / Path(name).name
            if candidate.exists():
                return str(candidate)
            return None if "/" not in name else real_which(name)

        monkeypatch.setattr(firewall_module, "PLATFORM", "linux")
        monkeypatch.setattr("shutil.which", which)
        monkeypatch.setattr(
            firewall_module, "firewall_privilege", lambda: PrivilegeCheck(True, "running as root")
        )
        monkeypatch.setattr(firewall_module, "_probe_cache", {}, raising=False)
        return tools

    @staticmethod
    def tool(directory: Path, name: str, body: str) -> Path:
        import stat

        path = directory / name
        log = directory / f"{name}.calls"
        path.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\n{body}', encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return log

    @pytest.mark.skipif(sys.platform == "win32", reason="fake tools are shell scripts")
    def test_kernel_without_nf_tables_is_unavailable_with_the_real_error(self, host: Path) -> None:
        from sentinelx.firewall import create_firewall, firewall_capabilities, resolve_backend

        nft_calls = self.tool(
            host,
            "nft",
            'echo "Error: Could not process rule: Operation not supported" >&2\nexit 1\n',
        )
        iptables_calls = self.tool(host, "iptables", "echo '-P INPUT ACCEPT'\nexit 0\n")

        report = firewall_capabilities("nftables")
        assert not report.available
        assert "'nft list tables' failed" in report.reason
        assert "Operation not supported" in report.reason and report.remedy
        assert firewall_capabilities("iptables").available

        # auto skips the backend that does not work; detection and doctor say why.
        assert resolve_backend("auto")[0] == "iptables"
        capabilities = detect_capabilities(Settings(response={"firewall_backend": "nftables"}))
        assert not capabilities.firewall.available
        assert "Operation not supported" in capabilities.firewall.detail
        assert not capabilities.automatic_blocking.available
        checks = diagnostics._platform_checks(
            Settings(response={"firewall_backend": "nftables"}), capabilities
        )
        doctor = next(c for c in checks if c.name == "firewall backend")
        assert doctor.status == "WARN" and "Operation not supported" in doctor.detail
        assert create_firewall(ResponseSettings(firewall_backend="auto")).backend == "iptables"

        # Probes are read-only, and cached like the rest of capability detection.
        assert set(nft_calls.read_text().splitlines()) == {"list tables"}
        assert set(iptables_calls.read_text().splitlines()) == {"-w -S INPUT"}
        assert len(nft_calls.read_text().splitlines()) == 1

    @pytest.mark.skipif(sys.platform == "win32", reason="fake tools are shell scripts")
    def test_probe_that_hangs_is_bounded(self, host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        import sentinelx.firewall as firewall_module

        monkeypatch.setattr(firewall_module, "PROBE_TIMEOUT_SECONDS", 0.3, raising=False)
        self.tool(host, "nft", "sleep 5\n")
        started = time.monotonic()
        report = firewall_module.firewall_capabilities("nftables")
        assert time.monotonic() - started < 3
        assert not report.available and "timed out" in report.reason
