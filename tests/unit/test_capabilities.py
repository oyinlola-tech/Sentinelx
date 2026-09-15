"""Capability detection and diagnostics must describe the host as it is."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import sentinelx.system.environment as environment_module
from sentinelx.config.settings import Settings
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
