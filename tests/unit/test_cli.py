"""CLI behaviour: exit codes, stdout/stderr discipline and JSON output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelx.cli.main import app

REPO_RULES = Path(__file__).resolve().parents[2] / "rules"


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setenv("PCAP_DIRECTORY", str(tmp_path / "pcaps"))
    monkeypatch.setenv("RULES_DIRECTORY", str(REPO_RULES))
    monkeypatch.setenv("COLUMNS", "200")
    return tmp_path


def invoke(*args: str) -> object:
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def test_version() -> None:
    result = invoke("--version")
    assert result.exit_code == 0 and "sentinelx" in result.output  # type: ignore[attr-defined]


def test_fixtures_and_replay_json_is_clean_on_stdout(cli_env: Path) -> None:
    assert invoke("fixtures", "generate", "tcp_port_scan", "-o", str(cli_env / "fx")).exit_code == 0  # type: ignore[attr-defined]
    result = CliRunner().invoke(
        app,
        ["replay", str(cli_env / "fx" / "tcp_port_scan.pcap"), "--json"],
        catch_exceptions=False,
    )
    report = json.loads(result.stdout)  # would fail if diagnostics leaked onto stdout
    assert result.exit_code == 0
    assert report["frames"] == 440 and "tcp_port_scan" in report["detections_by_detector"]
    assert report["safety_note"].startswith("Replay responses are always simulated")


def test_rules_validate_and_test_exit_codes(cli_env: Path, tmp_path: Path) -> None:
    assert invoke("rules", "validate").exit_code == 0  # type: ignore[attr-defined]
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "rules:\n  - name: Blocks Everyone\n    condition: protocol == TCP\n    action: block_ip\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["rules", "validate", str(bad)])
    assert result.exit_code == 1 and "count threshold" in result.output
    assert invoke("rules", "test", str(REPO_RULES / "authentication.yml")).exit_code == 0  # type: ignore[attr-defined]


def test_block_is_simulated_and_unsafe_block_fails(cli_env: Path) -> None:
    simulated = CliRunner().invoke(app, ["block", "203.0.113.9", "-r", "scanner", "--json"])
    assert simulated.exit_code == 0 and json.loads(simulated.stdout)["outcome"] == "simulated"
    refused = CliRunner().invoke(app, ["block", "127.0.0.1", "-r", "mistake", "--json"])
    assert refused.exit_code == 1 and "safety guard" in json.loads(refused.stdout)["error"]


def test_invalid_configuration_exits_2(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RESPONSE_MODE", "automatic")
    monkeypatch.setenv("DRY_RUN", "false")
    result = CliRunner().invoke(app, ["status"])
    assert result.exit_code == 2 and "FIREWALL_BACKEND" in result.output


def test_status_and_doctor_json(cli_env: Path) -> None:
    status = CliRunner().invoke(app, ["status", "--json"])
    assert status.exit_code == 0 and json.loads(status.stdout)["safety"].startswith(
        "DETECTION ONLY"
    )
    doctor = CliRunner().invoke(app, ["doctor", "--json"])
    checks = {c["check"]: c["status"] for c in json.loads(doctor.stdout)}
    assert checks["rules"] == "ok" and checks["database"] == "ok" and checks["redis"] == "warn"


def test_config_set_rejects_prevention_without_confirmation(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FIREWALL_BACKEND", "nftables")
    monkeypatch.setenv("RESPONSE_MODE", "automatic")
    result = CliRunner().invoke(app, ["config", "set", "response", "dry_run", "false"])
    assert result.exit_code == 1 and "ENABLE PREVENTION" in result.output
