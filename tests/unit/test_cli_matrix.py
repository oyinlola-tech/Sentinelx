"""Every CLI command: help, usage errors, exit codes, JSON discipline, doctor accuracy.

Exit codes: 0 success, 1 runtime failure, 2 usage error. A failure is a message, never
a Python traceback. Commands are enumerated from the Typer app, so a new command is
covered by the help and usage tests without editing this file.
"""

from __future__ import annotations

import http.server
import json
import os
import platform
import socket
import stat
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import click
import pytest
import typer
from click.testing import Result
from typer.testing import CliRunner

from sentinelx.cli.main import app

REPO_RULES = Path(__file__).resolve().parents[2] / "rules"
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


# ------------------------------------------------------------------ helpers


def _walk(
    command: click.Command, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], click.Command]]:
    yield path, command
    if isinstance(command, click.Group):
        for name, sub in sorted(command.commands.items()):
            yield from _walk(sub, (*path, name))


COMMANDS = dict(_walk(typer.main.get_command(app)))
LEAVES = {path: cmd for path, cmd in COMMANDS.items() if not isinstance(cmd, click.Group)}


def _required_arguments(command: click.Command) -> list[click.Parameter]:
    return [p for p in command.params if isinstance(p, click.Argument) and p.required]


def invoke(*args: str, input: str | None = None) -> Result:
    return CliRunner().invoke(app, list(args), input=input)


def no_traceback(result: Result) -> bool:
    """The command ended through an exit code, not an unhandled exception."""
    return result.exception is None or isinstance(result.exception, SystemExit)


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setenv("PCAP_DIRECTORY", str(tmp_path / "pcaps"))
    monkeypatch.setenv("RULES_DIRECTORY", str(REPO_RULES))
    monkeypatch.setenv("FIREWALL_BACKEND", "null")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("COLUMNS", "200")
    for name in (
        "ANOMALY__ML_ENABLED",
        "ANOMALY__ML_MODEL_PATH",
        "STORAGE__REDIS_REQUIRED",
        "API_HOST",
        "API__HOST",
        "SENTINELX_API_URL",
        "SENTINELX_DASHBOARD_URL",
        "ENVIRONMENT",
    ):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


@pytest.fixture
def unwritable(tmp_path: Path) -> Iterator[Path]:
    if ROOT or os.name == "nt":
        pytest.skip("root ignores directory permissions; Windows uses ACLs, not mode bits")
    directory = tmp_path / "read-only"
    directory.mkdir()
    directory.chmod(stat.S_IRUSR | stat.S_IXUSR)
    yield directory
    directory.chmod(stat.S_IRWXU)


@pytest.fixture
def fixture_pcap(cli_env: Path) -> Path:
    result = invoke("fixtures", "generate", "tcp_port_scan", "-o", str(cli_env / "fx"))
    assert result.exit_code == 0, result.output
    return cli_env / "fx" / "tcp_port_scan.pcap"


def doctor(*extra: str) -> tuple[Result, dict[str, dict[str, str]]]:
    closed = f"http://127.0.0.1:{closed_port()}"
    args = ["doctor", "--json", *extra]
    if "--api-url" not in extra:
        args += ["--api-url", closed]
    if "--dashboard-url" not in extra:
        args += ["--dashboard-url", closed]
    result = invoke(*args)
    assert no_traceback(result), result.output
    return result, {c["name"]: c for c in json.loads(result.stdout)}


# ------------------------------------------------------- enumeration and usage


def test_every_documented_command_exists() -> None:
    names = {" ".join(path) for path in LEAVES}
    assert names == {
        "start", "status", "interfaces", "detections", "incidents", "threats", "blocked",
        "block", "unblock", "replay", "monitor", "metrics", "doctor", "capabilities",
        "version", "fixtures list", "fixtures generate", "anomaly train", "rules list",
        "rules validate", "rules test", "rules enable", "rules disable", "rules fields",
        "config set", "db upgrade", "db current", "db purge", "users list", "users create",
        "users reset-password",
    }  # fmt: skip


@pytest.mark.parametrize("path", sorted(COMMANDS), ids=lambda p: " ".join(p) or "<root>")
def test_help_exits_0(path: tuple[str, ...]) -> None:
    result = invoke(*path, "--help")
    assert result.exit_code == 0, result.output
    assert "Usage" in result.output


@pytest.mark.parametrize(
    "path",
    sorted(p for p, c in LEAVES.items() if _required_arguments(c)),
    ids=" ".join,
)
def test_missing_required_argument_is_a_usage_error(path: tuple[str, ...]) -> None:
    result = invoke(*path, input="")
    assert result.exit_code == 2, result.output
    assert no_traceback(result)
    assert "Missing argument" in result.output and "Usage" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["start", "--port", "abc"],
        ["start", "--port", "99999"],  # used to bind 99999 - 65536 = 34463 while printing :99999
        ["start", "--port", "0"],  # used to fall back to API_PORT silently
        ["detections", "--limit", "0"],
        ["detections", "--hours", "x"],
        ["incidents", "--limit", "9999"],
        ["threats", "--limit", "x"],
        ["block", "203.0.113.9", "-r", "x", "-t", "5"],
        ["replay", "/nonexistent.pcap"],
        ["replay", ".", "--json"],
        ["monitor", "--scenario", "nope"],
        ["monitor", "--duration", "abc"],
        ["monitor", "--duration", "-1"],
        ["monitor", "--pcap", "/nonexistent.pcap"],  # used to open the live view, then exit 1
        ["fixtures", "generate", "nope"],
        ["anomaly", "train", "/nonexistent.pcap"],
        ["rules", "test", "/nonexistent.yml"],
        ["rules", "validate", "/nonexistent.yml"],  # used to report "0 valid" and exit 0
        ["users", "create", "bob", "--role", "wizard"],
        ["config", "--section", "nosuch"],  # used to print {"nosuch": null} and exit 0
        ["db", "upgrade", "extra-argument"],
        ["doctor", "--api-url"],
        ["nonexistent-command"],
    ],
    ids=" ".join,
)
def test_invalid_values_are_usage_errors(cli_env: Path, args: list[str]) -> None:
    result = invoke(*args, input="")
    assert result.exit_code == 2, result.output
    assert no_traceback(result)


@pytest.mark.parametrize("command", ["block", "unblock"])
def test_block_without_target_off_a_terminal_is_a_usage_error(cli_env: Path, command: str) -> None:
    # Prompting a pipe used to read EOF and exit 1 ("Aborted"), which scripts cannot
    # tell apart from a firewall failure.
    result = invoke(command, input="")
    assert result.exit_code == 2 and no_traceback(result)
    assert "Missing TARGET" in result.output
    result = invoke(command, "203.0.113.9", input="")
    assert result.exit_code == 2 and "Missing --reason" in result.output


@pytest.mark.parametrize("group", ["fixtures", "anomaly", "rules", "db", "users"])
def test_bare_group_prints_help(group: str) -> None:
    result = invoke(group)
    assert "Usage" in result.output and no_traceback(result)
    assert result.exit_code in (0, 2)  # click >= 8.2 treats no_args_is_help as a usage error


# ------------------------------------------------------------ normal operation


@pytest.mark.parametrize(
    "args",
    [
        ["status", "--json"],
        ["interfaces", "--json"],
        ["capabilities", "--json"],
        ["fixtures", "list", "--json"],
        ["rules", "list", "--json"],
        ["rules", "validate", "--json"],
        ["config", "--json"],
        ["config", "--section", "response", "--json"],
        ["detections", "--json"],
        ["incidents", "--json"],
        ["threats", "--json"],
        ["blocked", "--json"],
        ["block", "203.0.113.9", "-r", "test", "--json"],
        ["block", "203.0.113.0/24", "-r", "test", "-t", "60", "--json"],
        ["block", "203.0.113.10", "-r", "test", "--rate-limit", "--json"],
        ["unblock", "203.0.113.9", "-r", "test", "--json"],
    ],
    ids=" ".join,
)
def test_json_is_clean_on_stdout(cli_env: Path, args: list[str]) -> None:
    result = invoke(*args)
    assert result.exit_code == 0, result.output
    json.loads(result.stdout)  # diagnostics (log lines, warnings) must stay on stderr


@pytest.mark.parametrize(
    "args",
    [
        ["version"],
        ["--version"],
        ["status"],
        ["interfaces"],
        ["capabilities"],
        ["fixtures", "list"],
        ["rules", "list"],
        ["rules", "fields"],
        ["config"],
        ["db", "current"],
        ["db", "upgrade"],
        ["db", "purge"],
        ["users", "list"],
        ["detections"],
        ["incidents"],
        ["threats"],
        ["blocked"],
    ],
    ids=" ".join,
)
def test_commands_succeed_in_a_clean_environment(cli_env: Path, args: list[str]) -> None:
    result = invoke(*args)
    assert result.exit_code == 0, result.output


def test_block_and_unblock_are_simulated_in_dry_run(cli_env: Path) -> None:
    for command in ("block", "unblock"):
        result = invoke(command, "203.0.113.9", "-r", "audit", "--json")
        payload = json.loads(result.stdout)
        assert result.exit_code == 0 and payload["outcome"] == "simulated" and payload["dry_run"]


def test_replay_report_and_persist(cli_env: Path, fixture_pcap: Path) -> None:
    report = cli_env / "report.json"
    result = invoke("replay", str(fixture_pcap), "--json", "--report", str(report))
    assert result.exit_code == 0, result.output
    assert json.loads(report.read_text())["frames"] == json.loads(result.stdout)["frames"] == 440

    stored = invoke("replay", str(fixture_pcap), "--persist", "--json")
    assert stored.exit_code == 0, stored.output
    payload = json.loads(stored.stdout)
    assert payload["replay_id"] and payload["detection_count"] > 0
    assert "stored as replay" in stored.stderr


def test_monitor_scenario_and_pcap_finish(cli_env: Path, fixture_pcap: Path) -> None:
    result = invoke("monitor", "--scenario", "tcp_port_scan", "--duration", "5")
    assert result.exit_code == 0, result.output
    assert "finished" in result.stdout
    result = invoke("monitor", "--pcap", str(fixture_pcap), "--duration", "1")
    assert result.exit_code == 0, result.output


def test_rules_commands(cli_env: Path, fixture_pcap: Path) -> None:
    assert invoke("rules", "test", str(REPO_RULES / "authentication.yml")).exit_code == 0
    matched = invoke(
        "rules",
        "test",
        str(REPO_RULES / "network-recon.yml"),
        "--pcap",
        str(fixture_pcap),
        "--json",
    )
    assert matched.exit_code == 0 and json.loads(matched.stdout)
    assert invoke("rules", "disable", "ssh_brute_force").exit_code == 0
    assert invoke("rules", "enable", "ssh_brute_force").exit_code == 0
    unknown = invoke("rules", "enable", "no_such_rule")
    assert unknown.exit_code == 1 and "no rule" in unknown.output


def test_users_lifecycle(cli_env: Path) -> None:
    password = "Corr3ct-Horse-Battery\n" * 2
    assert invoke("users", "create", "alice", "--role", "analyst", input=password).exit_code == 0
    duplicate = invoke("users", "create", "alice", input=password)
    assert duplicate.exit_code == 1 and "already exists" in duplicate.stderr
    weak = invoke("users", "create", "weak", input="a\na\n")
    assert weak.exit_code == 1 and no_traceback(weak)
    listed = invoke("users", "list")
    assert listed.exit_code == 0 and "alice" in listed.stdout and "analyst" in listed.stdout
    assert invoke("users", "reset-password", "alice", input=password).exit_code == 0
    missing = invoke("users", "reset-password", "nobody", input=password)
    assert missing.exit_code == 1 and "no user" in missing.stderr


@pytest.mark.parametrize("kind", ["detections", "incidents"])
def test_unknown_id_fails_with_json_too(cli_env: Path, kind: str) -> None:
    # --json used to print "null" and exit 0.
    for extra in ([], ["--json"]):
        result = invoke(kind, "--id", "nope", *extra)
        assert result.exit_code == 1 and "not found" in result.stderr
        assert result.stdout.strip() == ""


def test_rules_validate_fails_when_rules_directory_is_missing(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RULES_DIRECTORY", str(cli_env / "missing"))
    result = invoke("rules", "validate", "--json")
    assert result.exit_code == 1
    assert "does not exist" in json.loads(result.stdout)["problems"][0]


def test_config_unknown_section_lists_the_real_ones(cli_env: Path) -> None:
    result = invoke("config", "--section", "nosuch")
    assert result.exit_code == 2 and "response" in result.stderr and result.stdout == ""


# ------------------------------------------------------- unavailable services


def test_metrics_without_a_server(cli_env: Path) -> None:
    for extra in ([], ["--json"]):
        result = invoke("metrics", "--url", f"http://127.0.0.1:{closed_port()}", *extra)
        assert result.exit_code == 1 and no_traceback(result)
        assert "could not read metrics" in result.stderr and result.stdout == ""


@pytest.mark.parametrize(
    "args",
    [
        ["status", "--json"],
        ["detections"],
        ["users", "list"],
        ["rules", "list"],
        ["db", "current"],  # migrations used to print a SQLAlchemy traceback
        ["db", "upgrade"],
        ["db", "purge"],
        ["block", "203.0.113.9", "-r", "x", "--json"],
    ],
    ids=" ".join,
)
def test_unopenable_database_is_a_clean_failure(
    cli_env: Path, unwritable: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{unwritable / 'sub' / 'x.db'}")
    result = invoke(*args)
    assert result.exit_code == 1, result.output
    assert no_traceback(result), result.exception
    assert "database" in result.stderr and result.stdout == ""


@pytest.mark.parametrize("args", [["db", "current"], ["db", "upgrade"], ["status"]], ids=" ".join)
def test_unreachable_postgres_never_prints_the_password(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    pytest.importorskip("asyncpg")
    secret = "hunter2-not-for-output"
    monkeypatch.setenv(
        "DATABASE_URL", f"postgresql+asyncpg://sentinelx:{secret}@127.0.0.1:{closed_port()}/sx"
    )
    result = invoke(*args)
    assert result.exit_code == 1 and no_traceback(result), result.output
    assert secret not in result.output and "***" in result.output


def test_redis_required_but_unreachable_is_a_clean_failure(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STORAGE__REDIS_REQUIRED", "true")
    result = invoke("status")
    assert result.exit_code == 1 and no_traceback(result) and "Redis" in result.stderr


def test_unwritable_outputs_are_clean_failures(
    cli_env: Path, unwritable: Path, fixture_pcap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each of these used to end in a PermissionError traceback.
    generated = invoke("fixtures", "generate", "tcp_port_scan", "-o", str(unwritable / "fx"))
    assert generated.exit_code == 1 and no_traceback(generated)
    assert "Permission denied" in generated.stderr

    report = invoke("replay", str(fixture_pcap), "--report", str(unwritable / "r.json"))
    assert report.exit_code == 1 and no_traceback(report) and "report" in report.stderr

    monkeypatch.setenv("PCAP_DIRECTORY", str(unwritable / "pcaps"))
    persisted = invoke("replay", str(fixture_pcap), "--persist")
    assert persisted.exit_code == 1 and no_traceback(persisted)
    assert "Permission denied" in persisted.stderr


def test_anomaly_train_without_the_ml_extra(
    cli_env: Path, fixture_pcap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hide_ml_packages(monkeypatch)
    result = invoke("anomaly", "train", str(fixture_pcap), "-o", str(cli_env / "m.joblib"))
    assert result.exit_code == 1 and no_traceback(result), result.exception
    assert "sentinelx[ml]" in result.stderr


def test_anomaly_train_with_too_little_traffic(cli_env: Path, fixture_pcap: Path) -> None:
    pytest.importorskip("sklearn")
    result = invoke("anomaly", "train", str(fixture_pcap), "-o", str(cli_env / "m.joblib"))
    assert no_traceback(result)
    assert result.exit_code in (0, 1)
    if result.exit_code == 1:
        assert "training samples" in result.stderr


@pytest.fixture
def normal_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enough training samples without generating minutes of normal traffic."""
    pytest.importorskip("sklearn")
    import random

    import sentinelx.anomaly.ml as ml

    rng = random.Random(3)
    vectors = [[rng.random() for _ in ml.FEATURE_NAMES] for _ in range(80)]
    monkeypatch.setattr(ml, "collect_training_vectors", lambda frames, settings: vectors)


def test_anomaly_train_success(cli_env: Path, fixture_pcap: Path, normal_vectors: None) -> None:
    model = cli_env / "models" / "m.joblib"
    model.parent.mkdir(mode=0o700)
    result = invoke("anomaly", "train", str(fixture_pcap), "-o", str(model))
    assert result.exit_code == 0, result.output
    assert "model saved" in result.stdout
    if os.name != "nt":
        assert stat.S_IMODE(model.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission checks")
def test_anomaly_train_into_a_shared_directory_fails(
    cli_env: Path, fixture_pcap: Path, normal_vectors: None
) -> None:
    # The model used to be reported as saved; the server then refused to load it and
    # ran without ML, with only a log line.
    shared = cli_env / "shared"
    shared.mkdir()
    shared.chmod(0o775)
    result = invoke("anomaly", "train", str(fixture_pcap), "-o", str(shared / "m.joblib"))
    assert result.exit_code == 1 and no_traceback(result)
    assert "refuse to load" in result.stderr


def _hide_ml_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    real = importlib.util.find_spec

    def find_spec(name: str, package: str | None = None) -> Any:
        if name.split(".")[0] in {"numpy", "sklearn", "joblib"}:
            return None
        return real(name, package)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)


# ----------------------------------------------------------- live capture


class _IdleLiveBackend:
    """Stands in for a privileged, silent interface: opens, then yields nothing."""

    async def _open(self: Any) -> None:
        return None

    async def _frames(self: Any) -> AsyncIterator[Any]:
        import asyncio

        deadline = time.monotonic() + 15  # fail the test rather than hang it
        # Polls like the real backends' read timeout; stop() only flips a flag.
        while self.running and time.monotonic() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(0.05)
        nothing: tuple[Any, ...] = ()
        for frame in nothing:  # an async generator that yields nothing
            yield frame

    async def _close(self: Any) -> None:
        return None


def test_monitor_duration_stops_an_idle_interface(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --duration was only checked when frames arrived: a quiet interface never stopped.
    from sentinelx.capture.live import LiveCapture

    for name in ("_open", "_frames", "_close"):
        monkeypatch.setattr(LiveCapture, name, getattr(_IdleLiveBackend, name))
    started = time.monotonic()
    result = invoke("monitor", "-i", "lo", "--duration", "0.5")
    assert result.exit_code == 0, result.output
    assert time.monotonic() - started < 10


def test_monitor_without_capture_privilege_explains_and_draws_nothing(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinelx.capture.live import LiveCapture
    from sentinelx.common.errors import BackendUnavailableError

    async def refused(self: Any) -> None:
        raise BackendUnavailableError(
            "live capture requires CAP_NET_RAW or root: run as root, or grant the capability"
        )

    monkeypatch.setattr(LiveCapture, "_open", refused)
    result = invoke("monitor", "-i", "any", "--duration", "1")
    assert result.exit_code == 1 and no_traceback(result)
    assert "CAP_NET_RAW" in result.stderr
    assert "Latest detections" not in result.stdout  # no empty live view above the error


@pytest.mark.skipif(sys.platform != "linux" or ROOT, reason="needs an unprivileged Linux user")
def test_real_unprivileged_live_monitor_and_interfaces(cli_env: Path) -> None:
    from sentinelx.capture.live import LiveCapture

    if LiveCapture.capabilities().available:
        pytest.skip("this interpreter has capture capabilities")
    result = invoke("monitor", "-i", "any", "--duration", "1")
    assert result.exit_code == 1 and no_traceback(result)
    assert "CAP_NET_RAW" in result.stderr
    listed = invoke("interfaces")
    assert listed.exit_code == 0 and "LIVE CAPTURE UNAVAILABLE" in listed.stderr


# ------------------------------------------------------------------ doctor


def test_doctor_default_environment(cli_env: Path) -> None:
    result, checks = doctor()
    assert result.exit_code == (1 if any(c["status"] == "FAIL" for c in checks.values()) else 0)
    status = {name: check["status"] for name, check in checks.items()}
    assert status["python"] == "PASS" and status["dependencies"] == "PASS"
    assert status["pcap replay"] == "PASS"
    assert status["rules"] == "PASS" and status["database"] == "PASS"
    assert status["migrations"] == "WARN"  # fresh SQLite, migrated at start
    assert status["redis"] == "WARN"
    assert status["api"] == "WARN" and "not reachable" in checks["api"]["detail"]
    assert status["dashboard"] == "WARN" and "not reachable" in checks["dashboard"]["detail"]
    assert status["firewall backend"] == "INFO" and status["automatic blocking"] == "INFO"
    assert status["jwt secret"] == "WARN"
    assert result.exit_code == 0

    # Detail text describes this machine.
    assert checks["python"]["detail"] == platform.python_version()
    assert platform.machine().lower() in checks["operating system"]["detail"].lower()
    from sentinelx.system.interfaces import list_interfaces

    assert checks["interface enumeration"]["detail"].startswith(f"{len(list_interfaces())} ")

    from sentinelx.capture.live import LiveCapture

    live = LiveCapture.capabilities()
    assert (status["live capture"] == "PASS") is live.available
    if not live.available:
        assert status["live capture"] == "WARN" and checks["live capture"]["remedy"]


@pytest.mark.skipif(sys.platform != "linux", reason="nftables is Linux-only")
def test_doctor_never_passes_an_unusable_firewall(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinelx.firewall import firewall_capabilities

    monkeypatch.setenv("FIREWALL_BACKEND", "nftables")
    usable = firewall_capabilities("nftables").available
    result, checks = doctor()
    firewall = checks["firewall backend"]
    if usable:
        assert firewall["status"] == "PASS"
    else:
        assert firewall["status"] == "WARN" and firewall["remedy"]
        monkeypatch.setenv("DRY_RUN", "false")
        monkeypatch.setenv("RESPONSE_MODE", "manual_approval")
        result, checks = doctor()
        assert checks["firewall backend"]["status"] == "FAIL" and result.exit_code == 1


def test_doctor_auto_firewall_detail_is_not_prefixed_with_null(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FIREWALL_BACKEND", "auto")
    _, checks = doctor()
    firewall = checks["firewall backend"]
    assert not firewall["detail"].startswith("null:")
    if firewall["status"] != "PASS":
        assert firewall["status"] == "WARN"


def test_doctor_missing_rules_directory_fails(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RULES_DIRECTORY", str(cli_env / "missing"))
    result, checks = doctor()
    assert checks["rules"]["status"] == "FAIL" and result.exit_code == 1


def test_doctor_unreachable_postgres(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("asyncpg")
    secret = "doctor-secret-password"
    monkeypatch.setenv("DATABASE_URL", f"postgresql+asyncpg://sx:{secret}@127.0.0.1:1/sx")
    result, checks = doctor()
    assert checks["database"]["status"] == "FAIL" and result.exit_code == 1
    assert "cannot connect" in checks["database"]["detail"]
    assert "migrations" not in checks
    assert secret not in result.output


@pytest.fixture
def impostor() -> Iterator[str]:
    """An HTTP service answering 200 JSON that is not SentinelX."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = json.dumps({"status": "fine", "service": "something-else"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_doctor_does_not_mistake_another_service_for_sentinelx(
    cli_env: Path, impostor: str
) -> None:
    _, checks = doctor("--api-url", impostor, "--dashboard-url", impostor)
    for name in ("api", "dashboard"):
        assert checks[name]["status"] == "WARN"
        assert "not as SentinelX" in checks[name]["detail"]


def test_doctor_probes_an_ipv6_api_host(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # API_HOST=::1 built "http://::1:8000/...", which httpx rejects with InvalidURL:
    # doctor crashed with a traceback.
    monkeypatch.setenv("API_HOST", "::1")
    monkeypatch.setenv("API_PORT", str(closed_port()))
    closed = f"http://127.0.0.1:{closed_port()}"
    result = invoke("doctor", "--json", "--dashboard-url", closed)
    assert no_traceback(result), result.exception
    api = next(c for c in json.loads(result.stdout) if c["name"] == "api")
    assert "http://[::1]:" in api["detail"] and api["status"] == "WARN"


def test_doctor_malformed_probe_url_is_reported(cli_env: Path) -> None:
    _, checks = doctor("--api-url", "http://[not-a-host")
    assert checks["api"]["status"] == "WARN"


def test_doctor_redis_required_reports_instead_of_aborting(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Used to exit 1 with only "Redis is required but unreachable" and no report.
    monkeypatch.setenv("STORAGE__REDIS_REQUIRED", "true")
    result, checks = doctor()
    assert checks["redis"]["status"] == "FAIL" and result.exit_code == 1
    assert checks["database"]["status"] == "PASS"  # the other checks still ran


def test_doctor_ml_enabled_without_the_extra_fails(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANOMALY__ML_ENABLED", "true")
    _hide_ml_packages(monkeypatch)
    result, checks = doctor()
    ml = checks["machine learning"]
    assert ml["status"] == "FAIL" and "[ml]" in ml["remedy"] and result.exit_code == 1


def test_doctor_ml_enabled_without_a_model_fails(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The server silently disables the detector when the model is missing; doctor
    # used to say nothing at all.
    pytest.importorskip("sklearn")
    monkeypatch.setenv("ANOMALY__ML_ENABLED", "true")
    monkeypatch.setenv("ANOMALY__ML_MODEL_PATH", str(cli_env / "missing.joblib"))
    result, checks = doctor()
    ml = checks["machine learning"]
    assert ml["status"] == "FAIL" and "not found" in ml["detail"] and result.exit_code == 1


def test_doctor_ml_enabled_with_a_trained_model_passes(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("sklearn")
    import random

    from sentinelx.anomaly.ml import FEATURE_NAMES, save_model, train_model

    rng = random.Random(7)
    vectors = [[rng.random() for _ in FEATURE_NAMES] for _ in range(80)]
    model = cli_env / "model.joblib"
    save_model(train_model(vectors), model)
    monkeypatch.setenv("ANOMALY__ML_ENABLED", "true")
    monkeypatch.setenv("ANOMALY__ML_MODEL_PATH", str(model))
    _, checks = doctor()
    assert checks["machine learning"]["status"] == "PASS"


def test_doctor_invalid_configuration_exits_1_with_json(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RESPONSE_MODE", "automatic")
    monkeypatch.setenv("DRY_RUN", "false")
    result = invoke("doctor", "--json")
    assert result.exit_code == 1
    [check] = json.loads(result.stdout)
    assert check["name"] == "configuration" and check["status"] == "FAIL"
    assert "sentinelx config" not in check["remedy"]  # that command fails the same way


@pytest.mark.skipif(not ROOT or sys.platform != "linux", reason="run under: unshare -rn")
def test_doctor_with_capture_and_firewall_privileges(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    monkeypatch.setenv("FIREWALL_BACKEND", "nftables")
    _, checks = doctor()
    assert checks["live capture"]["status"] == "PASS"
    if shutil.which("nft"):
        assert checks["firewall backend"]["status"] == "PASS"
    else:
        assert checks["firewall backend"]["status"] == "WARN"


# ------------------------------------------------------------------- start


@pytest.fixture
def fake_uvicorn(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record what ``start`` hands to uvicorn instead of binding a port."""
    import uvicorn

    calls: list[dict[str, Any]] = []

    def run(app: str, **kwargs: Any) -> None:
        calls.append({**kwargs, "capture": os.environ.get("SENTINELX_START_CAPTURE")})

    monkeypatch.setattr(uvicorn, "run", run)
    return calls


def test_start_ignores_an_inherited_capture_variable(
    fake_uvicorn: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # server.py starts capture whenever the variable is set; one exported in the shell
    # used to start live capture without --capture.
    monkeypatch.setenv("SENTINELX_START_CAPTURE", "eth0")
    assert invoke("start", "--port", "8199").exit_code == 0
    assert fake_uvicorn[-1]["capture"] is None
    assert invoke("start", "--port", "8199", "--capture", "-i", "lo").exit_code == 0
    assert fake_uvicorn[-1]["capture"] == "lo"


def test_start_keeps_uvicorn_from_logging_query_strings(
    fake_uvicorn: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    import logging.config

    assert invoke("start", "--port", "8199").exit_code == 0
    options = fake_uvicorn[-1]
    # uvicorn would otherwise reset its loggers to INFO and install its own handlers.
    assert options["log_level"] is None
    logging.config.dictConfig(options["log_config"])

    records: list[logging.LogRecord] = []

    class Recorder(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Recorder()
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [handler])
    monkeypatch.setattr(root, "level", logging.INFO)
    logging.getLogger("uvicorn.error").info(
        '%s - "WebSocket %s" [accepted]', "127.0.0.1:5", "/api/v1/ws/events?ticket=SECRET"
    )
    logging.getLogger("uvicorn.access").info('"GET /x?ticket=SECRET HTTP/1.1" 200')
    logging.getLogger("uvicorn.error").error("error while attempting to bind")
    messages = [record.getMessage() for record in records]
    assert not any("SECRET" in message for message in messages)
    assert messages == ["error while attempting to bind"]  # through the root handler


@pytest.mark.parametrize(
    ("host", "shown"),
    [
        ("0.0.0.0", "http://127.0.0.1:8199/"),
        ("::", "http://[::1]:8199/"),
        ("::1", "http://[::1]:8199/"),
    ],
)
def test_start_prints_an_openable_url(
    fake_uvicorn: list[dict[str, Any]], host: str, shown: str
) -> None:
    result = invoke("start", "--host", host, "--port", "8199")
    assert result.exit_code == 0 and shown in result.stdout, result.output


def test_doctor_sees_a_secret_set_with_a_lower_case_name(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinelx.config.settings import Settings
    from sentinelx.services import diagnostics

    monkeypatch.setenv("jwt_secret", "lower-case-name-0123456789abcdefghijklmnop")
    settings = Settings()
    assert settings.api.jwt_secret.startswith("lower-case-name")  # settings accept it
    [jwt] = [c for c in diagnostics._local_checks(settings) if c.name == "jwt secret"]
    assert jwt.status == "PASS"


def test_doctor_reads_a_utf8_env_file_case_insensitively(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentinelx.config.settings import Settings
    from sentinelx.services import diagnostics

    # conftest runs each test in its own empty directory, so this is the only .env.
    Path(".env").write_text(
        "# clé de session\napi__jwt_secret=from-dotenv-0123456789abcdefghijklmnop\n",
        encoding="utf-8",
    )
    [jwt] = [c for c in diagnostics._local_checks(Settings()) if c.name == "jwt secret"]
    assert jwt.status == "PASS"
