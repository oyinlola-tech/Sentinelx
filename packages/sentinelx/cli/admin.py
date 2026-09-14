"""Platform administration: rules, configuration, database, users, metrics, doctor."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.syntax import Syntax
from rich.text import Text

from sentinelx import __version__
from sentinelx.cli.output import console, emit_json, err, safety_panel, table
from sentinelx.cli.runtime import actor, load_settings, platform_context, run
from sentinelx.common.enums import UserRole

JsonOption = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


def register(app: typer.Typer) -> None:
    # ------------------------------------------------------------------ rules
    rules = typer.Typer(help="Custom detection rules.", no_args_is_help=True)
    app.add_typer(rules, name="rules", rich_help_panel="Configure")

    @rules.command("list")
    def rules_list(as_json: JsonOption = False) -> None:
        """Rules known to the platform, with their state and origin."""
        settings = load_settings()

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                return {
                    "rules": await platform.rules.list_rules(),
                    "problems": platform.rules.load_problems,
                }

        result = run(main)
        if as_json:
            emit_json(result)
            return
        console.print(
            table(
                "Rules",
                ["ID", "Name", "Enabled", "Severity", "Action", "Within", "Origin", "Condition"],
                [
                    (
                        r["rule_id"],
                        r["name"],
                        "yes" if r["enabled"] else "no",
                        r.get("severity"),
                        r.get("action"),
                        f"{r.get('within_seconds', 0):g}s",
                        r["origin"],
                        r.get("condition"),
                    )
                    for r in result["rules"]
                ],
            )
        )
        for problem in result["problems"]:
            err.print(f"[yellow]invalid rule skipped:[/] {problem}")

    @rules.command("validate")
    def rules_validate(
        paths: Annotated[
            list[Path] | None,
            typer.Argument(help="Rule files or directories; default RULES_DIRECTORY."),
        ] = None,
        as_json: JsonOption = False,
    ) -> None:
        """Validate rule files without loading them. Exit 1 if any are invalid (for CI)."""
        settings = load_settings()
        from sentinelx.services.rules import max_rule_window
        from sentinelx.signatures import load_rules

        targets = paths or [Path(settings.rules_directory)]
        report: dict[str, Any] = {"valid": [], "problems": []}
        for target in targets:
            result = load_rules(target, max_window_seconds=max_rule_window(settings))
            report["valid"].extend(rule.id for rule in result.rules)
            report["problems"].extend(result.problems)
        if as_json:
            emit_json(report)
        else:
            for rule_id in report["valid"]:
                console.print(f"[green]valid[/]   {rule_id}")
            for problem in report["problems"]:
                console.print(f"[red]invalid[/] {problem}")
            console.print(f"\n{len(report['valid'])} valid, {len(report['problems'])} problem(s)")
        if report["problems"]:
            raise typer.Exit(1)

    @rules.command("test")
    def rules_test(
        path: Annotated[
            Path, typer.Argument(exists=True, help="Rule file (all rules in it are tested).")
        ],
        pcap: Annotated[
            Path | None,
            typer.Option(
                "--pcap", exists=True, dir_okay=False, help="Test against a capture instead."
            ),
        ] = None,
        scenario: Annotated[
            str | None, typer.Option("--scenario", help="Test against one synthetic scenario.")
        ] = None,
        as_json: JsonOption = False,
    ) -> None:
        """Run rules' embedded positive/negative tests, or test them against a PCAP. Exit 1 on failure."""
        settings = load_settings()
        from sentinelx.services.rules import max_rule_window
        from sentinelx.signatures import (
            load_rules,
            run_rule_on_frames,
            run_rule_on_pcap,
            run_rule_tests,
        )
        from sentinelx.testing import get_scenario

        loaded = load_rules(path, max_window_seconds=max_rule_window(settings))
        for problem in loaded.problems:
            err.print(f"[red]invalid:[/] {problem}")
        results: list[dict[str, Any]] = []
        failed = bool(loaded.problems)
        for rule in loaded.rules:
            if pcap:
                result = run(lambda rule=rule: run_rule_on_pcap(rule, pcap, settings.detection))  # type: ignore[misc]
                results.append({"rule": rule.id, "target": str(pcap), **result.as_dict()})
            elif scenario:
                result = run_rule_on_frames(rule, get_scenario(scenario).frames, settings.detection)
                results.append({"rule": rule.id, "target": scenario, **result.as_dict()})
            else:
                outcomes = run_rule_tests(rule, settings.detection)
                if not outcomes:
                    err.print(f"[yellow]{rule.id} has no embedded tests[/]")
                results.extend(o.as_dict() for o in outcomes)
                failed = failed or any(not o.passed for o in outcomes)
        if as_json:
            emit_json(results)
        elif pcap or scenario:
            console.print(
                table(
                    "Rule matches",
                    ["Rule", "Target", "Packets", "Matched", "Detections", "Sources"],
                    [
                        (
                            r["rule"],
                            r["target"],
                            r["packets"],
                            "yes" if r["matched"] else "no",
                            r["detection_count"],
                            ", ".join(r["sources"]),
                        )
                        for r in results
                    ],
                )
            )
        else:
            console.print(
                table(
                    "Rule tests",
                    ["Rule", "Scenario", "Expected", "Actual", "Result"],
                    [
                        (
                            r["rule_id"],
                            r["scenario"],
                            r["expected"],
                            r["actual"],
                            Text.from_markup("[green]pass[/]" if r["passed"] else "[red]FAIL[/]"),
                        )
                        for r in results
                    ],
                )
            )
        if failed:
            raise typer.Exit(1)

    @rules.command("enable")
    def rules_enable(rule_id: str) -> None:
        """Enable a rule."""
        _toggle_rule(rule_id, True)

    @rules.command("disable")
    def rules_disable(rule_id: str) -> None:
        """Disable a rule."""
        _toggle_rule(rule_id, False)

    @rules.command("fields")
    def rules_fields() -> None:
        """Fields available in rule conditions."""
        from sentinelx.services.rules import RuleService

        console.print(
            table(
                "Rule fields",
                ["Field", "Kind", "Meaning"],
                [(f["name"], f["kind"], f["description"]) for f in RuleService.fields()],
            )
        )

    # ----------------------------------------------------------------- config
    config = typer.Typer(help="Show or change settings.", invoke_without_command=True)
    app.add_typer(config, name="config", rich_help_panel="Configure")

    @config.callback()
    def config_show(
        ctx: typer.Context,
        section: Annotated[str | None, typer.Option("--section")] = None,
        as_json: JsonOption = False,
    ) -> None:
        """Show the effective settings (secrets removed)."""
        if ctx.invoked_subcommand:
            return
        settings = load_settings()
        from sentinelx.services.config import EDITABLE

        data = settings.model_dump(mode="json")
        data["api"].pop("jwt_secret", None)
        data["api"].pop("bootstrap_admin_password", None)
        data["api"].pop("metrics_token", None)
        from sentinelx.services.config import redact_url

        data["storage"]["database_url"] = redact_url(settings.storage.database_url)
        data["storage"]["redis_url"] = redact_url(settings.storage.redis_url)
        if section:
            data = {section: data.get(section)}
        if as_json:
            emit_json(data)
            return
        console.print(safety_panel(settings.safety_banner()))
        console.print(
            Syntax(
                json.dumps(data, indent=2), "json", theme="ansi_dark", background_color="default"
            )
        )
        console.print(
            "[dim]Runtime-editable sections: "
            + ", ".join(sorted(EDITABLE))
            + ". Change with: sentinelx config set SECTION KEY VALUE[/]"
        )

    @config.command("set")
    def config_set(
        section: str,
        key: str,
        value: Annotated[
            str, typer.Argument(help='JSON value, e.g. 30, true, "automatic", ["10.0.0.0/8"]')
        ],
        confirm_prevention: Annotated[
            bool,
            typer.Option("--confirm-prevention", help="Required to enable automatic enforcement."),
        ] = False,
    ) -> None:
        """Persist a runtime setting change (audited). Takes effect on the next start of the server."""
        settings = load_settings()
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = value
        from sentinelx.services.config import PREVENTION_CONFIRMATION

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                return await platform.config.update(
                    section,
                    {key: parsed},
                    actor=actor(),
                    source="cli",
                    confirmation=PREVENTION_CONFIRMATION if confirm_prevention else None,
                )

        if confirm_prevention:
            err.print(
                "[bold red]WARNING:[/] enabling prevention lets SentinelX modify this host's firewall automatically."
            )
            if not typer.confirm("Type y to confirm you understand"):
                raise typer.Exit(1)
        result = run(main)
        console.print(safety_panel(result["safety"]["banner"]))
        console.print(f"[green]saved[/] {section}.{key} = {json.dumps(parsed)}")

    # --------------------------------------------------------------- database
    db = typer.Typer(help="Database schema management.", no_args_is_help=True)
    app.add_typer(db, name="db", rich_help_panel="Operate")

    @db.command("upgrade")
    def db_upgrade(revision: str = "head") -> None:
        """Apply migrations (required for PostgreSQL before first start)."""
        settings = load_settings()
        from sentinelx.storage.migrate import current_revision, upgrade

        run(lambda: upgrade(settings.storage.database_url, revision))
        console.print(
            f"[green]database at revision[/] {run(lambda: current_revision(settings.storage.database_url))}"
        )

    @db.command("current")
    def db_current() -> None:
        """Show the applied and latest migration revisions."""
        settings = load_settings()
        from sentinelx.storage.migrate import current_revision, head_revision

        applied = run(lambda: current_revision(settings.storage.database_url))
        head = head_revision()
        console.print(
            f"applied: {applied or 'none'}   latest: {head}   {'[green]up to date[/]' if applied == head else '[yellow]upgrade needed[/]'}"
        )

    @db.command("purge")
    def db_purge() -> None:
        """Apply retention policies now."""
        settings = load_settings()

        async def main() -> Any:
            async with platform_context(settings, persist=False) as platform:
                return await platform.run_retention()

        console.print(table("Purged rows", ["Table", "Rows"], sorted(run(main).items())))

    # ------------------------------------------------------------------ users
    users = typer.Typer(help="Dashboard and API users.", no_args_is_help=True)
    app.add_typer(users, name="users", rich_help_panel="Operate")

    @users.command("list")
    def users_list() -> None:
        settings = load_settings()
        from sentinelx.storage.repositories import UserRepository

        async def main() -> Any:
            async with (
                platform_context(settings, persist=False) as platform,
                platform.database.session() as session,
            ):
                return [
                    (u.id, u.username, u.role, "yes" if u.is_active else "no", u.last_login_at)
                    for u in await UserRepository(session).all()
                ]

        console.print(table("Users", ["ID", "Username", "Role", "Active", "Last login"], run(main)))

    @users.command("create")
    def users_create(
        username: str, role: Annotated[UserRole, typer.Option()] = UserRole.VIEWER
    ) -> None:
        """Create a user. The password is read from a hidden prompt, never from arguments."""
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
        settings = load_settings()

        async def main() -> None:
            async with platform_context(settings, persist=False) as platform:
                await platform.auth.create_user(username, password, role)
                await platform.audit.record(
                    actor=actor(),
                    action="CREATE_USER",
                    target=username,
                    source="cli",
                    details={"role": role.value},
                )

        run(main)
        console.print(f"[green]created[/] {username} ({role.value})")

    @users.command("reset-password")
    def users_reset(username: str) -> None:
        """Set a new password; the user must change it at next login."""
        password = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
        settings = load_settings()
        from sentinelx.storage.repositories import UserRepository

        async def main() -> None:
            async with platform_context(settings, persist=False) as platform:
                async with platform.database.session() as session:
                    user = await UserRepository(session).by_username(username)
                if user is None:
                    from sentinelx.services.auth import AuthError

                    raise AuthError(f"no user named {username!r}", status=404)
                await platform.auth.set_password(user.id, password)
                await platform.audit.record(
                    actor=actor(), action="RESET_PASSWORD", target=username, source="cli"
                )

        run(main)
        console.print(f"[green]password reset[/] for {username}; sessions revoked")

    # ----------------------------------------------------------------- metrics
    @app.command(rich_help_panel="Operate")
    def metrics(
        url: Annotated[
            str, typer.Option(envvar="SENTINELX_API_URL", help="Running API base URL.")
        ] = "http://127.0.0.1:8000",
        token: Annotated[
            str,
            typer.Option(
                envvar="SENTINELX_METRICS_TOKEN", help="API__METRICS_TOKEN, when set on the server."
            ),
        ] = "",
        as_json: JsonOption = False,
    ) -> None:
        """Key Prometheus metrics from a running server (values are measured, not estimated)."""
        import httpx
        from prometheus_client.parser import text_string_to_metric_families

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            response = httpx.get(f"{url.rstrip('/')}/api/v1/metrics", headers=headers, timeout=5)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            err.print(f"[red]could not read metrics from {url}:[/] {exc}")
            err.print(
                "[dim]Is the server running (sentinelx start)? Remote scrapes need API__METRICS_TOKEN.[/]"
            )
            raise typer.Exit(1) from None
        wanted = {
            "sentinelx_packets_processed": "Packets processed",
            "sentinelx_packets_dropped": "Packets dropped",
            "sentinelx_detections": "Detections",
            "sentinelx_incidents_opened": "Incidents opened",
            "sentinelx_blocked_addresses": "Blocked addresses",
            "sentinelx_active_flows": "Active flows",
            "sentinelx_detector_errors": "Detector errors",
            "sentinelx_safety_refusals": "Safety refusals",
            "sentinelx_process_cpu_percent": "CPU %",
            "sentinelx_process_memory_bytes": "Memory bytes",
            "sentinelx_websocket_clients": "WebSocket clients",
            "sentinelx_storage_errors": "Storage errors",
        }
        totals: dict[str, float] = {}
        latency: dict[str, tuple[float, float]] = {}
        for family in text_string_to_metric_families(response.text):
            for sample in family.samples:
                if sample.name.removesuffix("_total") in wanted and not sample.name.endswith(
                    "_created"
                ):
                    key = wanted[sample.name.removesuffix("_total")]
                    totals[key] = totals.get(key, 0.0) + sample.value
                if sample.name in (
                    "sentinelx_pipeline_latency_seconds_sum",
                    "sentinelx_pipeline_latency_seconds_count",
                ):
                    total, count = latency.get("pipeline", (0.0, 0.0))
                    latency["pipeline"] = (
                        (total + sample.value, count)
                        if sample.name.endswith("_sum")
                        else (total, count + sample.value)
                    )
        if "pipeline" in latency and latency["pipeline"][1]:
            totals["Mean pipeline latency (ms)"] = round(
                1000 * latency["pipeline"][0] / latency["pipeline"][1], 4
            )
        if as_json:
            emit_json(totals)
            return
        console.print(
            table(
                f"Metrics from {url}",
                ["Metric", "Value"],
                [(k, f"{v:,.2f}".rstrip("0").rstrip(".")) for k, v in totals.items()],
            )
        )

    # ----------------------------------------------------------------- doctor
    @app.command(rich_help_panel="Operate")
    def doctor(as_json: JsonOption = False) -> None:
        """Check this host and configuration for everything SentinelX needs. Exit 1 on failures."""
        checks: list[dict[str, str]] = []

        def check(name: str, status: str, detail: str) -> None:
            checks.append({"check": name, "status": status, "detail": detail})

        version = sys.version_info
        check(
            "python",
            "ok" if version >= (3, 12) else "fail",
            f"{version.major}.{version.minor}.{version.micro}",
        )
        try:
            settings = load_settings()
            check("configuration", "ok", f"environment={settings.environment}")
        except typer.Exit:
            check("configuration", "fail", "settings failed validation (run: sentinelx config)")
            _print_checks(checks, as_json)
            raise typer.Exit(1) from None

        check(
            "safety posture",
            "warn" if settings.prevention_active else "ok",
            settings.safety_banner(),
        )
        from sentinelx.capture.live import has_capture_privileges, list_interfaces

        privileged = has_capture_privileges()
        check(
            "capture privileges",
            "ok" if privileged else "warn",
            "CAP_NET_RAW available"
            if privileged
            else "no CAP_NET_RAW: live capture unavailable (replay still works). "
            "Grant with: sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))",
        )
        interfaces = list_interfaces()
        wanted = settings.capture.interface
        present = wanted == "any" or any(i["name"] == wanted for i in interfaces)
        check(
            "capture interface",
            "ok" if present else "fail",
            f"{wanted} ({len(interfaces)} interfaces found)",
        )

        for binary, backend in (("nft", "nftables"), ("iptables", "iptables")):
            found = shutil.which(binary)
            needed = settings.response.firewall_backend == backend
            check(
                f"{backend} binary",
                "ok" if found else ("fail" if needed else "info"),
                found or ("missing - required by FIREWALL_BACKEND" if needed else "not installed"),
            )
        can_admin = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        if settings.response.firewall_backend != "null":
            check(
                "firewall privileges",
                "ok" if can_admin else "warn",
                "running as root" if can_admin else "firewall changes need root or CAP_NET_ADMIN",
            )

        from sentinelx.services.rules import max_rule_window
        from sentinelx.signatures import load_rules

        loaded = load_rules(
            Path(settings.rules_directory), max_window_seconds=max_rule_window(settings)
        )
        check(
            "rules",
            "ok" if not loaded.problems else "fail",
            f"{len(loaded.rules)} valid, {len(loaded.problems)} invalid in {settings.rules_directory}",
        )

        pcap_dir = Path(settings.capture.pcap_directory)
        try:
            pcap_dir.mkdir(parents=True, exist_ok=True)
            probe = pcap_dir / ".doctor"
            probe.write_bytes(b"")
            probe.unlink()
            check("pcap directory", "ok", f"{pcap_dir} writable")
        except OSError as exc:
            check("pcap directory", "fail", f"{pcap_dir}: {exc}")

        if len(settings.api.jwt_secret) < 32:
            check("jwt secret", "fail", "JWT_SECRET shorter than 32 characters")
        elif not os.environ.get("JWT_SECRET") and not os.environ.get("API__JWT_SECRET"):
            check(
                "jwt secret",
                "warn",
                "not set: an ephemeral secret is used and sessions end on restart",
            )
        else:
            check("jwt secret", "ok", "set")

        async def services() -> None:
            from sentinelx.storage.database import Database
            from sentinelx.storage.migrate import current_revision, head_revision
            from sentinelx.storage.redis_state import SharedState

            database = Database(settings.storage)
            try:
                await database.connect(create_schema=False)
                check("database", "ok", database.safe_url)
                if database.dialect != "sqlite":
                    applied = await current_revision(settings.storage.database_url)
                    head = head_revision()
                    check(
                        "migrations",
                        "ok" if applied == head else "fail",
                        f"applied {applied or 'none'}, latest {head}"
                        + ("" if applied == head else " - run: sentinelx db upgrade"),
                    )
            except Exception as exc:
                check("database", "fail", str(exc))
            finally:
                await database.close()
            state = SharedState(settings.storage)
            await state.connect()
            check(
                "redis",
                "ok"
                if not state.degraded
                else ("fail" if settings.storage.redis_required else "warn"),
                "connected"
                if not state.degraded
                else "unreachable: degraded to per-process limits",
            )
            await state.close()

        run(services)
        _print_checks(checks, as_json)
        if any(c["status"] == "fail" for c in checks):
            raise typer.Exit(1)

    @app.command(rich_help_panel="Operate")
    def version() -> None:
        """Print the version."""
        console.print(f"sentinelx {__version__}")


def _toggle_rule(rule_id: str, enabled: bool) -> None:
    settings = load_settings()

    async def main() -> Any:
        async with platform_context(settings, persist=False) as platform:
            return await platform.rules.set_enabled(rule_id, enabled, actor=actor(), source="cli")

    try:
        run(main)
    except KeyError:
        err.print(f"no rule with id {rule_id!r}")
        raise typer.Exit(1) from None
    console.print(
        f"[green]{'enabled' if enabled else 'disabled'}[/] {rule_id} (a running server picks this up on restart)"
    )


def _print_checks(checks: list[dict[str, str]], as_json: bool) -> None:
    if as_json:
        emit_json(checks)
        return
    style = {
        k: Text.from_markup(v)
        for k, v in {
            "ok": "[green]ok[/]",
            "warn": "[yellow]warn[/]",
            "fail": "[bold red]FAIL[/]",
            "info": "[dim]info[/]",
        }.items()
    }
    console.print(
        table(
            "sentinelx doctor",
            ["Check", "Status", "Detail"],
            [(c["check"], style[c["status"]], c["detail"]) for c in checks],
        )
    )
