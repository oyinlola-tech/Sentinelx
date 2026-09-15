"""The ``sentinelx`` command.

Every command accepts arguments for scripting and ``--json`` where it produces data.
Run ``sentinelx`` with no arguments in a terminal for a numbered menu.

Exit codes: 0 success, 1 failure, 2 usage or configuration error, 130 interrupted.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

import typer

from sentinelx import __version__
from sentinelx.cli import admin, lab, security
from sentinelx.cli.output import console, emit_json, err, safety_panel, table
from sentinelx.cli.runtime import load_settings, platform_context, run

app = typer.Typer(
    name="sentinelx",
    help="SentinelX - explainable network intrusion detection and prevention.",
    add_completion=True,
    rich_markup_mode="rich",
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    # Tracebacks must never print local variables: they include Settings objects,
    # and with them the JWT secret and database credentials.
    pretty_exceptions_show_locals=False,
)

JsonOption = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


MENU: list[tuple[str, list[str]]] = [
    ("Show platform status", ["status"]),
    ("List network interfaces", ["interfaces"]),
    ("Recent detections", ["detections"]),
    ("Incidents", ["incidents"]),
    ("Threat sources", ["threats"]),
    ("Blocked addresses", ["blocked"]),
    ("Block an address", ["block"]),
    ("Unblock an address", ["unblock"]),
    ("List rules", ["rules", "list"]),
    ("Run rule tests", ["rules", "test", "rules"]),
    ("Replay a PCAP", ["replay"]),
    ("Monitor a synthetic attack scenario", ["monitor", "--scenario", "mixed_intrusion"]),
    ("Check this host (doctor)", ["doctor"]),
    ("Start the server", ["start"]),
]


@app.callback()
def root(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Print the version and exit.")] = False,
) -> None:
    if version:
        console.print(f"sentinelx {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is not None:
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        console.print(ctx.get_help())
        raise typer.Exit()
    _menu()


def _menu() -> None:
    console.print(f"[bold]SentinelX {__version__}[/]\n")
    for index, (label, _) in enumerate(MENU, start=1):
        console.print(f"  [bold cyan]{index:>2}[/]  {label}")
    console.print("   [bold cyan]0[/]  Exit\n")
    choice = typer.prompt("Select", type=int, default=1)
    if choice == 0:
        raise typer.Exit()
    if not 1 <= choice <= len(MENU):
        err.print("invalid selection")
        raise typer.Exit(2)
    label, argv = MENU[choice - 1]
    if argv == ["replay"]:
        argv = ["replay", typer.prompt("Path to pcap")]
    console.print(f"[dim]$ sentinelx {' '.join(argv)}[/]\n")
    app(argv, standalone_mode=False)


@app.command(rich_help_panel="Operate")
def start(
    host: Annotated[str | None, typer.Option(help="Listen address (API_HOST).")] = None,
    port: Annotated[int | None, typer.Option(help="Listen port (API_PORT).")] = None,
    capture: Annotated[
        bool,
        typer.Option(
            "--capture/--no-capture", help="Start live capture on CAPTURE_INTERFACE at startup."
        ),
    ] = False,
    interface: Annotated[str | None, typer.Option("--interface", "-i")] = None,
    reload: Annotated[
        bool, typer.Option(help="Auto-reload on code changes (development).")
    ] = False,
) -> None:
    """Start the API, WebSocket stream and detection pipeline."""
    import uvicorn

    settings = load_settings(quiet=False)
    console.print(safety_panel(settings.safety_banner()))
    listen_host = host or settings.api.host
    listen_port = port or settings.api.port
    if (
        listen_host not in ("127.0.0.1", "localhost", "::1")
        and settings.environment != "production"
    ):
        err.print(f"[yellow]listening on {listen_host}: the API is reachable from the network[/]")

    if capture:
        # Started from the application lifespan so it shares the server's event loop.
        import os

        os.environ["SENTINELX_START_CAPTURE"] = interface or settings.capture.interface
    docs = "   docs /api/docs" if settings.api.docs_enabled else "   (API docs off in production)"
    console.print(
        f"API    http://{listen_host}:{listen_port}/api/v1{docs}\n"
        f"Events ws://{listen_host}:{listen_port}/api/v1/ws/events"
    )
    uvicorn.run(
        "sentinelx.api.server:app",
        host=listen_host,
        port=listen_port,
        reload=reload,
        workers=1,
        log_level=settings.telemetry.log_level.lower(),
        proxy_headers=bool(settings.api.trusted_proxies),
        forwarded_allow_ips=",".join(settings.api.trusted_proxies) or None,
        server_header=False,
    )


@app.command(rich_help_panel="Operate")
def status(as_json: JsonOption = False) -> None:
    """Platform health: database, Redis, firewall, rules, sensor and safety posture."""
    settings = load_settings()

    async def main() -> Any:
        async with platform_context(settings, persist=False) as platform:
            report = await platform.health()
            pipeline, _, _, queries = platform.require()
            report["detectors"] = [d.stats() for d in pipeline.detection.detectors]
            report["overview"] = await queries.overview()
            return report

    report = run(main)
    if as_json:
        emit_json(report)
        return
    console.print(safety_panel(report["safety"]))
    components = report["components"]
    rows = [
        ("database", components["database"].get("ok"), components["database"].get("url")),
        (
            "redis",
            components["redis"].get("ok"),
            "degraded (per-process limits)" if components["redis"].get("degraded") else "connected",
        ),
        (
            "firewall",
            components["firewall"].get("ok"),
            f"{components['firewall'].get('backend')} enforcing={components['firewall'].get('enforcing')}",
        ),
        (
            "rules",
            components["rules"]["ok"],
            "; ".join(components["rules"]["problems"][:2]) or "all valid",
        ),
    ]
    console.print(
        table(
            f"SentinelX {report['version']} - {report['status'].upper()}",
            ["Component", "OK", "Detail"],
            [(name, "yes" if ok else "no", detail) for name, ok, detail in rows],
        )
    )
    overview = report["overview"]
    console.print(
        table(
            "Last 24 hours",
            ["Metric", "Value"],
            [
                ("Detections", overview["detections_24h"]),
                ("Open incidents", overview["open_incidents"]),
                ("Critical incidents", overview["critical_incidents"]),
                ("Blocked sources", overview["blocked_sources"]),
                ("Pending approvals", overview["pending_approvals"]),
                ("Detectors loaded", len(report["detectors"])),
            ],
        )
    )


@app.command(rich_help_panel="Operate")
def interfaces(as_json: JsonOption = False) -> None:
    """Network interfaces available for capture."""
    from rich.markup import escape

    from sentinelx.capture.live import LiveCapture
    from sentinelx.system.interfaces import list_interfaces

    entries = list_interfaces()
    capture = LiveCapture.capabilities()
    if as_json:
        emit_json({"capture": capture.as_dict(), "interfaces": entries})
        return
    console.print(
        table(
            "Interfaces",
            ["Name", "State", "Addresses", "MAC", "MTU", "RX packets", "Dropped"],
            [
                (
                    i["name"],
                    i["state"],
                    ", ".join(i["addresses"]) or "-",
                    i["mac"] or "-",
                    i["mtu"],
                    f"{i['statistics']['rx_packets']:,}",
                    i["statistics"]["rx_dropped"],
                )
                for i in entries
            ],
        )
    )
    if capture.available:
        err.print(f"Live capture: available via {capture.backend} ({capture.reason}).")
    else:
        err.print(
            f"[yellow]LIVE CAPTURE UNAVAILABLE:[/] {escape(capture.reason)}. "
            "PCAP replay and fixtures still work."
        )
        if capture.remedy:
            err.print(f"To enable it: {escape(capture.remedy)}")


security.register(app)
lab.register(app)
admin.register(app)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
