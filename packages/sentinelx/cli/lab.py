"""Replay, live monitoring, fixtures and the optional ML model."""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from collections import deque
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinelx.capture import LiveCapture, MockCapture, PcapFileCapture, pcap_metadata
from sentinelx.capture.base import PacketCapture
from sentinelx.cli.output import (
    console,
    emit_json,
    err,
    risk_text,
    safety_panel,
    severity_text,
    table,
)
from sentinelx.cli.runtime import load_settings, run
from sentinelx.common.models import PacketEvent
from sentinelx.config.settings import Settings
from sentinelx.events.bus import EventBus
from sentinelx.events.serialize import detection_to_dict, incident_to_dict
from sentinelx.firewall import MemoryFirewall, create_firewall
from sentinelx.pipeline import DetectionRecord, Pipeline, RunReport
from sentinelx.testing import SCENARIOS, get_scenario, write_pcap

JsonOption = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


async def _rules_into(pipeline: Pipeline, settings: Settings) -> int:
    """Load file rules straight from disk: replay and monitor need no database."""
    from sentinelx.services.rules import max_rule_window
    from sentinelx.signatures import RuleDetector, load_rules

    result = load_rules(
        Path(settings.rules_directory), max_window_seconds=max_rule_window(settings)
    )
    for problem in result.problems:
        err.print(f"[yellow]rule skipped:[/] {problem}")
    for rule in result.rules:
        pipeline.detection.add_detector(RuleDetector(rule, settings.detection))
    if settings.anomaly.enabled:
        from sentinelx.anomaly import StatisticalAnomalyDetector

        pipeline.detection.add_detector(
            StatisticalAnomalyDetector(settings.anomaly, settings.detection)
        )
    return len(result.rules)


def register(app: typer.Typer) -> None:
    @app.command(rich_help_panel="Lab")
    def replay(
        pcap: Annotated[
            Path,
            typer.Argument(exists=True, dir_okay=False, readable=True, help="pcap or pcapng file."),
        ],
        speed: Annotated[
            float, typer.Option(help="0 = as fast as possible, 1 = original timing.", min=0)
        ] = 0.0,
        limit: Annotated[int | None, typer.Option(help="Stop after N packets.", min=1)] = None,
        persist: Annotated[
            bool, typer.Option("--persist", help="Store results in the database under a replay id.")
        ] = False,
        report: Annotated[
            Path | None, typer.Option("--report", help="Write the full JSON report to this file.")
        ] = None,
        as_json: JsonOption = False,
    ) -> None:
        """Run a capture through the exact live detection pipeline and report the results.

        Responses are always simulated during replay: no firewall is modified.
        """
        settings = load_settings()
        settings.response.dry_run = True  # replays never enforce, whatever the configuration says

        if persist:
            stored = run(lambda: _replay_persisted(settings, pcap, speed, limit))
            if report:
                report.write_text(json.dumps(stored, indent=2, default=str), encoding="utf-8")
            if as_json:
                emit_json(stored)
            else:
                console.print(
                    table(
                        "Replay report (stored)",
                        ["Metric", "Value"],
                        [
                            (key, stored.get(key))
                            for key in (
                                "replay_id",
                                "frames",
                                "packets_per_second",
                                "wall_seconds",
                                "detection_count",
                                "incident_count",
                                "response_decisions",
                            )
                        ],
                    )
                )
            return

        async def main() -> tuple[RunReport, dict[str, Any], int]:
            metadata = await asyncio.to_thread(pcap_metadata, pcap)
            pipeline = Pipeline(settings, firewall=MemoryFirewall())
            rules = await _rules_into(pipeline, settings)
            await pipeline.start()
            try:
                with _ReplayProgress(metadata["packet_count"], quiet=as_json) as update:
                    result = await pipeline.run(
                        PcapFileCapture(pcap, speed=speed, limit=limit),
                        progress=update,
                        progress_interval=0.2,
                    )
            finally:
                await pipeline.stop()
            return result, metadata, rules

        result, metadata, rule_count = run(main)
        data = _report_dict(result, metadata)
        if report:
            report.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            err.print(f"[dim]report written to {report}[/]")
        if as_json:
            emit_json(data)
        else:
            _print_report(result, metadata, rule_count)

    @app.command(rich_help_panel="Lab")
    def monitor(
        interface: Annotated[
            str | None,
            typer.Option("--interface", "-i", help="Interface to capture (needs CAP_NET_RAW)."),
        ] = None,
        pcap: Annotated[
            Path | None,
            typer.Option("--pcap", help="Monitor a capture at its original speed instead."),
        ] = None,
        scenario: Annotated[
            str | None,
            typer.Option("--scenario", help="Monitor a synthetic scenario (no privileges needed)."),
        ] = None,
        bpf: Annotated[
            str, typer.Option("--bpf", help="Kernel BPF filter, e.g. 'tcp or udp'.")
        ] = "",
        duration: Annotated[float | None, typer.Option(help="Stop after N seconds.")] = None,
        enforce: Annotated[
            bool,
            typer.Option(
                "--enforce", help="Apply configured responses (still subject to DRY_RUN)."
            ),
        ] = False,
    ) -> None:
        """Live terminal view of traffic, detections and incidents as they happen."""
        settings = load_settings()
        if scenario and scenario not in SCENARIOS:
            err.print(f"unknown scenario; available: {', '.join(sorted(SCENARIOS))}")
            raise typer.Exit(2)

        async def main() -> None:
            capture: PacketCapture
            if scenario:
                capture = MockCapture(get_scenario(scenario).frames, delay=0.0005)
            elif pcap:
                capture = PcapFileCapture(pcap, speed=1.0)
            else:
                capture = LiveCapture(
                    interface or settings.capture.interface,
                    bpf_filter=bpf,
                    snapshot_length=settings.capture.snapshot_length,
                )
            firewall = create_firewall(settings.response) if enforce else MemoryFirewall()
            if not enforce:
                settings.response.dry_run = True
            pipeline = Pipeline(settings, bus=EventBus(), firewall=firewall)
            await _rules_into(pipeline, settings)
            view = _MonitorView(settings, capture)
            pipeline.add_packet_hook(view.packet)
            await pipeline.start()
            started = time.monotonic()
            try:
                with Live(
                    view.render(), console=console, refresh_per_second=4, transient=False
                ) as live:

                    async def progress(stats: dict[str, Any]) -> None:
                        view.stats = stats
                        if duration and time.monotonic() - started >= duration:
                            capture.stop()

                    task = asyncio.create_task(
                        pipeline.run(
                            capture, progress=progress, progress_interval=0.25, record_latency=False
                        )
                    )
                    seen = 0
                    while not task.done():
                        await asyncio.sleep(0.25)
                        report = pipeline.last_report
                        records = report.detections if report else []
                        view.detections.extend(records[seen:])
                        seen = len(records)
                        live.update(view.render())
                    result = await task
                    view.detections.extend(result.detections[seen:])
                    view.stats["final"] = True
                    live.update(view.render())
            finally:
                await pipeline.stop()

        run(main)

    fixtures = typer.Typer(
        help="Synthetic traffic fixtures (written to files, never transmitted).",
        no_args_is_help=True,
    )
    app.add_typer(fixtures, name="fixtures", rich_help_panel="Lab")

    @fixtures.command("list")
    def fixtures_list(as_json: JsonOption = False) -> None:
        """Available scenarios and what a correct detector should find in each."""
        rows: list[dict[str, Any]] = []
        for name in SCENARIOS:
            scenario = get_scenario(name)
            rows.append(
                {
                    "name": name,
                    "packets": scenario.packet_count,
                    "benign": scenario.benign,
                    "expected_detectors": sorted(scenario.expected_detectors),
                    "description": scenario.description,
                }
            )
        if as_json:
            emit_json(rows)
            return
        console.print(
            table(
                "Scenarios",
                ["Name", "Packets", "Expected detectors", "Description"],
                [
                    (
                        r["name"],
                        r["packets"],
                        ", ".join(r["expected_detectors"]) or "none (benign)",
                        r["description"],
                    )
                    for r in rows
                ],
            )
        )

    @fixtures.command("generate")
    def fixtures_generate(
        names: Annotated[
            list[str] | None, typer.Argument(help="Scenario names; default all.")
        ] = None,
        output: Annotated[
            Path, typer.Option("--output", "-o", help="Directory for the pcap files.")
        ] = Path("pcaps/fixtures"),
    ) -> None:
        """Write scenario pcaps for replay, rule testing and benchmarks."""
        selected = names or sorted(SCENARIOS)
        unknown = [n for n in selected if n not in SCENARIOS]
        if unknown:
            err.print(f"unknown scenario(s): {', '.join(unknown)}")
            raise typer.Exit(2)
        output.mkdir(parents=True, exist_ok=True)
        for name in selected:
            scenario = get_scenario(name)
            path = output / f"{name}.pcap"
            write_pcap(path, scenario.frames)
            console.print(f"[green]wrote[/] {path}  ({scenario.packet_count} packets)")

    anomaly = typer.Typer(help="Optional machine-learning anomaly model.", no_args_is_help=True)
    app.add_typer(anomaly, name="anomaly", rich_help_panel="Lab")

    @anomaly.command("train")
    def anomaly_train(
        pcaps: Annotated[
            list[Path],
            typer.Argument(exists=True, dir_okay=False, help="Captures of NORMAL traffic."),
        ],
        output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
        contamination: Annotated[float, typer.Option(min=0.001, max=0.4)] = 0.02,
    ) -> None:
        """Train the Isolation Forest on known-normal traffic. The capture must be clean."""
        settings = load_settings()
        from sentinelx.anomaly.ml import collect_training_vectors, save_model, train_model

        async def gather() -> list[Any]:
            frames: list[Any] = []
            for path in pcaps:
                async with PcapFileCapture(path) as capture:
                    frames.extend([frame async for frame in capture.frames()])
            frames.sort(key=lambda f: f.timestamp)
            return frames

        frames = run(gather)
        vectors = collect_training_vectors(frames, settings.detection)
        try:
            bundle = train_model(vectors, contamination=contamination)
        except ValueError as exc:
            err.print(f"[red]{exc}[/]")
            raise typer.Exit(1) from None
        target = output or Path(settings.anomaly.ml_model_path)
        save_model(bundle, target)
        console.print(f"[green]model saved[/] to {target} (mode 600)")
        console.print(
            table(
                "Model",
                ["Field", "Value"],
                [(k, v) for k, v in bundle.info().items() if k != "features"],
            )
        )
        console.print(
            "[dim]Enable with ANOMALY__ML_ENABLED=true. Treat its output as leads, not verdicts.[/]"
        )


async def _replay_persisted(
    settings: Settings, pcap: Path, speed: float, limit: int | None
) -> dict[str, Any]:
    """Replay through the platform's replay service so results are stored under a replay id.

    The service only reads inside ``PCAP_DIRECTORY``, so a file elsewhere is copied in first.
    """
    from sentinelx.cli.runtime import actor, platform_context
    from sentinelx.common.errors import PcapError

    async with platform_context(settings) as platform:
        _, _, service, _ = platform.require()
        await asyncio.to_thread(service.directory.mkdir, parents=True, exist_ok=True)
        source = await asyncio.to_thread(pcap.resolve)
        if service.directory not in source.parents:
            copy = service.directory / "cli" / pcap.name
            await asyncio.to_thread(copy.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copyfile, source, copy)
            source = copy
        started = await service.start(
            source.relative_to(service.directory).as_posix(),
            actor=actor(),
            speed=speed,
            limit=limit,
        )
        await service.wait(started["replay_id"])
        record = await service.get(started["replay_id"])
        if record is None or record["status"] != "completed":
            raise PcapError(f"replay failed: {record.get('error') if record else 'record missing'}")
        # Give the persister one flush interval so the detections are queryable on exit.
        await asyncio.sleep(settings.storage.flush_interval_seconds + 0.2)
    err.print(f"[dim]stored as replay {started['replay_id']}; view it in the PCAP Lab[/]")
    return {"replay_id": started["replay_id"], **record["report"]}


def _report_dict(result: RunReport, metadata: dict[str, Any]) -> dict[str, Any]:
    data = result.as_dict()
    data["file"] = metadata
    data["detections"] = [detection_to_dict(r.detection, r.risk) for r in result.detections]
    data["incidents"] = [incident_to_dict(i) for i in result.incidents.values()]
    data["safety_note"] = "Replay responses are always simulated; no firewall changes were made."
    return data


class _ReplayProgress:
    def __init__(self, total: int, *, quiet: bool) -> None:
        from rich.progress import (
            BarColumn,
            MofNCompleteColumn,
            Progress,
            TextColumn,
            TimeElapsedColumn,
        )

        self.quiet = quiet
        self.progress = Progress(
            TextColumn("[bold]replaying"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("{task.fields[detail]}"),
            TimeElapsedColumn(),
            console=err,
            transient=True,
        )
        self.task = self.progress.add_task("replay", total=total or None, detail="")

    def __enter__(self) -> Any:
        if not self.quiet:
            self.progress.start()

        def update(stats: dict[str, Any]) -> None:
            self.progress.update(
                self.task,
                completed=stats["frames"],
                detail=f"{stats['packets_per_second']:,.0f} pkt/s  {stats['detections']} detections",
            )

        return update

    def __exit__(self, *exc: object) -> None:
        if not self.quiet:
            self.progress.stop()


def _print_report(result: RunReport, metadata: dict[str, Any], rule_count: int) -> None:
    data = result.as_dict()
    summary = Table.grid(padding=(0, 3))
    summary.add_column(style="dim")
    summary.add_column()
    rows = [
        (
            "File",
            f"{metadata['filename']}  ({metadata['packet_count']:,} packets over {metadata['duration_seconds']:.1f}s)",
        ),
        ("Processed", f"{data['frames']:,} frames in {data['wall_seconds']:.2f}s"),
        ("Throughput", f"{data['packets_per_second']:,.0f} packets/s (measured)"),
        (
            "Latency",
            f"p50 {data['latency']['per_packet_p50_ms']} ms, p99 {data['latency']['per_packet_p99_ms']} ms per packet; "
            f"{data['latency']['detection_mean_ms']} ms mean to a response decision",
        ),
        (
            "Resources",
            f"CPU mean {data['resources']['cpu_percent_mean']}% (max {data['resources']['cpu_percent_max']}%), "
            f"peak RSS {data['resources']['memory_peak_mb']} MB",
        ),
        (
            "Detectors",
            f"{len(result.detections)} detections, {len(result.incidents)} incidents, {rule_count} custom rules loaded",
        ),
        ("Decode failures", str(data["decode_failures"])),
    ]
    for label, value in rows:
        summary.add_row(label, value)
    console.print(Panel(summary, title="Replay report", expand=False))
    if result.detections:
        console.print(
            table(
                "Detections",
                ["Severity", "Risk", "Threat", "Source", "Detector", "Decision"],
                [
                    (
                        severity_text(r.detection.severity.value),
                        risk_text(r.risk.score),
                        r.detection.title,
                        r.detection.source_ip,
                        r.detection.detector,
                        ", ".join(
                            f"{d.action.value}:{d.outcome}"
                            for d in r.decisions
                            if d.action.is_preventive
                        )
                        or "alert",
                    )
                    for r in result.detections
                ],
            )
        )
    for incident in result.incidents.values():
        body = Text()
        body.append(f"{incident.title}  ", style="bold")
        body.append_text(risk_text(incident.risk.score))
        body.append(f"/100\n{incident.summary}\n")
        for line in incident.risk.rationale:
            body.append(f"  {line}\n", style="dim")
        console.print(
            Panel(body, title=f"Incident ({incident.detection_count} detections)", expand=False)
        )
    console.print("[dim]Replay responses are always simulated; no firewall changes were made.[/]")


class _MonitorView:
    def __init__(self, settings: Settings, capture: PacketCapture) -> None:
        self.settings = settings
        self.capture = capture
        self.stats: dict[str, Any] = {}
        self.detections: deque[DetectionRecord] = deque(maxlen=12)
        self.recent_packets: deque[str] = deque(maxlen=8)
        self._counter = 0

    def packet(self, packet: PacketEvent) -> None:
        self._counter += 1
        if self._counter % 50 == 0:  # sample; printing every packet is unreadable and slow
            self.recent_packets.append(packet.summary())

    def render(self) -> Group:
        stats = self.stats
        header = Table.grid(padding=(0, 3))
        for _ in range(4):
            header.add_column()
        header.add_row(
            Text(f"source {self.capture.interface}", style="bold"),
            f"packets {stats.get('frames', 0):,}",
            f"{stats.get('packets_per_second', 0):,.0f} pkt/s",
            f"flows {stats.get('active_flows', 0):,}",
        )
        header.add_row(
            f"detections {stats.get('detections', 0)}",
            f"incidents {stats.get('incidents', 0)}",
            f"dropped {stats.get('dropped', 0)}",
            "protocols "
            + " ".join(f"{k}:{v:.0%}" for k, v in (stats.get("protocols") or {}).items() if v),
        )
        detection_table = table(
            "Latest detections",
            ["Severity", "Risk", "Threat", "Source", "Evidence"],
            [
                (
                    severity_text(r.detection.severity.value),
                    risk_text(r.risk.score),
                    r.detection.title,
                    r.detection.source_ip,
                    r.detection.evidence[0].description[:60] if r.detection.evidence else "",
                )
                for r in reversed(self.detections)
            ],
        )
        packets = Panel(
            Text("\n".join(self.recent_packets) or "waiting for traffic...", style="dim"),
            title="Sampled packets",
            expand=False,
        )
        footer = Text("finished" if stats.get("final") else "Ctrl-C to stop", style="dim")
        return Group(
            safety_panel(self.settings.safety_banner()), header, detection_table, packets, footer
        )
