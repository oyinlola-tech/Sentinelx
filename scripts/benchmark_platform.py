#!/usr/bin/env python3
"""Platform benchmark: API latency, WebSocket delivery, storage throughput, pipeline load.

Complements ``scripts/benchmark.py`` (detection quality and packet throughput). Every
figure is measured here, on this machine, against a real server started on an
ephemeral loopback port; nothing is estimated. Results are written to
``benchmarks/results/platform-<timestamp>.json`` and ``.md``.

    python scripts/benchmark_platform.py
    python scripts/benchmark_platform.py --postgres postgresql://user:pass@127.0.0.1:5432/db

The PostgreSQL URL must point at a disposable database: the benchmark creates tables
and writes data.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform as host
import socket
import statistics
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
ADMIN_PASSWORD = "Benchmark-Passphrase-2026"  # noqa: S105 - throwaway benchmark server


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def summarise(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def pct(p: float) -> float:
        return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]

    return {
        "count": len(ordered),
        "mean_ms": round(1000 * statistics.fmean(ordered), 3),
        "p50_ms": round(1000 * pct(50), 3),
        "p95_ms": round(1000 * pct(95), 3),
        "p99_ms": round(1000 * pct(99), 3),
        "max_ms": round(1000 * ordered[-1], 3),
    }


async def start_server(
    database_url: str, workdir: Path
) -> tuple[Any, asyncio.Task[None], str, Any]:
    import uvicorn

    from sentinelx.api.app import create_app
    from sentinelx.config.settings import Settings

    port = free_port()
    settings = Settings(
        storage={"database_url": database_url, "redis_url": "redis://127.0.0.1:1/0"},
        api={
            "bootstrap_admin_password": ADMIN_PASSWORD,
            "jwt_secret": "b" * 48,
            "rate_limit_requests": 1_000_000,
            "login_rate_limit_attempts": 1_000_000,
            "lockout_threshold": 1_000_000,
            "cors_origins": [f"http://127.0.0.1:{port}"],
        },
        capture={"pcap_directory": workdir / "pcaps"},
        rules_directory=ROOT / "rules",
        telemetry={"log_level": "WARNING"},
    )
    app = create_app(settings)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    base = f"http://127.0.0.1:{port}"
    async with httpx.AsyncClient() as client:
        for _ in range(200):
            try:
                if (await client.get(f"{base}/api/v1/system/health")).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.05)
    return server, task, base, app


async def seed(app: Any) -> int:
    """Put live (non-replay) detections and incidents in the database to query."""
    from sentinelx.capture import MockCapture
    from sentinelx.testing import get_scenario, shift_to

    platform = app.state.platform
    pipeline = platform.require()[0]
    frames = shift_to(get_scenario("mixed_intrusion").frames, time.time())
    settings = pipeline.detection.settings
    default_cooldown = settings.detection_cooldown_seconds
    settings.detection_cooldown_seconds = 0  # seed many rows, then restore the default
    try:
        report = await pipeline.run(MockCapture(frames, repeat=4), record_latency=False)
    finally:
        settings.detection_cooldown_seconds = default_cooldown
    await platform.bus.drain(wait_seconds=60)
    await platform.persister.flush()
    return int(report.detections_seen)


async def measure(
    requests: int, concurrency: int, call: Callable[[], Awaitable[httpx.Response]]
) -> dict[str, Any]:
    samples: list[float] = []
    failures = 0
    queue: asyncio.Queue[None] = asyncio.Queue()
    for _ in range(requests):
        queue.put_nowait(None)

    async def worker() -> None:
        nonlocal failures
        while not queue.empty():
            queue.get_nowait()
            started = time.perf_counter()
            response = await call()
            samples.append(time.perf_counter() - started)
            if response.status_code >= 400:
                failures += 1

    started = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    wall = time.perf_counter() - started
    return {
        **summarise(samples),
        "concurrency": concurrency,
        "requests_per_second": round(requests / wall, 1),
        "failures": failures,
    }


async def api_benchmark(base: str) -> dict[str, Any]:
    results: dict[str, Any] = {}
    async with httpx.AsyncClient(base_url=f"{base}/api/v1", timeout=30) as client:
        login = await client.post(
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        endpoints: dict[str, Callable[[], Awaitable[httpx.Response]]] = {
            "GET /system/health (unauthenticated)": lambda: client.get("/system/health"),
            "GET /detections?limit=50": lambda: client.get("/detections?limit=50", headers=headers),
            "GET /stats/overview": lambda: client.get("/stats/overview", headers=headers),
            "GET /incidents?limit=50": lambda: client.get("/incidents?limit=50", headers=headers),
        }
        for name, call in endpoints.items():
            for _ in range(20):  # warm up
                await call()
            results[name] = {
                "sequential": await measure(300, 1, call),
                "concurrency_10": await measure(600, 10, call),
            }
        login_call = lambda: client.post(  # noqa: E731
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        results["POST /auth/login (Argon2id)"] = {
            "sequential": await measure(40, 1, login_call),
            "concurrency_10": await measure(80, 10, login_call),
        }
    return results


async def websocket_benchmark(base: str) -> dict[str, Any]:
    import websockets

    async with httpx.AsyncClient(base_url=f"{base}/api/v1", timeout=30) as client:
        login = await client.post(
            "/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        ticket = (await client.post("/auth/ws-ticket", headers=headers)).json()["ticket"]
        url = (
            base.replace("http", "ws")
            + f"/api/v1/ws/events?ticket={ticket}&types=detection.created,incident.opened,incident.updated"
        )
        latencies: list[float] = []
        async with websockets.connect(url, max_size=2**22) as socket_:
            await socket_.recv()  # hello
            await client.post("/replay/scenarios/syn_flood", headers=headers, json={"params": {}})
            await client.post("/replay", headers=headers, json={"path": "fixtures/syn_flood.pcap"})
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                try:
                    raw = await asyncio.wait_for(socket_.recv(), timeout=5)
                except TimeoutError:
                    break
                received = datetime.now(UTC)
                message = json.loads(raw)
                if message.get("type") in {"ping", "hello"}:
                    continue
                published = datetime.fromisoformat(message["timestamp"])
                latencies.append((received - published).total_seconds())
    if not latencies:
        return {"error": "no events received"}
    return {
        "events": len(latencies),
        "publish_to_client": summarise(latencies),
        "note": "time from the server publishing an event to this client receiving it, same host",
    }


async def storage_benchmark(database_url: str, label: str) -> dict[str, Any]:
    """Detections persisted per second through the production persister."""
    from sqlalchemy import func, select

    from sentinelx.capture import MockCapture
    from sentinelx.config.settings import Settings
    from sentinelx.firewall import MemoryFirewall
    from sentinelx.services.platform import Platform
    from sentinelx.storage.models import DetectionRecord
    from sentinelx.testing import get_scenario

    settings = Settings(
        storage={"database_url": database_url, "redis_url": "redis://127.0.0.1:1/0"},
        api={"bootstrap_admin_password": ADMIN_PASSWORD, "jwt_secret": "b" * 48},
        rules_directory=ROOT / "rules",
        # Every detection is reported: the cooldown would otherwise suppress repeats.
        detection={"detection_cooldown_seconds": 0},
        telemetry={"log_level": "WARNING"},
    )
    if not database_url.startswith("sqlite"):
        from sentinelx.storage.migrate import upgrade

        await upgrade(database_url)
    platform = Platform(settings, firewall=MemoryFirewall())
    await platform.start(background=False)
    pipeline = platform.require()[0]
    frames = get_scenario("mixed_intrusion").frames
    started = time.perf_counter()
    report = await pipeline.run(MockCapture(frames, repeat=3), record_latency=False)
    produced = time.perf_counter() - started
    await platform.bus.drain(wait_seconds=120)
    assert platform.persister is not None
    await platform.persister.flush()
    elapsed = time.perf_counter() - started
    async with platform.database.session() as session:
        stored = int(await session.scalar(select(func.count()).select_from(DetectionRecord)) or 0)
    await platform.stop()
    return {
        "database": label,
        "detections_produced": report.detections_seen,
        "detections_stored": stored,
        "pipeline_seconds": round(produced, 3),
        "produced_and_stored_seconds": round(elapsed, 3),
        "stored_per_second": round(stored / elapsed, 1) if elapsed else None,
    }


async def pipeline_load_benchmark() -> list[dict[str, Any]]:
    """Per-packet latency and memory as traffic volume grows."""
    import psutil

    from sentinelx.assembly import attach_anomaly_detectors, attach_file_rules, build_intel
    from sentinelx.capture import MockCapture
    from sentinelx.config.settings import Settings
    from sentinelx.firewall import MemoryFirewall
    from sentinelx.pipeline import Pipeline
    from sentinelx.testing import get_scenario

    results = []
    process = psutil.Process()
    for packets in (1_000, 10_000, 50_000):
        settings = Settings(rules_directory=ROOT / "rules", telemetry={"log_level": "WARNING"})
        pipeline = Pipeline(settings, firewall=MemoryFirewall(), intel=build_intel(settings))
        attach_file_rules(pipeline, settings)
        attach_anomaly_detectors(pipeline, settings)
        await pipeline.start()
        frames = get_scenario("normal_traffic", packet_count=packets).frames
        before = process.memory_info().rss
        report = await pipeline.run(MockCapture(frames))
        after = process.memory_info().rss
        await pipeline.stop()
        latencies = report.processing_latencies
        results.append(
            {
                "packets": packets,
                "packets_per_second": round(report.packets_per_second, 1),
                "per_packet": summarise(latencies),
                "rss_growth_mb": round((after - before) / 1_048_576, 1),
                "tracked_sources": len(pipeline.extractor.profiles),
            }
        )
    return results


def environment() -> dict[str, Any]:
    from sentinelx import __version__

    cpu = host.processor() or host.machine()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "sentinelx": __version__,
        "python": host.python_version(),
        "platform": host.platform(),
        "cpu": cpu,
        "cpu_count": os.cpu_count(),
        "timestamp": datetime.now(UTC).isoformat(),
    }


def to_markdown(result: dict[str, Any]) -> str:
    env = result["environment"]
    lines = [
        "# SentinelX platform benchmark",
        "",
        f"Measured {env['timestamp']} on `{env['cpu']}` ({env['cpu_count']} logical CPUs), Python {env['python']}, SentinelX {env['sentinelx']}, {env['platform']}.",
        "Single uvicorn worker on loopback; SQLite unless stated; Redis not used (degraded in-process mode).",
        "",
        "## API latency",
        "",
        "| Endpoint | Mode | p50 ms | p95 ms | p99 ms | req/s | failures |",
        "|---|---|---|---|---|---|---|",
    ]
    for endpoint, modes in result["api"].items():
        for mode, data in modes.items():
            lines.append(
                f"| {endpoint} | {mode.replace('_', ' ')} | {data['p50_ms']} | {data['p95_ms']} | {data['p99_ms']} | {data['requests_per_second']} | {data['failures']} |"
            )
    ws = result["websocket"]
    lines += ["", "## WebSocket event delivery", ""]
    if "error" in ws:
        lines.append(f"Not measured: {ws['error']}")
    else:
        d = ws["publish_to_client"]
        lines.append(
            f"{ws['events']} events during a SYN flood replay; publish to client p50 {d['p50_ms']} ms, p95 {d['p95_ms']} ms, p99 {d['p99_ms']} ms, max {d['max_ms']} ms."
        )
    lines += [
        "",
        "## Storage",
        "",
        "| Database | Detections produced | Stored | Seconds (produce and store) | Stored per second |",
        "|---|---|---|---|---|",
    ]
    for entry in result["storage"]:
        lines.append(
            f"| {entry['database']} | {entry['detections_produced']} | {entry['detections_stored']} | {entry['produced_and_stored_seconds']} | {entry['stored_per_second']} |"
        )
    lines += [
        "",
        "## Pipeline under growing traffic volume",
        "",
        "| Packets | Packets/s | p50 ms | p99 ms | RSS growth MB | Sources tracked |",
        "|---|---|---|---|---|---|",
    ]
    for entry in result["pipeline_load"]:
        lines.append(
            f"| {entry['packets']:,} | {entry['packets_per_second']:,} | {entry['per_packet']['p50_ms']} | {entry['per_packet']['p99_ms']} | {entry['rss_growth_mb']} | {entry['tracked_sources']} |"
        )
    return "\n".join(lines) + "\n"


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--postgres", help="disposable PostgreSQL URL for the storage benchmark")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results")
    args = parser.parse_args()

    result: dict[str, Any] = {"environment": environment()}
    with tempfile.TemporaryDirectory() as directory:
        workdir = Path(directory)
        server, task, base, app = await start_server(
            f"sqlite+aiosqlite:///{workdir / 'api.db'}", workdir
        )
        try:
            result["seeded_detections"] = await seed(app)
            result["api"] = await api_benchmark(base)
            result["websocket"] = await websocket_benchmark(base)
        finally:
            server.should_exit = True
            await task
        result["storage"] = [
            await storage_benchmark(f"sqlite+aiosqlite:///{workdir / 'storage.db'}", "SQLite")
        ]
    if args.postgres:
        result["storage"].append(await storage_benchmark(args.postgres, "PostgreSQL"))
    result["pipeline_load"] = await pipeline_load_benchmark()

    args.output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (args.output / f"platform-{stamp}.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    markdown = to_markdown(result)
    (args.output / f"platform-{stamp}.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
