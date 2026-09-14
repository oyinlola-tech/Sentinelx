#!/usr/bin/env python3
"""Populate a development database with detections from synthetic scenarios.

DEVELOPMENT ONLY. Runs the bundled scenario fixtures through the real Platform
pipeline (decode, features, detection, scoring, correlation, response in dry run,
persistence) exactly as live capture would, so the dashboard has realistic data to
show on a machine without capture privileges. Nothing is sent on the network, and
every detection produced here is labelled with the sensor name "demo-seed".

    DATABASE_URL=sqlite+aiosqlite:///./sentinelx.db python scripts/seed_demo.py

Refuses to run when ENVIRONMENT=production.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sentinelx.capture import MockCapture
from sentinelx.config.settings import reload_settings
from sentinelx.services.platform import Platform
from sentinelx.testing import get_scenario

SCENARIOS: list[tuple[str, dict[str, object]]] = [
    ("normal_traffic", {"packet_count": 3000}),
    ("mixed_intrusion", {}),
    ("horizontal_scan", {"port": 445}),
    ("udp_scan", {}),
    ("dns_tunneling", {}),
    ("http_flood", {}),
    ("syn_flood", {"count": 1200}),
]


async def main(delay: float) -> int:
    settings = reload_settings()
    if settings.environment == "production":
        print("refusing to seed demo data into a production environment", file=sys.stderr)
        return 2
    settings.sensor_name = "demo-seed"
    settings.response.dry_run = True
    platform = Platform(settings)
    await platform.start(background=False)
    pipeline, _, _, _ = platform.require()
    try:
        for name, params in SCENARIOS:
            report = await pipeline.run(MockCapture(get_scenario(name, **params).frames))
            print(
                f"{name:18} {report.frames:6d} packets -> {len(report.detections)} detections, {len(report.incidents)} incidents"
            )
            pipeline.reset_state()  # keep scenarios from correlating with each other
            await asyncio.sleep(delay)
        await asyncio.sleep(settings.storage.flush_interval_seconds + 0.5)
    finally:
        await platform.stop()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--delay", type=float, default=1.0, help="Seconds between scenarios, spreading timestamps."
    )
    sys.exit(asyncio.run(main(parser.parse_args().delay)))
