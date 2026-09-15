"""Regenerate the committed PCAP suite in ``tests/pcaps`` and its ``MANIFEST.json``.

Every file is synthetic: built in memory by ``sentinelx.testing.scenarios`` or crafted
byte by byte below. Nothing was captured from a real network, so the files carry no
third-party data and are distributed under the project's licence.

The manifest records each file's SHA-256 and the detections the full detection
pipeline (built-in detectors, anomaly detection, local threat intelligence and the
shipped rules) produces when the file is replayed. ``tests/capture/test_pcap_suite.py``
checks both, so a change to the generator or to detection shows up as a test failure
and, after running this script, as a reviewable manifest diff.

Usage:
    python scripts/generate_test_pcaps.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
from pathlib import Path

from sentinelx.assembly import attach_anomaly_detectors, attach_file_rules, build_intel
from sentinelx.capture import PcapFileCapture
from sentinelx.config.settings import Settings, TelemetrySettings
from sentinelx.firewall import MemoryFirewall
from sentinelx.pipeline import Pipeline
from sentinelx.telemetry.logging import configure_logging
from sentinelx.testing import get_scenario, write_pcap

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "tests" / "pcaps"

#: Category -> scenarios. Kept small (well under 1 MiB in total); every other scenario
#: is available through ``sentinelx fixtures generate``.
SCENARIO_FILES: dict[str, list[str]] = {
    "benign": ["normal_traffic"],
    "attacks": [
        "tcp_port_scan",
        "horizontal_scan",
        "udp_scan",
        "ssh_brute_force",
        "dns_tunneling",
        "mixed_intrusion",
    ],
    # Deliberately below the default thresholds: documents what is NOT detected.
    "evasion": ["slow_port_scan", "low_rate_brute_force"],
}

_PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _malformed() -> dict[str, bytes]:
    record = struct.pack("<IIII", 1_700_000_000, 0, 60, 60)
    return {
        "truncated_record.pcap": _PCAP_HEADER + record + b"\x00" * 20,
        "oversized_record.pcap": _PCAP_HEADER + struct.pack("<IIII", 0, 0, 2**31, 2**31),
        "not_a_capture.pcap": b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "empty.pcap": b"",
        # A section header block whose trailing length disagrees with its header.
        "bad_block_length.pcapng": (
            struct.pack("<II", 0x0A0D0D0A, 28)
            + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
            + struct.pack("<I", 32)
        ),
    }


async def _replay(path: Path) -> dict[str, object]:
    settings = Settings(
        storage={"database_url": "sqlite+aiosqlite:///:memory:"},
        rules_directory=str(ROOT / "rules"),
    )
    pipeline = Pipeline(settings, firewall=MemoryFirewall(), intel=build_intel(settings))
    attach_file_rules(pipeline, settings)
    attach_anomaly_detectors(pipeline, settings)
    await pipeline.start()
    report = await pipeline.run(PcapFileCapture(path))
    await pipeline.stop()
    return {
        "packets": report.frames,
        "detections": sorted(
            {f"{r.detection.detector}@{r.detection.source_ip}" for r in report.detections}
        ),
        "incidents": report.as_dict()["incident_count"],
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def main() -> None:
    configure_logging(TelemetrySettings(log_level="CRITICAL"))
    logging.disable(logging.CRITICAL)
    manifest: dict[str, dict[str, object]] = {}
    for category, names in SCENARIO_FILES.items():
        (SUITE / category).mkdir(parents=True, exist_ok=True)
        for name in names:
            scenario = get_scenario(name)
            path = SUITE / category / f"{name}.pcap"
            write_pcap(path, scenario.frames)
            manifest[f"{category}/{name}.pcap"] = {
                "scenario": name,
                "sha256": _sha256(path),
                "benign": scenario.benign,
                "expected_source": scenario.expected_source,
                "intended_detectors": sorted(scenario.expected_detectors),
                **await _replay(path),
            }
    (SUITE / "malformed").mkdir(parents=True, exist_ok=True)
    for filename, data in _malformed().items():
        path = SUITE / "malformed" / filename
        path.write_bytes(data)
        manifest[f"malformed/{filename}"] = {"sha256": _sha256(path), "error": "PcapError"}
    (SUITE / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(manifest)} files to {SUITE.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
