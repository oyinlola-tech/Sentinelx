"""The committed PCAP suite (tests/pcaps) replays to exactly what its manifest records.

Regenerate with ``python scripts/generate_test_pcaps.py`` after an intended change to
the generator or to detection, and review the manifest diff.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from sentinelx.capture.pcapfile import read_capture
from sentinelx.common.errors import PcapError
from sentinelx.testing import get_scenario, write_pcap

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "tests" / "pcaps"
MANIFEST: dict[str, dict[str, Any]] = json.loads((SUITE / "MANIFEST.json").read_text())

sys.path.insert(0, str(ROOT / "scripts"))
from generate_test_pcaps import _replay  # noqa: E402

REPLAYED = sorted(name for name, entry in MANIFEST.items() if "scenario" in entry)
MALFORMED = sorted(name for name, entry in MANIFEST.items() if "error" in entry)


def test_every_file_in_the_suite_is_in_the_manifest() -> None:
    on_disk = {
        path.relative_to(SUITE).as_posix()
        for path in SUITE.rglob("*")
        if path.is_file() and path.suffix in {".pcap", ".pcapng"}
    }
    assert on_disk == set(MANIFEST)


@pytest.mark.parametrize("name", [*REPLAYED, *MALFORMED])
def test_committed_file_is_unchanged(name: str) -> None:
    assert hashlib.sha256((SUITE / name).read_bytes()).hexdigest() == MANIFEST[name]["sha256"]


@pytest.mark.parametrize("name", REPLAYED)
def test_generator_still_produces_the_committed_file(name: str, tmp_path: Path) -> None:
    path = tmp_path / "regenerated.pcap"
    write_pcap(path, get_scenario(MANIFEST[name]["scenario"]).frames)
    assert path.read_bytes() == (SUITE / name).read_bytes()


@pytest.mark.parametrize("name", REPLAYED)
async def test_replay_matches_manifest(name: str) -> None:
    entry = MANIFEST[name]
    result = await _replay(SUITE / name)
    assert result == {
        "packets": entry["packets"],
        "detections": entry["detections"],
        "incidents": entry["incidents"],
    }
    fired = {item.split("@")[0] for item in result["detections"]}
    sources = {item.split("@")[1] for item in result["detections"]}
    if entry["benign"]:
        assert not result["detections"], "benign traffic must not produce detections"
    elif name.startswith("evasion/"):
        # Known limitation, kept visible: below-threshold attacks are not detected.
        assert not set(entry["intended_detectors"]) & fired
    else:
        assert set(entry["intended_detectors"]) <= fired
        assert sources == {entry["expected_source"]}


@pytest.mark.parametrize("name", MALFORMED)
def test_malformed_file_is_rejected_cleanly(name: str) -> None:
    with pytest.raises(PcapError):
        list(read_capture(SUITE / name))
