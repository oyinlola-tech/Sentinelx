"""Shared fixtures.

Every test gets isolated settings, a fresh event bus and silenced logging, so no
state leaks between cases and no test depends on the machine's environment.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

import pytest
import structlog

from sentinelx.capture.base import RawFrame
from sentinelx.common.models import PacketEvent
from sentinelx.config.settings import DetectionSettings, Settings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.events.bus import EventBus, reset_event_bus
from sentinelx.features.extractor import FeatureContext, FeatureExtractor
from sentinelx.parser.decoder import PacketDecoder

_SETTINGS_ENV = (
    "DATABASE_URL",
    "REDIS_URL",
    "API_HOST",
    "API_PORT",
    "CAPTURE_INTERFACE",
    "DETECTION_MODE",
    "RESPONSE_MODE",
    "DRY_RUN",
    "JWT_SECRET",
    "LOG_LEVEL",
    "PCAP_DIRECTORY",
    "RETENTION_DAYS",
    "FIREWALL_BACKEND",
    "CORS_ORIGINS",
    "BPF_FILTER",
    "LOG_FORMAT",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for name in _SETTINGS_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)  # no stray .env or sentinelx.db from the repo
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture
def settings() -> Settings:
    return Settings(storage={"database_url": "sqlite+aiosqlite:///:memory:"})


@pytest.fixture
def detection_settings() -> DetectionSettings:
    return DetectionSettings()


@pytest.fixture
async def bus() -> AsyncIterator[EventBus]:
    event_bus = EventBus()
    await event_bus.start()
    yield event_bus
    await event_bus.stop()


@pytest.fixture
def decoder() -> PacketDecoder:
    return PacketDecoder()


@pytest.fixture
def run_detection() -> Callable[..., list]:  # type: ignore[type-arg]
    """Feed frames through decode -> features -> detection and return detections."""

    def run(
        frames: list[RawFrame],
        settings: DetectionSettings | None = None,
        engine: DetectionEngine | None = None,
    ) -> list:  # type: ignore[type-arg]
        detection_settings = settings or DetectionSettings()
        decoder = PacketDecoder()
        extractor = FeatureExtractor(detection_settings)
        detection_engine = engine or DetectionEngine(detection_settings)
        found = []
        for frame in frames:
            packet = decoder.decode(frame.data, frame.timestamp, frame.link_type)
            if packet is not None:
                found.extend(detection_engine.evaluate(extractor.process(packet)))
        return found

    return run


@pytest.fixture
def contexts() -> Callable[[list[RawFrame]], list[FeatureContext]]:
    def build(frames: list[RawFrame]) -> list[FeatureContext]:
        decoder = PacketDecoder()
        extractor = FeatureExtractor()
        out = []
        for frame in frames:
            packet: PacketEvent | None = decoder.decode(
                frame.data, frame.timestamp, frame.link_type
            )
            if packet is not None:
                out.append(extractor.process(packet))
        return out

    return build


def frames_from(packets: list[tuple[bytes, float]]) -> list[RawFrame]:
    return [RawFrame(data=data, timestamp=ts) for data, ts in packets]
