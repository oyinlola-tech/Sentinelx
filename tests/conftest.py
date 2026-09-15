"""Shared fixtures.

Every test gets isolated settings, a fresh event bus and silenced logging, so no
state leaks between cases and no test depends on the machine's environment.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

import pytest
import structlog
from structlog._config import BoundLoggerLazyProxy

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


def _uncache_module_loggers() -> None:
    """Undo structlog's first-use caching on SentinelX module loggers.

    An app started by an earlier test configures logging with caching on; each module
    logger then keeps the processors of that moment forever, and later tests that
    capture logs (structlog.testing.capture_logs) see nothing - an order-dependent
    failure. Removing the cached ``bind`` makes the proxy read the current config.
    """
    for name, module in list(sys.modules.items()):
        if not name.startswith("sentinelx"):
            continue
        for value in vars(module).values():
            if isinstance(value, BoundLoggerLazyProxy):
                value.__dict__.pop("bind", None)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for name in _SETTINGS_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)  # no stray .env or sentinelx.db from the repo
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
        cache_logger_on_first_use=False,
    )
    _uncache_module_loggers()
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
