"""Live capture control.

Runs the shared :class:`~sentinelx.pipeline.Pipeline` over a live interface as a
background task, reports its state, and publishes ``sensor.status`` events.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime
from typing import Any

from sentinelx.capture.live import LiveCapture
from sentinelx.common.errors import CaptureError
from sentinelx.config.settings import Settings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.pipeline import Pipeline, RunReport
from sentinelx.system.interfaces import list_interfaces
from sentinelx.telemetry.logging import get_logger

__all__ = ["SensorService"]

log = get_logger(__name__)


class SensorService:
    def __init__(self, settings: Settings, pipeline: Pipeline, bus: EventBus) -> None:
        self.settings = settings
        self.pipeline = pipeline
        self.bus = bus
        self._task: asyncio.Task[RunReport] | None = None
        self._capture: LiveCapture | None = None
        self.state = "stopped"
        self.error: str | None = None
        self.started_at: datetime | None = None
        self.interface: str | None = None
        self.bpf_filter: str | None = None
        self._capabilities: tuple[float, dict[str, Any]] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(
        self, interface: str | None = None, bpf_filter: str | None = None
    ) -> dict[str, Any]:
        """Start live capture.

        Raises:
            CaptureError: when capture is already running, or the interface cannot
                be opened (missing privilege, unknown interface). Opening happens
                before this returns, so the caller sees the real error.
        """
        if self.running:
            raise CaptureError(f"capture is already running on {self.interface}")
        interface = interface or self.settings.capture.interface
        bpf = self.settings.capture.bpf_filter if bpf_filter is None else bpf_filter
        if bpf and set(";|`$\n\r\\") & set(bpf):
            raise CaptureError("BPF filter contains forbidden characters")

        capture = LiveCapture(
            interface=interface,
            backend=self.settings.capture.backend,
            bpf_filter=bpf,
            snapshot_length=self.settings.capture.snapshot_length,
            promiscuous=self.settings.capture.promiscuous,
            buffer_size_mb=self.settings.capture.buffer_size_mb,
            queue_size=self.settings.capture.queue_size,
        )
        try:
            await capture.open()
        except CaptureError as exc:
            self.state, self.error = "error", str(exc)
            await self._publish()
            raise
        self._capture, self.interface, self.bpf_filter = capture, interface, bpf or None
        self.state, self.error, self.started_at = "running", None, datetime.now(UTC)
        self._task = asyncio.create_task(self._run(capture), name=f"capture-{interface}")
        await self._publish()
        return self.status()

    async def _run(self, capture: LiveCapture) -> RunReport:
        try:
            report = await self.pipeline.run(capture, record_latency=False, progress_interval=1.0)
        except CaptureError as exc:
            self.state, self.error = "error", str(exc)
            log.error("capture_failed", error=str(exc))
            raise
        except asyncio.CancelledError:
            self.state = "stopped"
            raise
        else:
            self.state = "stopped"
            return report
        finally:
            await self._publish()

    async def stop(self) -> dict[str, Any]:
        task, capture = self._task, self._capture
        if capture is not None:
            capture.stop()
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=3.0)
            except (TimeoutError, CaptureError):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, CaptureError):
                    await task
        self._task, self._capture = None, None
        self.state = "stopped"
        await self._publish()
        return self.status()

    def status(self) -> dict[str, Any]:
        capture = self._capture
        return {
            "sensor": self.settings.sensor_name,
            "state": self.state,
            "running": self.running,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "started_at": self.started_at.isoformat() if self.started_at and self.running else None,
            "error": self.error,
            "backend": capture.backend if capture else None,
            "capture": capture.stats.as_dict() if capture else None,
            "capture_capabilities": self.capture_capabilities(),
            "safety": self.settings.safety_banner(),
        }

    def capture_capabilities(self) -> dict[str, Any]:
        """Whether live capture can run here, cached briefly.

        The health loop reads status every few seconds; probing privileges opens a raw
        socket, which is cheap once but not worth repeating that often.
        """
        now = time.monotonic()
        cached = self._capabilities
        if cached is None or now - cached[0] > 30:
            report = LiveCapture.capabilities(self.settings.capture.backend).as_dict()
            cached = self._capabilities = (now, report)
        return cached[1]

    @staticmethod
    def interfaces() -> list[dict[str, Any]]:
        return list_interfaces()

    async def _publish(self) -> None:
        await self.bus.publish(EventType.SENSOR_STATUS, self.status())
