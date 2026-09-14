"""Prometheus-compatible metrics.

All instrumentation is declared here so that metric names, labels and buckets stay
consistent, and so the rest of the codebase imports a value rather than
constructing a collector (which would raise on duplicate registration under test).

Only quantities the platform genuinely measures are exposed.  There are no
hard-coded throughput figures anywhere: every number in the dashboard and in
``docs/benchmarking.md`` comes from these counters at runtime.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.core import REGISTRY as _DEFAULT_REGISTRY

__all__ = [
    "REGISTRY",
    "ProcessSampler",
    "measure_latency",
    "metrics",
    "render_metrics",
]

#: A dedicated registry keeps SentinelX metrics separate from anything a host
#: application may already have registered, and makes tests trivially isolatable.
REGISTRY: CollectorRegistry = CollectorRegistry(auto_describe=True)

_LATENCY_BUCKETS = (
    0.00005,
    0.0001,
    0.00025,
    0.0005,
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
)


class _Metrics:
    """Namespace of every collector the platform publishes."""

    def __init__(self, registry: CollectorRegistry) -> None:
        ns = "sentinelx"

        # ---------------------------------------------------------- capture
        self.packets_captured = Counter(
            f"{ns}_packets_captured_total",
            "Packets handed to the pipeline by the capture layer.",
            ["source", "interface"],
            registry=registry,
        )
        self.packets_dropped = Counter(
            f"{ns}_packets_dropped_total",
            "Packets discarded before processing, by cause.",
            ["reason"],
            registry=registry,
        )
        self.packets_processed = Counter(
            f"{ns}_packets_processed_total",
            "Packets that completed the full pipeline.",
            ["protocol"],
            registry=registry,
        )
        self.capture_bytes = Counter(
            f"{ns}_capture_bytes_total",
            "Total bytes observed on the wire.",
            ["interface"],
            registry=registry,
        )
        self.parse_errors = Counter(
            f"{ns}_parse_errors_total",
            "Frames that could not be decoded.",
            ["layer"],
            registry=registry,
        )

        # -------------------------------------------------------- detection
        self.detections = Counter(
            f"{ns}_detections_total",
            "Detections emitted.",
            ["detector", "severity", "category"],
            registry=registry,
        )
        self.detections_suppressed = Counter(
            f"{ns}_detections_suppressed_total",
            "Detections withheld, by reason (cooldown, allowlist).",
            ["reason"],
            registry=registry,
        )
        self.detector_errors = Counter(
            f"{ns}_detector_errors_total",
            "Exceptions raised inside a detector.",
            ["detector"],
            registry=registry,
        )
        self.detection_latency = Histogram(
            f"{ns}_detection_latency_seconds",
            "Wall time for one packet to traverse the detection stage.",
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )
        self.pipeline_latency = Histogram(
            f"{ns}_pipeline_latency_seconds",
            "Wall time for one packet to traverse the entire pipeline.",
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )
        self.stage_latency = Histogram(
            f"{ns}_stage_latency_seconds",
            "Per-stage processing time.",
            ["stage"],
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )

        # ------------------------------------------------------- incidents
        self.incidents_opened = Counter(
            f"{ns}_incidents_opened_total",
            "Correlated incidents created.",
            ["severity"],
            registry=registry,
        )
        self.open_incidents = Gauge(
            f"{ns}_open_incidents",
            "Incidents currently open.",
            registry=registry,
        )

        # -------------------------------------------------------- response
        self.responses = Counter(
            f"{ns}_responses_total",
            "Response decisions, by action and outcome.",
            ["action", "outcome"],
            registry=registry,
        )
        self.firewall_actions = Counter(
            f"{ns}_firewall_actions_total",
            "Firewall operations attempted.",
            ["backend", "operation", "result"],
            registry=registry,
        )
        self.blocked_addresses = Gauge(
            f"{ns}_blocked_addresses",
            "Addresses currently blocked.",
            registry=registry,
        )
        self.safety_refusals = Counter(
            f"{ns}_safety_refusals_total",
            "Response actions refused by a safety guard.",
            ["reason"],
            registry=registry,
        )

        # ---------------------------------------------------------- runtime
        self.active_flows = Gauge(
            f"{ns}_active_flows",
            "Flows currently tracked by the feature extractor.",
            registry=registry,
        )
        self.tracked_sources = Gauge(
            f"{ns}_tracked_sources",
            "Distinct source addresses in the detection windows.",
            registry=registry,
        )
        self.queue_depth = Gauge(
            f"{ns}_queue_depth",
            "Packets waiting in the capture hand-off queue.",
            registry=registry,
        )
        self.websocket_clients = Gauge(
            f"{ns}_websocket_clients",
            "Connected dashboard WebSocket clients.",
            registry=registry,
        )
        self.events_published = Counter(
            f"{ns}_events_published_total",
            "Events pushed onto the event bus.",
            ["event_type"],
            registry=registry,
        )
        self.storage_errors = Counter(
            f"{ns}_storage_errors_total",
            "Database write failures.",
            ["operation"],
            registry=registry,
        )
        self.api_requests = Counter(
            f"{ns}_api_requests_total",
            "HTTP requests served.",
            ["method", "path", "status"],
            registry=registry,
        )
        self.api_latency = Histogram(
            f"{ns}_api_request_latency_seconds",
            "HTTP request duration.",
            ["method", "path"],
            registry=registry,
        )

        # ---------------------------------------------------------- process
        self.process_cpu_percent = Gauge(
            f"{ns}_process_cpu_percent",
            "CPU utilisation of the sensor process.",
            registry=registry,
        )
        self.process_memory_bytes = Gauge(
            f"{ns}_process_memory_bytes",
            "Resident set size of the sensor process.",
            registry=registry,
        )
        self.uptime_seconds = Gauge(
            f"{ns}_uptime_seconds",
            "Seconds since the sensor started.",
            registry=registry,
        )


metrics = _Metrics(REGISTRY)


@contextmanager
def measure_latency(histogram: Histogram, **labels: str) -> Iterator[None]:
    """Time a block and record it.

    Uses :func:`time.perf_counter` rather than the histogram's own ``time()``
    helper so the same idiom works for labelled and unlabelled histograms.
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        target = histogram.labels(**labels) if labels else histogram
        target.observe(elapsed)


class ProcessSampler:
    """Samples CPU and memory for the current process.

    Falls back to ``/proc`` when ``psutil`` is unavailable so that resource
    figures in benchmark reports are never silently missing on Linux.
    """

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._psutil: Any | None = None
        try:
            import psutil

            self._psutil = psutil.Process(os.getpid())
            self._psutil.cpu_percent(None)  # prime the interval
        except Exception:  # pragma: no cover - optional dependency
            self._psutil = None

    def sample(self) -> dict[str, float]:
        """Current CPU percent, RSS bytes and uptime. Also updates the gauges."""
        cpu = 0.0
        rss = 0.0
        if self._psutil is not None:
            try:
                cpu = float(self._psutil.cpu_percent(None))
                rss = float(self._psutil.memory_info().rss)
            except Exception:  # pragma: no cover - process may have changed state
                cpu, rss = 0.0, 0.0
        else:
            rss = self._read_proc_rss()

        uptime = time.monotonic() - self._started
        metrics.process_cpu_percent.set(cpu)
        metrics.process_memory_bytes.set(rss)
        metrics.uptime_seconds.set(uptime)
        return {"cpu_percent": cpu, "memory_bytes": rss, "uptime_seconds": uptime}

    @staticmethod
    def _read_proc_rss() -> float:
        try:
            fields = Path(f"/proc/{os.getpid()}/statm").read_text(encoding="ascii").split()
            return float(fields[1]) * os.sysconf("SC_PAGE_SIZE")
        except (OSError, IndexError, ValueError):  # pragma: no cover
            return 0.0


def render_metrics(include_process: bool = True) -> bytes:
    """Render the registry in Prometheus text format.

    Args:
        include_process: also emit the default Python/process collectors, which
            carry GC and file-descriptor stats useful when diagnosing a sensor.
    """
    payload = generate_latest(REGISTRY)
    if include_process:
        payload += generate_latest(_DEFAULT_REGISTRY)
    return payload
