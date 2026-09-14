"""Chooses a capture source from configuration.

Keeps the "which backend" decision in one place so the CLI, the API and the
benchmark harness all resolve sources identically.
"""

from __future__ import annotations

from pathlib import Path

from sentinelx.capture.base import PacketCapture
from sentinelx.capture.live import LiveCapture
from sentinelx.capture.pcap import PcapFileCapture
from sentinelx.config.settings import CaptureSettings

__all__ = ["create_capture"]


def create_capture(
    settings: CaptureSettings,
    *,
    pcap_path: Path | str | None = None,
    speed: float = 0.0,
    limit: int | None = None,
) -> PacketCapture:
    """Build the capture source described by ``settings``.

    Args:
        settings: capture configuration.
        pcap_path: when given, replay this file instead of capturing live.
        speed: replay pacing; see :class:`PcapFileCapture`.
        limit: stop after this many packets.

    Returns:
        An unopened capture source. The caller owns its lifecycle.
    """
    if pcap_path is not None:
        return PcapFileCapture(pcap_path, speed=speed, limit=limit)
    return LiveCapture(
        interface=settings.interface,
        bpf_filter=settings.bpf_filter,
        snapshot_length=settings.snapshot_length,
        promiscuous=settings.promiscuous,
        buffer_size_mb=settings.buffer_size_mb,
    )
