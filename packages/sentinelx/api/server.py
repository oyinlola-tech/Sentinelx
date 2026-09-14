"""ASGI entry used by ``sentinelx start``.

Separate from :func:`create_app` so ``--capture`` can start live capture from the
application lifespan, inside the server's own event loop.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinelx.api.app import create_app
from sentinelx.telemetry.logging import get_logger

__all__ = ["app"]

log = get_logger(__name__)

app = create_app()
_inner_lifespan = app.router.lifespan_context


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    async with _inner_lifespan(application):
        interface = os.environ.get("SENTINELX_START_CAPTURE")
        if interface:
            platform = application.state.platform
            try:
                await platform.sensor.start(interface)
            except Exception as exc:
                # The API stays up: replay, investigation and configuration still work.
                log.error("startup_capture_failed", interface=interface, error=str(exc))
        yield


app.router.lifespan_context = _lifespan
