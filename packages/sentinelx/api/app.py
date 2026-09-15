"""FastAPI application factory.

Routes are thin: they validate input, check roles, call a service and shape the
response.  No detection, scoring or response logic lives under ``sentinelx.api``.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinelx import __version__
from sentinelx.api.errors import install_error_handlers
from sentinelx.api.routes import auth, detections, firewall, replay, rules, stats, system
from sentinelx.api.security import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from sentinelx.api.websocket import router as websocket_router
from sentinelx.config.settings import Settings, get_settings
from sentinelx.services.platform import Platform
from sentinelx.telemetry.logging import configure_logging

__all__ = ["create_app"]

API_PREFIX = "/api/v1"

DESCRIPTION = """
SentinelX network intrusion detection and prevention API.

**Authentication.** Obtain tokens from `POST /api/v1/auth/login` and send
`Authorization: Bearer <access_token>`. Browser sessions use httpOnly cookies and must
echo the `sx_csrf` cookie in an `X-CSRF-Token` header on state-changing requests.

**Roles.** `viewer` reads; `analyst` triages, tests rules and runs replays; `admin`
changes rules, firewall state and settings.

**Safety.** Prevention is off by default. Responses honour `DRY_RUN`, and every
block passes the safety guard whether it came from a detector or a person.
"""


def create_app(settings: Settings | None = None, *, platform: Platform | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = platform is None
        instance = platform or Platform(settings)
        app.state.platform = instance
        if owned:
            configure_logging(settings.telemetry, sensor_name=settings.sensor_name)
            await instance.start()
        if instance.bootstrap_password:
            # Printed once to the console, never logged: logs are shipped and retained.
            print(
                "\n" + "=" * 72 + "\n"
                f"  SentinelX created the administrator account '{settings.api.bootstrap_admin_username}'.\n"
                f"  One-time password: {instance.bootstrap_password}\n"
                "  You will be asked to change it at first login. It will not be shown again.\n"
                + "=" * 72
                + "\n",
                file=sys.stderr,
                flush=True,
            )
        try:
            yield
        finally:
            if owned:
                await instance.stop()

    docs = settings.api.docs_enabled
    app = FastAPI(
        title="SentinelX API",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url="/api/redoc" if docs else None,
        openapi_url=f"{API_PREFIX}/openapi.json" if docs else None,
        root_path=settings.api.root_path,
    )
    if platform is not None:
        app.state.platform = platform

    # Middleware order: the last added runs first. CORS must wrap everything so
    # rejected and rate-limited responses still carry CORS headers the browser can read.
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o for o in settings.api.cors_origins if o != "*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-SentinelX-Client"],
        expose_headers=["Retry-After", "X-RateLimit-Remaining"],
        max_age=600,
    )
    install_error_handlers(app)

    for module in (auth, system, detections, firewall, rules, stats, replay):
        app.include_router(module.router, prefix=API_PREFIX)
    app.include_router(websocket_router, prefix=API_PREFIX)
    return app
