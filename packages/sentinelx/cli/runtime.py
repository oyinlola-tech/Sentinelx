"""Shared CLI plumbing: settings, event loop, platform lifecycle, operator identity."""

from __future__ import annotations

import asyncio
import getpass
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import typer

from sentinelx.common.errors import SentinelXError
from sentinelx.config.settings import Settings, reload_settings
from sentinelx.services.platform import Platform
from sentinelx.telemetry.logging import configure_logging

__all__ = ["actor", "load_settings", "platform_context", "run"]


def load_settings(*, quiet: bool = True) -> Settings:
    """Load settings, turning validation errors into a clean exit (code 2)."""
    from pydantic import ValidationError

    from sentinelx.cli.output import err

    try:
        settings = reload_settings()
    except ValidationError as exc:
        err.print("[bold red]configuration error[/]")
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"]) or "settings"
            err.print(f"  {location}: {error['msg']}")
        raise typer.Exit(2) from None
    if quiet and settings.telemetry.log_level in ("INFO", "DEBUG"):
        settings.telemetry.log_level = (
            "WARNING"  # keep CLI output clean; logs go to stderr regardless
        )
    configure_logging(settings.telemetry, sensor_name=settings.sensor_name)
    return settings


def actor() -> str:
    """The operator, recorded in audit events for CLI actions."""
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli:unknown"


def run[T](coroutine_factory: Callable[[], Awaitable[T]]) -> T:
    """Run an async command, mapping errors onto exit codes.

    Exit 1 for platform errors (message shown, no traceback), 130 on Ctrl-C.
    """
    from sentinelx.cli.output import err

    async def runner() -> T:
        return await coroutine_factory()

    try:
        return asyncio.run(runner())
    except KeyboardInterrupt:
        err.print("[dim]interrupted[/]")
        raise typer.Exit(130) from None
    except SentinelXError as exc:
        err.print(f"[bold red]error:[/] {exc}")
        problems = getattr(exc, "problems", None)
        for problem in problems or []:
            err.print(f"  - {problem}")
        raise typer.Exit(1) from None


@asynccontextmanager
async def platform_context(settings: Settings, **options: Any) -> AsyncIterator[Platform]:
    """A started platform without background loops, stopped on exit."""
    platform = Platform(settings)
    options.setdefault("background", False)
    options.setdefault("bootstrap", False)
    await platform.start(**options)
    try:
        yield platform
    finally:
        await platform.stop()
