"""Real-time event stream: ``/api/v1/ws/events``.

Connecting:

1. ``POST /api/v1/auth/ws-ticket`` with normal authentication -> ``{"ticket": ...}``
2. ``GET /api/v1/ws/events?ticket=<ticket>[&types=detection.created,incident.opened]``

Tickets are single use and expire after 30 seconds, so a long-lived credential never
appears in a URL.  Tickets live in Redis when available, so a ticket issued by one
API worker is honoured by another.

Every message is ``{"id", "type", "timestamp", "payload"}`` where ``type`` is an
:class:`~sentinelx.events.bus.EventType` value.  The server sends
``{"type": "ping"}`` every 25 seconds.  A client that cannot keep up has events
dropped (the bus's bounded per-subscriber queue) and, if a single send stalls for
10 seconds, is disconnected - a slow dashboard never slows detection.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from sentinelx.common.enums import UserRole
from sentinelx.events.bus import EventType
from sentinelx.services.auth import AuthError
from sentinelx.services.platform import Platform
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["router"]

log = get_logger(__name__)
router = APIRouter()

_ANALYST_ONLY = {EventType.AUDIT_EVENT, EventType.CONFIG_CHANGED}
_SEND_TIMEOUT = 10.0
_PING_INTERVAL = 25.0


def _origin_allowed(websocket: WebSocket, platform: Platform) -> bool:
    """Browsers always send Origin on WebSocket upgrades; enforce it like CORS.

    Without this check any website a logged-in analyst visits could open a socket
    (cross-site WebSocket hijacking). Non-browser clients typically omit Origin.
    """
    origin = websocket.headers.get("origin")
    if origin is None:
        return True
    allowed = set(platform.settings.api.cors_origins)
    host = websocket.headers.get("host", "")
    return origin in allowed or origin in {f"http://{host}", f"https://{host}"}


@router.websocket("/ws/events")
async def events(websocket: WebSocket) -> None:
    platform: Platform = websocket.app.state.platform
    if not _origin_allowed(websocket, platform):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="origin not allowed")
        return

    if platform.settings.api.auth_enabled:
        try:
            principal = await platform.auth.redeem_ws_ticket(
                websocket.query_params.get("ticket", "")
            )
        except AuthError:
            # Accept, then close with an application code: a pre-accept rejection
            # surfaces as a bare HTTP 403, which a client cannot distinguish from an
            # origin violation. 4401 tells the dashboard to fetch a fresh ticket.
            await websocket.accept()
            await websocket.close(code=4401, reason="invalid or expired ticket")
            return
        role = principal.role
        username = principal.username
    else:
        role, username = UserRole.ADMIN, "anonymous"

    requested: set[EventType] | None = None
    raw_types = websocket.query_params.get("types")
    if raw_types:
        try:
            requested = {EventType(t.strip()) for t in raw_types.split(",")[:32] if t.strip()}
        except ValueError:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="unknown event type")
            return
    allowed = (
        set(EventType) if role.can_act_as(UserRole.ANALYST) else set(EventType) - _ANALYST_ONLY
    )
    types = (requested & allowed) if requested else allowed

    await websocket.accept()
    metrics.websocket_clients.inc()
    log.info("websocket_connected", user=username, types=len(types))
    await websocket.send_json(
        {
            "type": "hello",
            "payload": {
                "user": username,
                "role": role.value,
                "subscribed": sorted(t.value for t in types),
                "safety": platform.settings.safety_banner(),
            },
        }
    )
    receiver = asyncio.create_task(_drain_client(websocket))
    try:
        async with platform.bus.subscribe(
            f"ws:{username}", types, queue_size=platform.settings.api.websocket_max_queue
        ) as stream:
            iterator = stream.__aiter__()
            while not receiver.done():
                try:
                    event = await asyncio.wait_for(anext(iterator), timeout=_PING_INTERVAL)
                    message: dict[str, Any] = event.to_dict()
                except TimeoutError:
                    message = {"type": "ping"}
                await asyncio.wait_for(websocket.send_json(message), timeout=_SEND_TIMEOUT)
    except (WebSocketDisconnect, TimeoutError, RuntimeError):
        pass
    finally:
        receiver.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await receiver
        metrics.websocket_clients.dec()
        with contextlib.suppress(RuntimeError):
            await websocket.close()
        log.info("websocket_disconnected", user=username)


async def _drain_client(websocket: WebSocket) -> None:
    """Consume client frames so disconnects are noticed. Client messages carry no commands."""
    while True:
        message = await websocket.receive()
        if message.get("type") == "websocket.disconnect":
            return
