"""Real-time event stream: ``/api/v1/ws/events``.

Connecting:

1. ``POST /api/v1/auth/ws-ticket`` with normal authentication -> ``{"ticket": ...}``
2. ``GET /api/v1/ws/events?ticket=<ticket>[&types=detection.created,incident.opened]``

Tickets are single use and expire after 30 seconds, so a long-lived credential never
appears in a URL.  Tickets live in Redis when available, so a ticket issued by one
API worker is honoured by another.

Every message is ``{"id", "type", "timestamp", "payload"}`` where ``type`` is an
:class:`~sentinelx.events.bus.EventType` value.  The server sends
``{"type": "ping"}`` after 25 idle seconds. The account is re-checked at least that
often, whether the stream is idle or busy: a deactivated user is disconnected with
4401, a user whose role changed with 4403. Each user may hold 10 streams (4429 beyond that). A client that cannot keep up
has events dropped (the bus's bounded per-subscriber queue) and, if a single send
stalls for 10 seconds, is disconnected - a slow dashboard never slows detection.

Refusals are sent as close codes after the handshake: 4401 invalid or expired ticket,
1008 disallowed origin, unknown event type, or a ``types`` list containing only types
the role may not receive, 4429 too many streams.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
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


_MAX_CONNECTIONS_PER_USER = 10
_connections: dict[str, int] = {}


async def _reject(websocket: WebSocket, code: int, reason: str) -> None:
    """Accept, then close with an application code.

    Closing before the handshake completes reaches the client as a bare HTTP 403,
    which it cannot tell apart from any other refusal. After accepting, the close code
    says exactly what to do: 4401 fetch a new ticket, 1008 fix the request, 4429 back
    off. Nothing but the close frame is sent.
    """
    await websocket.accept()
    await websocket.close(code=code, reason=reason)


@router.websocket("/ws/events")
async def events(websocket: WebSocket) -> None:
    platform: Platform = websocket.app.state.platform
    if not _origin_allowed(websocket, platform):
        await _reject(websocket, status.WS_1008_POLICY_VIOLATION, "origin not allowed")
        return

    user_id: int | None = None
    if platform.settings.api.auth_enabled:
        try:
            principal = await platform.auth.redeem_ws_ticket(
                websocket.query_params.get("ticket", "")
            )
        except AuthError:
            await _reject(websocket, 4401, "invalid or expired ticket")
            return
        role, username, user_id = principal.role, principal.username, principal.user_id
    else:
        role, username = UserRole.ADMIN, "anonymous"

    requested: set[EventType] | None = None
    raw_types = websocket.query_params.get("types")
    if raw_types:
        try:
            requested = {EventType(t.strip()) for t in raw_types.split(",")[:32] if t.strip()}
        except ValueError:
            await _reject(websocket, status.WS_1008_POLICY_VIOLATION, "unknown event type")
            return
    allowed = (
        set(EventType) if role.can_act_as(UserRole.ANALYST) else set(EventType) - _ANALYST_ONLY
    )
    types = (requested & allowed) if requested else allowed
    if not types:
        # Every requested type is one this role may not see. An empty filter must not
        # reach the bus, which reads "no filter" as "every event".
        await _reject(websocket, status.WS_1008_POLICY_VIOLATION, "no permitted event types")
        return

    if _connections.get(username, 0) >= _MAX_CONNECTIONS_PER_USER:
        await _reject(websocket, 4429, "too many open event streams for this user")
        return
    _connections[username] = _connections.get(username, 0) + 1

    await websocket.accept()
    metrics.websocket_clients.inc()
    log.info("websocket_connected", user=username, types=len(types))
    receiver: asyncio.Task[None] | None = None
    close_code, close_reason = 1000, ""
    try:
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
        async with platform.bus.subscribe(
            f"ws:{username}", types, queue_size=platform.settings.api.websocket_max_queue
        ) as stream:
            iterator = stream.__aiter__()
            # One long-lived pending read. Cancelling a read on every ping interval
            # (wait_for) would close the async generator and silently end the stream.
            next_event: asyncio.Future[Any] = asyncio.ensure_future(anext(iterator))
            last_checked = time.monotonic()
            try:
                while not receiver.done():
                    done, _ = await asyncio.wait(
                        {next_event, receiver},
                        timeout=_PING_INTERVAL,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if receiver in done:
                        break
                    # Confirm the account may still see this stream at least every ping
                    # interval, whether the stream is idle or busy with events.
                    if user_id is not None and time.monotonic() - last_checked >= _PING_INTERVAL:
                        last_checked = time.monotonic()
                        verdict = await _still_permitted(platform, user_id, role)
                        if verdict is not None:
                            close_code, close_reason = verdict
                            break
                    if next_event in done:
                        event = next_event.result()
                        next_event = asyncio.ensure_future(anext(iterator))
                        if event.type not in types:
                            continue  # defence in depth: never forward an unsubscribed type
                        message: dict[str, Any] = event.to_dict()
                    else:
                        message = {"type": "ping"}
                    await asyncio.wait_for(websocket.send_json(message), timeout=_SEND_TIMEOUT)
            finally:
                next_event.cancel()
                with contextlib.suppress(asyncio.CancelledError, StopAsyncIteration, Exception):
                    await next_event
    except (WebSocketDisconnect, TimeoutError, RuntimeError, OSError):
        # OSError covers the server's ClientDisconnected: a browser closing the tab is
        # routine, not an application error.
        pass
    finally:
        if receiver is not None:
            receiver.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await receiver
        _connections[username] = max(_connections.get(username, 1) - 1, 0)
        if not _connections[username]:
            _connections.pop(username, None)
        metrics.websocket_clients.dec()
        # The client may already be gone; closing an absent socket is not an error.
        with contextlib.suppress(RuntimeError, OSError, WebSocketDisconnect):
            await websocket.close(code=close_code, reason=close_reason)
        log.info("websocket_disconnected", user=username, code=close_code)


async def _still_permitted(
    platform: Platform, user_id: int, role: UserRole
) -> tuple[int, str] | None:
    """``None`` while the user may keep this stream, else the close code and reason."""
    from sentinelx.storage.repositories import UserRepository

    async with platform.database.session() as session:
        user = await UserRepository(session).get(user_id)
    if user is None or not user.is_active:
        return 4401, "account disabled"
    if user.role != role.value:
        return 4403, "role changed; reconnect"
    return None


async def _drain_client(websocket: WebSocket) -> None:
    """Consume client frames so disconnects are noticed. Client messages carry no commands."""
    while True:
        message = await websocket.receive()
        if message.get("type") == "websocket.disconnect":
            return
