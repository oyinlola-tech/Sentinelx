"""Request authentication, authorisation, CSRF, rate limiting and headers.

Authentication accepts either:

* ``Authorization: Bearer <access token>`` - CLI, scripts, integrations; or
* the ``sx_access`` httpOnly cookie - the dashboard.

Cookie authentication is ambient (the browser attaches it automatically), which is
what makes CSRF possible, so every state-changing request authenticated by cookie
must also carry ``X-CSRF-Token`` matching the ``sx_csrf`` cookie (double-submit).
Bearer requests are exempt: an attacker's page cannot make a browser add that header.
Cookies are additionally ``SameSite=Strict``.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinelx.common.enums import UserRole
from sentinelx.common.netutils import in_any_network, parse_ip, parse_networks
from sentinelx.services.auth import AuthError, Principal, TokenPair
from sentinelx.services.platform import Platform
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = [
    "ACCESS_COOKIE",
    "CSRF_COOKIE",
    "REFRESH_COOKIE",
    "Admin",
    "Analyst",
    "BodySizeLimitMiddleware",
    "PlatformDep",
    "RateLimitMiddleware",
    "SecurityHeadersMiddleware",
    "Viewer",
    "app_path",
    "clear_auth_cookies",
    "client_ip",
    "get_platform",
    "require_role",
    "set_auth_cookies",
]

log = get_logger(__name__)

ACCESS_COOKIE = "sx_access"
REFRESH_COOKIE = "sx_refresh"
CSRF_COOKIE = "sx_csrf"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def app_path(request: Request) -> str:
    """The request path without the ASGI ``root_path`` prefix.

    With ``api.root_path`` set, a request may arrive as ``/prefix/api/v1/...`` (the
    prefix kept, as ASGI servers pass it) or without it (a proxy that strips it). Path
    checks must see ``/api/v1/...`` either way, or the prefixed form escapes them.
    """
    path = request.url.path
    root = request.scope.get("root_path") or ""
    if root and (path == root or path.startswith(root.rstrip("/") + "/")):
        path = path[len(root.rstrip("/")) :] or "/"
    return path


def get_platform(request: Request) -> Platform:
    platform: Platform = request.app.state.platform
    return platform


def client_ip(request: Request) -> str:
    """The caller's address, believing X-Forwarded-For only from trusted proxies.

    The header is read right to left: each trusted proxy appends the address it
    received the request from, so the first entry that is *not* a trusted proxy is the
    real client. The leftmost entry is whatever the client chose to send and is never
    believed on its own.
    """
    peer = request.client.host if request.client else "0.0.0.0"
    platform: Platform = request.app.state.platform
    proxies = platform.settings.api.trusted_proxies
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded or not proxies:
        return peer
    try:
        trusted = parse_networks(proxies)
        if not in_any_network(parse_ip(peer), trusted):
            return peer
        hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
        for hop in reversed(hops):
            address = parse_ip(hop)
            if not in_any_network(address, trusted):
                return str(address)
    except ValueError:
        return peer
    # Every hop was a trusted proxy: the innermost is as close to the client as we know.
    return hops[0] if hops else peer


def set_auth_cookies(response: Response, pair: TokenPair, *, secure: bool) -> str:
    """Set session cookies. Returns the CSRF token the client must echo back."""
    csrf = secrets.token_urlsafe(32)
    now = datetime.now(pair.access_expires_at.tzinfo)
    response.set_cookie(
        ACCESS_COOKIE,
        pair.access_token,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api",
        max_age=int((pair.access_expires_at - now).total_seconds()),
    )
    response.set_cookie(
        REFRESH_COOKIE,
        pair.refresh_token,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api/v1/auth",
        max_age=int((pair.refresh_expires_at - now).total_seconds()),
    )
    # Deliberately readable by JavaScript: that is how double-submit works.
    response.set_cookie(
        CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="strict", path="/"
    )
    return csrf


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/api")
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")


async def current_principal(
    request: Request, platform: Annotated[Platform, Depends(get_platform)]
) -> Principal:
    if not platform.settings.api.auth_enabled:
        # Development only; Settings refuses auth_enabled=False in production.
        return Principal(user_id=0, username="anonymous", role=UserRole.ADMIN)

    header = request.headers.get("authorization", "")
    token: str | None = None
    via_cookie = False
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
    elif request.cookies.get(ACCESS_COOKIE):
        token = request.cookies[ACCESS_COOKIE]
        via_cookie = True
    if not token:
        raise HTTPException(
            status_code=401,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if via_cookie and request.method not in _SAFE_METHODS:
        expected = request.cookies.get(CSRF_COOKIE, "")
        supplied = request.headers.get("x-csrf-token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")

    try:
        principal = await platform.auth.authenticate(token)
    except AuthError as exc:
        raise HTTPException(
            status_code=401, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}
        ) from exc

    # An account with a generated or reset password may only change it.
    allowed_paths = ("/api/v1/auth/change-password", "/api/v1/auth/me", "/api/v1/auth/logout")
    if principal.must_change_password and app_path(request) not in allowed_paths:
        raise HTTPException(status_code=403, detail="password change required before continuing")
    request.state.principal = principal
    platform.note_operator_address(client_ip(request))
    return principal


def require_role(role: UserRole) -> Callable[..., Awaitable[Principal]]:
    async def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if not principal.can(role):
            raise HTTPException(status_code=403, detail=f"requires the {role.value} role")
        return principal

    dependency.__name__ = f"require_{role.value}"
    return dependency


Viewer = Annotated[Principal, Depends(require_role(UserRole.VIEWER))]
Analyst = Annotated[Principal, Depends(require_role(UserRole.ANALYST))]
Admin = Annotated[Principal, Depends(require_role(UserRole.ADMIN))]
PlatformDep = Annotated[Platform, Depends(get_platform)]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Conservative headers for an API that serves no HTML of its own (except docs)."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        path = app_path(request)
        headers = response.headers
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "no-referrer"
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if path.startswith("/api/") and not path.startswith(("/api/docs", "/api/redoc")):
            headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
            headers.setdefault("Cache-Control", "no-store")
        platform: Platform = request.app.state.platform
        if platform.settings.api.cookie_secure:
            headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        route = request.scope.get("route")
        template = getattr(route, "path", "unmatched")
        # FastAPI >= 0.14x matches the router's own route, whose path lacks the
        # include prefix; label with the full template on every version so metric
        # series (and dashboards built on them) do not change with the dependency.
        if template != "unmatched" and not template.startswith("/api/"):
            template = "/api/v1" + template
        metrics.api_requests.labels(
            method=request.method, path=template, status=str(response.status_code)
        ).inc()
        metrics.api_latency.labels(method=request.method, path=template).observe(
            time.perf_counter() - started
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-client sliding-window limit on API requests, shared across workers via Redis."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = app_path(request)
        if not path.startswith("/api/") or path == "/api/v1/system/health":
            return await call_next(request)
        platform: Platform = request.app.state.platform
        settings = platform.settings.api
        allowed, remaining, retry_after = await platform.state.hit(
            "api",
            client_ip(request),
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )
        if not allowed:
            return JSONResponse(
                {"detail": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(max(1, int(retry_after)))},
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


#: Largest request body accepted by any endpoint except the streamed capture upload.
#: The biggest legitimate JSON body (a 20 KB rule, a 1,000-entry allowlist) is far below.
MAX_JSON_BODY_BYTES = 1_048_576


class BodySizeLimitMiddleware:
    """Refuse request bodies over ``max_bytes`` before the application buffers them.

    FastAPI reads a JSON body into memory in full, and nginx normally caps it; a bare
    uvicorn deployment would otherwise accept an unbounded body on any route,
    including unauthenticated sign-in. A declared ``Content-Length`` over the limit is
    refused immediately. A chunked body is counted as it is read: past the limit the
    application sees the body end, and whatever it answers is replaced by a 413. The
    capture upload streams to disk under its own limits and is exempt.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int = MAX_JSON_BODY_BYTES,
        exempt: tuple[str, ...] = ("/api/v1/replay/upload",),
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.exempt = exempt

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        root = scope.get("root_path") or ""
        if root and path.startswith(root.rstrip("/") + "/"):
            path = path[len(root.rstrip("/")) :]
        if path in self.exempt:
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await self._refuse(send)
            return
        received = 0
        exceeded = False
        refused = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            if exceeded:
                return {"type": "http.request", "body": b"", "more_body": False}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal refused
            if not exceeded:
                await send(message)
            elif not refused and message["type"] == "http.response.start":
                refused = True
                await self._refuse(send)

        await self.app(scope, counting_receive, guarded_send)

    async def _refuse(self, send: Send) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
