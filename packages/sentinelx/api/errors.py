"""Exception handlers.

Deliberate platform errors become precise 4xx responses.  Anything unexpected
becomes a generic 500 with a correlation id; the detail goes to the log, never to
the client, because stack traces and exception text leak internals.
"""

from __future__ import annotations

import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sentinelx.common.errors import (
    CaptureError,
    ConfigurationError,
    FirewallError,
    InterfaceNotFoundError,
    PcapError,
    PermissionDeniedError,
    RuleValidationError,
    SafetyViolationError,
    StorageError,
    UploadQuotaExhaustedError,
    UploadTooLargeError,
)
from sentinelx.services.auth import AuthError
from sentinelx.telemetry.logging import get_logger

__all__ = ["install_error_handlers"]

log = get_logger(__name__)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def _auth(request: Request, exc: AuthError) -> JSONResponse:
        headers = {"Retry-After": str(max(1, int(exc.retry_after)))} if exc.retry_after else None
        return JSONResponse({"detail": str(exc)}, status_code=exc.status, headers=headers)

    @app.exception_handler(RuleValidationError)
    async def _rule(request: Request, exc: RuleValidationError) -> JSONResponse:
        return JSONResponse(
            {"detail": "rule is invalid", "problems": exc.problems}, status_code=422
        )

    @app.exception_handler(SafetyViolationError)
    async def _safety(request: Request, exc: SafetyViolationError) -> JSONResponse:
        return JSONResponse(
            {"detail": f"refused by safety guard: {exc.reason}", "target": exc.target},
            status_code=422,
        )

    @app.exception_handler(ConfigurationError)
    async def _config(request: Request, exc: ConfigurationError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(InterfaceNotFoundError)
    async def _iface(request: Request, exc: InterfaceNotFoundError) -> JSONResponse:
        return JSONResponse({"detail": str(exc), "available": exc.available}, status_code=404)

    @app.exception_handler(PermissionDeniedError)
    async def _perm(request: Request, exc: PermissionDeniedError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(UploadTooLargeError)
    async def _too_large(request: Request, exc: UploadTooLargeError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=413)

    @app.exception_handler(UploadQuotaExhaustedError)
    async def _quota(request: Request, exc: UploadQuotaExhaustedError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=507)

    @app.exception_handler(PcapError)
    async def _pcap(request: Request, exc: PcapError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(CaptureError)
    async def _capture(request: Request, exc: CaptureError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(FirewallError)
    async def _firewall(request: Request, exc: FirewallError) -> JSONResponse:
        log.error("firewall_error", error=str(exc), command=exc.command)
        return JSONResponse({"detail": f"firewall operation failed: {exc}"}, status_code=502)

    @app.exception_handler(StorageError)
    async def _storage(request: Request, exc: StorageError) -> JSONResponse:
        incident = secrets.token_hex(6)
        log.error("storage_error", error=str(exc), error_id=incident, path=request.url.path)
        return JSONResponse(
            {"detail": "storage unavailable", "error_id": incident}, status_code=503
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        incident = secrets.token_hex(6)
        log.exception(
            "unhandled_error", error_id=incident, path=request.url.path, method=request.method
        )
        return JSONResponse({"detail": "internal error", "error_id": incident}, status_code=500)
