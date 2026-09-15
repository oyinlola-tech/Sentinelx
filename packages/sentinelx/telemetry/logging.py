"""Structured logging.

One configuration point for the whole platform.  Console rendering for humans in
development, JSON for log shippers in production.

Secret redaction is enforced by a processor rather than by convention.  Relying on
every call site to remember not to log a password is how passwords end up in logs;
here the pipeline scrubs known-sensitive keys no matter who logged them.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.typing import EventDict, Processor

from sentinelx.config.settings import TelemetrySettings

__all__ = ["SENSITIVE_KEYS", "configure_logging", "get_logger", "redact_secrets"]

#: Keys whose values are replaced with a placeholder before a record is emitted.
#: Matched case-insensitively against the whole key, against ``_``/``-``-separated parts,
#: and (for API keys) against the joined name, so ``X-Api-Key`` is caught too.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "jwt",
        "jwt_secret",
        "private_key",
        "credential",
        "credentials",
        "session",
        "cookie",
        "hashed_password",
        "password_hash",
        "passphrase",
        "ticket",
        "dsn",
        "database_url",
        "redis_url",
    }
)

_REDACTED = "[redacted]"

#: Catches secrets embedded in free-text messages and URLs, which key-based
#: redaction alone would miss (e.g. a DSN logged as part of an error string).
_INLINE_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(password|token|secret|api[-_]?key)\s*[=:]\s*\S+"),
    # user:pass@host in a URL, including an empty user (redis://:pass@host)
    re.compile(r"(?i)(?<=://)[^:/@\s]*:[^@/\s]+(?=@)"),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/\-]+=*", re.IGNORECASE),
)


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    if lowered in SENSITIVE_KEYS:
        return True
    parts = re.split(r"[_\-]", lowered)
    if "".join(parts).endswith("apikey"):
        return True
    return any(part in SENSITIVE_KEYS for part in parts)


def _scrub_text(text: str) -> str:
    for pattern in _INLINE_SECRET_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


def _scrub_value(value: Any, depth: int = 0) -> Any:
    """Recursively redact nested containers, with a depth guard."""
    if depth > 6:
        return value
    if isinstance(value, dict):
        return {
            key: (_REDACTED if _is_sensitive(str(key)) else _scrub_value(val, depth + 1))
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        scrubbed = [_scrub_value(item, depth + 1) for item in value]
        return type(value)(scrubbed) if isinstance(value, tuple) else scrubbed
    if isinstance(value, str):
        return _scrub_text(value)
    return value


def redact_secrets(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """structlog processor that removes secrets from every record.

    Installed unconditionally.  There is no way to opt out, because the cases
    where someone wants to opt out are exactly the cases where they should not.
    """
    result: EventDict = {}
    for key, value in event_dict.items():
        if _is_sensitive(str(key)):
            result[key] = _REDACTED
        else:
            result[key] = _scrub_value(value)
    return result


def _add_sensor(sensor_name: str) -> Processor:
    """Tag every record with the sensor it came from, for multi-sensor deployments."""

    def processor(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
        event_dict.setdefault("sensor", sensor_name)
        return event_dict

    return processor


def configure_logging(
    settings: TelemetrySettings | None = None,
    *,
    sensor_name: str = "sentinelx",
) -> None:
    """Configure structlog and the stdlib root logger.

    Safe to call more than once; the last call wins.  Third-party libraries that
    use the stdlib logger are routed through the same renderer so output stays
    consistent.
    """
    settings = settings or TelemetrySettings()
    level = getattr(logging, settings.log_level)

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        _add_sensor(sensor_name),
        # Tracebacks become plain text *before* redaction, so secrets inside exception
        # messages (a DSN in a driver error, say) are scrubbed like any other value.
        # Rich-style tracebacks are never used: they print every frame's local
        # variables, which would put settings objects and their secrets in the log.
        structlog.processors.format_exc_info,
        redact_secrets,
    ]

    renderer: Processor
    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(
            colors=sys.stderr.isatty(), exception_formatter=structlog.dev.plain_traceback
        )

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )

    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if settings.log_file is not None:
        path = Path(settings.log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.setLevel(level)

    # These are chatty at INFO and say nothing useful about security posture.
    # alembic.runtime.plugins announces every autogenerate plugin at start-up; the
    # migration lines themselves (alembic.runtime.migration) stay visible.
    for noisy in (
        "uvicorn.access",
        "sqlalchemy.engine",
        "asyncio",
        "scapy.runtime",
        "alembic.runtime.plugins",
    ):
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger. Use the module's ``__name__`` as ``name``."""
    return structlog.stdlib.get_logger(name)
