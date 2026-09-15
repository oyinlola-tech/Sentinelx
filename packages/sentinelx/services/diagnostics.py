"""``sentinelx doctor``: a complete, honest environment diagnostic.

Every check reports one of:

``PASS``  the feature works here, as far as can be tested without side effects
``WARN``  optional or degraded: SentinelX runs, but something is unavailable
``FAIL``  something the current configuration needs is missing or broken
``INFO``  context, never a verdict

A check never reports ``PASS`` for a capability that is unavailable; when in doubt it
reports what was actually observed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import httpx

from sentinelx.config.settings import Settings
from sentinelx.system.capabilities import PlatformCapabilities, detect_capabilities

__all__ = ["Check", "run_diagnostics", "url_host"]

Status = Literal["PASS", "WARN", "FAIL", "INFO"]

#: Runtime imports SentinelX cannot start without.
REQUIRED_MODULES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "sqlalchemy": "sqlalchemy",
    "alembic": "alembic",
    "pydantic_settings": "pydantic-settings",
    "argon2": "argon2-cffi",
    "jwt": "pyjwt",
    "yaml": "pyyaml",
    "structlog": "structlog",
    "psutil": "psutil",
    "scapy": "scapy",
    "prometheus_client": "prometheus-client",
    "redis": "redis",
    "httpx": "httpx",
}


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: Status
    detail: str
    remedy: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def url_host(host: str) -> str:
    """``host`` as it must appear in a URL: IPv6 literals need brackets."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _module_present(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _secret_was_configured(settings: Settings) -> bool:
    """Whether JWT_SECRET came from the environment or .env, not the dev fallback."""
    names = {"JWT_SECRET", "API__JWT_SECRET"}
    # Settings names are case-insensitive, so jwt_secret=... configures the secret too.
    if any(value and key.upper() in names for key, value in os.environ.items()):
        return True
    env_file = settings.model_config.get("env_file")
    if isinstance(env_file, str | Path) and Path(env_file).is_file():
        from dotenv import dotenv_values

        encoding = settings.model_config.get("env_file_encoding") or "utf-8"
        values = dotenv_values(env_file, encoding=encoding)
        return any(value and key.upper() in names for key, value in values.items())
    return False


def _ml_check(settings: Settings) -> Check:
    """The ML detector is enabled: can it actually run?

    The server skips an unloadable model with only a log line, so detection carries on
    without it. Doctor is where that must be visible.
    """
    missing = [name for name in ("numpy", "sklearn", "joblib") if not _module_present(name)]
    if missing:
        return Check(
            "machine learning",
            "FAIL",
            f"ANOMALY__ML_ENABLED=true but {', '.join(missing)} not installed",
            'pip install -e ".[ml]"',
        )
    from sentinelx.anomaly.ml import load_model

    path = Path(settings.anomaly.ml_model_path)
    try:
        # The same checks the server applies: presence, ownership, permissions, format.
        bundle = load_model(path)
    except Exception as exc:
        return Check(
            "machine learning",
            "FAIL",
            f"ANOMALY__ML_ENABLED=true but the model cannot be used, so the ML detector "
            f"is disabled: {exc}"[:600],
            "train one: sentinelx anomaly train NORMAL.pcap (or set ANOMALY__ML_MODEL_PATH)",
        )
    info = bundle.info()
    return Check(
        "machine learning",
        "PASS",
        f"model {path} loaded ({info.get('samples')} samples, trained {info.get('trained_at')})",
    )


def _platform_checks(settings: Settings, capabilities: PlatformCapabilities) -> list[Check]:
    env = capabilities.environment
    checks = [Check("operating system", "INFO", f"{env.label()} (Python {env.python_version})")]
    if env.wsl:
        checks.append(
            Check(
                "wsl",
                "INFO",
                f"running under WSL{env.wsl}: live capture and firewall changes apply to the "
                "WSL virtual machine, not to the Windows host",
                "run SentinelX natively on Windows to protect the Windows host",
            )
        )
    if env.container:
        checks.append(
            Check(
                "container",
                "INFO",
                f"running inside {env.container}: capture sees the container's network "
                "namespace unless the container uses host networking",
            )
        )

    missing = [
        package for module, package in REQUIRED_MODULES.items() if not _module_present(module)
    ]
    database_driver = (
        "asyncpg"
        if settings.storage.database_url.startswith(("postgres", "postgresql"))
        else "aiosqlite"
    )
    if not _module_present(database_driver):
        missing.append(database_driver)
    checks.append(
        Check(
            "dependencies",
            "FAIL" if missing else "PASS",
            f"missing: {', '.join(missing)}" if missing else "all required packages import",
            "pip install -e ." if missing else "",
        )
    )
    if settings.anomaly.ml_enabled:
        checks.append(_ml_check(settings))

    for label, capability, missing_status in (
        ("pcap replay", capabilities.pcap_replay, "FAIL"),
        ("interface enumeration", capabilities.interface_enumeration, "WARN"),
        ("packet capture backend", capabilities.packet_capture, "WARN"),
        ("live capture", capabilities.live_capture, "WARN"),
    ):
        checks.append(
            Check(
                label,
                "PASS" if capability.available else missing_status,  # type: ignore[arg-type]
                (f"{capability.backend}: " if capability.backend else "") + capability.detail,
                "" if capability.available else capability.remedy,
            )
        )

    wanted = settings.capture.interface
    if wanted != "any" and capabilities.interface_enumeration.available:
        from sentinelx.system.interfaces import list_interfaces

        names = [entry["name"] for entry in list_interfaces()]
        checks.append(
            Check(
                "capture interface",
                "PASS" if wanted in names else "FAIL",
                f"{wanted} "
                + ("exists" if wanted in names else f"not found (have: {', '.join(names)})"),
                "" if wanted in names else "set CAPTURE_INTERFACE to one of the listed interfaces",
            )
        )

    firewall = capabilities.firewall
    response = settings.response
    needs_firewall = not response.dry_run and response.mode.value != "detect_only"
    if response.firewall_backend == "null":
        checks.append(
            Check(
                "firewall backend",
                "FAIL" if needs_firewall else "INFO",
                "none configured: SentinelX detects and explains but cannot block",
                "set FIREWALL_BACKEND=auto (or a specific backend) to enable prevention",
            )
        )
    else:
        checks.append(
            Check(
                "firewall backend",
                "PASS" if firewall.available else ("FAIL" if needs_firewall else "WARN"),
                # "null" is what an unresolved "auto" reports; its detail already says why.
                firewall.detail
                if firewall.backend == "null"
                else f"{firewall.backend}: {firewall.detail}",
                "" if firewall.available else firewall.remedy,
            )
        )
    checks.append(
        Check(
            "automatic blocking",
            "PASS"
            if capabilities.automatic_blocking.available
            else ("FAIL" if response.prevention_active else "INFO"),
            capabilities.automatic_blocking.detail,
            capabilities.automatic_blocking.remedy,
        )
    )
    checks.append(
        Check(
            "safety posture",
            "WARN" if settings.prevention_active else "PASS",
            settings.safety_banner(),
        )
    )
    return checks


def _local_checks(settings: Settings) -> list[Check]:
    checks: list[Check] = []
    from sentinelx.services.rules import max_rule_window
    from sentinelx.signatures import load_rules

    rules_directory = Path(settings.rules_directory)
    if not rules_directory.is_dir():
        checks.append(
            Check(
                "rules",
                "FAIL",
                f"rules directory {rules_directory.resolve()} does not exist",
                "run SentinelX from the repository root or set RULES_DIRECTORY",
            )
        )
    else:
        loaded = load_rules(rules_directory, max_window_seconds=max_rule_window(settings))
        status: Status = "FAIL" if loaded.problems else ("PASS" if loaded.rules else "WARN")
        checks.append(
            Check(
                "rules",
                status,
                f"{len(loaded.rules)} valid, {len(loaded.problems)} invalid in {rules_directory}",
                "run: sentinelx rules validate"
                if loaded.problems
                else (
                    "" if loaded.rules else "no custom rules loaded; built-in detectors still run"
                ),
            )
        )

    directory = Path(settings.capture.pcap_directory)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".sentinelx-doctor"
        probe.write_bytes(b"")
        probe.unlink()
        checks.append(Check("pcap directory", "PASS", f"{directory} is writable"))
    except OSError as exc:
        checks.append(
            Check(
                "pcap directory",
                "FAIL",
                f"{directory}: {exc}",
                "fix permissions or set PCAP_DIRECTORY",
            )
        )

    if len(settings.api.jwt_secret) < 32:
        checks.append(Check("jwt secret", "FAIL", "shorter than 32 characters", "set JWT_SECRET"))
    elif not _secret_was_configured(settings):
        checks.append(
            Check(
                "jwt secret",
                "WARN" if settings.environment != "production" else "FAIL",
                "not configured: an ephemeral secret is generated, so sessions end on restart",
                'python -c "import secrets; print(secrets.token_urlsafe(48))"',
            )
        )
    else:
        checks.append(Check("jwt secret", "PASS", "configured"))
    return checks


def _missing_sqlite_file(url: str) -> Path | None:
    """The path of a SQLite database file named by ``url`` that does not exist yet.

    ``None`` for other databases, in-memory SQLite, URI filenames and existing files.
    """
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return None
    name = parsed.database or ""
    if not name or name == ":memory:" or name.startswith("file:") or parsed.query.get("uri"):
        return None
    path = Path(name)
    return None if path.exists() else path


async def _service_checks(settings: Settings) -> list[Check]:
    from sentinelx.storage.database import Database
    from sentinelx.storage.migrate import current_revision, head_revision
    from sentinelx.storage.redis_state import SharedState

    checks: list[Check] = []
    database = Database(settings.storage)
    missing = _missing_sqlite_file(database.url)
    if missing is not None:
        # Connecting would create an empty file; starting SentinelX creates and migrates it.
        checks.append(
            Check(
                "database",
                "WARN",
                f"database file does not exist yet ({missing}); it is created and migrated "
                "when SentinelX starts",
                "start SentinelX, or create it now: sentinelx db upgrade",
            )
        )
    else:
        try:
            # Inspect only: doctor must not migrate the database it is diagnosing.
            await database.connect(prepare_schema=False)
            checks.append(Check("database", "PASS", database.safe_url))
            applied = await current_revision(settings.storage.database_url)
            head = head_revision()
            if applied == head:
                checks.append(Check("migrations", "PASS", f"at the latest revision ({head})"))
            elif database.dialect == "sqlite":
                checks.append(
                    Check(
                        "migrations",
                        "WARN",
                        f"applied {applied or 'none'}, latest {head}: SQLite databases are "
                        "migrated automatically when SentinelX starts",
                        "or migrate now: sentinelx db upgrade",
                    )
                )
            else:
                checks.append(
                    Check(
                        "migrations",
                        "FAIL",
                        f"applied {applied or 'none'}, latest {head}: SentinelX refuses to start "
                        "on an outdated PostgreSQL schema",
                        "run: sentinelx db upgrade",
                    )
                )
        except Exception as exc:
            checks.append(
                Check(
                    "database", "FAIL", f"{type(exc).__name__}: {exc}"[:300], "check DATABASE_URL"
                )
            )
        finally:
            await database.close()

    state = SharedState(settings.storage)
    try:
        # With STORAGE__REDIS_REQUIRED=true connect() raises instead of degrading; that
        # is a finding to report, not a reason to abandon every other check.
        await state.connect()
    except Exception as exc:
        checks.append(
            Check(
                "redis",
                "FAIL",
                f"{exc} (STORAGE__REDIS_REQUIRED=true)"[:300],
                "start Redis or set REDIS_URL",
            )
        )
    else:
        if state.degraded:
            checks.append(
                Check(
                    "redis",
                    "FAIL" if settings.storage.redis_required else "WARN",
                    "unreachable: rate limits and tickets are per process",
                    "start Redis or set REDIS_URL",
                )
            )
        else:
            checks.append(Check("redis", "PASS", "connected"))
    finally:
        with contextlib.suppress(Exception):
            await state.close()
    return checks


async def _probe(url: str, name: str, expect: str, identify: str) -> Check:
    """Probe a SentinelX HTTP endpoint and confirm it is SentinelX that answered.

    Something else listening on the same port must not count as a working service.
    """
    try:
        async with httpx.AsyncClient(timeout=2.0, follow_redirects=False) as client:
            response = await client.get(url)
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        return Check(
            name, "WARN", f"not reachable at {url} ({type(exc).__name__})", f"start the {expect}"
        )
    try:
        body = response.json()
    except ValueError:
        body = None
    if response.status_code >= 500:
        return Check(name, "FAIL", f"{url} answered HTTP {response.status_code}")
    if not isinstance(body, dict) or not _identifies(body, identify):
        return Check(
            name,
            "WARN",
            f"{url} answered HTTP {response.status_code}, but not as SentinelX: another "
            "service is using this address",
            f"stop the other service, or point the probe at the {expect.split(' ')[0]}'s real address",
        )
    return Check(name, "PASS", f"{url} is SentinelX ({_describe(body, identify)})")


def _identifies(body: dict[str, object], identify: str) -> bool:
    if identify == "api":
        return body.get("status") in {"ok", "degraded", "error"} and "version" in body
    return body.get("app") == "sentinelx-dashboard"


def _describe(body: dict[str, object], identify: str) -> str:
    if identify == "api":
        return f"status {body.get('status')}, version {body.get('version')}"
    return "dashboard"


async def run_diagnostics(
    settings: Settings, *, api_url: str | None = None, dashboard_url: str | None = None
) -> list[Check]:
    """Run every check. Never raises for an environment problem; reports it instead."""
    version = sys.version_info
    checks = [
        Check(
            "python",
            "PASS" if version >= (3, 12) else "FAIL",
            f"{version.major}.{version.minor}.{version.micro}",
            "" if version >= (3, 12) else "install Python 3.12 or newer",
        )
    ]
    capabilities = detect_capabilities(settings)
    checks.extend(_platform_checks(settings, capabilities))
    checks.extend(_local_checks(settings))
    checks.extend(await _service_checks(settings))
    host = settings.api.host if settings.api.host not in {"0.0.0.0", "::"} else "127.0.0.1"
    checks.append(
        await _probe(
            (api_url or f"http://{url_host(host)}:{settings.api.port}").rstrip("/")
            + "/api/v1/system/health",
            "api",
            "API with: sentinelx start",
            "api",
        )
    )
    checks.append(
        await _probe(
            (
                dashboard_url
                or os.environ.get("SENTINELX_DASHBOARD_URL")
                or "http://127.0.0.1:3000"
            ).rstrip("/")
            + "/runtime-config",
            "dashboard",
            "dashboard (see README: Running the platform)",
            "dashboard",
        )
    )
    return checks
