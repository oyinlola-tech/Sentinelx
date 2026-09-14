"""Typed configuration, loaded once from the environment.

Every environment-specific value in SentinelX lives here.  Nothing else in the
codebase calls ``os.getenv``.  Settings are grouped into nested models so that a
detector can be handed just ``settings.detection`` rather than the whole world,
which keeps the security core testable without an environment at all.

Safety defaults are deliberate and documented in :mod:`sentinelx.response.safety`:
``RESPONSE_MODE=detect_only`` and ``DRY_RUN=true`` mean a fresh install observes
and explains but never touches traffic.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelx.common.enums import DetectionMode, ResponseMode
from sentinelx.common.netutils import parse_networks

__all__ = [
    "AnomalySettings",
    "ApiSettings",
    "CaptureSettings",
    "CorrelationSettings",
    "DetectionSettings",
    "ResponseSettings",
    "ScoringSettings",
    "Settings",
    "StorageSettings",
    "get_settings",
    "reload_settings",
]

Fraction = Annotated[float, Field(ge=0.0, le=1.0)]
Percent = Annotated[float, Field(ge=0.0, le=100.0)]


# ===================================================================== capture


class CaptureSettings(BaseModel):
    """Packet source configuration."""

    interface: str = Field(
        default="any",
        description="Interface to capture from. 'any' uses the Linux cooked-capture device.",
    )
    bpf_filter: str = Field(
        default="",
        description="Optional BPF expression applied in the kernel, before userspace sees a packet.",
    )
    snapshot_length: int = Field(
        default=2048,
        ge=64,
        le=65535,
        description="Bytes captured per frame. 2048 keeps full headers plus DNS/TLS handshakes.",
    )
    promiscuous: bool = True
    buffer_size_mb: int = Field(default=16, ge=1, le=1024)
    queue_size: int = Field(
        default=20_000,
        ge=100,
        description="Bounded hand-off queue between capture and the pipeline. "
        "When full, packets are dropped and counted rather than growing memory.",
    )
    home_networks: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
        description="Prefixes treated as 'inside'. Used only to label packet direction.",
    )
    pcap_directory: Path = Field(default=Path("pcaps"))
    max_pcap_size_mb: int = Field(default=512, ge=1)

    @field_validator("home_networks")
    @classmethod
    def _validate_home_networks(cls, value: list[str]) -> list[str]:
        parse_networks(value)  # raises ValueError listing every bad entry
        return value

    @field_validator("bpf_filter")
    @classmethod
    def _validate_bpf(cls, value: str) -> str:
        """Reject shell metacharacters.

        The filter is passed to libpcap as a string argument, never through a
        shell, but rejecting these characters early turns a confusing pcap
        compile error into a clear configuration error.
        """
        forbidden = set(";|`$\n\r\\")
        if forbidden & set(value):
            raise ValueError("bpf_filter must not contain shell metacharacters")
        return value.strip()


# =================================================================== detection


class DetectionSettings(BaseModel):
    """Thresholds for the built-in detectors.

    Defaults are tuned against the synthetic scenarios in ``scripts/benchmark.py``
    and the fixtures in ``tests/detection``.  They are starting points, not
    universal truths - every deployment should re-tune using its own baseline
    traffic, and ``docs/detection-engine.md`` explains how.
    """

    mode: DetectionMode = DetectionMode.BALANCED
    enabled_detectors: list[str] = Field(
        default_factory=list,
        description="Allow-list of detector names. Empty means 'all detectors for this mode'.",
    )
    disabled_detectors: list[str] = Field(default_factory=list)

    # --- port scanning
    port_scan_window_seconds: float = Field(default=15.0, gt=0)
    port_scan_unique_ports: int = Field(
        default=20, ge=2, description="Distinct destination ports from one source that trigger."
    )
    port_scan_min_syn_ratio: Fraction = Field(
        default=0.7,
        description="Fraction of packets that must be bare SYNs. Separates scans from "
        "legitimate multi-port clients, which complete handshakes.",
    )
    horizontal_scan_unique_hosts: int = Field(
        default=25, ge=2, description="Distinct destination hosts on one port (a sweep)."
    )
    udp_scan_unique_ports: int = Field(default=25, ge=2)

    # --- brute force
    brute_force_window_seconds: float = Field(default=60.0, gt=0)
    brute_force_attempts: int = Field(default=15, ge=2)
    brute_force_ports: list[int] = Field(
        default_factory=lambda: [22, 23, 21, 3389, 445, 5900, 1433, 3306, 5432],
        description="Services where repeated short-lived connections imply credential guessing.",
    )

    # --- floods
    connection_rate_window_seconds: float = Field(default=10.0, gt=0)
    connection_rate_threshold: int = Field(default=200, ge=1)
    syn_flood_threshold: int = Field(default=500, ge=1)
    icmp_flood_window_seconds: float = Field(default=10.0, gt=0)
    icmp_flood_threshold: int = Field(default=200, ge=1)
    http_flood_window_seconds: float = Field(default=10.0, gt=0)
    http_flood_threshold: int = Field(default=300, ge=1)

    # --- DNS
    dns_window_seconds: float = Field(default=30.0, gt=0)
    dns_query_threshold: int = Field(default=300, ge=1)
    dns_unique_domain_threshold: int = Field(
        default=100, ge=1, description="Many distinct names from one client suggests tunnelling or DGA."
    )
    dns_long_label_length: int = Field(
        default=52,
        ge=10,
        le=63,
        description="Label length above which a name looks like encoded data rather than a hostname.",
    )
    dns_high_entropy_threshold: float = Field(
        default=3.8, ge=0.0, description="Shannon entropy (bits/char) suggesting an algorithmic name."
    )

    # --- general
    max_tracked_sources: int = Field(default=50_000, ge=100)
    detection_cooldown_seconds: float = Field(
        default=60.0,
        ge=0,
        description="Suppress repeat detections of the same (detector, source) pair. "
        "Prevents one scan producing thousands of identical alerts.",
    )
    denylist_networks: list[str] = Field(default_factory=list)
    allowlist_networks: list[str] = Field(
        default_factory=list,
        description="Sources never reported on. Applied before any detector runs.",
    )

    @field_validator("denylist_networks", "allowlist_networks")
    @classmethod
    def _validate_nets(cls, value: list[str]) -> list[str]:
        parse_networks(value)
        return value

    @field_validator("brute_force_ports")
    @classmethod
    def _validate_ports(cls, value: list[int]) -> list[int]:
        bad = [p for p in value if not 0 < p < 65536]
        if bad:
            raise ValueError(f"invalid port numbers: {bad}")
        return value


# ===================================================================== scoring


class ScoringSettings(BaseModel):
    """Weights for the risk engine.

    The score is a weighted sum of factors clamped to 0-100; see
    ``docs/risk-scoring.md``.  Exposed as settings so an operator can express
    their own priorities (e.g. weigh threat intel heavily, ignore history).
    """

    severity_weight: float = Field(default=45.0, ge=0, le=100)
    confidence_weight: float = Field(default=20.0, ge=0, le=100)
    frequency_weight: float = Field(default=10.0, ge=0, le=100)
    history_weight: float = Field(default=10.0, ge=0, le=100)
    intel_weight: float = Field(default=15.0, ge=0, le=100)
    correlation_weight: float = Field(default=15.0, ge=0, le=100)
    sensitive_target_weight: float = Field(default=10.0, ge=0, le=100)

    history_window_seconds: float = Field(default=3600.0, gt=0)
    frequency_saturation: int = Field(
        default=10,
        ge=1,
        description="Repeat count at which the frequency factor reaches its full weight.",
    )
    history_saturation: int = Field(default=5, ge=1)
    allowlist_penalty: float = Field(
        default=40.0,
        ge=0,
        le=100,
        description="Points subtracted when the source is allowlisted but still detected. "
        "Keeps the finding visible for tuning without escalating it.",
    )

    auto_block_threshold: Percent = Field(
        default=85.0,
        description="Risk at or above which an automatic block may be proposed. "
        "Only acted on when RESPONSE_MODE=automatic and DRY_RUN=false.",
    )
    incident_threshold: Percent = Field(
        default=60.0, description="Risk at or above which a correlated incident is opened."
    )


# ================================================================= correlation


class CorrelationSettings(BaseModel):
    """How separate detections are folded into one incident."""

    enabled: bool = True
    window_seconds: float = Field(
        default=600.0,
        gt=0,
        description="How long an incident stays open for new, related detections.",
    )
    min_detections: int = Field(default=2, ge=1)
    standalone_risk_threshold: Percent = Field(
        default=85.0,
        description="A single critical detection at or above this risk opens an incident "
        "without waiting for corroboration.",
    )
    max_open_incidents: int = Field(default=1000, ge=1)
    group_by_source: bool = True
    group_by_destination: bool = False


# ==================================================================== anomaly


class AnomalySettings(BaseModel):
    """Statistical baselining and the optional ML layer."""

    enabled: bool = True
    baseline_alpha: Fraction = Field(
        default=0.05, description="EWMA decay. Lower adapts more slowly and is less jumpy."
    )
    min_samples: int = Field(
        default=60, ge=5, description="Observations required before deviations are reported."
    )
    sample_interval_seconds: float = Field(default=1.0, gt=0)
    anomaly_threshold: Fraction = Field(
        default=0.85, description="Anomaly score at or above which a detection is emitted."
    )
    sigma_saturation: float = Field(default=6.0, gt=0)

    ml_enabled: bool = Field(
        default=False,
        description="Enable the IsolationForest detector. Off by default: it needs a trained "
        "model, and an untrained one adds noise rather than signal.",
    )
    ml_model_path: Path = Field(default=Path("models/isolation_forest.joblib"))
    ml_contamination: float = Field(default=0.02, gt=0, lt=0.5)
    ml_min_score: Fraction = Field(default=0.75)


# =================================================================== response


class ResponseSettings(BaseModel):
    """Response and firewall behaviour.

    The defaults here are the single most safety-critical thing in the project.
    Changing ``mode`` away from ``detect_only`` or ``dry_run`` away from True must
    be a conscious act by an operator, not something that happens by upgrade.
    """

    mode: ResponseMode = ResponseMode.DETECT_ONLY
    dry_run: bool = Field(
        default=True,
        description="When true, response actions are decided, recorded and displayed, "
        "but never applied to the firewall.",
    )
    firewall_backend: Literal["nftables", "iptables", "null"] = "null"
    nft_table: str = Field(default="sentinelx", pattern=r"^[A-Za-z0-9_]{1,32}$")
    nft_set: str = Field(default="blocklist", pattern=r"^[A-Za-z0-9_]{1,32}$")
    nft_family: Literal["inet", "ip", "ip6"] = "inet"

    default_block_seconds: int = Field(default=900, ge=30, le=86_400)
    max_block_seconds: int = Field(default=86_400, ge=60)
    max_blocked_addresses: int = Field(
        default=10_000, ge=1, description="Hard cap on concurrent blocks. A runaway detector "
        "hits this limit instead of exhausting the firewall set."
    )
    max_block_prefix_hosts: int = Field(
        default=256,
        ge=1,
        description="Largest prefix that may be blocked, in addresses. 256 = a /24. "
        "Stops a malformed rule from taking out an entire network.",
    )

    allowlist_networks: list[str] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128"],
        description="Never blocked, under any circumstances. Loopback is non-negotiable "
        "and re-added even if removed here.",
    )
    protect_management_addresses: bool = Field(
        default=True,
        description="Refuse to block any address currently assigned to a local interface, "
        "and any address with an established connection to the API port.",
    )
    management_addresses: list[str] = Field(default_factory=list)

    webhook_url: str = ""
    webhook_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    webhook_min_risk: Percent = Field(default=60.0)

    rate_limit_packets_per_second: int = Field(default=100, ge=1)

    @field_validator("allowlist_networks", "management_addresses")
    @classmethod
    def _validate_nets(cls, value: list[str]) -> list[str]:
        parse_networks(value)
        return value

    @model_validator(mode="after")
    def _guard_loopback(self) -> ResponseSettings:
        """Force loopback into the allowlist even if an operator removed it."""
        required = ["127.0.0.0/8", "::1/128"]
        missing = [net for net in required if net not in self.allowlist_networks]
        if missing:
            self.allowlist_networks = [*self.allowlist_networks, *missing]
        return self

    @model_validator(mode="after")
    def _guard_prevention(self) -> ResponseSettings:
        """A live firewall backend is required before prevention can do anything."""
        if self.mode is ResponseMode.AUTOMATIC and not self.dry_run and self.firewall_backend == "null":
            raise ValueError(
                "RESPONSE_MODE=automatic with DRY_RUN=false requires a real "
                "FIREWALL_BACKEND (nftables or iptables), not 'null'"
            )
        return self

    @property
    def prevention_active(self) -> bool:
        """True only when responses will genuinely alter traffic."""
        return self.mode is ResponseMode.AUTOMATIC and not self.dry_run


# ==================================================================== storage


class StorageSettings(BaseModel):
    """Database, Redis and retention."""

    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinelx.db",
        description="SQLAlchemy async URL. PostgreSQL is the supported production target; "
        "the SQLite default exists so the platform runs with zero infrastructure.",
    )
    database_echo: bool = False
    pool_size: int = Field(default=10, ge=1)
    max_overflow: int = Field(default=20, ge=0)

    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_required: bool = Field(
        default=False,
        description="When false, Redis failures degrade to in-process counters "
        "instead of taking the platform down.",
    )
    redis_namespace: str = Field(default="sentinelx", pattern=r"^[A-Za-z0-9_:-]{1,64}$")

    retention_days: int = Field(default=30, ge=1, le=3650)
    audit_retention_days: int = Field(
        default=365, ge=1, description="Audit events are kept far longer than telemetry."
    )
    metrics_retention_days: int = Field(default=7, ge=1)
    batch_size: int = Field(default=200, ge=1, description="Rows flushed to the database per write.")
    flush_interval_seconds: float = Field(default=2.0, gt=0)

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith(("postgresql", "postgres"))

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


# ======================================================================== api


class ApiSettings(BaseModel):
    """HTTP/WebSocket server and authentication."""

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    root_path: str = ""
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="Explicit origins. '*' is rejected when authentication is enabled, "
        "because credentialed requests from any origin defeat the point.",
    )

    jwt_secret: str = Field(default="", description="HS256 signing key. Required in production.")
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_ttl_seconds: int = Field(
        default=900, ge=60, le=86_400, description="Short-lived; the dashboard refreshes silently."
    )
    refresh_token_ttl_seconds: int = Field(default=604_800, ge=300)
    jwt_issuer: str = "sentinelx"
    cookie_secure: bool = Field(
        default=False,
        description="Mark auth cookies Secure (HTTPS only). Forced on in production.",
    )
    password_min_length: int = Field(default=12, ge=8, le=128)
    lockout_threshold: int = Field(default=5, ge=1, description="Failed logins before an account locks.")
    lockout_seconds: int = Field(default=900, ge=30)

    auth_enabled: bool = True
    bootstrap_admin_username: str = Field(default="admin", min_length=3, max_length=64)
    bootstrap_admin_password: str = Field(
        default="",
        description="Used only to create the first admin when the user table is empty. "
        "If unset, a password is generated and printed once at startup.",
    )

    rate_limit_requests: int = Field(default=300, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    login_rate_limit_attempts: int = Field(default=8, ge=1)
    login_rate_limit_window_seconds: int = Field(default=300, ge=1)

    websocket_max_queue: int = Field(
        default=500,
        ge=10,
        description="Per-connection outbound buffer. A slow dashboard is disconnected "
        "rather than allowed to back-pressure the detection pipeline.",
    )
    max_upload_mb: int = Field(default=200, ge=1)
    trusted_proxies: list[str] = Field(
        default_factory=list,
        description="CIDRs of reverse proxies whose X-Forwarded-For header is believed. "
        "Empty means the header is ignored, so clients cannot spoof their address.",
    )
    metrics_token: str = Field(
        default="",
        description="Bearer token for the Prometheus endpoint. When empty, metrics are "
        "served to loopback clients only.",
    )
    docs_enabled: bool = Field(default=True, description="Serve interactive OpenAPI docs. Disabled in production.")

    @field_validator("trusted_proxies")
    @classmethod
    def _validate_proxies(cls, value: list[str]) -> list[str]:
        parse_networks(value)
        return value

    @field_validator("cors_origins")
    @classmethod
    def _validate_origins(cls, value: list[str], info: ValidationInfo) -> list[str]:
        for origin in value:
            if origin != "*" and not origin.startswith(("http://", "https://")):
                raise ValueError(f"CORS origin {origin!r} must include a scheme")
        return value


# =================================================================== telemetry


class TelemetrySettings(BaseModel):
    """Logging and metrics."""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["console", "json"] = "console"
    log_file: Path | None = None
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    profile_pipeline: bool = Field(
        default=False, description="Record per-stage latency histograms. Small but non-zero cost."
    )


# ==================================================================== root


class Settings(BaseSettings):
    """Root settings object.

    Environment variables map to nested fields with a double underscore, e.g.
    ``DETECTION__PORT_SCAN_UNIQUE_PORTS=30``.  The flat aliases required by the
    project brief (``DATABASE_URL``, ``DRY_RUN``, ...) are also supported and are
    applied in :meth:`_apply_flat_aliases`.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Literal["development", "staging", "production"] = "development"
    sensor_name: str = Field(default="sentinelx-local", min_length=1, max_length=64)

    capture: CaptureSettings = Field(default_factory=CaptureSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    anomaly: AnomalySettings = Field(default_factory=AnomalySettings)
    response: ResponseSettings = Field(default_factory=ResponseSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)

    rules_directory: Path = Field(default=Path("rules"))

    @model_validator(mode="before")
    @classmethod
    def _apply_flat_aliases(cls, data: Any) -> Any:
        """Map the documented flat env vars onto their nested homes.

        The brief specifies short names like ``DRY_RUN``; the nested structure is
        better for code.  Rather than choose, we support both, with the nested
        form winning when a variable is set twice.
        """
        if not isinstance(data, dict):
            return data
        import os

        flat_map: dict[str, tuple[str, str]] = {
            "DATABASE_URL": ("storage", "database_url"),
            "REDIS_URL": ("storage", "redis_url"),
            "RETENTION_DAYS": ("storage", "retention_days"),
            "API_HOST": ("api", "host"),
            "API_PORT": ("api", "port"),
            "JWT_SECRET": ("api", "jwt_secret"),
            "CORS_ORIGINS": ("api", "cors_origins"),
            "CAPTURE_INTERFACE": ("capture", "interface"),
            "BPF_FILTER": ("capture", "bpf_filter"),
            "PCAP_DIRECTORY": ("capture", "pcap_directory"),
            "DETECTION_MODE": ("detection", "mode"),
            "RESPONSE_MODE": ("response", "mode"),
            "DRY_RUN": ("response", "dry_run"),
            "FIREWALL_BACKEND": ("response", "firewall_backend"),
            "LOG_LEVEL": ("telemetry", "log_level"),
            "LOG_FORMAT": ("telemetry", "log_format"),
        }
        list_fields = {"cors_origins"}
        bool_fields = {"dry_run"}

        for env_name, (section, field_name) in flat_map.items():
            raw = os.environ.get(env_name)
            if raw is None:
                continue
            section_data = data.get(section)
            if not isinstance(section_data, dict):
                section_data = {} if section_data is None else section_data
            if not isinstance(section_data, dict):
                continue
            if field_name in section_data:
                continue  # nested form already supplied it; it wins
            value: Any = raw
            if field_name in list_fields:
                value = [part.strip() for part in raw.split(",") if part.strip()]
            elif field_name in bool_fields:
                value = raw.strip().lower() in {"1", "true", "yes", "on"}
            section_data[field_name] = value
            data[section] = section_data
        return data

    @model_validator(mode="after")
    def _validate_production(self) -> Settings:
        """Refuse insecure configurations in production rather than warning about them."""
        if self.environment != "production":
            if not self.api.jwt_secret:
                # Dev convenience: a per-process ephemeral secret. Tokens do not
                # survive a restart, which is correct for development.
                self.api.jwt_secret = secrets.token_urlsafe(48)
            return self

        problems: list[str] = []
        self.api.cookie_secure = True
        self.api.docs_enabled = False
        if len(self.api.jwt_secret) < 32:
            problems.append("JWT_SECRET must be set to at least 32 characters in production")
        if not self.api.auth_enabled:
            problems.append("authentication cannot be disabled in production")
        if "*" in self.api.cors_origins:
            problems.append("CORS origin '*' is not permitted in production")
        if self.storage.is_sqlite:
            problems.append("SQLite is not supported in production; set DATABASE_URL to PostgreSQL")
        if problems:
            raise ValueError("invalid production configuration: " + "; ".join(problems))
        return self

    @property
    def prevention_active(self) -> bool:
        return self.response.prevention_active

    def safety_banner(self) -> str:
        """One-line description of the current safety posture, shown at startup."""
        if self.prevention_active:
            return (
                f"PREVENTION ACTIVE - responses will modify the {self.response.firewall_backend} "
                f"firewall on this host"
            )
        if self.response.dry_run and self.response.mode is not ResponseMode.DETECT_ONLY:
            return "DRY RUN - response decisions are recorded and shown but not applied"
        return "DETECTION ONLY - no traffic will be modified"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """The process-wide settings singleton.

    Cached so that importing settings from anywhere is cheap and always yields the
    same object.  Call :func:`reload_settings` in tests that need to vary config.
    """
    return Settings()


def reload_settings() -> Settings:
    """Clear the cache and re-read the environment. Intended for tests and the CLI."""
    get_settings.cache_clear()
    return get_settings()
