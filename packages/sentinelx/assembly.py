"""One place that decides which detectors and intelligence a pipeline gets.

Live capture, API and dashboard replays, ``sentinelx replay``, ``sentinelx monitor``
and the benchmark all assemble their pipelines here, so "a replay runs exactly the
detection a live sensor runs" is enforced by construction rather than by keeping
several copies of the wiring in step.

Detection modes:

``disabled``        no detectors at all
``signature_only``  denylist, TCP flag anomalies and custom rules; no rate or
                    statistical detection
``balanced``        everything enabled in configuration (the default)
``aggressive``      as balanced (reserved for more sensitive thresholds; it does not
                    change detector selection today)
"""

from __future__ import annotations

from pathlib import Path

from sentinelx.common.enums import DetectionMode, ResponseMode
from sentinelx.config.settings import Settings
from sentinelx.pipeline import Pipeline
from sentinelx.signatures import LoadResult, RuleDetector, load_rules
from sentinelx.telemetry.logging import get_logger
from sentinelx.threat_intel import (
    LocalAllowlistProvider,
    LocalDenylistProvider,
    ThreatIntelService,
)

__all__ = [
    "attach_anomaly_detectors",
    "attach_file_rules",
    "build_intel",
    "rules_enabled",
    "simulation_settings",
]

log = get_logger(__name__)


def rules_enabled(settings: Settings) -> bool:
    return settings.detection.mode is not DetectionMode.DISABLED


def simulation_settings(settings: Settings) -> Settings:
    """A copy of ``settings`` for a replay: responses are decided, never applied.

    Used by API, dashboard and CLI replays alike. Manual approval becomes automatic so
    a replay shows what would have been decided instead of queueing approvals that
    nobody can act on.
    """
    simulated = settings.model_copy(deep=True)
    simulated.response.dry_run = True
    simulated.response.firewall_backend = "null"
    if simulated.response.mode is ResponseMode.MANUAL_APPROVAL:
        simulated.response.mode = ResponseMode.AUTOMATIC
    return simulated


def build_intel(settings: Settings) -> ThreatIntelService:
    """The local, offline threat-intelligence providers every pipeline uses."""
    directory = Path(settings.rules_directory) / "intel"
    return ThreatIntelService(
        [
            LocalAllowlistProvider(path=directory / "allowlist.txt"),
            LocalDenylistProvider(path=directory / "denylist.txt"),
        ]
    )


def attach_anomaly_detectors(pipeline: Pipeline, settings: Settings) -> list[str]:
    """Add the statistical (and, if configured and available, ML) detectors.

    Returns:
        Names of the detectors attached (including any attached switched off).
    """
    mode = settings.detection.mode
    if mode in (DetectionMode.DISABLED, DetectionMode.SIGNATURE_ONLY):
        return []
    anomaly = settings.anomaly
    disabled = set(settings.detection.disabled_detectors)
    # DETECTION__ENABLED_DETECTORS is an allow-list for every detector, anomaly included.
    allowed = set(settings.detection.enabled_detectors)
    attached: list[str] = []
    # Detectors switched off in the dashboard are attached but disabled, like the
    # built-in detectors, so they can be switched back on without a restart.
    if anomaly.enabled and (not allowed or "statistical_anomaly" in allowed):
        from sentinelx.anomaly import StatisticalAnomalyDetector

        statistical = StatisticalAnomalyDetector(anomaly, settings.detection)
        statistical.enabled = "statistical_anomaly" not in disabled
        pipeline.detection.add_detector(statistical)
        attached.append("statistical_anomaly")
    if anomaly.ml_enabled and (not allowed or "ml_anomaly" in allowed):
        from sentinelx.anomaly.ml import MlAnomalyDetector, load_model

        try:
            bundle = load_model(Path(anomaly.ml_model_path))
        except Exception as exc:
            # ML is optional; a missing or untrusted model must not stop detection.
            log.error("ml_model_unavailable", error=str(exc), effect="ML detector disabled")
        else:
            ml = MlAnomalyDetector(bundle, anomaly, settings.detection)
            ml.enabled = "ml_anomaly" not in disabled
            pipeline.detection.add_detector(ml)
            attached.append("ml_anomaly")
    return attached


def attach_file_rules(pipeline: Pipeline, settings: Settings) -> LoadResult:
    """Load rules straight from the rules directory (no database needed).

    Used where there is no platform database (CLI replay and monitor, benchmarks).
    The platform itself attaches rules through the rule service, which also honours
    rules disabled in the dashboard.
    """
    from sentinelx.services.rules import max_rule_window

    result = load_rules(
        Path(settings.rules_directory), max_window_seconds=max_rule_window(settings)
    )
    if rules_enabled(settings):
        for rule in result.rules:
            pipeline.detection.add_detector(RuleDetector(rule, settings.detection))
    return result
