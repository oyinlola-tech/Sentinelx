from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
import structlog
from pydantic import ValidationError

from sentinelx.common.enums import DetectionMode, ResponseMode
from sentinelx.config.settings import ResponseSettings, Settings, TelemetrySettings
from sentinelx.telemetry.logging import configure_logging, get_logger, redact_secrets


class TestSafetyDefaults:
    def test_fresh_install_is_detection_only_and_dry_run(self) -> None:
        settings = Settings()
        assert settings.response.mode is ResponseMode.DETECT_ONLY
        assert settings.response.dry_run is True
        assert settings.prevention_active is False
        assert settings.safety_banner().startswith("DETECTION ONLY")

    def test_loopback_is_restored_to_allowlist_if_removed(self) -> None:
        response = ResponseSettings(allowlist_networks=["10.0.0.0/8"])
        assert "127.0.0.0/8" in response.allowlist_networks
        assert "::1/128" in response.allowlist_networks

    def test_automatic_enforcement_requires_real_firewall(self) -> None:
        with pytest.raises(ValidationError, match="FIREWALL_BACKEND"):
            ResponseSettings(mode=ResponseMode.AUTOMATIC, dry_run=False, firewall_backend="null")

    def test_automatic_dry_run_with_null_backend_is_allowed(self) -> None:
        response = ResponseSettings(mode=ResponseMode.AUTOMATIC, dry_run=True)
        assert response.prevention_active is False


class TestEnvironment:
    def test_flat_aliases_map_to_nested_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DETECTION_MODE", "aggressive")
        monkeypatch.setenv("DRY_RUN", "false")
        monkeypatch.setenv("RESPONSE_MODE", "automatic")
        monkeypatch.setenv("FIREWALL_BACKEND", "nftables")
        monkeypatch.setenv("CORS_ORIGINS", "https://a.example,https://b.example")
        settings = Settings()
        assert settings.detection.mode is DetectionMode.AGGRESSIVE
        assert settings.prevention_active is True
        assert settings.api.cors_origins == ["https://a.example", "https://b.example"]

    def test_nested_variable_overrides_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DETECTION__PORT_SCAN_UNIQUE_PORTS", "77")
        assert Settings().detection.port_scan_unique_ports == 77

    def test_flat_aliases_are_read_from_dotenv_file(self, tmp_path: Path) -> None:
        # .env.example documents the flat names, so they must work from .env too.
        (tmp_path / ".env").write_text(
            "CAPTURE_INTERFACE=eth9\nDETECTION_MODE=aggressive\nCORS_ORIGINS=https://a.example\n",
            encoding="utf-8",
        )
        settings = Settings()
        assert settings.capture.interface == "eth9"
        assert settings.detection.mode is DetectionMode.AGGRESSIVE
        assert settings.api.cors_origins == ["https://a.example"]

    def test_precedence_environment_over_dotenv_and_nested_over_flat(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / ".env").write_text(
            "CAPTURE_INTERFACE=from-dotenv\nBPF_FILTER=tcp\n", encoding="utf-8"
        )
        monkeypatch.setenv("CAPTURE_INTERFACE", "from-env")
        assert Settings().capture.interface == "from-env"
        monkeypatch.setenv("CAPTURE__INTERFACE", "nested-env")
        assert Settings().capture.interface == "nested-env"
        assert Settings().capture.bpf_filter == "tcp"

    @pytest.mark.parametrize("value", ["ture", "nope", "enabled", "2"])
    def test_mistyped_dry_run_is_an_error_not_false(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        # Fail closed: a typo must never silently switch dry run off.
        monkeypatch.setenv("DRY_RUN", value)
        with pytest.raises(ValidationError, match="dry_run"):
            Settings()

    def test_mistyped_dry_run_in_dotenv_is_an_error(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("DRY_RUN=flase\n", encoding="utf-8")
        with pytest.raises(ValidationError, match="dry_run"):
            Settings()

    def test_invalid_network_lists_every_bad_entry(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            ResponseSettings(allowlist_networks=["10.0.0.0/8", "nope", "300.1.1.1"])
        message = str(excinfo.value)
        assert "nope" in message and "300.1.1.1" in message

    def test_bpf_filter_rejects_shell_metacharacters(self) -> None:
        with pytest.raises(ValidationError):
            Settings(capture={"bpf_filter": "tcp; rm -rf /"})

    def test_production_refuses_insecure_configuration(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            Settings(environment="production", api={"jwt_secret": "short", "cors_origins": ["*"]})
        message = str(excinfo.value)
        assert "JWT_SECRET" in message and "CORS" in message and "SQLite" in message

    def test_development_generates_ephemeral_jwt_secret(self) -> None:
        assert len(Settings().api.jwt_secret) >= 32


class TestRedaction:
    def test_sensitive_keys_are_redacted_recursively(self) -> None:
        event = redact_secrets(
            None, "info", {"event": "x", "password": "p", "nested": {"api_key": "k", "ok": 1}}
        )
        assert event["password"] == "[redacted]"
        assert event["nested"] == {"api_key": "[redacted]", "ok": 1}

    def test_inline_credentials_are_scrubbed_from_text(self) -> None:
        event = redact_secrets(
            None,
            "info",
            {"event": "x", "dsn": "postgresql://u:hunter2@db/x", "h": "Bearer abc.def"},
        )
        assert "hunter2" not in json.dumps(event)
        assert "abc.def" not in json.dumps(event)

    def test_audit_gaps_in_redaction_are_closed(self) -> None:
        # Compose builds REDIS_URL with an empty user; API keys arrive as X-Api-Key.
        event = redact_secrets(
            None,
            "info",
            {
                "event": "connect failed: redis://:redispass@redis:6379/0",
                "error": "ConnectionError for redis://:redispass@redis:6379/0",
                "X-Api-Key": "k-123",
                "x_api_key": "k-456",
                "header": "Authorization: Basic dXNlcjpodW50ZXIy",
                "redis_url": "redis://cache:6379/0",
                "ticket": "one-time-ticket",
                "passphrase": "hunter2",
                "session_count": 3,
            },
        )
        text = json.dumps(event)
        for secret in (
            "redispass",
            "k-123",
            "k-456",
            "dXNlcjpodW50ZXIy",
            "SECRETPATH",
            "one-time-ticket",
            "hunter2",
        ):
            assert secret not in text, secret

    def test_configured_json_logger_never_emits_password(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_logging(TelemetrySettings(log_format="json"))
        get_logger("t").info("login", username="alice", password="hunter2")
        captured = capsys.readouterr().err
        assert "hunter2" not in captured and "alice" in captured
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

    @pytest.mark.parametrize("log_format", ["console", "json"])
    def test_exception_logs_never_include_frame_locals_or_message_secrets(
        self, capsys: pytest.CaptureFixture[str], log_format: str
    ) -> None:
        # Regression: rich console tracebacks printed every frame's local variables,
        # which put settings objects (JWT secret, bootstrap password) into the log.
        configure_logging(TelemetrySettings(log_format=log_format))

        def fail() -> None:
            jwt_secret = "local-variable-secret-0123456789abcdef"
            assert jwt_secret
            raise RuntimeError("connect failed postgresql://svc:hunter2@db/sentinelx")

        try:
            fail()
        except RuntimeError:
            get_logger("t").exception("unhandled_error")
        captured = capsys.readouterr().err
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
        assert "RuntimeError" in captured
        assert "local-variable-secret" not in captured
        assert "hunter2" not in captured
