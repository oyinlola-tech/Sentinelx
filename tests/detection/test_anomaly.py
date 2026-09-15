from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx.anomaly import StatisticalAnomalyDetector
from sentinelx.config.settings import AnomalySettings, DetectionSettings
from sentinelx.detection.engine import DetectionEngine
from sentinelx.testing import get_scenario


def run(detector, frames):  # type: ignore[no-untyped-def]
    from sentinelx.features import FeatureExtractor
    from sentinelx.parser.decoder import PacketDecoder

    engine = DetectionEngine(DetectionSettings(), detectors=[detector])
    decoder, extractor, found = PacketDecoder(), FeatureExtractor(), []
    for frame in frames:
        packet = decoder.decode(frame.data, frame.timestamp, frame.link_type)
        if packet is not None:
            found.extend(engine.evaluate(extractor.process(packet)))
    return found


class TestStatistical:
    def test_spike_after_baseline_is_detected_with_honest_evidence(self) -> None:
        detections = run(StatisticalAnomalyDetector(), get_scenario("dns_rate_spike").frames)
        assert detections, "spike was not detected"
        first = detections[0]
        evidence = first.evidence_dict()
        assert first.source_ip == "192.168.30.99" and evidence["metric"] == "dns_per_second"
        baseline = evidence["baseline"]
        # The evidence must describe the baseline the value was scored against,
        # i.e. one that has not absorbed the spike.
        assert 15 < baseline["mean"] < 25 and baseline["stddev"] < 6
        assert first.recommended_action.value == "alert"

    def test_steady_traffic_is_silent(self) -> None:
        assert (
            run(
                StatisticalAnomalyDetector(),
                get_scenario("dns_rate_spike", spike_seconds=0, baseline_seconds=300).frames,
            )
            == []
        )

    def test_no_reports_during_warmup(self) -> None:
        detector = StatisticalAnomalyDetector(AnomalySettings(min_samples=500))
        assert run(detector, get_scenario("dns_rate_spike").frames) == []

    def test_small_absolute_values_are_ignored(self) -> None:
        # 1 -> 8 queries/s is a large relative jump but below the reporting floor.
        scenario = get_scenario("dns_rate_spike", normal_qps=1, spike_qps=7, baseline_seconds=120)
        assert run(StatisticalAnomalyDetector(), scenario.frames) == []

    def test_sustained_attack_does_not_become_normal(self) -> None:
        detector = StatisticalAnomalyDetector()
        run(detector, get_scenario("dns_rate_spike", spike_seconds=60).frames)
        baseline = detector.baselines["dns_per_second"]
        # After a full minute of attack, the attack rate must still score as anomalous.
        assert baseline.anomaly_score(320.0) >= AnomalySettings().anomaly_threshold
        assert baseline.stddev < 10

    def test_baseline_report_shape(self) -> None:
        report = StatisticalAnomalyDetector().baseline_report()
        assert (
            set(report) >= {"dns_per_second", "syn_per_second"}
            and report["dns_per_second"]["ready"] is False
        )


class TestMachineLearning:
    @pytest.fixture(scope="class")
    @classmethod
    def bundle(cls):  # type: ignore[no-untyped-def]
        pytest.importorskip("sklearn")
        from sentinelx.anomaly.ml import collect_training_vectors, train_model

        frames = sorted(
            (
                f
                for seed in range(1, 6)
                for f in get_scenario("normal_traffic", seed=seed, packet_count=2500).frames
            ),
            key=lambda f: f.timestamp,
        )
        return train_model(collect_training_vectors(frames), seed=1)

    def test_training_requires_enough_samples(self) -> None:
        pytest.importorskip("sklearn")
        from sentinelx.anomaly.ml import train_model

        with pytest.raises(ValueError, match="at least 50"):
            train_model([[0.0] * 14] * 10)

    def test_model_metadata_is_exposed(self, bundle) -> None:  # type: ignore[no-untyped-def]
        from sentinelx.anomaly.ml import FEATURE_NAMES

        info = bundle.info()
        assert (
            info["model"] == "IsolationForest"
            and info["features"] == list(FEATURE_NAMES)
            and info["samples"] >= 50
        )

    def test_ml_detections_are_leads_not_blocks(self, bundle) -> None:  # type: ignore[no-untyped-def]
        from sentinelx.anomaly.ml import MlAnomalyDetector

        detections = run(MlAnomalyDetector(bundle), get_scenario("tcp_port_scan").frames)
        for detection in detections:
            assert detection.recommended_action.value == "alert" and detection.confidence <= 0.6
            assert "anomaly_score" in detection.evidence_dict()

    def test_save_load_round_trip_and_untrusted_file_refused(self, bundle, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        from sentinelx.anomaly.ml import load_model, save_model
        from sentinelx.common.errors import ConfigurationError

        path = tmp_path / "model.joblib"
        save_model(bundle, path)
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert load_model(path).version == bundle.version
        path.chmod(0o666)
        with pytest.raises(ConfigurationError, match="writable"):
            load_model(path)

    def test_missing_or_incompatible_model(self, tmp_path: Path) -> None:
        pytest.importorskip("joblib")
        import joblib

        from sentinelx.anomaly.ml import load_model
        from sentinelx.common.errors import ConfigurationError

        with pytest.raises(ConfigurationError, match="not found"):
            load_model(tmp_path / "absent.joblib")
        old = tmp_path / "old.joblib"
        joblib.dump({"format": 0}, old)
        old.chmod(0o600)
        with pytest.raises(ConfigurationError, match="incompatible"):
            load_model(old)


async def test_anomaly_detector_disabled_in_dashboard_can_be_switched_back_on() -> None:
    from sentinelx.assembly import attach_anomaly_detectors
    from sentinelx.config.settings import Settings
    from sentinelx.firewall import MemoryFirewall
    from sentinelx.pipeline import Pipeline

    settings = Settings(
        storage={"database_url": "sqlite+aiosqlite:///:memory:"},
        detection={"disabled_detectors": ["statistical_anomaly"]},
    )
    pipeline = Pipeline(settings, firewall=MemoryFirewall())
    assert attach_anomaly_detectors(pipeline, settings) == ["statistical_anomaly"]
    detector = next(d for d in pipeline.detection.detectors if d.name == "statistical_anomaly")
    assert detector.enabled is False
    # Previously the detector was never attached, so this toggle returned "not found".
    assert pipeline.detection.set_enabled("statistical_anomaly", True)
    assert detector.enabled is True
