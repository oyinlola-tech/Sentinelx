"""Optional machine-learning anomaly detection (Isolation Forest).

What this is, and is not.  An Isolation Forest trained on a sensor's own normal
traffic learns which *combinations* of per-source behaviour are rare there.  It is
useful for surfacing sources worth a look that no rule describes.  It does not
"detect cyberattacks": rare is not malicious, attacks that resemble normal traffic
are invisible to it, and its quality depends entirely on the training capture
having been genuinely clean.  Treat its output as a lead, which is why detections
are capped at medium confidence and never recommend blocking.

Training is offline and separate from detection::

    sentinelx anomaly train normal-week.pcap --output models/isolation_forest.joblib

Model files are pickles, and loading a pickle executes code.  :func:`load_model`
therefore refuses files that are group- or world-writable, or not owned by the
current user, and every model carries a metadata block (version, feature list,
training size) that is checked against this code before use.
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sentinelx.common.enums import ActionType, Severity, ThreatCategory
from sentinelx.common.errors import ConfigurationError
from sentinelx.common.models import Detection, Evidence
from sentinelx.config.settings import AnomalySettings, DetectionSettings
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext

__all__ = [
    "FEATURE_NAMES",
    "MODEL_FORMAT_VERSION",
    "MlAnomalyDetector",
    "ModelBundle",
    "collect_training_vectors",
    "feature_vector",
    "load_model",
    "save_model",
    "train_model",
]

MODEL_FORMAT_VERSION: Final = 2  # 2: log1p-scaled counts

#: The vector the model sees, in order. Changing this invalidates saved models,
#: which is why it is versioned together with MODEL_FORMAT_VERSION.
FEATURE_NAMES: Final[tuple[str, ...]] = (
    "packet_rate",
    "unique_dst_ports",
    "unique_dst_ips",
    "unique_udp_ports",
    "syn_ratio",
    "syn_ack_ratio",
    "refusal_ratio",
    "short_sessions",
    "icmp_count",
    "dns_query_count",
    "dns_unique_domains",
    "http_request_count",
    "packet_size_mean",
    "packet_size_stddev",
)


#: Features already bounded to 0-1; everything else is a heavy-tailed count or rate.
_RATIO_FEATURES: Final = frozenset({"syn_ratio", "syn_ack_ratio", "refusal_ratio"})


def feature_vector(features: dict[str, Any]) -> list[float]:
    """Model input, with ``log1p`` applied to counts and rates.

    Network counts are heavy-tailed: a server legitimately reaches hundreds of
    distinct ports while a client touches two. On the raw scale that spread
    dominates the forest's random splits and hides deviations in the bounded ratio
    features, which is where scanning and brute force actually differ from normal.
    """
    import math

    return [
        float(features.get(name) or 0.0)
        if name in _RATIO_FEATURES
        else math.log1p(max(float(features.get(name) or 0.0), 0.0))
        for name in FEATURE_NAMES
    ]


@dataclass(slots=True)
class ModelBundle:
    model: Any
    version: str
    trained_at: str
    samples: int
    contamination: float
    feature_names: tuple[str, ...]
    score_floor: float
    """Lowest raw ``score_samples`` value seen in training (maps to 1.0)."""
    score_ceiling: float
    """The fitted model's decision boundary, ``offset_`` (maps to 0.0)."""

    def info(self) -> dict[str, Any]:
        return {
            "model": "IsolationForest",
            "version": self.version,
            "trained_at": self.trained_at,
            "samples": self.samples,
            "contamination": self.contamination,
            "features": list(self.feature_names),
        }


def train_model(
    vectors: list[list[float]], *, contamination: float = 0.02, seed: int = 0
) -> ModelBundle:
    """Fit an Isolation Forest on feature vectors from known-normal traffic.

    Raises:
        ValueError: with fewer than 50 samples - a forest fitted on a handful of
            points describes nothing and would flag almost everything.
    """
    if len(vectors) < 50:
        raise ValueError(
            f"need at least 50 training samples, got {len(vectors)}; capture more normal traffic"
        )
    require_ml_dependencies()
    import numpy as np
    from sklearn.ensemble import IsolationForest

    data = np.asarray(vectors, dtype=float)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(data)
    scores = model.score_samples(data)
    return ModelBundle(
        model=model,
        version=f"{MODEL_FORMAT_VERSION}.{datetime.now(UTC):%Y%m%d%H%M%S}",
        trained_at=datetime.now(UTC).isoformat(),
        samples=len(vectors),
        contamination=contamination,
        feature_names=FEATURE_NAMES,
        # 0.0 at the model's own contamination boundary, 1.0 at the most anomalous
        # point in the training data. Anything the model considers inside normal
        # therefore scores 0, rather than scoring against the median as before,
        # which flagged ordinary servers in held-out normal traffic.
        score_floor=float(scores.min()),
        score_ceiling=float(model.offset_),
    )


def require_ml_dependencies() -> None:
    """Raise a clear error when the optional machine-learning packages are missing.

    Raises:
        ConfigurationError: naming the extra to install.
    """
    import importlib.util

    missing = [
        name for name in ("numpy", "sklearn", "joblib") if importlib.util.find_spec(name) is None
    ]
    if missing:
        raise ConfigurationError(
            "the optional machine-learning detector needs "
            + ", ".join(missing)
            + ' (install with: pip install "sentinelx[ml]")'
        )


def save_model(bundle: ModelBundle, path: Path) -> None:
    require_ml_dependencies()
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"format": MODEL_FORMAT_VERSION, **{k: getattr(bundle, k) for k in bundle.__slots__}}, path
    )
    path.chmod(0o600)


def _check_file_is_trusted(path: Path) -> None:
    """Refuse model files (and directories) another local user could have replaced.

    A model is unpickled, so whoever can write it can run code as SentinelX. POSIX
    permission bits are checked; on Windows every writable file reports mode 0o666 and
    ownership is expressed in ACLs, so the POSIX checks would reject every model there
    and are skipped (keep the model directory under a profile only you can write).
    """
    if os.name == "nt":
        return
    info = path.stat()
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigurationError(
            f"refusing to load {path}: it is group- or world-writable (chmod 600 it)"
        )
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ConfigurationError(f"refusing to load {path}: it is not owned by the current user")
    parent = path.parent.stat()
    writable_by_others = parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    sticky = parent.st_mode & stat.S_ISVTX
    if writable_by_others and not sticky:
        raise ConfigurationError(
            f"refusing to load {path}: its directory {path.parent} is writable by other "
            "users, who could replace the model (chmod 700 the directory)"
        )


def load_model(path: Path) -> ModelBundle:
    """Load a trained model after checking the file's ownership and permissions.

    Raises:
        ConfigurationError: when the file is missing, untrusted or incompatible.
    """
    if not path.is_file():
        raise ConfigurationError(
            f"model file not found: {path}; train one with 'sentinelx anomaly train'"
        )
    _check_file_is_trusted(path)
    require_ml_dependencies()
    import joblib

    data = joblib.load(path)
    if not isinstance(data, dict) or data.get("format") != MODEL_FORMAT_VERSION:
        raise ConfigurationError(f"{path} was produced by an incompatible version; retrain it")
    if tuple(data.get("feature_names", ())) != FEATURE_NAMES:
        raise ConfigurationError(f"{path} uses a different feature set; retrain it")
    return ModelBundle(**{k: data[k] for k in ModelBundle.__slots__})


class MlAnomalyDetector(Detector):
    """Scores each active source's behaviour vector with a trained Isolation Forest."""

    name = "ml_anomaly"
    description = (
        "Per-source behaviour that a model trained on this network's normal traffic finds rare."
    )
    category = ThreatCategory.ANOMALY
    default_severity = Severity.LOW

    def __init__(
        self,
        bundle: ModelBundle,
        anomaly: AnomalySettings | None = None,
        settings: DetectionSettings | None = None,
    ) -> None:
        super().__init__(settings)
        self.bundle = bundle
        self.anomaly = anomaly or AnomalySettings()
        #: Seconds of packet time between scoring the same source. Scoring is far
        #: more expensive than a threshold check, so it must not run per packet.
        self.rescore_interval = 5.0
        self._last_scored: dict[str, tuple[float, int]] = {}
        """source -> (packet time, packets in window) at its last scoring."""
        self.inference_seconds = 0.0

    def score(self, vector: list[float]) -> float:
        """Normalised anomaly score, 0 (typical of training data) to 1 (rarer than anything seen)."""
        raw = float(self.bundle.model.score_samples([vector])[0])
        span = self.bundle.score_ceiling - self.bundle.score_floor
        if span <= 0:
            return 0.0
        return max(0.0, min(1.0, (self.bundle.score_ceiling - raw) / span))

    def inspect(self, context: FeatureContext) -> Detection | None:
        if context.own_traffic:
            return None  # SentinelX talking to its own database or Redis
        source = context.profile.source_ip
        now = context.now
        packets = len(context.profile.packets)
        if packets < 10:
            return None  # too little behaviour to describe
        last = self._last_scored.get(source)
        # Rescore on elapsed time *or* when the source's activity has doubled, so a
        # burst shorter than the interval (a 2-second scan) is judged on its full
        # shape rather than on its first ten packets.
        if last is not None and now - last[0] < self.rescore_interval and packets < 2 * last[1]:
            return None
        self._last_scored[source] = (now, packets)
        if len(self._last_scored) > 100_000:
            self._last_scored.clear()

        self.evaluations += 1
        features = context.features()
        vector = feature_vector(features)
        started = time.perf_counter()
        score = self.score(vector)
        self.inference_seconds += time.perf_counter() - started
        if score < self.anomaly.ml_min_score:
            return None

        # Report which features are furthest from typical, so the finding is not a
        # bare number. Ranking by magnitude is a heuristic, and is labelled as one.
        notable = sorted(
            (
                (name, features.get(name) or 0)
                for name in FEATURE_NAMES
                if (features.get(name) or 0)
            ),
            key=lambda pair: float(pair[1]),
            reverse=True,
        )[:4]
        self.hits += 1
        return self.build(
            context=context,
            title="Unusual source behaviour (model)",
            description=f"The anomaly model rates {source}'s behaviour as rarer than {score:.0%} of the training data range.",
            evidence=[
                Evidence(
                    key="anomaly_score",
                    value=round(score, 3),
                    threshold=self.anomaly.ml_min_score,
                    description=f"model anomaly score {score:.2f}",
                    weight=1.0,
                ),
                Evidence(
                    key="model",
                    value=self.bundle.info(),
                    description=f"IsolationForest v{self.bundle.version}, trained on {self.bundle.samples} samples",
                    weight=0.3,
                ),
                *(
                    Evidence(
                        key=f"feature:{name}",
                        value=value,
                        description=f"{name} = {value}",
                        weight=0.4,
                    )
                    for name, value in notable
                ),
                Evidence(
                    key="interpretation",
                    value="lead",
                    weight=0.1,
                    description="statistical rarity, not proof of malice; review before acting",
                ),
            ],
            confidence=round(min(0.6, 0.3 + 0.3 * score), 3),
            severity=Severity.MEDIUM if score >= 0.95 else Severity.LOW,
            recommended_action=ActionType.ALERT,
            source_ip=source,
            tags=("anomaly", "ml"),
        )

    def stats(self) -> dict[str, object]:
        return {
            **super().stats(),
            "model": self.bundle.info(),
            "mean_inference_ms": round(1000 * self.inference_seconds / self.evaluations, 3)
            if self.evaluations
            else 0.0,
        }


def collect_training_vectors(
    frames: Any, settings: DetectionSettings | None = None, every_seconds: float = 5.0
) -> list[list[float]]:
    """Sample per-source feature vectors from (assumed normal) traffic for training.

    Samples each active source at most every ``every_seconds`` of packet time,
    mirroring how :class:`MlAnomalyDetector` scores at detection time, so the
    model trains on the same distribution it will later see.
    """
    from sentinelx.features.extractor import FeatureExtractor
    from sentinelx.parser.decoder import PacketDecoder

    decoder = PacketDecoder()
    extractor = FeatureExtractor(settings or DetectionSettings())
    last: dict[str, float] = {}
    vectors: list[list[float]] = []
    for frame in frames:
        packet = decoder.decode(
            frame.data, frame.timestamp, frame.link_type, frame.interface, frame.wire_length
        )
        if packet is None:
            continue
        context = extractor.process(packet)
        source = context.profile.source_ip
        if (
            len(context.profile.packets) < 10
            or context.now - last.get(source, -1e18) < every_seconds
        ):
            continue
        last[source] = context.now
        vectors.append(feature_vector(context.features()))
    return vectors
