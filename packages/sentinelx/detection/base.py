"""The detector interface.

Every detection method - signature, threshold, behavioural, statistical, machine
learning - implements :class:`Detector` and returns :class:`Detection` objects.
That uniformity is what keeps the risk engine, the correlation engine, the API and
the dashboard detector-agnostic: adding a detector never requires changing them.

Two rules every detector must honour:

1. **Explain yourself.**  A detection without :class:`Evidence` is rejected by the
   engine.  "Malicious, trust me" is not a finding an analyst can act on.
2. **Never raise on traffic.**  Malformed or surprising traffic is the normal
   case. The engine catches exceptions and counts them, but a detector that
   relies on that is hiding a bug.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING

from sentinelx.common.enums import ActionType, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.config.settings import DetectionSettings

if TYPE_CHECKING:
    from sentinelx.features.extractor import FeatureContext

__all__ = ["Detector", "DetectorInfo"]


class DetectorInfo:
    """Static description of a detector, for the API and ``sentinelx rules list``."""

    __slots__ = ("category", "default_severity", "description", "name", "references")

    def __init__(
        self,
        name: str,
        description: str,
        category: ThreatCategory,
        default_severity: Severity,
        references: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.description = description
        self.category = category
        self.default_severity = default_severity
        self.references = references

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "default_severity": self.default_severity.value,
            "references": list(self.references),
        }


class Detector(abc.ABC):
    """Base class for all detectors.

    Subclasses implement :meth:`inspect`, which is called once per packet with the
    fully populated :class:`FeatureContext`.  Returning ``None`` (the common case)
    means "nothing to report".

    Detectors are *stateless with respect to counting*: all the counting lives in
    the feature extractor.  A detector's job is to decide whether the numbers it is
    handed constitute a finding, and to explain why.
    """

    #: Stable identifier. Appears in metrics, the API and rule ``detector`` fields,
    #: so it must not change once released.
    name: str = "unnamed"
    description: str = ""
    category: ThreatCategory = ThreatCategory.OTHER
    default_severity: Severity = Severity.MEDIUM
    references: tuple[str, ...] = ()

    def __init__(self, settings: DetectionSettings | None = None) -> None:
        self.settings = settings or DetectionSettings()
        self.enabled = True
        self.evaluations = 0
        self.hits = 0

    @abc.abstractmethod
    def inspect(self, context: FeatureContext) -> Detection | None:
        """Examine one packet in context.

        Returns:
            A :class:`Detection` when the traffic meets this detector's criteria,
            otherwise ``None``. Must not raise for any input.
        """

    # ------------------------------------------------------------- helpers

    def build(
        self,
        *,
        context: FeatureContext,
        title: str,
        description: str,
        evidence: list[Evidence],
        confidence: float,
        severity: Severity | None = None,
        recommended_action: ActionType = ActionType.ALERT,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        observation_window: float | None = None,
        packet_count: int | None = None,
        tags: tuple[str, ...] = (),
    ) -> Detection:
        """Construct a :class:`Detection` with this detector's identity filled in.

        Using this rather than building ``Detection`` directly keeps detector
        metadata (name, category, protocol) consistent and means a new field on
        ``Detection`` needs updating in one place.
        """
        packet = context.packet
        return Detection(
            detector=self.name,
            category=self.category,
            severity=severity or self.default_severity,
            confidence=confidence,
            title=title,
            description=description,
            source_ip=source_ip or packet.src_ip,
            destination_ip=destination_ip if destination_ip is not None else packet.dst_ip,
            source_port=packet.src_port,
            destination_port=(
                destination_port if destination_port is not None else packet.dst_port
            ),
            protocol=packet.protocol,
            evidence=evidence,
            recommended_action=recommended_action,
            observation_window_seconds=observation_window,
            packet_count=packet_count,
            tags=tags,
        )

    @staticmethod
    def scaled_confidence(
        observed: float,
        threshold: float,
        *,
        floor: float = 0.55,
        ceiling: float = 0.98,
        saturation: float = 3.0,
    ) -> float:
        """Confidence that grows with how far past the threshold the value is.

        A source one port over the scan threshold is a borderline call; one at ten
        times the threshold is not. Encoding that as a curve rather than a constant
        is what lets the risk engine separate the two, and what keeps a
        conservative threshold from producing uniformly over-confident alerts.

        The value saturates at ``ceiling`` - never 1.0, because a single detector
        looking at one window is never certain.
        """
        if threshold <= 0:
            return floor
        ratio = observed / threshold
        if ratio <= 1.0:
            return floor
        progress = min((ratio - 1.0) / max(saturation - 1.0, 1e-9), 1.0)
        return round(floor + (ceiling - floor) * progress, 4)

    def info(self) -> DetectorInfo:
        return DetectorInfo(
            name=self.name,
            description=self.description or (self.__doc__ or "").strip().split("\n")[0],
            category=self.category,
            default_severity=self.default_severity,
            references=self.references,
        )

    def stats(self) -> dict[str, object]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "evaluations": self.evaluations,
            "hits": self.hits,
        }

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} enabled={self.enabled}>"
