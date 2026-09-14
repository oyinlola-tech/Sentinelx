from __future__ import annotations

import pytest

from sentinelx.common.enums import ActionType, RiskBand, Severity, UserRole
from sentinelx.common.models import Detection, Evidence, FlowKey, RiskAssessment, TcpFlags
from sentinelx.common.netutils import (
    in_any_network,
    is_special,
    parse_ip,
    parse_network,
    parse_networks,
)


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, RiskBand.INFORMATIONAL),
        (20, RiskBand.INFORMATIONAL),
        (21, RiskBand.LOW),
        (40, RiskBand.LOW),
        (41, RiskBand.MEDIUM),
        (61, RiskBand.HIGH),
        (80, RiskBand.HIGH),
        (81, RiskBand.CRITICAL),
        (100, RiskBand.CRITICAL),
    ],
)
def test_risk_band_boundaries_match_documented_scale(score: float, band: RiskBand) -> None:
    assert RiskBand.from_score(score) is band


def test_tcp_flags_round_trip_every_value() -> None:
    for value in range(256):
        assert TcpFlags.from_int(value).to_int() == value


def test_tcp_flag_labels() -> None:
    assert TcpFlags.from_int(0x12).label() == "SA"
    assert TcpFlags.from_int(0x02).is_syn_only
    assert not TcpFlags.from_int(0x12).is_syn_only
    assert TcpFlags.from_int(0).label() == "."


def test_flow_key_canonical_is_direction_independent() -> None:
    forward = FlowKey("10.0.0.1", "10.0.0.2", 5000, 22, "tcp")  # type: ignore[arg-type]
    assert forward.canonical() == forward.reversed().canonical()


def test_detection_rejects_out_of_range_confidence() -> None:
    with pytest.raises(ValueError, match="confidence"):
        Detection(
            detector="d",
            category="other",
            severity=Severity.LOW,
            confidence=1.2,  # type: ignore[arg-type]
            title="t",
            description="d",
            source_ip="1.1.1.1",
        )


def test_detection_explain_includes_every_evidence_line() -> None:
    detection = Detection(
        detector="tcp_port_scan",
        category="reconnaissance",
        severity=Severity.HIGH,
        confidence=0.9,  # type: ignore[arg-type]
        title="TCP port scan",
        description="d",
        source_ip="203.0.113.5",
        evidence=[Evidence("a", 94, "94 destination ports"), Evidence("b", 12, "12 second window")],
        recommended_action=ActionType.TEMPORARY_BLOCK,
    )
    text = detection.explain()
    assert (
        "94 destination ports" in text and "12 second window" in text and "temporary_block" in text
    )


def test_risk_assessment_rejects_out_of_range_score() -> None:
    with pytest.raises(ValueError):
        RiskAssessment(score=101, band=RiskBand.CRITICAL, contributions={}, rationale=[])


def test_severity_and_role_ordering() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert UserRole.ADMIN.can_act_as(UserRole.ANALYST)
    assert not UserRole.VIEWER.can_act_as(UserRole.ANALYST)
    assert ActionType.BLOCK_IP.is_preventive and not ActionType.ALERT.is_preventive


@pytest.mark.parametrize("bad", ["", "1.2.3", "1.2.3.4.5", "abc", "1.2.3.4; ls", "999.1.1.1"])
def test_parse_ip_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_ip(bad)


def test_parse_networks_reports_all_failures() -> None:
    with pytest.raises(ValueError) as excinfo:
        parse_networks(["10.0.0.0/8", "x", "y"])
    assert "'x'" in str(excinfo.value) and "'y'" in str(excinfo.value)


def test_in_any_network_never_mixes_families() -> None:
    assert not in_any_network(parse_ip("10.0.0.1"), [parse_network("::/0")])
    assert in_any_network(parse_ip("10.0.0.1"), [parse_network("10.0.0.0/8")])


@pytest.mark.parametrize(
    ("address", "special"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("169.254.3.3", True),
        ("224.0.0.5", True),
        ("0.0.0.0", True),
        ("8.8.8.8", False),
        ("10.1.1.1", False),
    ],
)
def test_is_special(address: str, special: bool) -> None:
    assert is_special(parse_ip(address)) is special
