"""DNS behaviour detection.

DNS is the channel malware reaches for when everything else is blocked, because
almost no network blocks outbound DNS.  Two patterns are covered:

* **Tunnelling / exfiltration** - data encoded into query labels, which makes the
  labels unusually long and unusually random (high Shannon entropy).
* **Query floods / DGA** - a client resolving a very large number of distinct
  names, most of which do not exist, as domain-generation-algorithm malware does
  while searching for its command-and-control server.
"""

from __future__ import annotations

from sentinelx.common.enums import ActionType, Severity, ThreatCategory
from sentinelx.common.models import Detection, Evidence
from sentinelx.detection.base import Detector
from sentinelx.features.extractor import FeatureContext

__all__ = ["DnsAnomalyDetector"]


class DnsAnomalyDetector(Detector):
    """Suspicious DNS: tunnelling-shaped labels or query floods."""

    name = "dns_anomaly"
    description = "DNS queries with tunnelling characteristics or at flood volume."
    category = ThreatCategory.EXFILTRATION
    default_severity = Severity.MEDIUM
    references = (
        "https://attack.mitre.org/techniques/T1071/004/",
        "https://attack.mitre.org/techniques/T1568/002/",
    )

    #: Minimum suspicious queries before the tunnelling path reports. One long
    #: random label is a CDN hostname; dozens is a channel.
    _MIN_SUSPICIOUS_QUERIES = 20

    def inspect(self, context: FeatureContext) -> Detection | None:
        dns = context.packet.metadata.get("dns")
        if not isinstance(dns, dict) or dns.get("is_response"):
            return None
        self.evaluations += 1
        return self._tunnelling(context, dns) or self._flood(context)

    def _tunnelling(self, context: FeatureContext, dns: dict[str, object]) -> Detection | None:
        settings = self.settings
        raw_length = dns.get("max_label_length")
        raw_entropy = dns.get("name_entropy")
        label_length = raw_length if isinstance(raw_length, int) else 0
        entropy = float(raw_entropy) if isinstance(raw_entropy, (int, float)) else 0.0
        if (
            label_length < settings.dns_long_label_length
            and entropy < settings.dns_high_entropy_threshold
        ):
            return None

        profile = context.profile
        suspicious_count = len(profile.dns_suspicious)
        if suspicious_count < self._MIN_SUSPICIOUS_QUERIES:
            return None

        parent, parent_count = profile.dns_suspicious.most_common(1)[0]
        # Tunnels concentrate on one parent domain the attacker controls. Spread
        # across many parents, long names are far more likely to be CDN noise.
        concentration = parent_count / suspicious_count
        if concentration < 0.6:
            return None

        span = max(profile.dns_queries.span(), 0.001)
        evidence = [
            Evidence(
                key="suspicious_queries",
                value=suspicious_count,
                threshold=self._MIN_SUSPICIOUS_QUERIES,
                description=f"{suspicious_count} queries with long or high-entropy labels in {span:.0f}s",
                weight=1.0,
            ),
            Evidence(
                key="max_label_length",
                value=label_length,
                threshold=settings.dns_long_label_length,
                description=(
                    f"labels up to {label_length} characters long (legitimate hostnames rarely "
                    f"exceed {settings.dns_long_label_length})"
                ),
                weight=0.8,
            ),
            Evidence(
                key="label_entropy",
                value=round(entropy, 2),
                threshold=settings.dns_high_entropy_threshold,
                description=f"label entropy {entropy:.2f} bits/char, consistent with encoded data",
                weight=0.8,
            ),
            Evidence(
                key="parent_domain",
                value=parent,
                description=f"{concentration:.0%} of these queries target one domain: {parent}",
                weight=0.9,
            ),
        ]
        if dns.get("query_type") in {"TXT", "NULL", "CNAME"}:
            evidence.append(
                Evidence(
                    key="query_type",
                    value=dns["query_type"],
                    description=f"uses {dns['query_type']} records, which carry the most data per response",
                    weight=0.5,
                )
            )

        self.hits += 1
        return self.build(
            context=context,
            title="Possible DNS tunnelling",
            description=(
                f"{context.packet.src_ip} sent {suspicious_count} DNS queries with encoded-looking "
                f"labels under {parent}."
            ),
            evidence=evidence,
            confidence=self.scaled_confidence(
                suspicious_count,
                self._MIN_SUSPICIOUS_QUERIES,
                floor=0.6,
                ceiling=0.92,
                saturation=5.0,
            ),
            severity=Severity.HIGH,
            recommended_action=ActionType.ALERT,
            observation_window=round(span, 3),
            packet_count=len(profile.packets),
            tags=("dns", "tunnel", parent),
        )

    def _flood(self, context: FeatureContext) -> Detection | None:
        settings = self.settings
        profile = context.profile
        window = settings.dns_window_seconds
        count = profile.dns_times.count(window, context.now)
        unique = profile.dns_queries.distinct
        if count < settings.dns_query_threshold and unique < settings.dns_unique_domain_threshold:
            return None

        rate = count / window
        evidence = [
            Evidence(
                key="dns_queries",
                value=count,
                threshold=settings.dns_query_threshold,
                description=f"{count} DNS queries in {window:.0f}s ({rate:.1f}/s)",
                weight=0.9,
            ),
            Evidence(
                key="unique_domains",
                value=unique,
                threshold=settings.dns_unique_domain_threshold,
                description=(
                    f"{unique} distinct names resolved - a normal client repeats a small set"
                ),
                weight=1.0,
            ),
        ]
        self.hits += 1
        return self.build(
            context=context,
            title="Abnormal DNS query volume",
            description=f"{context.packet.src_ip} resolved {unique} distinct names ({count} queries) in {window:.0f}s.",
            evidence=evidence,
            confidence=self.scaled_confidence(
                max(
                    count / settings.dns_query_threshold,
                    unique / settings.dns_unique_domain_threshold,
                ),
                1.0,
                floor=0.55,
                ceiling=0.9,
                saturation=4.0,
            ),
            severity=Severity.MEDIUM,
            recommended_action=ActionType.ALERT,
            observation_window=window,
            packet_count=len(profile.packets),
            tags=("dns", "volume"),
        )
