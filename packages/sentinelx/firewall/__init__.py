"""Firewall adapters."""

from sentinelx.common.errors import FirewallError
from sentinelx.config.settings import ResponseSettings
from sentinelx.firewall.base import BlockEntry, CommandResult, CommandRunner, FirewallAdapter
from sentinelx.firewall.memory import MemoryFirewall, NullFirewall

__all__ = [
    "BlockEntry",
    "CommandResult",
    "CommandRunner",
    "FirewallAdapter",
    "MemoryFirewall",
    "NullFirewall",
    "create_firewall",
]


def create_firewall(settings: ResponseSettings) -> FirewallAdapter:
    """Build the configured adapter.

    Raises:
        FirewallError: when a real backend is requested but its binary is missing.
    """
    if settings.firewall_backend == "nftables":
        from sentinelx.firewall.nftables import NftablesAdapter

        return NftablesAdapter(
            table=settings.nft_table,
            set_prefix=settings.nft_set,
            family=settings.nft_family,
            rate_limit_pps=settings.rate_limit_packets_per_second,
        )
    if settings.firewall_backend == "iptables":
        from sentinelx.firewall.iptables import IptablesAdapter

        return IptablesAdapter(rate_limit_pps=settings.rate_limit_packets_per_second)
    if settings.firewall_backend == "null":
        return NullFirewall()
    raise FirewallError(f"unknown firewall backend {settings.firewall_backend!r}")
