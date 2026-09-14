"""Test fixtures: synthetic traffic scenarios and a pcap writer.

Nothing in this package transmits packets. Scenarios build bytes in memory and
``write_pcap`` writes them to a file.
"""

from sentinelx.testing.pcap import write_pcap
from sentinelx.testing.scenarios import SCENARIOS, Scenario, get_scenario, shift_to

__all__ = ["SCENARIOS", "Scenario", "get_scenario", "shift_to", "write_pcap"]
