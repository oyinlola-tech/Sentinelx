"""Kernel tests: real packet capture and real firewall changes.

They need CAP_NET_RAW and CAP_NET_ADMIN and must never run against a real host's
network. ``make test-kernel`` runs them inside a private network namespace (``unshare
-rn``) with a dummy interface carrying the test addresses; anywhere else they skip.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx.system.interfaces import local_addresses
from sentinelx.system.privileges import capture_privilege, firewall_privilege

ATTACKER = "203.0.113.5"
VICTIM = "203.0.113.6"


_HERE = Path(__file__).parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    # This hook receives every collected test in the session, not only this directory's.
    kernel_items = [item for item in items if _HERE in Path(item.path).parents]
    if not kernel_items:
        return
    ready = (
        capture_privilege().granted
        and firewall_privilege().granted
        and {ATTACKER, VICTIM} <= local_addresses()
    )
    for item in kernel_items:
        item.add_marker(pytest.mark.root)
        if not ready:
            item.add_marker(
                pytest.mark.skip(
                    reason="kernel tests run only via 'make test-kernel' (private netns)"
                )
            )
