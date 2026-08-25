"""VibeGuard cost rule pack.

Spend that accrues quietly: per-row logging, per-iteration billed API calls,
container images an order of magnitude larger than they need to be, and scheduled
work or storage that keeps running long after anyone stopped looking at it.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.cost.hot_loops import BilledCallInLoopRule, LoggingInHotLoopRule
from vibeguard.rules.cost.images import OversizedBaseImageRule
from vibeguard.rules.cost.waste import WastefulWorkAndStorageRule

RULES: list[type[Rule]] = [
    LoggingInHotLoopRule,  # VG-COST-001
    BilledCallInLoopRule,  # VG-COST-002
    OversizedBaseImageRule,  # VG-COST-003
    WastefulWorkAndStorageRule,  # VG-COST-004
]

__all__ = [
    "RULES",
    "BilledCallInLoopRule",
    "LoggingInHotLoopRule",
    "OversizedBaseImageRule",
    "WastefulWorkAndStorageRule",
]
