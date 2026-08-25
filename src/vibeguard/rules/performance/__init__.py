"""VibeGuard performance rule pack — what happens on the request path.

Blocking calls, unbounded list responses, serverless platform limits, and heavy CPU
or memory work done inline instead of on a worker.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.performance.blocking import BlockingCallInHandlerRule
from vibeguard.rules.performance.heavy_work import HeavyWorkInRequestPathRule
from vibeguard.rules.performance.pagination import ListEndpointWithoutPaginationRule
from vibeguard.rules.performance.serverless import ServerlessLimitsIgnoredRule

RULES: list[type[Rule]] = [
    BlockingCallInHandlerRule,  # VG-PERF-001
    ListEndpointWithoutPaginationRule,  # VG-PERF-002
    ServerlessLimitsIgnoredRule,  # VG-PERF-003
    HeavyWorkInRequestPathRule,  # VG-PERF-004
]

__all__ = [
    "RULES",
    "BlockingCallInHandlerRule",
    "HeavyWorkInRequestPathRule",
    "ListEndpointWithoutPaginationRule",
    "ServerlessLimitsIgnoredRule",
]
