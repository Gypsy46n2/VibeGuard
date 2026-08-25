"""VibeGuard observability rule pack — can you tell what the service is doing?

Two flavours live here: line-level defects (printing instead of logging, DEBUG
pinned on) and project-level gaps (no logger, no error tracking, no health check,
no correlation ids, no metrics). The gap rules are advisory and scale-gated so a
toy project is never told to adopt an SRE practice it has no use for.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.observability.health import NoCorrelationIdRule, NoHealthCheckRule
from vibeguard.rules.observability.logging_practices import (
    DebugLogLevelRule,
    NoLoggingFrameworkRule,
    PrintDiagnosticsRule,
)
from vibeguard.rules.observability.monitoring import NoErrorTrackingRule, NoMetricsRule

RULES: list[type[Rule]] = [
    PrintDiagnosticsRule,  # VG-OBS-001
    NoLoggingFrameworkRule,  # VG-OBS-002
    NoErrorTrackingRule,  # VG-OBS-003
    NoHealthCheckRule,  # VG-OBS-004
    NoCorrelationIdRule,  # VG-OBS-005
    DebugLogLevelRule,  # VG-OBS-006
    NoMetricsRule,  # VG-OBS-007
]

__all__ = [
    "DebugLogLevelRule",
    "NoCorrelationIdRule",
    "NoErrorTrackingRule",
    "NoHealthCheckRule",
    "NoLoggingFrameworkRule",
    "NoMetricsRule",
    "PrintDiagnosticsRule",
    "RULES",
]
