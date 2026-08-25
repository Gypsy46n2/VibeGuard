"""VibeGuard disaster_recovery rule pack.

Backups, restore verification, container data durability, incident readiness, and
— gated to LARGE projects only — chaos engineering and failover posture.

Most of this pack reports *absence of evidence*: static analysis can see whether a
backup job is committed, never whether one runs. Those rules are MEDIUM/LOW
confidence and INFORMATIONAL so the checklist resolves them to REVIEW_REQUIRED.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.disaster_recovery.backups import (
    NoBackupConfigurationRule,
    UnverifiedBackupRestoreRule,
)
from vibeguard.rules.disaster_recovery.readiness import IncidentReadinessRule
from vibeguard.rules.disaster_recovery.resilience import (
    FailoverStrategyRule,
    FailureInjectionRule,
)
from vibeguard.rules.disaster_recovery.sqlite_container import SqliteInContainerRule

RULES: list[type[Rule]] = [
    NoBackupConfigurationRule,  # VG-DR-001
    UnverifiedBackupRestoreRule,  # VG-DR-002
    SqliteInContainerRule,  # VG-DR-003
    IncidentReadinessRule,  # VG-DR-004
    FailureInjectionRule,  # VG-DR-005
    FailoverStrategyRule,  # VG-DR-006
]

__all__ = [
    "FailoverStrategyRule",
    "FailureInjectionRule",
    "IncidentReadinessRule",
    "NoBackupConfigurationRule",
    "RULES",
    "SqliteInContainerRule",
    "UnverifiedBackupRestoreRule",
]
