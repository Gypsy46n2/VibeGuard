"""VibeGuard database rule pack — VG-DB-001 … VG-DB-010.

Grouped by what they look at:

``queries``      how the application talks to the database (VG-DB-001/003/007)
``connections``  connection lifecycle and pooling (VG-DB-002)
``schema``       what the schema declares and enforces (VG-DB-004/008)
``migrations``   schema change safety and versioning (VG-DB-005/006)
``scaleout``     scale-gated review prompts (VG-DB-009/010)
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.database.connections import ConnectionPerRequestRule
from vibeguard.rules.database.migrations import (
    DestructiveMigrationRule,
    NoMigrationToolingRule,
)
from vibeguard.rules.database.queries import (
    NPlusOneQueryRule,
    SelectStarRule,
    UntransactedMultiWriteRule,
)
from vibeguard.rules.database.scaleout import IsolationAndLockingRule, ScaleOutReadinessRule
from vibeguard.rules.database.schema import IntegrityConstraintRule, MissingIndexRule

#: Registry order is rule-id order.
RULES: list[type[Rule]] = [
    NPlusOneQueryRule,  # VG-DB-001
    ConnectionPerRequestRule,  # VG-DB-002
    SelectStarRule,  # VG-DB-003
    MissingIndexRule,  # VG-DB-004
    DestructiveMigrationRule,  # VG-DB-005
    NoMigrationToolingRule,  # VG-DB-006
    UntransactedMultiWriteRule,  # VG-DB-007
    IntegrityConstraintRule,  # VG-DB-008
    IsolationAndLockingRule,  # VG-DB-009
    ScaleOutReadinessRule,  # VG-DB-010
]

__all__ = [
    "RULES",
    "ConnectionPerRequestRule",
    "DestructiveMigrationRule",
    "IntegrityConstraintRule",
    "IsolationAndLockingRule",
    "MissingIndexRule",
    "NPlusOneQueryRule",
    "NoMigrationToolingRule",
    "ScaleOutReadinessRule",
    "SelectStarRule",
    "UntransactedMultiWriteRule",
]
