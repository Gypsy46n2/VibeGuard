"""VibeGuard deployment rule pack.

CI configuration, deploy-pipeline safety, environment separation, and rollback
readiness. Detection parses CI YAML (guarded ``yaml.safe_load_all``) and the
repository layout rather than grepping source code.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.deployment.ci import (
    DeployWithoutTestsRule,
    NoCiConfigurationRule,
    SecretExposedInCiRule,
)
from vibeguard.rules.deployment.environments import (
    NoEnvironmentSeparationRule,
    NoRollbackProcedureRule,
    ProductionEnvFileCommittedRule,
)

RULES: list[type[Rule]] = [
    NoCiConfigurationRule,  # VG-DEP-001
    DeployWithoutTestsRule,  # VG-DEP-002
    SecretExposedInCiRule,  # VG-DEP-003
    NoEnvironmentSeparationRule,  # VG-DEP-004
    ProductionEnvFileCommittedRule,  # VG-DEP-005
    NoRollbackProcedureRule,  # VG-DEP-006
]

__all__ = [
    "RULES",
    "DeployWithoutTestsRule",
    "NoCiConfigurationRule",
    "NoEnvironmentSeparationRule",
    "NoRollbackProcedureRule",
    "ProductionEnvFileCommittedRule",
    "SecretExposedInCiRule",
]
