"""VibeGuard testing rule pack — which *kinds* of test the suite is missing.

``VG-MAINT-001`` (rules/core) already reports a project with no tests at all, so
every rule here returns ``[]`` when no test suite exists: one clear finding beats
five variations on the same advice.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.testing.coverage_gaps import NoDatabaseTestsRule, NoIntegrationTestsRule
from vibeguard.rules.testing.nonfunctional import NoEndToEndTestsRule, NoNonFunctionalTestsRule
from vibeguard.rules.testing.pipeline import CiDoesNotRunTestsRule

RULES: list[type[Rule]] = [
    NoIntegrationTestsRule,  # VG-TEST-001
    CiDoesNotRunTestsRule,  # VG-TEST-002
    NoDatabaseTestsRule,  # VG-TEST-003
    NoEndToEndTestsRule,  # VG-TEST-004
    NoNonFunctionalTestsRule,  # VG-TEST-005
]

__all__ = [
    "CiDoesNotRunTestsRule",
    "NoDatabaseTestsRule",
    "NoEndToEndTestsRule",
    "NoIntegrationTestsRule",
    "NoNonFunctionalTestsRule",
    "RULES",
]
