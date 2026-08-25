"""VibeGuard core rule pack — stack-agnostic project hygiene rules."""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.core.no_tests import NoTestSuiteRule

RULES: list[type[Rule]] = [NoTestSuiteRule]

__all__ = ["RULES", "NoTestSuiteRule"]
