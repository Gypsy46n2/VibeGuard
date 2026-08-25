"""VibeGuard dependencies rule pack.

Manifest parsing only (``requirements*.txt``, ``pyproject.toml``,
``package.json``): lockfile presence, version pinning, duplicate declarations,
runtime pinning, and an honest note about what offline rules cannot know.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.dependencies.conflicts import DuplicateDependencyRule
from vibeguard.rules.dependencies.pinning import NoLockfileRule, UnpinnedDependencyRule
from vibeguard.rules.dependencies.runtime import (
    DependencyHealthUnverifiedRule,
    UnpinnedRuntimeVersionRule,
)

RULES: list[type[Rule]] = [
    NoLockfileRule,  # VG-DEPS-001
    UnpinnedDependencyRule,  # VG-DEPS-002
    DuplicateDependencyRule,  # VG-DEPS-003
    UnpinnedRuntimeVersionRule,  # VG-DEPS-004
    DependencyHealthUnverifiedRule,  # VG-DEPS-005
]

__all__ = [
    "RULES",
    "DependencyHealthUnverifiedRule",
    "DuplicateDependencyRule",
    "NoLockfileRule",
    "UnpinnedDependencyRule",
    "UnpinnedRuntimeVersionRule",
]
