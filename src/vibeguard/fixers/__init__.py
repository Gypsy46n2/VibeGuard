"""Repair engine and git safety net — ARCHITECTURE.md §7, INTERFACES.md §5."""

from vibeguard.fixers.engine import FixerEngine
from vibeguard.fixers.git_safety import (
    BACKUP_SUFFIX,
    BRANCH_PREFIX,
    CO_AUTHOR_TRAILER,
    DirtyWorktreeError,
    GitCommandError,
    GitSafety,
    GitSafetyError,
    NoGitRepoError,
)

__all__ = [
    "BACKUP_SUFFIX",
    "BRANCH_PREFIX",
    "CO_AUTHOR_TRAILER",
    "DirtyWorktreeError",
    "FixerEngine",
    "GitCommandError",
    "GitSafety",
    "GitSafetyError",
    "NoGitRepoError",
]
