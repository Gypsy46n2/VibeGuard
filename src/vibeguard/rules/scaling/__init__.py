"""VibeGuard scaling rule pack.

The four ways a vibe-coded app stops working the moment a second instance starts:
state in process memory, uploads on local disk, a per-process cache, and slow work
done inline instead of queued.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.scaling.caching import InProcessCacheRule
from vibeguard.rules.scaling.state import InProcessStateRule
from vibeguard.rules.scaling.storage import LocalUploadStorageRule
from vibeguard.rules.scaling.workers import InlineLongRunningWorkRule

RULES: list[type[Rule]] = [
    InProcessStateRule,  # VG-SCALE-001
    LocalUploadStorageRule,  # VG-SCALE-002
    InProcessCacheRule,  # VG-SCALE-003
    InlineLongRunningWorkRule,  # VG-SCALE-004
]

__all__ = [
    "InProcessCacheRule",
    "InProcessStateRule",
    "InlineLongRunningWorkRule",
    "LocalUploadStorageRule",
    "RULES",
]
