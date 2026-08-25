"""VibeGuard network rule pack — delivery path and connection posture.

The ``network`` checklist section rolls up to reliability, so findings here use
:attr:`Category.RELIABILITY`.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.network.cdn import NoCdnForStaticAssetsRule
from vibeguard.rules.network.connection_reuse import NoConnectionReuseRule
from vibeguard.rules.network.protocol import NoProtocolPostureRule

RULES: list[type[Rule]] = [
    NoCdnForStaticAssetsRule,  # VG-NET-001
    NoConnectionReuseRule,  # VG-NET-002
    NoProtocolPostureRule,  # VG-NET-003
]

__all__ = [
    "RULES",
    "NoCdnForStaticAssetsRule",
    "NoConnectionReuseRule",
    "NoProtocolPostureRule",
]
