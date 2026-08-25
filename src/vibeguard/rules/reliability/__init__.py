"""VibeGuard reliability rule pack — VG-REL-001 … VG-REL-011.

Grouped by what fails:

``errors``       swallowed exceptions and leaked resources (VG-REL-001/002)
``concurrency``  event-loop blocking and unbounded fan-out (VG-REL-003/004)
``state``        unbounded caches and unsynchronised shared state (VG-REL-005/006)
``jobs``         background work and process lifecycle (VG-REL-007/008/009)
``distributed``  messaging semantics and multi-service failure modes (VG-REL-010/011)
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.reliability.concurrency import (
    BlockingCallInAsyncRule,
    UnboundedConcurrencyRule,
)
from vibeguard.rules.reliability.distributed import (
    DistributedFailureModesRule,
    MessageDeliverySemanticsRule,
)
from vibeguard.rules.reliability.errors import (
    SwallowedExceptionRule,
    UnreleasedResourceRule,
)
from vibeguard.rules.reliability.jobs import (
    JobResilienceRule,
    NoGracefulShutdownRule,
    QueueObservabilityRule,
)
from vibeguard.rules.reliability.state import SharedMutableStateRule, UnboundedCacheRule

#: Registry order is rule-id order.
RULES: list[type[Rule]] = [
    SwallowedExceptionRule,  # VG-REL-001
    UnreleasedResourceRule,  # VG-REL-002
    BlockingCallInAsyncRule,  # VG-REL-003
    UnboundedConcurrencyRule,  # VG-REL-004
    UnboundedCacheRule,  # VG-REL-005
    SharedMutableStateRule,  # VG-REL-006
    JobResilienceRule,  # VG-REL-007
    NoGracefulShutdownRule,  # VG-REL-008
    QueueObservabilityRule,  # VG-REL-009
    MessageDeliverySemanticsRule,  # VG-REL-010
    DistributedFailureModesRule,  # VG-REL-011
]

__all__ = [
    "RULES",
    "BlockingCallInAsyncRule",
    "DistributedFailureModesRule",
    "JobResilienceRule",
    "MessageDeliverySemanticsRule",
    "NoGracefulShutdownRule",
    "QueueObservabilityRule",
    "SharedMutableStateRule",
    "SwallowedExceptionRule",
    "UnboundedCacheRule",
    "UnboundedConcurrencyRule",
    "UnreleasedResourceRule",
]
