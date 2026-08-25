"""VG-DR-005 / VG-DR-006 — chaos engineering and failover, gated to LARGE.

Both rules exist mainly to be *silent*. A toy or small project must see these
topics reported NOT_APPLICABLE, never as advice: telling a two-file Flask app to
adopt chaos engineering or multi-region failover is exactly the overengineering
VibeGuard's scale gate is there to prevent.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.disaster_recovery._signals import find_markers, name_hits

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["FailureInjectionRule", "FailoverStrategyRule"]

_CHAOS_RE = re.compile(
    r"chaos[- _]?mesh|chaosmesh|litmuschaos|litmus|gremlin|toxiproxy|chaos[- _]?monkey|"
    r"chaostoolkit|chaos[- _]?(?:test|experiment|engineering)|fault[- _]?injection|"
    r"failure[- _]?injection|pumba|powerfulseal",
    re.IGNORECASE,
)
_CHAOS_NAME_HINTS = ("chaos", "toxiproxy", "fault_injection", "fault-injection")

_FAILOVER_RE = re.compile(
    r"multi[- _]?region|multi[- _]?az|multiaz|availability_zones|failover|"
    r"standby|hot[- _]?spare|read[- _]?replica|replica_count|replicaCount|"
    r"global[- _]?accelerator|route53.*health|health[- _]?check[- _]?(?:routing|policy)|"
    r"traffic[- _]?(?:manager|director|steering)|geo[- _]?routing|"
    r"cross[- _]?region|disaster[- _]?recovery[- _]?(?:region|site)",
    re.IGNORECASE,
)


class FailureInjectionRule(ProjectRule):
    """No chaos or fault-injection tooling in a large system."""

    id: ClassVar[str] = "VG-DR-005"
    category: ClassVar[Category] = Category.DISASTER_RECOVERY
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "Failure injection never exercised"
    description: ClassVar[str] = (
        "No chaos or fault-injection tooling was found in a system large enough that "
        "partial failure is the normal operating state."
    )
    why_it_matters: ClassVar[str] = (
        "Once a system spans several services, something is always broken somewhere — a "
        "slow dependency, a dropped connection, a restarting pod. Systems that have never "
        "had failure deliberately injected tend to fail in surprising, correlated ways the "
        "first time it happens for real, usually under peak load."
    )
    references: ClassVar[list[str]] = [
        "https://principlesofchaos.org/",
        "https://chaos-mesh.org/docs/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"disaster-recovery.chaos-engineering"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.LARGE
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Start with one cheap experiment in staging: put toxiproxy in front of your "
        "slowest dependency, add 500ms of latency, and assert the service still serves "
        "traffic — then promote the experiment into a scheduled job."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if find_markers(ctx, _CHAOS_RE, max_hits=1) or name_hits(
            ctx, _CHAOS_NAME_HINTS, max_hits=1
        ):
            return None
        return (
            "This project is classified LARGE "
            f"({ctx.scale.loc} LOC, {ctx.scale.service_count} service(s)) but no chaos or "
            "fault-injection tooling was found — no chaos-mesh, litmus, gremlin, "
            "toxiproxy, and no fault-injection test suite. VibeGuard can only observe that "
            "no such tooling is committed here; it cannot tell whether failure modes have "
            "been rehearsed some other way.",
            "searched for chaos-mesh, litmus, gremlin, toxiproxy, chaos-monkey, and "
            "fault-injection tests",
        )


class FailoverStrategyRule(ProjectRule):
    """No failover, standby, or multi-region strategy in a large system."""

    id: ClassVar[str] = "VG-DR-006"
    category: ClassVar[Category] = Category.DISASTER_RECOVERY
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "No failover or multi-region strategy"
    description: ClassVar[str] = (
        "A large deployment shows a single region, a single replica, and no failover, "
        "standby, multi-AZ, or health-based traffic-steering configuration."
    )
    why_it_matters: ClassVar[str] = (
        "At this size an outage of one zone, one region, or one database primary takes the "
        "whole product down, and recovery means a human rebuilding infrastructure under "
        "pressure. Deciding in advance what fails over where — and proving it — is the "
        "difference between a few minutes of degradation and a day-long outage."
    )
    references: ClassVar[list[str]] = [
        "https://aws.amazon.com/builders-library/static-stability-using-availability-zones/",
        "https://sre.google/sre-book/managing-critical-state/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "disaster-recovery.failover",
        "disaster-recovery.multi-region-readiness",
        "scaling.multi-region-deployment",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.LARGE
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Write down the intended failure domain first (single AZ? single region?), then "
        "make it real: run the stateless tier across at least two availability zones, "
        "enable a standby or read replica for the primary datastore, and route traffic "
        "through a health-checked endpoint so an unhealthy zone drops out automatically."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        hits = find_markers(ctx, _FAILOVER_RE, max_hits=1)
        if hits:
            return None
        return (
            "This project is classified LARGE "
            f"({ctx.scale.loc} LOC, {ctx.scale.service_count} service(s)) but no failover "
            "or redundancy configuration was found: no multi-AZ or multi-region setting, "
            "no standby or read replica, no replica count above one, and no health-based "
            "traffic steering. VibeGuard is reporting the absence of a configured "
            "strategy in this repository, not that a failover has been shown to fail.",
            "searched IaC, manifests, and docs for multi-region, multi-AZ, failover, "
            "standby, read replica, and health-checked traffic steering",
        )


RULES: list[type[Rule]] = [FailureInjectionRule, FailoverStrategyRule]
