"""VG-CTR-012 — no progressive rollout or autoscaling configuration."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.containers._parse import (
    compose_files,
    compose_services,
    k8s_documents,
    workload_documents,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoProgressiveRolloutRule"]

#: Kinds that already provide autoscaling or progressive delivery.
_SCALING_KINDS = frozenset(
    {
        "HorizontalPodAutoscaler",
        "VerticalPodAutoscaler",
        "ScaledObject",
        "ScaledJob",
        "Rollout",
        "Canary",
        "AnalysisTemplate",
        "PodDisruptionBudget",
    }
)
_TRAFFIC_KINDS = frozenset({"VirtualService", "DestinationRule", "TrafficSplit", "HTTPRoute"})


def _has_rolling_strategy(doc: dict[str, Any]) -> bool:
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return False
    strategy = spec.get("strategy") or spec.get("updateStrategy")
    if not isinstance(strategy, dict):
        return False
    rolling = strategy.get("rollingUpdate")
    return isinstance(rolling, dict) and bool(rolling)


class NoProgressiveRolloutRule(ProjectRule):
    """An orchestrated project deploying with no rollout or autoscaling story."""

    id: ClassVar[str] = "VG-CTR-012"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No progressive rollout or autoscaling configuration"
    description: ClassVar[str] = (
        "The project runs an orchestrator but configures no tuned rolling update, no "
        "autoscaler, no canary or blue-green mechanism, and no Helm-style packaging."
    )
    why_it_matters: ClassVar[str] = (
        "Every deploy is then all-or-nothing: a bad build reaches 100% of users at once, "
        "and the only recovery is a hand-run rollback while the site is down. Without an "
        "autoscaler the same fixed replica count has to cover both the quiet night and the "
        "traffic spike, so you are either paying for idle capacity or falling over. This is "
        "a review item, not a defect — small deployments legitimately live without it."
    )
    references: ClassVar[list[str]] = [
        "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy",
        "https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/",
    ]
    topics: ClassVar[set[str]] = {
        "containers.rolling-deployments",
        "containers.blue-green-deployments",
        "containers.canary-releases",
        "containers.autoscaling-config",
        "containers.horizontal-scaling",
        "containers.helm-charts",
        "scaling.autoscaling",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Pick the smallest option that fits: tune `strategy.rollingUpdate` "
        "(`maxUnavailable: 0`, `maxSurge: 1`) on each Deployment, add a "
        "HorizontalPodAutoscaler driven by CPU or a queue depth, and package the manifests "
        "as a Helm chart (or Kustomize overlay) so a rollback is one versioned command."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        if not super().applicable(ctx):
            return False
        return bool(self._orchestrator(ctx))

    @staticmethod
    def _orchestrator(ctx: ScanContext) -> str:
        if workload_documents(ctx):
            return "kubernetes"
        for rel in compose_files(ctx):
            if len(compose_services(ctx, rel)) > 1:
                return "docker-compose"
        return ""

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        orchestrator = self._orchestrator(ctx)
        if not orchestrator:
            return None

        present: list[str] = []
        for _rel, doc in k8s_documents(ctx):
            kind = str(doc.get("kind"))
            if kind in _SCALING_KINDS:
                present.append(kind)
            elif kind in _TRAFFIC_KINDS:
                present.append(f"{kind} (traffic splitting)")
            elif _has_rolling_strategy(doc):
                present.append(f"{kind} rollingUpdate tuning")
        if any(
            PurePosixPath(rel).name.lower() in {"chart.yaml", "kustomization.yaml"}
            for rel in ctx.files
        ):
            present.append("Helm/Kustomize packaging")
        if present:
            return None

        return (
            f"The project is orchestrated with {orchestrator} but no progressive rollout "
            "(tuned rollingUpdate, canary, blue-green), no autoscaler (HPA/KEDA), and no "
            "Helm/Kustomize packaging were found, so a bad release reaches every user at "
            "once and capacity is fixed.",
            (
                f"orchestrator={orchestrator}; searched manifests for "
                "strategy.rollingUpdate, HorizontalPodAutoscaler, KEDA ScaledObject, "
                "Argo Rollout, Flagger Canary, Istio VirtualService, Chart.yaml, "
                "kustomization.yaml"
            ),
        )
