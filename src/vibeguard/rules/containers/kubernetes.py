"""VG-CTR-009, VG-CTR-010, VG-CTR-011 — Kubernetes workload hardening.

Every rule here gates on ``applicable()``: with no Kubernetes manifest in the tree
these rules must return nothing at all, so their checklist topics resolve to
NOT_APPLICABLE rather than to noise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules.containers._parse import (
    image_ref,
    pod_containers,
    pod_spec,
    tag_is_mutable,
    workload_documents,
    workload_name,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "K8sInsecureWorkloadRule",
    "K8sNoProbesRule",
    "K8sNoResourceLimitsRule",
]

_MAX = 8


class _K8sRule(Rule):
    """Base class gating on the presence of a Kubernetes workload manifest."""

    def applicable(self, ctx: ScanContext) -> bool:
        if not super().applicable(ctx):
            return False
        return bool(workload_documents(ctx))


class K8sNoProbesRule(_K8sRule):
    """Workload containers with no liveness or readiness probe."""

    id: ClassVar[str] = "VG-CTR-009"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Kubernetes workload without liveness/readiness probes"
    description: ClassVar[str] = (
        "A Deployment/StatefulSet/DaemonSet container declares no livenessProbe or "
        "readinessProbe, so Kubernetes cannot tell a healthy pod from a wedged one."
    )
    why_it_matters: ClassVar[str] = (
        "Without a readiness probe, a pod receives traffic the instant the process starts — "
        "before it has connected to the database — so every rollout drops requests. Without "
        "a liveness probe, a deadlocked pod stays in the Service endpoints forever and a "
        "share of your users get hangs and timeouts until a human notices."
    )
    references: ClassVar[list[str]] = [
        "https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/",
        "https://kubernetes.io/docs/concepts/services-networking/service/",
    ]
    topics: ClassVar[set[str]] = {
        "containers.kubernetes",
        "containers.liveness-probes",
        "containers.readiness-probes",
        "containers.startup-probes",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel, doc in workload_documents(ctx):
            for container in pod_containers(doc):
                if len(findings) >= _MAX:
                    return findings
                missing = [
                    probe
                    for probe in ("livenessProbe", "readinessProbe")
                    if not isinstance(container.get(probe), dict)
                ]
                if not missing:
                    continue
                name = str(container.get("name", "<unnamed>"))
                note = f"{doc.get('kind')} {workload_name(doc)}/{name}: missing " + ", ".join(
                    missing
                )
                if not isinstance(container.get("startupProbe"), dict):
                    note += " (and no startupProbe, which a slow-starting app also needs)"
                findings.append(
                    self.make_finding(
                        file=rel,
                        evidence=[Evidence(file=rel, note=note)],
                        description=f"{rel}: {note}.",
                        recommended_followup=(
                            f"Add a `readinessProbe` (httpGet /healthz) so `{name}` only "
                            "receives traffic once it is ready, and a `livenessProbe` with a "
                            "conservative `failureThreshold` so a wedged pod is restarted; "
                            "add a `startupProbe` if boot takes longer than the liveness "
                            "period."
                        ),
                    )
                )
        return findings


def _has_resource(container: dict[str, Any], section: str) -> bool:
    resources = container.get("resources")
    if not isinstance(resources, dict):
        return False
    block = resources.get(section)
    if not isinstance(block, dict) or not block:
        return False
    return bool(block.get("cpu") or block.get("memory"))


class K8sNoResourceLimitsRule(_K8sRule):
    """Workload containers scheduled without requests or limits."""

    id: ClassVar[str] = "VG-CTR-010"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Kubernetes workload without resource requests and limits"
    description: ClassVar[str] = (
        "A workload container declares no `resources.requests` and/or no "
        "`resources.limits`, so the scheduler is guessing and nothing caps its usage."
    )
    why_it_matters: ClassVar[str] = (
        "With no requests, the scheduler treats the pod as free and packs nodes until they "
        "tip over; with no limits, one leaking pod can consume a whole node and get its "
        "neighbours OOM-killed. Pods without requests also land in the BestEffort QoS class "
        "and are the first thing evicted under pressure — so your API dies before the batch "
        "job does. It is also the single biggest source of silent cloud overspend."
    )
    references: ClassVar[list[str]] = [
        "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
        "https://kubernetes.io/docs/concepts/workloads/pods/pod-qos/",
    ]
    topics: ClassVar[set[str]] = {
        "containers.resource-limits",
        "containers.vertical-scaling",
        "iac.missing-resource-limits",
        "cost.overprovisioned-resources",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel, doc in workload_documents(ctx):
            for container in pod_containers(doc):
                if len(findings) >= _MAX:
                    return findings
                missing = [
                    section
                    for section in ("requests", "limits")
                    if not _has_resource(container, section)
                ]
                if not missing:
                    continue
                name = str(container.get("name", "<unnamed>"))
                note = (
                    f"{doc.get('kind')} {workload_name(doc)}/{name}: no resources."
                    + "/resources.".join(missing)
                )
                findings.append(
                    self.make_finding(
                        file=rel,
                        evidence=[Evidence(file=rel, note=note)],
                        description=f"{rel}: {note}.",
                        recommended_followup=(
                            f"Set both on `{name}`, e.g. `resources: {{requests: {{cpu: "
                            '"100m", memory: "128Mi"}, limits: {cpu: "500m", memory: '
                            '"512Mi"}}}` — size them from observed usage, then enforce a '
                            "LimitRange on the namespace."
                        ),
                    )
                )
        return findings


class K8sInsecureWorkloadRule(_K8sRule):
    """Workloads with a permissive security context or a mutable image."""

    id: ClassVar[str] = "VG-CTR-011"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Kubernetes workload with an insecure security context or mutable image"
    description: ClassVar[str] = (
        "A workload runs privileged, allows privilege escalation, runs as root, shares a "
        "host namespace, keeps a writable root filesystem, or pulls a floating image tag."
    )
    why_it_matters: ClassVar[str] = (
        "These settings remove the isolation you are paying for: a privileged or "
        "root-running pod that is compromised can reach the node, its kubelet credentials, "
        "and from there the rest of the cluster. A floating `:latest` image additionally "
        "means two pods of the same Deployment can run different code, and a rollback does "
        "not actually roll the image back."
    )
    references: ClassVar[list[str]] = [
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
    ]
    topics: ClassVar[set[str]] = {
        "containers.container-privileges",
        "containers.image-security",
        "containers.dependency-pinning",
        "containers.rollbacks",
        "iac.insecure-defaults",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel, doc in workload_documents(ctx):
            spec = pod_spec(doc)
            pod_ctx = spec.get("securityContext")
            pod_ctx = pod_ctx if isinstance(pod_ctx, dict) else {}
            pod_reasons = self._pod_reasons(spec, pod_ctx)
            for container in pod_containers(doc):
                if len(findings) >= _MAX:
                    return findings
                reasons = pod_reasons + self._container_reasons(container, pod_ctx)
                if not reasons:
                    continue
                name = str(container.get("name", "<unnamed>"))
                note = f"{doc.get('kind')} {workload_name(doc)}/{name}: " + "; ".join(reasons)
                findings.append(
                    self.make_finding(
                        file=rel,
                        evidence=[Evidence(file=rel, note=note)],
                        description=f"{rel}: {note}.",
                        recommended_followup=(
                            "Apply the restricted Pod Security Standard to this workload: "
                            "`securityContext: {runAsNonRoot: true, "
                            "allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, "
                            "capabilities: {drop: [ALL]}}`, drop hostNetwork/hostPID, and "
                            "pin the image by digest."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _pod_reasons(spec: dict[str, Any], pod_ctx: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        if spec.get("hostNetwork") is True:
            reasons.append("`hostNetwork: true`")
        if spec.get("hostPID") is True:
            reasons.append("`hostPID: true`")
        if spec.get("hostIPC") is True:
            reasons.append("`hostIPC: true`")
        if pod_ctx.get("runAsUser") == 0:
            reasons.append("pod `runAsUser: 0`")
        return reasons

    @staticmethod
    def _container_reasons(container: dict[str, Any], pod_ctx: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        sec = container.get("securityContext")
        sec = sec if isinstance(sec, dict) else {}
        if sec.get("privileged") is True:
            reasons.append("`privileged: true`")
        if sec.get("allowPrivilegeEscalation") is not False:
            reasons.append("`allowPrivilegeEscalation` is not set to false")
        if sec.get("runAsUser") == 0:
            reasons.append("`runAsUser: 0`")
        elif sec.get("runAsNonRoot") is not True and pod_ctx.get("runAsNonRoot") is not True:
            reasons.append("no `runAsNonRoot: true`")
        if sec.get("readOnlyRootFilesystem") is not True:
            reasons.append("no `readOnlyRootFilesystem: true`")
        ref = image_ref(str(container.get("image", "")))
        if ref is not None and not ref.digest and tag_is_mutable(ref.tag):
            reasons.append(f"image `{container.get('image')}` uses a floating tag")
        return reasons
