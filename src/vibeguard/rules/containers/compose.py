"""VG-CTR-007, VG-CTR-008 — docker-compose service hardening and limits."""

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
from vibeguard.rules.containers._parse import compose_files, compose_services

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ComposeNoResourceLimitsRule", "ComposePrivilegedServiceRule"]

_MAX = 6

_DANGEROUS_CAPS = {"SYS_ADMIN", "ALL", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


class ComposePrivilegedServiceRule(Rule):
    """A compose service that disables the container boundary."""

    id: ClassVar[str] = "VG-CTR-007"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Compose service with elevated privileges"
    description: ClassVar[str] = (
        "A compose service runs privileged, shares a host namespace, adds dangerous "
        "capabilities, mounts the docker socket, or runs as root."
    )
    why_it_matters: ClassVar[str] = (
        "Each of these settings hands the container the keys to the host. A privileged "
        "container or a mounted `/var/run/docker.sock` is a full host takeover for anyone "
        "who gets code execution inside it — they can start a new container that mounts the "
        "host root filesystem. Host networking additionally exposes every port the "
        "container binds, bypassing your published-port list."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/engine/security/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    ]
    topics: ClassVar[set[str]] = {
        "containers.docker-compose",
        "containers.container-privileges",
        "iac.insecure-defaults",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in compose_files(ctx):
            for name, service in compose_services(ctx, rel).items():
                if len(findings) >= _MAX:
                    return findings
                reasons = self._reasons(service)
                if not reasons:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        evidence=[
                            Evidence(file=rel, note=f"service {name}: " + "; ".join(reasons))
                        ],
                        description=(
                            f"{rel}: service `{name}` weakens container isolation "
                            f"({'; '.join(reasons)})."
                        ),
                        recommended_followup=(
                            f"Drop the elevated settings from `{name}`: remove "
                            "`privileged`, `network_mode: host`, `pid: host` and the docker "
                            "socket mount, replace broad `cap_add` entries with the single "
                            "capability actually needed, and set a non-root `user:`."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _reasons(service: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        if service.get("privileged") is True:
            reasons.append("`privileged: true`")
        if str(service.get("network_mode", "")).lower() == "host":
            reasons.append("`network_mode: host`")
        if str(service.get("pid", "")).lower() == "host":
            reasons.append("`pid: host`")
        if str(service.get("ipc", "")).lower() == "host":
            reasons.append("`ipc: host`")
        caps = {cap.upper() for cap in _as_list(service.get("cap_add"))} & _DANGEROUS_CAPS
        if caps:
            reasons.append("cap_add: " + ", ".join(sorted(caps)))
        volumes = service.get("volumes")
        entries = volumes if isinstance(volumes, list) else []
        for volume in entries:
            text = str(volume.get("source", "")) if isinstance(volume, dict) else str(volume)
            if "/var/run/docker.sock" in text:
                reasons.append("bind-mounts the docker socket")
                break
        user = str(service.get("user", "")).split(":")[0].strip()
        if user in {"root", "0"}:
            reasons.append("`user: root`")
        return reasons


class ComposeNoResourceLimitsRule(Rule):
    """A compose service with neither resource limits nor a restart policy."""

    id: ClassVar[str] = "VG-CTR-008"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Compose service without resource limits"
    description: ClassVar[str] = (
        "A compose service declares no memory/CPU limit and no restart policy, so it can "
        "consume the whole host and stays down after a crash."
    )
    why_it_matters: ClassVar[str] = (
        "One service with a memory leak or a runaway query will starve every other service "
        "on the box — including the database — and the host OOM killer picks the victim, "
        "not you. Without a restart policy the crashed process simply stays dead until "
        "someone notices, which on a single-host deployment means a full outage."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/reference/compose-file/deploy/#resources",
        "https://docs.docker.com/reference/compose-file/services/#restart",
    ]
    topics: ClassVar[set[str]] = {
        "containers.resource-limits",
        "cost.overprovisioned-resources",
        "iac.missing-resource-limits",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in compose_files(ctx):
            for name, service in compose_services(ctx, rel).items():
                if len(findings) >= _MAX:
                    return findings
                if not (service.get("image") or service.get("build")):
                    continue
                if self._has_limits(service) or service.get("restart"):
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        evidence=[
                            Evidence(
                                file=rel,
                                note=(
                                    f"service {name}: no deploy.resources.limits, no "
                                    "mem_limit, no cpus, and no restart policy"
                                ),
                            )
                        ],
                        description=(
                            f"{rel}: service `{name}` sets no memory or CPU limit and no "
                            "restart policy."
                        ),
                        recommended_followup=(
                            f"Give `{name}` a ceiling and a restart policy, e.g. "
                            "`mem_limit: 512m`, `cpus: 0.5`, `restart: unless-stopped` "
                            "(or the `deploy.resources.limits` block under Swarm)."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _has_limits(service: dict[str, Any]) -> bool:
        if service.get("mem_limit") or service.get("cpus") or service.get("cpu_quota"):
            return True
        deploy = service.get("deploy")
        if not isinstance(deploy, dict):
            return False
        resources = deploy.get("resources")
        if not isinstance(resources, dict):
            return False
        limits = resources.get("limits")
        return isinstance(limits, dict) and bool(limits)
