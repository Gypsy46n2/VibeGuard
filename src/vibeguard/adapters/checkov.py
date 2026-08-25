"""checkov adapter — infrastructure-as-code policy scanning."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["CheckovAdapter"]

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class CheckovAdapter(ToolAdapter):
    """Runs ``checkov -d . -o json`` when IaC or container manifests are present."""

    name: ClassVar[str] = "checkov"
    command: ClassVar[str] = "checkov"
    description: ClassVar[str] = "Infrastructure-as-code policy checks"
    category: ClassVar[Category] = Category.DEPLOYMENT
    technologies: ClassVar[set[str]] = {
        "terraform",
        "cloudformation",
        "helm",
        "k8s",
        "docker",
        "compose",
        "ansible",
        "pulumi",
    }
    topics: ClassVar[set[str]] = {
        "iac.insecure-defaults",
        "iac.public-resources",
        "iac.overly-broad-permissions",
        "iac.missing-encryption",
        "iac.missing-backups",
        "iac.missing-lifecycle-rules",
        "iac.hardcoded-secrets",
        "iac.missing-resource-limits",
        "iac.configuration-drift",
        "containers.resource-limits",
        "containers.container-privileges",
        "security.encryption-at-rest",
    }

    def run(self, ctx: ScanContext) -> list[Finding]:
        payload = self.exec_json(
            ["checkov", "-d", ".", "-o", "json", "--compact", "--quiet"], ctx
        )
        findings: list[Finding] = []
        for block in self._blocks(payload):
            results = block.get("results")
            if not isinstance(results, dict):
                continue
            for check in results.get("failed_checks") or []:
                mapped = self._map(check)
                if mapped is not None:
                    findings.append(mapped)
        return findings

    @staticmethod
    def _blocks(payload: Any) -> list[dict[str, Any]]:
        """checkov emits one object per framework, or a bare object for a single one."""
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            return [payload]
        return []

    def _map(self, check: Any) -> Finding | None:
        if not isinstance(check, dict):
            return None
        check_id = str(check.get("check_id") or "unknown")
        path = str(check.get("file_path") or "").lstrip("/")
        line_range = check.get("file_line_range")
        line = None
        if isinstance(line_range, list) and line_range and isinstance(line_range[0], int):
            line = line_range[0]
        return self.make_finding(
            native_id=check_id,
            title=f"IaC policy failure {check_id}: {str(check.get('check_name') or '')[:70]}",
            description=str(check.get("check_name") or check_id),
            why_it_matters=(
                "Infrastructure defined in code inherits its defaults verbatim into "
                "production; a policy failure here is a live misconfiguration, not a style "
                "nit."
            ),
            severity=_SEVERITY.get(str(check.get("severity") or "").upper(), Severity.MEDIUM),
            confidence=Confidence.HIGH,
            category=Category.DEPLOYMENT,
            file=path or None,
            line=line,
            references=[str(check["guideline"])] if check.get("guideline") else [],
            recommended_followup="Apply the checkov guideline or record an explicit exception.",
            autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
        )
