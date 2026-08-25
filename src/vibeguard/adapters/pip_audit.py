"""pip-audit adapter — known-vulnerable Python dependencies (queries the PyPI API)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["PipAuditAdapter"]

_REQUIREMENT_FILES = ("requirements.txt", "requirements/base.txt", "requirements-prod.txt")


class PipAuditAdapter(ToolAdapter):
    """Runs ``pip-audit -f json`` against the project's Python dependency manifest."""

    name: ClassVar[str] = "pip-audit"
    command: ClassVar[str] = "pip-audit"
    description: ClassVar[str] = "Known-vulnerable Python dependency detection"
    category: ClassVar[Category] = Category.DEPENDENCIES
    technologies: ClassVar[set[str]] = {"pip", "poetry", "uv"}
    #: Resolves advisories against the PyPI advisory API.
    requires_network: ClassVar[bool] = True
    topics: ClassVar[set[str]] = {
        "dependencies.vulnerable-dependencies",
        "dependencies.outdated-libraries",
        "dependencies.transitive-dependencies",
        "security.dependency-vulnerabilities",
    }

    def applicable(self, ctx: ScanContext) -> bool:
        return "python" in ctx.tech.languages and bool(self._target(ctx))

    @staticmethod
    def _target(ctx: ScanContext) -> list[str]:
        """Arguments selecting what pip-audit should resolve."""
        for candidate in _REQUIREMENT_FILES:
            if candidate in ctx.files:
                return ["-r", candidate]
        if "pyproject.toml" in ctx.files or "poetry.lock" in ctx.files or "uv.lock" in ctx.files:
            return ["."]
        return []

    def run(self, ctx: ScanContext) -> list[Finding]:
        target = self._target(ctx)
        if not target:
            return []
        payload = self.exec_json(["pip-audit", "-f", "json", "--progress-spinner", "off", *target],
                                 ctx)
        dependencies = self._dependencies(payload)
        findings: list[Finding] = []
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            name = str(dep.get("name") or "?")
            version = str(dep.get("version") or "?")
            for vuln in dep.get("vulns") or []:
                if not isinstance(vuln, dict):
                    continue
                findings.append(self._map(name, version, vuln))
        return findings

    @staticmethod
    def _dependencies(payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            deps = payload.get("dependencies")
            return deps if isinstance(deps, list) else []
        if isinstance(payload, list):  # pip-audit < 2.5 emitted a bare list
            return payload
        return []

    def _map(self, name: str, version: str, vuln: dict[str, Any]) -> Finding:
        vuln_id = str(vuln.get("id") or "UNKNOWN")
        fixes = [str(f) for f in (vuln.get("fix_versions") or [])]
        return self.make_finding(
            native_id=vuln_id,
            title=f"Vulnerable dependency {name} {version} ({vuln_id})",
            description=(
                f"{name}=={version} is affected by {vuln_id}. "
                + (str(vuln.get("description") or "")[:400])
            ),
            why_it_matters=(
                "Published advisories come with public exploit details; an unpatched "
                "dependency is the cheapest way into an application."
            ),
            severity=Severity.HIGH if fixes else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=Category.DEPENDENCIES,
            file=None,
            references=[f"https://osv.dev/vulnerability/{vuln_id}"],
            recommended_followup=(
                f"Upgrade {name} to {', '.join(fixes)}." if fixes
                else f"No fixed version published yet for {name}; assess exposure and pin/patch."
            ),
            autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
        )
