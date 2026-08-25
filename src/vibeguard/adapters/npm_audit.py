"""npm audit adapter — known-vulnerable JS dependencies (queries the npm registry)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NpmAuditAdapter"]

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NpmAuditAdapter(ToolAdapter):
    """Runs ``npm audit --json``; requires a lockfile so npm can resolve the tree."""

    name: ClassVar[str] = "npm-audit"
    command: ClassVar[str] = "npm"
    description: ClassVar[str] = "Known-vulnerable npm dependency detection"
    category: ClassVar[Category] = Category.DEPENDENCIES
    technologies: ClassVar[set[str]] = {"npm"}
    #: npm audit posts the dependency tree to the registry advisory endpoint.
    requires_network: ClassVar[bool] = True
    topics: ClassVar[set[str]] = {
        "dependencies.vulnerable-dependencies",
        "dependencies.outdated-libraries",
        "dependencies.transitive-dependencies",
        "security.dependency-vulnerabilities",
    }

    def applicable(self, ctx: ScanContext) -> bool:
        return "package.json" in ctx.files and "package-lock.json" in ctx.files

    def run(self, ctx: ScanContext) -> list[Finding]:
        payload = self.exec_json(["npm", "audit", "--json"], ctx)
        if not isinstance(payload, dict):
            return []
        findings = self._from_v7(payload)
        if not findings:
            findings = self._from_v6(payload)
        return findings

    def _from_v7(self, payload: dict[str, Any]) -> list[Finding]:
        vulns = payload.get("vulnerabilities")
        if not isinstance(vulns, dict):
            return []
        findings: list[Finding] = []
        for name, entry in vulns.items():
            if not isinstance(entry, dict):
                continue
            advisories = [v for v in (entry.get("via") or []) if isinstance(v, dict)]
            native = str(advisories[0].get("source")) if advisories else str(name)
            title = str(advisories[0].get("title")) if advisories else "vulnerable dependency"
            findings.append(
                self._finding(
                    native_id=native,
                    package=str(name),
                    severity=str(entry.get("severity") or "moderate"),
                    title=title,
                    detail=str(entry.get("range") or ""),
                    url=str(advisories[0].get("url")) if advisories else "",
                    fixable=bool(entry.get("fixAvailable")),
                )
            )
        return findings

    def _from_v6(self, payload: dict[str, Any]) -> list[Finding]:
        advisories = payload.get("advisories")
        if not isinstance(advisories, dict):
            return []
        findings: list[Finding] = []
        for key, entry in advisories.items():
            if not isinstance(entry, dict):
                continue
            findings.append(
                self._finding(
                    native_id=str(entry.get("id") or key),
                    package=str(entry.get("module_name") or "?"),
                    severity=str(entry.get("severity") or "moderate"),
                    title=str(entry.get("title") or "vulnerable dependency"),
                    detail=str(entry.get("vulnerable_versions") or ""),
                    url=str(entry.get("url") or ""),
                    fixable=bool(entry.get("patched_versions")),
                )
            )
        return findings

    def _finding(
        self,
        *,
        native_id: str,
        package: str,
        severity: str,
        title: str,
        detail: str,
        url: str,
        fixable: bool,
    ) -> Finding:
        return self.make_finding(
            native_id=native_id,
            title=f"Vulnerable npm dependency {package}: {title[:80]}",
            description=(
                f"npm audit reports {package} as vulnerable"
                + (f" (affected range {detail})" if detail else "")
                + "."
            ),
            why_it_matters=(
                "Transitive npm dependencies execute with full application privileges; a "
                "known advisory means working exploit details are already public."
            ),
            severity=_SEVERITY.get(severity.lower(), Severity.MEDIUM),
            confidence=Confidence.HIGH,
            category=Category.DEPENDENCIES,
            references=[url] if url else [],
            recommended_followup=(
                "Run `npm audit fix` and re-test." if fixable
                else f"No patched version available for {package}; assess exposure or replace it."
            ),
            autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
        )
