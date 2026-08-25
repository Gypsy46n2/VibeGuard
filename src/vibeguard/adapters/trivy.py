"""trivy adapter — filesystem scan for vulnerabilities, secrets, and misconfiguration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["TrivyAdapter"]

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyAdapter(ToolAdapter):
    """Runs ``trivy fs`` with the vuln, secret, and misconfig scanners."""

    name: ClassVar[str] = "trivy"
    command: ClassVar[str] = "trivy"
    description: ClassVar[str] = "Vulnerability, secret, and IaC misconfiguration scanning"
    category: ClassVar[Category] = Category.DEPENDENCIES
    #: The vulnerability DB is downloaded/refreshed from a remote registry.
    requires_network: ClassVar[bool] = True
    topics: ClassVar[set[str]] = {
        "dependencies.vulnerable-dependencies",
        "dependencies.outdated-libraries",
        "security.dependency-vulnerabilities",
        "security.secret-leakage",
        "secrets.api-keys-in-repo",
        "secrets.cloud-credentials",
        "containers.image-security",
        "iac.insecure-defaults",
        "iac.public-resources",
        "iac.overly-broad-permissions",
        "iac.missing-encryption",
        "iac.hardcoded-secrets",
        "iac.missing-resource-limits",
    }

    def run(self, ctx: ScanContext) -> list[Finding]:
        payload = self.exec_json(
            [
                "trivy",
                "fs",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                ".",
            ],
            ctx,
        )
        if not isinstance(payload, dict):
            return []
        findings: list[Finding] = []
        for result in payload.get("Results") or []:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or "")
            findings.extend(self._vulns(result, target))
            findings.extend(self._secrets(result, target))
            findings.extend(self._misconfig(result, target))
        return findings

    def _sev(self, raw: Any, default: Severity = Severity.MEDIUM) -> Severity:
        return _SEVERITY.get(str(raw or "").upper(), default)

    def _vulns(self, result: dict[str, Any], target: str) -> list[Finding]:
        out: list[Finding] = []
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("VulnerabilityID") or "UNKNOWN")
            pkg = str(vuln.get("PkgName") or "?")
            out.append(
                self.make_finding(
                    native_id=vuln_id,
                    title=f"Vulnerable dependency {pkg} ({vuln_id})",
                    description=(
                        f"{pkg} {vuln.get('InstalledVersion', '?')} in {target} is affected by "
                        f"{vuln_id}: {str(vuln.get('Title') or '')[:200]}"
                    ),
                    why_it_matters=(
                        "Known-vulnerable packages are exploited by automated scanners within "
                        "days of an advisory."
                    ),
                    severity=self._sev(vuln.get("Severity")),
                    confidence=Confidence.HIGH,
                    category=Category.DEPENDENCIES,
                    file=target or None,
                    references=[str(vuln.get("PrimaryURL"))] if vuln.get("PrimaryURL") else [],
                    recommended_followup=(
                        f"Upgrade {pkg} to {vuln.get('FixedVersion')}."
                        if vuln.get("FixedVersion")
                        else f"No fix published for {pkg}; assess exposure."
                    ),
                    autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
                )
            )
        return out

    def _secrets(self, result: dict[str, Any], target: str) -> list[Finding]:
        out: list[Finding] = []
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            rule = str(secret.get("RuleID") or "secret")
            out.append(
                self.make_finding(
                    native_id=rule,
                    title=f"Secret detected in repository ({rule})",
                    description=(
                        f"trivy matched the {rule!r} secret rule in {target}. "
                        f"{str(secret.get('Title') or '')[:200]}"
                    ),
                    why_it_matters=(
                        "Committed credentials are compromised as soon as the repository is "
                        "shared; rotation, not deletion, is the fix."
                    ),
                    severity=self._sev(secret.get("Severity"), Severity.HIGH),
                    confidence=Confidence.HIGH,
                    category=Category.SECRETS,
                    file=target or None,
                    line=secret.get("StartLine") if isinstance(secret.get("StartLine"), int)
                    else None,
                    snippet=str(secret.get("Match") or "")[:200],
                    recommended_followup="Rotate the credential and move it to a secret store.",
                    autofix_safety=AutofixSafety.MANUAL_CHANGE_REQUIRED,
                    redact_evidence=True,
                )
            )
        return out

    def _misconfig(self, result: dict[str, Any], target: str) -> list[Finding]:
        out: list[Finding] = []
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            check = str(item.get("ID") or "misconfig")
            out.append(
                self.make_finding(
                    native_id=check,
                    title=f"Infrastructure misconfiguration {check}: "
                    f"{str(item.get('Title') or '')[:70]}",
                    description=str(item.get("Description") or item.get("Message") or check)[:400],
                    why_it_matters=(
                        "Insecure infrastructure defaults (public buckets, open security "
                        "groups, unencrypted volumes) are exploited without touching the app."
                    ),
                    severity=self._sev(item.get("Severity")),
                    confidence=Confidence.HIGH,
                    category=Category.DEPLOYMENT,
                    file=target or None,
                    line=(item.get("CauseMetadata") or {}).get("StartLine")
                    if isinstance(item.get("CauseMetadata"), dict)
                    else None,
                    references=[str(item.get("PrimaryURL"))] if item.get("PrimaryURL") else [],
                    recommended_followup=str(item.get("Resolution") or "")[:300],
                    autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
                )
            )
        return out
