"""bandit adapter — Python SAST (Apache-2.0, subprocess only)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["BanditAdapter"]

_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}
_CONFIDENCE = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
    "UNDEFINED": Confidence.LOW,
}


class BanditAdapter(ToolAdapter):
    """Runs ``bandit -r . -f json`` over Python sources."""

    name: ClassVar[str] = "bandit"
    command: ClassVar[str] = "bandit"
    description: ClassVar[str] = "Python static application security testing"
    category: ClassVar[Category] = Category.SECURITY
    technologies: ClassVar[set[str]] = {"python"}
    topics: ClassVar[set[str]] = {
        "security.sql-injection",
        "security.command-injection",
        "security.insecure-deserialization",
        "security.weak-cryptography",
        "security.unsafe-randomness",
        "security.path-traversal",
        "security.hardcoded-credentials",
        "security.tls",
        "security.encryption-in-transit",
        "security.template-injection",
    }

    def applicable(self, ctx: ScanContext) -> bool:
        return "python" in ctx.tech.languages

    def run(self, ctx: ScanContext) -> list[Finding]:
        payload = self.exec_json(
            ["bandit", "-r", ".", "-f", "json", "-q", "--exclude", ".venv,venv,node_modules"],
            ctx,
        )
        if not isinstance(payload, dict):
            return []
        findings: list[Finding] = []
        for result in payload.get("results") or []:
            finding = self._map(result, ctx)
            if finding is not None:
                findings.append(finding)
        return findings

    def _map(self, result: Any, ctx: ScanContext) -> Finding | None:
        if not isinstance(result, dict):
            return None
        test_id = str(result.get("test_id") or "unknown")
        filename = str(result.get("filename") or "")
        rel = filename
        if filename.startswith("./"):
            rel = filename[2:]
        else:
            try:
                rel = str(ctx.root.joinpath(filename).resolve().relative_to(ctx.root).as_posix())
            except (ValueError, OSError):
                rel = filename
        text = str(result.get("issue_text") or test_id)
        return self.make_finding(
            native_id=test_id,
            title=f"bandit {test_id}: {str(result.get('test_name') or text)[:80]}",
            description=text,
            why_it_matters=(
                "bandit flags Python code patterns with known exploitation history. "
                "Confirm the flagged call is reachable with attacker-controlled input."
            ),
            severity=_SEVERITY.get(str(result.get("issue_severity", "")).upper(), Severity.MEDIUM),
            confidence=_CONFIDENCE.get(
                str(result.get("issue_confidence", "")).upper(), Confidence.MEDIUM
            ),
            file=rel or None,
            line=result.get("line_number") if isinstance(result.get("line_number"), int) else None,
            snippet=str(result.get("code") or "")[:400],
            references=[str(result["more_info"])] if result.get("more_info") else [],
            recommended_followup="Review the bandit guidance and remove or justify the pattern.",
        )
