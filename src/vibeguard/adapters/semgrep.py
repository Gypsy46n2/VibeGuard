"""semgrep adapter — multi-language SAST via ``--config auto``.

``--config auto`` downloads the community ruleset from the semgrep registry, so this
adapter is skipped whenever ``local_only`` is set (ARCHITECTURE.md §9).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["SemgrepAdapter"]

_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_CATEGORY_HINTS: tuple[tuple[str, Category], ...] = (
    ("secret", Category.SECRETS),
    ("sql", Category.SECURITY),
    ("performance", Category.PERFORMANCE),
    ("correctness", Category.RELIABILITY),
)


class SemgrepAdapter(ToolAdapter):
    """Runs ``semgrep --config auto --json``."""

    name: ClassVar[str] = "semgrep"
    command: ClassVar[str] = "semgrep"
    description: ClassVar[str] = "Multi-language static analysis (registry ruleset)"
    category: ClassVar[Category] = Category.SECURITY
    requires_network: ClassVar[bool] = True
    topics: ClassVar[set[str]] = {
        "security.sql-injection",
        "security.xss",
        "security.ssrf",
        "security.command-injection",
        "security.path-traversal",
        "security.insecure-deserialization",
        "security.open-redirects",
        "security.weak-cryptography",
        "security.hardcoded-credentials",
        "security.cors",
        "security.jwt-handling",
        "security.template-injection",
        "security.file-upload",
    }

    def run(self, ctx: ScanContext) -> list[Finding]:
        payload = self.exec_json(
            ["semgrep", "--config", "auto", "--json", "--quiet", "--disable-version-check", "."],
            ctx,
        )
        if not isinstance(payload, dict):
            return []
        findings: list[Finding] = []
        for result in payload.get("results") or []:
            finding = self._map(result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _map(self, result: Any) -> Finding | None:
        if not isinstance(result, dict):
            return None
        check_id = str(result.get("check_id") or "unknown")
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        message = str(extra.get("message") or check_id)
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        lowered = check_id.lower()
        category = self.category
        for hint, mapped in _CATEGORY_HINTS:
            if hint in lowered:
                category = mapped
                break
        references: list[str] = []
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        for key in ("source", "shortlink"):
            if metadata.get(key):
                references.append(str(metadata[key]))
        return self.make_finding(
            native_id=check_id.rsplit(".", 1)[-1],
            title=f"semgrep: {message[:80]}",
            description=message,
            why_it_matters=(
                "semgrep's community rules encode exploited real-world patterns. Treat a hit "
                "as a lead to confirm against the data flow, not as proof on its own."
            ),
            severity=_SEVERITY.get(str(extra.get("severity") or "").upper(), Severity.MEDIUM),
            confidence=Confidence.MEDIUM,
            category=category,
            file=str(result.get("path") or "") or None,
            line=start.get("line") if isinstance(start.get("line"), int) else None,
            snippet=str(extra.get("lines") or "")[:400],
            references=references,
            recommended_followup="Confirm the data flow reaches the sink, then remediate.",
            autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
            redact_evidence=category is Category.SECRETS,
        )
