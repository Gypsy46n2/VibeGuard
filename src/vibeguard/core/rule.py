"""Rule ABC — INTERFACES.md §3.

Rules never construct :class:`Finding` directly: :meth:`Rule.make_finding` computes
the fingerprint, applies secret redaction, and stamps the finding id.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.fingerprint import PROJECT_PATH, fingerprint
from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    Patch,
    ScaleClass,
    Severity,
)
from vibeguard.core.redact import redact

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["Rule"]


class Rule(ABC):
    """Base class for every built-in and third-party rule."""

    id: ClassVar[str]
    category: ClassVar[Category]
    severity: ClassVar[Severity]
    confidence: ClassVar[Confidence]
    title: ClassVar[str]
    description: ClassVar[str]
    why_it_matters: ClassVar[str]
    references: ClassVar[list[str]] = []
    technologies: ClassVar[set[str]] = set()
    #: Master-checklist topic ids this rule evaluates (INTERFACES.md §11).
    topics: ClassVar[set[str]] = set()
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    requires_ai: ClassVar[bool] = False
    #: Why this rule's topics are NOT_APPLICABLE when a custom ``applicable()``
    #: precondition (rather than the tech/scale gate) rejects a repository.
    not_applicable_note: ClassVar[str] = ""

    # ------------------------------------------------------------ applicability
    def applicable(self, ctx: ScanContext) -> bool:
        """Default gate: technology match ∧ scale match.

        ``technologies`` empty means "any stack". Override to add file-presence or
        other preconditions (call ``super().applicable(ctx)`` first).
        """
        if ctx.scale.scale.order < self.min_scale.order:
            return False
        if not self.technologies:
            return True
        detected = ctx.tech.all_technologies()
        return bool({tech.lower() for tech in self.technologies} & detected)

    # ------------------------------------------------------------- detection
    @abstractmethod
    def detect(self, ctx: ScanContext) -> list[Finding]:
        """Return findings for this repository. Must never raise for normal input."""

    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Return a patch repairing ``finding``, or None when not auto-fixable."""
        return None

    # ------------------------------------------------------------ construction
    def make_finding(
        self,
        *,
        file: str | None = None,
        line: int | None = None,
        snippet: str = "",
        evidence: list[Evidence] | None = None,
        description: str | None = None,
        title: str | None = None,
        why_it_matters: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        recommended_followup: str = "",
        references: list[str] | None = None,
        redact_evidence: bool = False,
    ) -> Finding:
        """Build a :class:`Finding` with fingerprint, id, and redaction applied.

        ``snippet`` (or the first evidence snippet) feeds the fingerprint. Redaction
        is applied to every evidence snippet when the rule's category is SECRETS,
        when ``redact_evidence`` is set, or when the evidence item sets ``redact``.
        """
        items = list(evidence or [])
        if snippet and not items:
            items = [Evidence(file=file or PROJECT_PATH, line=line, snippet=snippet)]

        fp_path = file or (items[0].file if items else PROJECT_PATH)
        fp_snippet = snippet or (items[0].snippet if items else "")
        fp = fingerprint(self.id, fp_path, fp_snippet)

        force = redact_evidence or self.category is Category.SECRETS
        redacted_items = [
            item.model_copy(update={"snippet": redact(item.snippet)})
            if (force or item.redact) and item.snippet
            else item
            for item in items
        ]

        return Finding(
            id=f"{self.id}:{fp[:12]}",
            rule_id=self.id,
            category=self.category,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            title=title or self.title,
            description=redact(description if description is not None else self.description),
            why_it_matters=why_it_matters or self.why_it_matters,
            evidence=redacted_items,
            file=file,
            line=line,
            autofix_safety=self.autofix_safety,
            fingerprint=fp,
            references=list(references if references is not None else self.references),
            recommended_followup=recommended_followup,
        )
