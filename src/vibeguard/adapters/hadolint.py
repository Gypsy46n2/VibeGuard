"""hadolint adapter — Dockerfile linting.

hadolint is GPL-3.0: it is invoked as a subprocess only and never vendored
(ARCHITECTURE.md §2).
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["HadolintAdapter", "dockerfiles"]

_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


def dockerfiles(ctx: ScanContext) -> list[str]:
    """Every Dockerfile-looking path in the scanned tree."""
    found: list[str] = []
    for rel in ctx.files:
        name = PurePosixPath(rel).name.lower()
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            found.append(rel)
    return found


class HadolintAdapter(ToolAdapter):
    """Runs ``hadolint --format json`` over every Dockerfile."""

    name: ClassVar[str] = "hadolint"
    command: ClassVar[str] = "hadolint"
    description: ClassVar[str] = "Dockerfile best-practice linting"
    category: ClassVar[Category] = Category.CONTAINERS
    technologies: ClassVar[set[str]] = {"docker"}
    topics: ClassVar[set[str]] = {
        "containers.docker",
        "containers.image-security",
        "containers.image-size",
        "containers.dependency-pinning",
        "containers.build-caching",
        "containers.container-privileges",
    }

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(dockerfiles(ctx))

    def run(self, ctx: ScanContext) -> list[Finding]:
        targets = dockerfiles(ctx)
        if not targets:
            return []
        payload = self.exec_json(["hadolint", "--format", "json", *targets], ctx)
        if not isinstance(payload, list):
            return []
        findings: list[Finding] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code") or "unknown")
            findings.append(
                self.make_finding(
                    native_id=code,
                    title=f"hadolint {code}: {str(item.get('message') or '')[:80]}",
                    description=str(item.get("message") or code),
                    why_it_matters=(
                        "Dockerfile smells become production incidents: unpinned bases drift, "
                        "root containers widen blast radius, and bad layer order wrecks builds."
                    ),
                    severity=_SEVERITY.get(str(item.get("level") or "").lower(), Severity.LOW),
                    confidence=Confidence.HIGH,
                    category=Category.CONTAINERS,
                    file=str(item.get("file") or (targets[0] if targets else "")) or None,
                    line=item.get("line") if isinstance(item.get("line"), int) else None,
                    references=[f"https://github.com/hadolint/hadolint/wiki/{code}"],
                    recommended_followup="Apply the hadolint rule guidance or add an inline "
                    "ignore with a justification.",
                    autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
                )
            )
        return findings
