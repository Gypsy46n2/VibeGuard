"""VG-DEPS-003 — duplicate or conflicting dependency declarations."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, ClassVar

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
from vibeguard.rules.dependencies._manifests import Requirement, manifests, requirements_of

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DuplicateDependencyRule"]

_MAX = 5


class DuplicateDependencyRule(Rule):
    """The same package declared more than once, with different constraints."""

    id: ClassVar[str] = "VG-DEPS-003"
    category: ClassVar[Category] = Category.DEPENDENCIES
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Duplicate or conflicting dependency declarations"
    description: ClassVar[str] = (
        "A package is declared twice in one manifest, or with different constraints across "
        "manifests, so which version you get depends on install order."
    )
    why_it_matters: ClassVar[str] = (
        "Whichever declaration the resolver happens to apply wins, and it may not be the "
        "same one locally, in CI, and in the production image — which is exactly the shape "
        "of a bug that cannot be reproduced. Conflicting constraints also make every future "
        "upgrade harder, because the resolver has to satisfy contradictory requirements."
    )
    references: ClassVar[list[str]] = [
        "https://pip.pypa.io/en/stable/topics/dependency-resolution/",
        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json",
    ]
    topics: ClassVar[set[str]] = {
        "dependencies.duplicate-dependencies",
        "dependencies.dependency-conflicts",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        by_package: dict[str, list[Requirement]] = defaultdict(list)
        for rel in manifests(ctx):
            for req in requirements_of(ctx, rel):
                # Peer/optional entries legitimately restate a runtime dependency.
                if req.section in {"peerDependencies", "optionalDependencies"}:
                    continue
                by_package[req.key].append(req)

        findings: list[Finding] = []
        for key, reqs in sorted(by_package.items()):
            if len(findings) >= _MAX:
                break
            if len(reqs) < 2:
                continue
            specs = {req.spec.strip() for req in reqs}
            same_file = len({req.file for req in reqs}) == 1
            same_section = len({req.section for req in reqs}) == 1
            if len(specs) == 1 and not (same_file and same_section):
                # One constraint, restated. Two optional groups that both need
                # `fastapi>=0.110` — a `ui` extra and the `dev` extra that tests it —
                # is normal packaging, and the resolver has nothing to choose between
                # (DECISIONS.md D67). Only a genuine repeat *within* one section, or
                # actually differing constraints, is a resolution hazard.
                continue
            where = "; ".join(
                f"{req.file}:{req.line} [{req.section}] {req.spec or '<no constraint>'}"
                for req in reqs[:4]
            )
            if same_file and same_section:
                scope = "twice in the same section of one manifest"
            elif same_file:
                scope = "twice in the same manifest with different constraints"
            else:
                scope = "with different constraints"
            first = reqs[0]
            findings.append(
                self.make_finding(
                    file=first.file,
                    line=first.line,
                    evidence=[
                        Evidence(file=req.file, line=req.line, note=f"{key}: {req.spec}")
                        for req in reqs[:4]
                    ],
                    description=(
                        f"`{key}` is declared {scope} — {where}. The effective version "
                        "depends on which declaration the resolver applies."
                    ),
                    recommended_followup=(
                        f"Keep exactly one declaration of `{key}`: pick the constraint you "
                        "want, delete the others (a dev-only package belongs in "
                        "devDependencies / an optional group only), and regenerate the "
                        "lockfile."
                    ),
                )
            )
        return findings
