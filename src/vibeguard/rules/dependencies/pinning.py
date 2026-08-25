"""VG-DEPS-001, VG-DEPS-002 — lockfiles and dependency version pinning."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
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
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.dependencies._manifests import (
    LOCKFILES,
    Requirement,
    manifests,
    node_manifests,
    python_manifests,
    requirements_of,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoLockfileRule", "UnpinnedDependencyRule"]

_PY_LOCKS = {"requirements.lock", "poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock"}
_NODE_LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}


def _lockfile_names(ctx: ScanContext) -> set[str]:
    return {
        PurePosixPath(rel).name.lower()
        for rel in ctx.files
        if PurePosixPath(rel).name.lower() in LOCKFILES
    }


class NoLockfileRule(ProjectRule):
    """Dependency manifests with no lockfile beside them."""

    id: ClassVar[str] = "VG-DEPS-001"
    category: ClassVar[Category] = Category.DEPENDENCIES
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "No dependency lockfile"
    description: ClassVar[str] = (
        "The project declares dependencies without a lockfile, so two installs of the same "
        "commit can resolve to different package versions."
    )
    why_it_matters: ClassVar[str] = (
        "Without a lockfile the build is a live download of whatever the registry serves "
        "today: a transitive dependency publishes a breaking release and CI goes red on a "
        "commit that changed nothing, or worse, production gets a version that was never "
        "tested. It also makes incidents unreproducible — you cannot rebuild the artifact "
        "that is currently running."
    )
    references: ClassVar[list[str]] = [
        "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json",
        "https://pip.pypa.io/en/stable/topics/repeatable-installs/",
    ]
    topics: ClassVar[set[str]] = {
        "dependencies.lockfiles",
        "dependencies.unpinned-dependencies",
        "deployment.build-reproducibility",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    recommended_followup: ClassVar[str] = (
        "Generate and commit a lockfile — `uv lock` / `pip-compile requirements.in -o "
        "requirements.txt` for Python, `npm install` (which writes package-lock.json) for "
        "Node — and install from it in CI and in the Dockerfile (`npm ci`, "
        "`pip install -r requirements.txt --require-hashes`)."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        locks = _lockfile_names(ctx)
        gaps: list[str] = []

        if not (locks & _PY_LOCKS):
            for rel in python_manifests(ctx):
                if PurePosixPath(rel).name.lower() == "pyproject.toml":
                    continue
                loose = [req for req in requirements_of(ctx, rel) if not req.spec.startswith("==")]
                if loose:
                    names = ", ".join(sorted({req.name for req in loose})[:5])
                    gaps.append(f"{rel} has unpinned entries ({names}) and no Python lockfile")
                    break

        if not (locks & _NODE_LOCKS):
            for rel in node_manifests(ctx):
                if requirements_of(ctx, rel):
                    gaps.append(f"{rel} declares dependencies but no npm/yarn/pnpm lockfile exists")
                    break

        if not gaps:
            return None
        return (
            "Dependencies are installed without a lockfile: " + "; ".join(gaps) + ".",
            "checked for " + ", ".join(sorted(LOCKFILES)),
        )


_NODE_RANGE = re.compile(r"^[\^~]")
_NODE_ANY = re.compile(r"^(\*|latest|x|\d+\.x|>=?[^<]*)$", re.IGNORECASE)
_PY_OPEN = re.compile(r"^>=?[^,<]*$")
_MAX_EXAMPLES = 6


def _looseness(req: Requirement) -> str | None:
    """Describe how ``req`` is unpinned, or None when it is pinned enough."""
    spec = req.spec.strip()
    is_node = PurePosixPath(req.file).name.lower() == "package.json"
    if is_node:
        if not spec or _NODE_ANY.match(spec):
            return f"`{spec or '<empty>'}` accepts any published version"
        if _NODE_RANGE.match(spec) and req.section == "dependencies":
            return f"`{spec}` is a floating range for a direct runtime dependency"
        return None
    if not spec:
        return "declared with no version specifier at all"
    if spec in {"*", "latest"} or spec.startswith("*"):
        return f"`{spec}` accepts any published version"
    if spec.startswith("^") or spec.startswith("~"):
        return f"`{spec}` is a floating range"
    if _PY_OPEN.match(spec):
        return f"`{spec}` has no upper bound, so a future major release installs silently"
    return None


class UnpinnedDependencyRule(Rule):
    """Manifest entries that do not pin a version."""

    id: ClassVar[str] = "VG-DEPS-002"
    category: ClassVar[Category] = Category.DEPENDENCIES
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Unpinned or wildcard dependency version"
    description: ClassVar[str] = (
        "A dependency is declared with no version, a wildcard, or an open-ended range, so "
        "the installed version drifts on its own."
    )
    why_it_matters: ClassVar[str] = (
        "A dependency that resolves freely will one day resolve to a major release with "
        "breaking changes — usually during a deploy, on an unrelated commit, when nobody is "
        "looking for it. Open ranges also widen the supply-chain window: a compromised "
        "release is pulled in automatically the moment it is published."
    )
    references: ClassVar[list[str]] = [
        "https://semver.org/",
        "https://pip.pypa.io/en/stable/topics/repeatable-installs/",
    ]
    topics: ClassVar[set[str]] = {
        "dependencies.unpinned-dependencies",
        "dependencies.version-incompatibilities",
        "dependencies.outdated-libraries",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in manifests(ctx):
            for req in requirements_of(ctx, rel):
                if len(findings) >= _MAX_EXAMPLES:
                    return findings
                note = _looseness(req)
                if note is None:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=req.line,
                        evidence=[
                            Evidence(
                                file=rel,
                                line=req.line,
                                snippet=f"{req.name} {req.spec}".strip()[:200],
                                note=f"{req.section}: {note}",
                            )
                        ],
                        description=f"{rel}:{req.line} — `{req.name}` {note}.",
                        recommended_followup=(
                            f"Pin `{req.name}` to the version you actually tested "
                            "(`==1.2.3` / an exact `\"1.2.3\"`), commit a lockfile, and let "
                            "Renovate or Dependabot propose upgrades as reviewable PRs."
                        ),
                    )
                )
        return findings
