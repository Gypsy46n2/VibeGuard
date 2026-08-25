"""VG-DEPS-004, VG-DEPS-005 — runtime version pinning and registry-backed health."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.containers._parse import dockerfiles, image_ref, parse_dockerfile
from vibeguard.rules.dependencies._manifests import (
    manifests,
    node_manifests,
    package_json,
    pyproject_data,
    python_manifests,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DependencyHealthUnverifiedRule", "UnpinnedRuntimeVersionRule"]

_MINOR = re.compile(r"^\d+\.\d+")
_PY_BASES = ("python", "pypy")
_NODE_BASES = ("node", "nodejs")


def _dockerfile_runtime_pins(ctx: ScanContext) -> dict[str, bool]:
    """``{"python": pinned?, "node": pinned?}`` from Dockerfile FROM lines."""
    pins: dict[str, bool] = {}
    for rel in dockerfiles(ctx):
        for ins in parse_dockerfile(ctx.read(rel)):
            if ins.upper != "FROM":
                continue
            ref = image_ref(ins.value)
            if ref is None:
                continue
            base = ref.image.rsplit("/", 1)[-1].lower()
            language = (
                "python"
                if base.startswith(_PY_BASES)
                else "node"
                if base.startswith(_NODE_BASES)
                else ""
            )
            if not language:
                continue
            pinned = bool(_MINOR.match(ref.tag))
            pins[language] = pins.get(language, False) or pinned
    return pins


class UnpinnedRuntimeVersionRule(ProjectRule):
    """No interpreter version declared anywhere."""

    id: ClassVar[str] = "VG-DEPS-004"
    category: ClassVar[Category] = Category.DEPENDENCIES
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Runtime version not pinned"
    description: ClassVar[str] = (
        "The project declares no supported interpreter version: no requires-python / "
        "python_requires / .python-version, no engines.node / .nvmrc, and no Dockerfile "
        "base image pinned to a minor version."
    )
    why_it_matters: ClassVar[str] = (
        "Everyone — every developer, CI, and the production image — silently runs whatever "
        "interpreter they happen to have. Code that uses a newer syntax feature fails only "
        "on the machine with the older runtime, and a base-image rebuild can jump a major "
        "version and break C extensions or native modules with no code change at all."
    )
    references: ClassVar[list[str]] = [
        "https://packaging.python.org/en/latest/specifications/pyproject-toml/",
        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines",
    ]
    topics: ClassVar[set[str]] = {"dependencies.runtime-incompatibilities"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED
    recommended_followup: ClassVar[str] = (
        "Declare the runtime once and reuse it everywhere: `requires-python = \">=3.12,"
        "<3.13\"` in pyproject.toml plus a `.python-version`, or `\"engines\": {\"node\": "
        '">=20 <21"}` plus a `.nvmrc`, and pin the Docker base image to the same minor '
        "version."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        languages = {name.lower() for name in ctx.tech.languages}
        docker_pins = _dockerfile_runtime_pins(ctx)
        names = {PurePosixPath(rel).name.lower() for rel in ctx.files}
        gaps: list[str] = []

        if "python" in languages or python_manifests(ctx):
            if not self._python_pinned(ctx, names, docker_pins):
                gaps.append(
                    "Python: no requires-python/python_requires, no .python-version, and no "
                    "Docker base pinned to a minor version"
                )
        if {"javascript", "typescript"} & languages or node_manifests(ctx):
            if not self._node_pinned(ctx, names, docker_pins):
                gaps.append(
                    "Node: no engines.node, no .nvmrc, and no Docker base pinned to a minor "
                    "version"
                )

        if not gaps:
            return None
        return (
            "The interpreter version is not pinned — " + "; ".join(gaps) + ".",
            "checked pyproject.toml, setup.cfg, setup.py, .python-version, package.json "
            "engines, .nvmrc, .node-version, and Dockerfile FROM tags",
        )

    @staticmethod
    def _python_pinned(ctx: ScanContext, names: set[str], pins: dict[str, bool]) -> bool:
        if pins.get("python"):
            return True
        if ".python-version" in names or "runtime.txt" in names:
            return True
        for rel in python_manifests(ctx):
            if PurePosixPath(rel).name.lower() != "pyproject.toml":
                continue
            data = pyproject_data(ctx, rel)
            project = data.get("project")
            if isinstance(project, dict) and project.get("requires-python"):
                return True
            tool = data.get("tool")
            poetry = tool.get("poetry") if isinstance(tool, dict) else None
            deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
            if isinstance(deps, dict) and deps.get("python"):
                return True
        for rel in ctx.files:
            if PurePosixPath(rel).name.lower() in {"setup.cfg", "setup.py"}:
                if "python_requires" in ctx.read(rel):
                    return True
        return False

    @staticmethod
    def _node_pinned(ctx: ScanContext, names: set[str], pins: dict[str, bool]) -> bool:
        if pins.get("node"):
            return True
        if ".nvmrc" in names or ".node-version" in names:
            return True
        for rel in node_manifests(ctx):
            engines = package_json(ctx, rel).get("engines")
            if isinstance(engines, dict) and engines.get("node"):
                return True
        return False


class DependencyHealthUnverifiedRule(ProjectRule):
    """VibeGuard's built-in rules cannot judge package health on their own."""

    id: ClassVar[str] = "VG-DEPS-005"
    category: ClassVar[Category] = Category.DEPENDENCIES
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "Dependency health not verified against a registry"
    description: ClassVar[str] = (
        "Whether a dependency is abandoned, yanked, or carrying a known CVE cannot be "
        "determined from the manifests alone — it needs a registry or advisory-database "
        "lookup."
    )
    why_it_matters: ClassVar[str] = (
        "Most real dependency risk is invisible in the manifest: the package that has not "
        "shipped a release in four years, the transitive dependency with a critical "
        "advisory, the maintainer account that changed hands. Stating this honestly matters "
        "more than guessing — a clean VibeGuard report is not evidence that your "
        "dependencies are safe, only that these offline checks found nothing."
    )
    references: ClassVar[list[str]] = [
        "https://pypi.org/project/pip-audit/",
        "https://docs.npmjs.com/cli/v10/commands/npm-audit",
    ]
    topics: ClassVar[set[str]] = {
        "dependencies.abandoned-packages",
        "dependencies.transitive-dependencies",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        found = manifests(ctx)
        if not found:
            return None
        tools = self._tools(ctx, found)
        listed = ", ".join(f"`{tool}`" for tool in tools)
        return (
            "VibeGuard's offline rules cannot tell whether these dependencies are "
            "abandoned, yanked, or vulnerable; that needs a registry lookup. For this "
            f"stack the applicable tools are {listed}. Run them (or enable the matching "
            "VibeGuard adapters) before trusting the dependency section of this report.",
            f"manifests inspected: {', '.join(found[:6])}; suggested tools: {listed}",
        )

    @staticmethod
    def _tools(ctx: ScanContext, found: list[str]) -> list[str]:
        tools: list[str] = []
        if python_manifests(ctx):
            tools.append("pip-audit")
        if node_manifests(ctx):
            tools.append("npm audit")
        if ctx.tech.containers:
            tools.append("trivy")
        return tools or ["pip-audit / npm audit / trivy"]
