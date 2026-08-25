"""The concrete validation ladder — ARCHITECTURE.md §7, INTERFACES.md §2/§5.

Order (and the exact ``ValidationStep.name`` values):

``syntax`` → ``typecheck`` → ``lint`` → ``tests:targeted`` → ``tests:full`` →
``build`` → ``container_build`` → ``startup``

Every rung is opt-in on evidence: a type checker runs only if the project already
configures one, tests run only if a test framework is detected, the container build
runs only under ``fix --deep-validate``. Anything else is ``skipped`` with a reason.
"""

from __future__ import annotations

import json
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import ValidationStep
from vibeguard.validation.base import (
    JS_EXTS,
    PY_EXTS,
    TS_EXTS,
    Validator,
    changed_with_suffix,
    run_command,
    tool_available,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "BuildValidator",
    "ContainerBuildValidator",
    "FullTestValidator",
    "LintValidator",
    "StartupValidator",
    "SyntaxValidator",
    "TargetedTestValidator",
    "TypecheckValidator",
    "default_validators",
]

#: Cap on how many files one syntax/lint invocation is handed.
_MAX_FILES = 200


# ------------------------------------------------------------------ project probes


def _read(root: Path, rel: str) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _pyproject(root: Path) -> dict:
    text = _read(root, "pyproject.toml")
    if not text:
        return {}
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}


def _package_json(root: Path) -> dict:
    text = _read(root, "package.json")
    if not text:
        return {}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _has_tool_section(root: Path, tool: str) -> bool:
    """True when ``[tool.<tool>]`` is configured in pyproject.toml."""
    return tool in (_pyproject(root).get("tool") or {})


def _mypy_configured(root: Path) -> bool:
    if (root / "mypy.ini").is_file() or (root / ".mypy.ini").is_file():
        return True
    if "[mypy]" in _read(root, "setup.cfg"):
        return True
    return _has_tool_section(root, "mypy")


def _ruff_configured(root: Path) -> bool:
    if (root / "ruff.toml").is_file() or (root / ".ruff.toml").is_file():
        return True
    return _has_tool_section(root, "ruff")


def _eslint_configured(root: Path) -> bool:
    for name in (
        ".eslintrc",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.json",
        ".eslintrc.yml",
        ".eslintrc.yaml",
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
    ):
        if (root / name).is_file():
            return True
    return "eslintConfig" in _package_json(root)


def _npm_script(root: Path, name: str) -> bool:
    scripts = _package_json(root).get("scripts")
    return isinstance(scripts, dict) and bool(scripts.get(name))


def _pytest_project(ctx: ScanContext) -> bool:
    if "pytest" in {t.lower() for t in ctx.tech.test_frameworks}:
        return True
    return any(
        PurePosixPath(rel).name.startswith("test_") or PurePosixPath(rel).name.endswith("_test.py")
        for rel in ctx.files
    )


def _jest_project(ctx: ScanContext) -> bool:
    frameworks = {t.lower() for t in ctx.tech.test_frameworks}
    if frameworks & {"jest", "vitest"}:
        return True
    return _npm_script(ctx.root, "test") and bool(_package_json(ctx.root))


def _python_files(ctx: ScanContext) -> list[str]:
    return [f for f in ctx.files if f.endswith(".py")][:_MAX_FILES]


def _js_files(ctx: ScanContext) -> list[str]:
    return [f for f in ctx.files if PurePosixPath(f).suffix.lower() in JS_EXTS][:_MAX_FILES]


def _targets(
    ctx: ScanContext, changed_files: Sequence[str], suffixes: Sequence[str]
) -> list[str]:
    """Changed files of interest, or the whole project when nothing changed (baseline)."""
    if changed_files:
        return changed_with_suffix(list(changed_files), suffixes)
    wanted = {s.lower() for s in suffixes}
    return [f for f in ctx.files if PurePosixPath(f).suffix.lower() in wanted][:_MAX_FILES]


# ----------------------------------------------------------------------- validators


class SyntaxValidator(Validator):
    """Parse every changed file with its language's own parser."""

    name: ClassVar[str] = "syntax"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        root = str(ctx.root)
        py = _targets(ctx, changed_files, PY_EXTS)
        js = _targets(ctx, changed_files, JS_EXTS)
        checked: list[str] = []

        if py:
            result = run_command(
                [sys.executable, "-m", "py_compile", *py[:_MAX_FILES]],
                cwd=root,
                timeout=self._timeout(ctx, full=False),
            )
            if not result.ok:
                return self._failed(f"py_compile rejected a changed file: {result.tail()}")
            checked.append(f"{len(py)} python file(s)")

        if js:
            if not tool_available("node"):
                if not checked:
                    return self._skipped("node is not installed; JavaScript was not parsed")
            else:
                for rel in js[:_MAX_FILES]:
                    result = run_command(
                        ["node", "--check", rel],
                        cwd=root,
                        timeout=self._timeout(ctx, full=False),
                    )
                    if not result.ok:
                        return self._failed(f"node --check rejected {rel}: {result.tail()}")
                checked.append(f"{len(js)} javascript file(s)")

        ts = _targets(ctx, changed_files, TS_EXTS)
        if not checked:
            if ts:
                return self._skipped(
                    "only TypeScript changed; syntax is covered by the typecheck rung"
                )
            return self._skipped("no parseable source file changed")
        return self._passed("parsed " + ", ".join(checked))


class TypecheckValidator(Validator):
    """mypy / tsc — only when the project already uses them."""

    name: ClassVar[str] = "typecheck"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        root = str(ctx.root)
        reasons: list[str] = []

        py = _targets(ctx, changed_files, PY_EXTS)
        if py and _mypy_configured(ctx.root):
            if tool_available("mypy"):
                result = run_command(
                    ["mypy", *py[:_MAX_FILES]],
                    cwd=root,
                    timeout=self._timeout(ctx),
                )
                if not result.ok:
                    return self._failed(f"mypy reported errors: {result.tail()}")
                return self._passed(f"mypy clean on {len(py)} file(s)")
            reasons.append("mypy is configured but not installed")
        elif py:
            reasons.append("the project configures no mypy settings")

        ts = _targets(ctx, changed_files, TS_EXTS + JS_EXTS)
        if ts and (ctx.root / "tsconfig.json").is_file():
            if tool_available("npx"):
                result = run_command(
                    ["npx", "--no-install", "tsc", "--noEmit"],
                    cwd=root,
                    timeout=self._timeout(ctx),
                )
                if result.error or "not found" in result.output.lower():
                    reasons.append("tsc is configured but not installed")
                elif not result.ok:
                    return self._failed(f"tsc reported errors: {result.tail()}")
                else:
                    return self._passed("tsc --noEmit clean")
            else:
                reasons.append("tsconfig.json exists but npx is unavailable")
        elif ts:
            reasons.append("no tsconfig.json")

        return self._skipped("; ".join(reasons) or "no type checker applies to the changes")


class LintValidator(Validator):
    """ruff / eslint — only when the project already configures them."""

    name: ClassVar[str] = "lint"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        root = str(ctx.root)
        reasons: list[str] = []

        py = _targets(ctx, changed_files, PY_EXTS)
        if py and _ruff_configured(ctx.root):
            if tool_available("ruff"):
                result = run_command(
                    ["ruff", "check", *py[:_MAX_FILES]],
                    cwd=root,
                    timeout=self._timeout(ctx, full=False),
                )
                if not result.ok:
                    return self._failed(f"ruff reported violations: {result.tail()}")
                return self._passed(f"ruff clean on {len(py)} file(s)")
            reasons.append("ruff is configured but not installed")
        elif py:
            reasons.append("the project configures no ruff settings")

        js = _targets(ctx, changed_files, JS_EXTS + TS_EXTS)
        if js and _eslint_configured(ctx.root):
            if tool_available("npx"):
                result = run_command(
                    ["npx", "--no-install", "eslint", *js[:_MAX_FILES]],
                    cwd=root,
                    timeout=self._timeout(ctx, full=False),
                )
                if result.error:
                    reasons.append("eslint is configured but not installed")
                elif not result.ok:
                    return self._failed(f"eslint reported violations: {result.tail()}")
                else:
                    return self._passed(f"eslint clean on {len(js)} file(s)")
            else:
                reasons.append("eslint is configured but npx is unavailable")
        elif js:
            reasons.append("the project configures no eslint settings")

        return self._skipped("; ".join(reasons) or "no linter applies to the changes")


class TargetedTestValidator(Validator):
    """Run only the tests related to the changed modules."""

    name: ClassVar[str] = "tests:targeted"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        if not changed_files:
            return self._skipped("baseline run — the full suite rung covers the project")
        root = str(ctx.root)
        py = changed_with_suffix(changed_files, PY_EXTS)
        js = changed_with_suffix(changed_files, JS_EXTS + TS_EXTS)

        if py and _pytest_project(ctx):
            expression = " or ".join(sorted({PurePosixPath(f).stem for f in py}))
            result = run_command(
                [sys.executable, "-m", "pytest", "-q", "-k", expression],
                cwd=root,
                timeout=self._timeout(ctx, full=False),
            )
            # pytest exit code 5 == "no tests matched", which is not a failure of ours.
            if result.returncode == 5:
                return self._skipped(f"no tests matched -k {expression!r}")
            if not result.ok:
                return self._failed(f"pytest -k {expression!r} failed: {result.tail()}")
            return self._passed(f"pytest -k {expression!r} passed")

        if js and _jest_project(ctx) and tool_available("npx"):
            result = run_command(
                ["npx", "--no-install", "jest", "--findRelatedTests", *js, "--passWithNoTests"],
                cwd=root,
                timeout=self._timeout(ctx, full=False),
            )
            if result.error:
                return self._skipped("jest is not installed")
            if not result.ok:
                return self._failed(f"jest --findRelatedTests failed: {result.tail()}")
            return self._passed("jest --findRelatedTests passed")

        return self._skipped("no test framework detected for the changed files")


class FullTestValidator(Validator):
    """Run the project's whole test suite."""

    name: ClassVar[str] = "tests:full"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        root = str(ctx.root)
        if _pytest_project(ctx):
            result = run_command(
                [sys.executable, "-m", "pytest", "-q"],
                cwd=root,
                timeout=self._timeout(ctx),
            )
            if result.returncode == 5:
                return self._skipped("pytest collected no tests")
            if not result.ok:
                return self._failed(f"the pytest suite failed: {result.tail()}")
            return self._passed("the pytest suite passed")

        if _npm_script(ctx.root, "test") and tool_available("npm"):
            result = run_command(
                ["npm", "test", "--silent"],
                cwd=root,
                timeout=self._timeout(ctx),
            )
            if not result.ok:
                return self._failed(f"npm test failed: {result.tail()}")
            return self._passed("npm test passed")

        return self._skipped("the project has no test suite to run")


class BuildValidator(Validator):
    """``npm run build`` when it exists; a Python package build when one is possible."""

    name: ClassVar[str] = "build"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        root = str(ctx.root)
        if _npm_script(ctx.root, "build"):
            if not tool_available("npm"):
                return self._skipped("a build script exists but npm is not installed")
            result = run_command(["npm", "run", "build"], cwd=root, timeout=self._timeout(ctx))
            if not result.ok:
                return self._failed(f"npm run build failed: {result.tail()}")
            return self._passed("npm run build succeeded")

        if "build-system" in _pyproject(ctx.root):
            probe = run_command(
                [sys.executable, "-c", "import build"], cwd=root, timeout=30
            )
            if not probe.ok:
                return self._skipped(
                    "the project is a Python package but the `build` module is not installed"
                )
            result = run_command(
                [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir",
                 ".vibeguard/build"],
                cwd=root,
                timeout=self._timeout(ctx),
            )
            if not result.ok:
                return self._failed(f"python -m build failed: {result.tail()}")
            return self._passed("python -m build produced a wheel")

        return self._skipped("no build step detected")


class ContainerBuildValidator(Validator):
    """``docker build`` — only under ``fix --deep-validate``."""

    name: ClassVar[str] = "container_build"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        if not ctx.config.fix.deep_validate:
            return self._skipped("container builds run only with --deep-validate")
        dockerfiles = [f for f in ctx.files if PurePosixPath(f).name.lower() == "dockerfile"]
        if not dockerfiles:
            return self._skipped("no Dockerfile in the repository")
        if not tool_available("docker"):
            return self._skipped("docker is not installed")
        rel = dockerfiles[0]
        result = run_command(
            ["docker", "build", "--quiet", "--file", rel, "."],
            cwd=str(ctx.root),
            timeout=self._timeout(ctx),
        )
        if not result.ok:
            return self._failed(f"docker build failed for {rel}: {result.tail()}")
        return self._passed(f"docker build succeeded for {rel}")


class StartupValidator(Validator):
    """App start-up smoke test — deliberately unimplemented in the MVP."""

    name: ClassVar[str] = "startup"

    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        return self._skipped(
            "start-up smoke tests are not implemented in the MVP: booting an unknown app "
            "needs its runtime configuration (ports, env, databases). Tracked as a known "
            "gap rather than faked."
        )


def default_validators() -> list[Validator]:
    """The ladder, in ARCHITECTURE.md §7 order."""
    return [
        SyntaxValidator(),
        TypecheckValidator(),
        LintValidator(),
        TargetedTestValidator(),
        FullTestValidator(),
        BuildValidator(),
        ContainerBuildValidator(),
        StartupValidator(),
    ]
