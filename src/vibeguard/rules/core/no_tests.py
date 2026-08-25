"""VG-MAINT-001 — no test suite detected."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.fingerprint import PROJECT_PATH
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

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoTestSuiteRule"]

_TEST_DIR_NAMES = {"tests", "test", "__tests__", "spec", "e2e"}
_TEST_FILE_HINTS = ("test_", "_test.", ".test.", ".spec.", "_spec.")


def _has_test_files(ctx: ScanContext) -> bool:
    for rel in ctx.files:
        path = PurePosixPath(rel)
        if any(part.lower() in _TEST_DIR_NAMES for part in path.parts[:-1]):
            return True
        name = path.name.lower()
        if any(hint in name for hint in _TEST_FILE_HINTS):
            return True
    return False


class NoTestSuiteRule(Rule):
    """Fires when neither a test framework nor any test files can be found."""

    id: ClassVar[str] = "VG-MAINT-001"
    category: ClassVar[Category] = Category.TESTING
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "No test suite detected"
    description: ClassVar[str] = (
        "No test framework is configured and no test files were found in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "Without tests, every change is unverified: regressions ship silently, and no "
        "automated repair (including VibeGuard's own fixes) can be validated before it "
        "lands. A minimal smoke-test suite is the cheapest safety net a project can have."
    )
    references: ClassVar[list[str]] = [
        "https://docs.pytest.org/en/stable/getting-started.html",
        "https://jestjs.io/docs/getting-started",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"testing.unit-tests"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        if ctx.tech.test_frameworks:
            return []
        if any(ctx.exists(name) for name in sorted(_TEST_DIR_NAMES)):
            return []
        if _has_test_files(ctx):
            return []

        languages = ", ".join(sorted(ctx.tech.languages)) or "unknown"
        suggestion = "pytest" if "python" in ctx.tech.languages else "a test runner"
        return [
            self.make_finding(
                file=None,
                description=(
                    "No test framework was detected in the manifests and no test "
                    f"directory or test file exists (languages detected: {languages})."
                ),
                evidence=[
                    Evidence(
                        file=PROJECT_PATH,
                        note=(
                            "checked manifests for test frameworks and the tree for "
                            "tests/, test/, __tests__/, *_test.*, test_*.py, *.spec.*"
                        ),
                    )
                ],
                recommended_followup=(
                    f"Add {suggestion} and one smoke test that imports the application "
                    "entrypoint and exercises its happy path, then wire it into CI."
                ),
            )
        ]
