"""VG-TEST-002 — the CI pipeline never runs the test suite."""

from __future__ import annotations

import logging
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.testing._common import has_test_suite

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["CiDoesNotRunTestsRule"]

log = logging.getLogger(__name__)


_CI_SUFFIXES = {".yml", ".yaml"}
_CI_FILE_NAMES = {".gitlab-ci.yml", ".gitlab-ci.yaml", "jenkinsfile"}

_TEST_COMMAND = re.compile(
    r"""(?ix)
    \bpytest\b | \bpy\.test\b | python\s+-m\s+(?:pytest|unittest)
  | \btox\b | \bnox\b | \bhatch\s+test\b
  | npm\s+(?:run\s+)?test | yarn\s+(?:run\s+)?test | pnpm\s+(?:run\s+)?test
  | npx\s+(?:jest|vitest|mocha|playwright) | \bjest\b | \bvitest\b | \bmocha\b
  | \bcypress\s+run\b | playwright\s+test
  | go\s+test\b | cargo\s+test\b | \bmvn\s+test\b | gradle\s+test\b
  | \bmake\s+test\b | \bbundle\s+exec\s+rspec\b | \brspec\b
  | coverage\s+run | \bnose2?\b | dotnet\s+test\b
    """
)


def _ci_files(ctx: ScanContext) -> list[str]:
    out: list[str] = []
    for rel in ctx.files:
        path = PurePosixPath(rel)
        name = path.name.lower()
        if rel.startswith(".github/workflows/") and path.suffix.lower() in _CI_SUFFIXES:
            out.append(rel)
        elif name in _CI_FILE_NAMES or name.startswith("jenkinsfile"):
            out.append(rel)
    return out[:25]


class CiDoesNotRunTestsRule(ProjectRule):
    """CI exists and tests exist, but no CI step invokes a test runner."""

    id: ClassVar[str] = "VG-TEST-002"
    category: ClassVar[Category] = Category.TESTING
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "CI does not run the test suite"
    description: ClassVar[str] = (
        "A CI configuration and a test suite both exist, but no CI step invokes a test "
        "runner."
    )
    why_it_matters: ClassVar[str] = (
        "Tests that only run when someone remembers to run them stop running within a "
        "few weeks, and then quietly rot: by the time anyone tries, half of them fail "
        "for reasons unrelated to the change being reviewed. A pipeline that does not "
        "execute the suite gives the worst of both worlds — a green checkmark on every "
        "pull request that proves nothing about whether the code works."
    )
    references: ClassVar[list[str]] = [
        "https://docs.github.com/actions/writing-workflows/quickstart",
        "https://docs.pytest.org/en/stable/how-to/usage.html",
    ]
    topics: ClassVar[set[str]] = {
        "testing.unit-tests",
        "testing.smoke-tests",
        "deployment.ci-cd-pipelines",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    # M3 fix(): append a `- run: pytest` step to the existing workflow job.
    recommended_followup: ClassVar[str] = (
        "Add a step that runs the suite and fails the job on a non-zero exit — "
        "`- run: pytest -q` (or `- run: npm test`) after the dependency-install step — "
        "and make that check required before merging."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            if not has_test_suite(ctx):
                return None  # VG-MAINT-001 already reports "no tests at all".
            ci_files = _ci_files(ctx)
            if not ci_files:
                return None
            for rel in ci_files:
                if _TEST_COMMAND.search(ctx.read(rel)):
                    return None
        except Exception:  # pragma: no cover - defensive
            # Broad by design: the rule/repository boundary. A scan must never
            # die on one unreadable input — but it must not go quiet either.
            log.debug("CI test-command search failed; skipping the check", exc_info=True)
            return None
        listed = ", ".join(ci_files[:5])
        return (
            f"CI configuration exists ({listed}) and the project has tests, but no "
            "pipeline step runs a test command.",
            "searched CI configs for pytest/tox/nox, npm|yarn|pnpm test, jest, vitest, "
            "mocha, playwright, cypress run, go test, cargo test, and make test",
        )
