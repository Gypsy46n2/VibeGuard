"""VG-TEST-004 / VG-TEST-005 — end-to-end, load, concurrency, and security tests."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.testing._common import has_test_suite, test_paths_text, test_text

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoEndToEndTestsRule", "NoNonFunctionalTestsRule"]

log = logging.getLogger(__name__)


_E2E_TOKENS = (
    "playwright",
    "cypress",
    "selenium",
    "webdriver",
    "puppeteer",
    "testcafe",
    "nightwatch",
    "capybara",
    "smoke",
    "end-to-end",
    "end_to_end",
    "/e2e/",
    "e2e/",
    "browser_context",
)


class NoEndToEndTestsRule(ProjectRule):
    """Nothing exercises the system the way a user does."""

    id: ClassVar[str] = "VG-TEST-004"
    category: ClassVar[Category] = Category.TESTING
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No end-to-end or smoke tests"
    description: ClassVar[str] = (
        "No browser-driving or end-to-end framework and no smoke test were found, so "
        "no test walks a complete user journey through the deployed system."
    )
    why_it_matters: ClassVar[str] = (
        "Every layer can pass its own tests while the assembled product is broken — a "
        "changed environment variable, a missing static file, a login redirect loop. A "
        "single smoke test that signs in and loads the main page after each deploy "
        "catches those in a minute, instead of leaving the first real user to discover "
        "that the site has been down since the morning."
    )
    references: ClassVar[list[str]] = [
        "https://playwright.dev/docs/intro",
        "https://martinfowler.com/bliki/TestPyramid.html",
    ]
    topics: ClassVar[set[str]] = {
        "testing.e2e-tests",
        "testing.smoke-tests",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Add one Playwright (or Cypress) test that performs the single most important "
        "journey — sign in, do the main action, see the result — and run it against a "
        "staging deploy in CI as a post-deploy smoke check."
    )

    not_applicable_note: ClassVar[str] = (
        "the project has no test suite at all — VG-MAINT-001 reports that, and this "
        "topic cannot be assessed until tests exist"
    )

    def applicable(self, ctx: ScanContext) -> bool:
        # Unassessable, not passing, when the project has no tests at all.
        return super().applicable(ctx) and has_test_suite(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            frameworks = {name.lower() for name in ctx.tech.test_frameworks}
            if frameworks & {"playwright", "cypress", "selenium", "puppeteer"}:
                return None
            haystack = test_text(ctx) + "\n" + test_paths_text(ctx)
            if any(token in haystack for token in _E2E_TOKENS):
                return None
        except Exception:  # pragma: no cover - defensive
            # Broad by design: the rule/repository boundary. A scan must never
            # die on one unreadable input — but it must not go quiet either.
            log.debug("end-to-end test search failed; skipping the check", exc_info=True)
            return None
        return (
            "No end-to-end framework (Playwright, Cypress, Selenium, Puppeteer), no "
            "`e2e/` directory, and no smoke test were found.",
            "searched dependencies, test paths, and test bodies for e2e frameworks, "
            "an e2e directory, and smoke-test naming",
        )


_LOAD_RE = re.compile(
    r"(?i)\b(?:locust|k6|jmeter|artillery|gatling|vegeta|wrk|hey|bombardier|"
    r"load[_\-]?test|loadtest|stress[_\-]?test|pytest[_\-]benchmark|benchmark)\b"
)
_CONCURRENCY_RE = re.compile(
    r"(?i)\b(?:threading|concurrent\.futures|asyncio\.gather|multiprocessing|"
    r"go\s+test\s+-race|-race\b|race[_\-]?condition|parallel[_\-]?test|"
    r"pytest[_\-]xdist|worker_threads)\b"
)
_SECURITY_RE = re.compile(
    r"(?i)\b(?:bandit|zap|sqlmap|nikto|security[_\-]?test|test[_\-]?security|"
    r"xss|csrf|sql[_\-]?injection|authz|authorization[_\-]?test|owasp|"
    r"safety\s+check|npm\s+audit|pip-audit)\b"
)


class NoNonFunctionalTestsRule(ProjectRule):
    """No load, concurrency, or security-regression coverage anywhere."""

    id: ClassVar[str] = "VG-TEST-005"
    category: ClassVar[Category] = Category.TESTING
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No non-functional test coverage"
    description: ClassVar[str] = (
        "The suite covers behaviour only: no load or benchmark test, no concurrency or "
        "race-condition test, and no security regression test were found."
    )
    why_it_matters: ClassVar[str] = (
        "Correctness tests answer \"does it do the right thing for one user?\". They "
        "say nothing about what happens at a hundred users at once, when two requests "
        "update the same row, or when someone sends a crafted payload. Those are "
        "precisely the failures that arrive with real traffic, and the ones that are "
        "hardest to reproduce afterwards from logs alone."
    )
    references: ClassVar[list[str]] = [
        "https://k6.io/docs/test-types/load-testing/",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]
    topics: ClassVar[set[str]] = {
        "testing.load-tests",
        "testing.concurrency-tests",
        "testing.security-regression-tests",
        "performance.throughput",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Start with the cheapest one that matches your risk: a k6 or Locust script "
        "hitting the busiest endpoint at expected peak, a test that fires two "
        "concurrent writes at the same record and asserts the invariant holds, or a "
        "regression test for each security bug you have already fixed."
    )

    not_applicable_note: ClassVar[str] = (
        "the project has no test suite at all — VG-MAINT-001 reports that, and this "
        "topic cannot be assessed until tests exist"
    )

    def applicable(self, ctx: ScanContext) -> bool:
        # Unassessable, not passing, when the project has no tests at all.
        return super().applicable(ctx) and has_test_suite(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            haystack = test_text(ctx) + "\n" + test_paths_text(ctx)
            manifests = "\n".join(ctx.read(rel).lower() for rel in ctx.tech.manifest_files)
            combined = haystack + "\n" + manifests
            missing = [
                label
                for label, pattern in (
                    ("load", _LOAD_RE),
                    ("concurrency", _CONCURRENCY_RE),
                    ("security regression", _SECURITY_RE),
                )
                if not pattern.search(combined)
            ]
            if len(missing) < 3:
                return None
        except Exception:  # pragma: no cover - defensive
            # Broad by design: the rule/repository boundary. A scan must never
            # die on one unreadable input — but it must not go quiet either.
            log.debug("non-functional test search failed; skipping the check", exc_info=True)
            return None
        return (
            "The test suite has no load or benchmark tests, no concurrency or "
            "race-condition tests, and no security regression tests.",
            "searched tests and manifests for locust/k6/jmeter/artillery/benchmark, "
            "threading/asyncio.gather/-race/xdist, and bandit/zap/xss/csrf/authz tests",
        )
