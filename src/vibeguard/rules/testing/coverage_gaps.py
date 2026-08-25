"""VG-TEST-001 / VG-TEST-003 — kinds of test the suite never exercises."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.testing._common import has_test_suite, test_files, test_text

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoDatabaseTestsRule", "NoIntegrationTestsRule"]

_HTTP_TEST_TOKENS = (
    "testclient",
    "test_client",
    "asyncclient",
    "httpx",
    "supertest",
    "apiclient",
    "webtestclient",
    "app.inject(",
    "client.get(",
    "client.post(",
    "client.put(",
    "client.patch(",
    "client.delete(",
    "requests.get(",
    "requests.post(",
    "axios.",
    "fetch(",
    "httptest",
    "rest_framework.test",
    "flask.testing",
    "aiohttp.test_utils",
)


class NoIntegrationTestsRule(ProjectRule):
    """Tests exist, but none of them go through the HTTP surface."""

    id: ClassVar[str] = "VG-TEST-001"
    category: ClassVar[Category] = Category.TESTING
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No integration or API tests"
    description: ClassVar[str] = (
        "The project serves HTTP but no test drives a request through the application "
        "— no test client, supertest, or HTTP call was found in the test suite."
    )
    why_it_matters: ClassVar[str] = (
        "Unit tests prove individual functions behave; only a request-level test "
        "proves the parts are wired together. Routing typos, broken serialisers, "
        "missing auth decorators, and misconfigured middleware all pass unit tests and "
        "fail in production, and they are exactly the bugs that a handful of "
        "\"call the endpoint, check the status code\" tests catch in seconds."
    )
    references: ClassVar[list[str]] = [
        "https://fastapi.tiangolo.com/tutorial/testing/",
        "https://flask.palletsprojects.com/en/stable/testing/",
    ]
    topics: ClassVar[set[str]] = {
        "testing.integration-tests",
        "testing.api-tests",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Add one request-level test per critical route using the framework's own test "
        "client (`TestClient(app)` for FastAPI/Starlette, `app.test_client()` for "
        "Flask, `supertest(app)` for Express) that asserts the status code and the "
        "shape of the response body."
    )

    not_applicable_note: ClassVar[str] = (
        "the project has no test suite at all — VG-MAINT-001 reports that, and this "
        "topic cannot be assessed until tests exist"
    )

    def applicable(self, ctx: ScanContext) -> bool:
        # No tests at all is VG-MAINT-001's finding; this topic is then unassessable,
        # which the checklist must show as NOT_APPLICABLE rather than PASS.
        return super().applicable(ctx) and bool(ctx.tech.backend) and has_test_suite(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            text = test_text(ctx)
            if any(token in text for token in _HTTP_TEST_TOKENS):
                return None
        except Exception:  # pragma: no cover - defensive
            return None
        return (
            f"A server framework ({', '.join(sorted(ctx.tech.backend))}) is present and "
            f"{len(test_files(ctx))} test file(s) exist, but none of them issue an HTTP "
            "request against the application.",
            "searched the test suite for TestClient, app.test_client(), supertest, "
            "httpx.AsyncClient, APIClient, and direct client.get/post calls",
        )


_DB_TEST_RE = re.compile(
    r"""(?ix)
    \bdb\b | \bdatabase\b | \bsession\b | sqlalchemy | create_engine | sessionmaker
  | \bcursor\b | \.execute\s*\( | testcontainers | \bmigrat | \bfixtures?\.db\b
  | prisma | mongoose | pymongo | psycopg | \.objects\. | \bqueryset\b | \brepository\b
  | \btransaction\b | \brollback\b | sqlite | postgres | mysql | \bmongo\b
    """
)


class NoDatabaseTestsRule(ProjectRule):
    """A database is in use but no test touches the persistence layer."""

    id: ClassVar[str] = "VG-TEST-003"
    category: ClassVar[Category] = Category.TESTING
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No database tests"
    description: ClassVar[str] = (
        "The project uses a database, but no test in the suite exercises the query, "
        "model, or migration layer."
    )
    why_it_matters: ClassVar[str] = (
        "The database layer is where the data you cannot recreate lives. Untested "
        "queries mean a wrong join or a missing filter silently returns another "
        "customer's rows, and untested migrations mean a deploy can fail halfway with "
        "the schema in a state no code expects. These are the failures that cost real "
        "data rather than a retry."
    )
    references: ClassVar[list[str]] = [
        "https://docs.sqlalchemy.org/en/20/orm/session_transaction.html",
        "https://testcontainers-python.readthedocs.io/en/latest/",
    ]
    topics: ClassVar[set[str]] = {"testing.database-tests"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Add a test fixture that creates a throwaway database (SQLite file, or a "
        "container via testcontainers), runs the migrations, and rolls back after each "
        "test — then cover the two or three queries whose results users actually see."
    )

    not_applicable_note: ClassVar[str] = (
        "the project has no test suite at all — VG-MAINT-001 reports that, and this "
        "topic cannot be assessed until tests exist"
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return (
            super().applicable(ctx)
            and bool(ctx.tech.databases or ctx.tech.orms)
            and has_test_suite(ctx)
        )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            if _DB_TEST_RE.search(test_text(ctx)):
                return None
        except Exception:  # pragma: no cover - defensive
            return None
        stores = ", ".join(sorted(set(ctx.tech.databases) | set(ctx.tech.orms))) or "a database"
        return (
            f"The project uses {stores} but no test file references a session, query, "
            "model, or migration.",
            "searched the test suite for db/session/cursor/execute, sqlalchemy, "
            "prisma, mongoose, testcontainers, and migration helpers",
        )
