"""VG-DB-001, VG-DB-003, VG-DB-007 — how the application talks to the database.

* **VG-DB-001** query issued inside a loop (the N+1 pattern).
* **VG-DB-003** ``SELECT *`` in application code.
* **VG-DB-007** several writes in one function with no transaction boundary.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    RegexRule,
    calls,
    enclosing_function,
    in_loop,
    node_text,
    source_files,
)
from vibeguard.rules.database._common import MAX_FINDINGS, function_name

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NPlusOneQueryRule", "SelectStarRule", "UntransactedMultiWriteRule"]

_CODE_SUFFIXES = PY_SUFFIXES + JS_SUFFIXES

# Call bases that are a database round-trip whatever the receiver is.
_DRIVER_BASES = {
    "execute",
    "executemany",
    "fetchone",
    "fetchall",
    "find_one",
    "findone",
    "findunique",
    "findfirst",
    "findmany",
    "aggregate",
    "get_or_404",
}
# Call bases that are only a query when the receiver looks like an ORM entry point.
_ORM_BASES = {
    "get",
    "filter",
    "filter_by",
    "query",
    "find",
    "first",
    "all",
    "one",
    "one_or_none",
    "scalar",
    "count",
}
_ORM_RECEIVER = re.compile(
    r"\b(session|objects|query|queryset|db|database|models?|repo|repository|"
    r"collection|prisma|knex|orm|conn|connection|cursor|client|table)\b",
    re.IGNORECASE,
)
#: A CapWords receiver is an ORM model class (``User.get(...)``). An ALL-CAPS one
#: is a module constant — ``SOURCE_EXTENSIONS.get(ext)`` is a dict lookup, not a
#: database round-trip — so at least one lowercase letter is required.
_MODEL_RECEIVER = re.compile(r"(^|\.)[A-Z][A-Za-z0-9_]*[a-z][A-Za-z0-9_]*$")


def _is_query_call(site: CallSite) -> bool:
    """True when this call site is (almost certainly) a database round-trip."""
    name = site.name
    if "." not in name:
        return False
    base = site.base.lower()
    receiver = name.rsplit(".", 1)[0]
    if base in _DRIVER_BASES:
        return True
    if base not in _ORM_BASES:
        return False
    if _ORM_RECEIVER.search(receiver):
        return True
    return bool(_MODEL_RECEIVER.search(receiver))


class NPlusOneQueryRule(Rule):
    """A query executed once per iteration of a loop."""

    id: ClassVar[str] = "VG-DB-001"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "N+1 query pattern"
    description: ClassVar[str] = (
        "A database query runs inside a loop, so the number of round-trips grows with "
        "the size of the collection being iterated."
    )
    why_it_matters: ClassVar[str] = (
        "One page that lists 500 rows becomes 501 separate database round-trips. Each "
        "one costs a network hop and a connection slot, so the endpoint gets slower as "
        "the data grows and eventually exhausts the connection pool under normal traffic. "
        "It is also pure waste on a metered database: you pay per query."
    )
    references: ClassVar[list[str]] = [
        "https://docs.sqlalchemy.org/en/20/orm/queryguide/relationships.html",
        "https://docs.djangoproject.com/en/stable/ref/models/querysets/#select-related",
    ]
    topics: ClassVar[set[str]] = {
        "database.n-plus-one",
        "database.query-optimization",
        "performance.database-bottlenecks",
        "cost.excessive-db-queries",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for rel in source_files(ctx, _CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            source = ctx.read(rel).encode("utf-8")
            for site in calls(ctx, rel):
                if len(findings) >= MAX_FINDINGS:
                    break
                if not _is_query_call(site) or not in_loop(site.node):
                    continue
                func = enclosing_function(site.node)
                key = (rel, function_name(source, func) or str(site.line))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=node_text(source, site.node)[:200],
                        description=(
                            f"{site.name}(...) is executed inside a loop in {rel} "
                            f"(line {site.line}); the query count scales with the "
                            "collection being iterated."
                        ),
                        recommended_followup=(
                            "Load the related rows in one query before the loop — e.g. "
                            "`select_related()`/`prefetch_related()` (Django), "
                            "`selectinload()`/`joinedload()` (SQLAlchemy), or a single "
                            "`WHERE id IN (...)` fetch keyed into a dict."
                        ),
                    )
                )
        return findings


class SelectStarRule(RegexRule):
    """``SELECT *`` in application code."""

    id: ClassVar[str] = "VG-DB-003"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "SELECT * in application code"
    description: ClassVar[str] = (
        "A query selects every column with `SELECT *` instead of naming the columns "
        "the caller actually needs."
    )
    why_it_matters: ClassVar[str] = (
        "`SELECT *` ships every column over the wire, including large blobs the caller "
        "never reads, and it silently changes shape the moment someone adds a column — "
        "which can break serialisation or leak a newly added sensitive field into an API "
        "response. It also defeats covering indexes, so the query is slower than it needs "
        "to be."
    )
    references: ClassVar[list[str]] = [
        "https://use-the-index-luke.com/sql/partial-results/fetch-only-what-you-need",
    ]
    topics: ClassVar[set[str]] = {
        "database.query-optimization",
        "performance.excessive-serialization",
        "performance.slow-queries",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    suffixes: ClassVar[tuple[str, ...]] = _CODE_SUFFIXES
    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"select\s+\*\s+from\s", re.IGNORECASE),
        re.compile(r"select\s+\*\s*$", re.IGNORECASE),
    )
    #: ``skip_generated`` already drops ``migrations/``; tests are dropped too.
    max_per_file: ClassVar[int] = 3
    max_total: ClassVar[int] = 10
    recommended_followup: ClassVar[str] = (
        "Name the columns the caller needs, e.g. `SELECT id, email FROM users ...`, so "
        "the result shape is stable and the payload stays small."
    )


_WRITE_BASES = {"save", "create", "delete", "insert", "update", "bulk_create", "destroy"}
_SESSION_WRITE_BASES = {"add", "add_all", "merge"}
_SQL_WRITE = re.compile(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.IGNORECASE)
_TRANSACTION = re.compile(
    r"with\s+\w[\w\.]*\s*:|"
    r"\.begin\s*\(|begin_nested\s*\(|session\.begin|"
    r"transaction\.atomic|\.atomic\s*\(|"
    r"\btransaction\s*\(|\$transaction\b|"
    r"\bBEGIN\b|START\s+TRANSACTION",
    re.IGNORECASE,
)


def _is_write_call(site: CallSite) -> bool:
    base = site.base.lower()
    receiver = site.name.rsplit(".", 1)[0] if "." in site.name else ""
    if base in {"execute", "executemany", "query", "raw"}:
        return bool(_SQL_WRITE.search(site.args))
    if base in _SESSION_WRITE_BASES:
        return bool(_ORM_RECEIVER.search(receiver))
    if base not in _WRITE_BASES:
        return False
    if not receiver:
        return False
    return bool(_ORM_RECEIVER.search(receiver) or _MODEL_RECEIVER.search(receiver))


class UntransactedMultiWriteRule(Rule):
    """Two or more writes in one function with no transaction boundary."""

    id: ClassVar[str] = "VG-DB-007"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Multi-statement write without a transaction"
    description: ClassVar[str] = (
        "A function performs two or more INSERT/UPDATE/DELETE operations without opening "
        "a transaction, so a failure part-way through leaves the database half-updated."
    )
    why_it_matters: ClassVar[str] = (
        "If the process crashes, the request times out, or the second write violates a "
        "constraint, the first write is already committed and there is nothing to roll "
        "back to. That is how orders get charged without being recorded and how users end "
        "up existing without their profile row. The damage is silent and only surfaces "
        "later as inconsistent data nobody can explain."
    )
    references: ClassVar[list[str]] = [
        "https://docs.sqlalchemy.org/en/20/orm/session_transaction.html",
        "https://docs.djangoproject.com/en/stable/topics/db/transactions/",
    ]
    topics: ClassVar[set[str]] = {"database.transactions", "database.data-integrity"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, _CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            source = ctx.read(rel).encode("utf-8")
            per_function: dict[int, list[CallSite]] = {}
            for site in calls(ctx, rel):
                if not _is_write_call(site):
                    continue
                func = enclosing_function(site.node)
                if func is None:
                    continue
                per_function.setdefault(func.start_byte, []).append(site)
            for start, sites in sorted(per_function.items()):
                if len(findings) >= MAX_FINDINGS:
                    break
                if len(sites) < 2:
                    continue
                func = enclosing_function(sites[0].node)
                body = node_text(source, func)
                if _TRANSACTION.search(body):
                    continue
                name = function_name(source, func) or f"<function at byte {start}>"
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=sites[0].line,
                        snippet="; ".join(site.name for site in sites[:4])[:200],
                        description=(
                            f"{name}() in {rel} performs {len(sites)} write operations "
                            "with no transaction boundary in scope."
                        ),
                        recommended_followup=(
                            "Wrap the writes in one transaction — `with session.begin():` "
                            "(SQLAlchemy), `with transaction.atomic():` (Django), "
                            "`with conn:` (DB-API), or `prisma.$transaction([...])` — so "
                            "they commit or roll back together."
                        ),
                    )
                )
        return findings
