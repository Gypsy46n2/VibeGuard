"""VG-PERF-002 — list endpoints that return the whole table."""

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
from vibeguard.rules.api._http import handlers

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ListEndpointWithoutPaginationRule"]

_MAX_FINDINGS = 8

_UNBOUNDED = re.compile(
    r"\.objects\.all\s*\(\s*\)|\.query\.all\s*\(\s*\)|\.all\s*\(\s*\)|"
    r"\.find\s*\(\s*\{?\s*\}?\s*\)|\.findAll\s*\(\s*\)|\.findMany\s*\(\s*\)|"
    r"fetchall\s*\(\s*\)|scan\s*\(\s*\)"
)
_RAW_SELECT = re.compile(r"SELECT\b(?![\s\S]{0,400}?\bLIMIT\b)", re.IGNORECASE)
#: A raw SELECT only counts as a *list* read when the handler actually drains the
#: cursor; `SELECT … WHERE id = ?` followed by fetchone() returns one row, not a page.
_DRAINS_CURSOR = re.compile(r"fetchall\s*\(|fetchmany\s*\(")
_SINGLE_ROW = re.compile(
    r"fetchone\s*\(|\.first\s*\(|\.one\s*\(|\.one_or_none\s*\(|\.scalar\s*\(|"
    r"get_object_or_404\s*\(|\.get\s*\(\s*(?:pk|id)\s*="
)
_PAGINATED = re.compile(
    r"\blimit\b|\boffset\b|\bpage\b|\bcursor\b|paginate|pagination|per_page|perPage|"
    r"page_size|pageSize|\btake\b|\bskip\b|\[:\s*\d|\[\s*\d+\s*:|slice\s*\(|"
    r"Paginator|LimitOffset|\.first\s*\(",
    re.IGNORECASE,
)


class ListEndpointWithoutPaginationRule(Rule):
    """A route that serialises an entire collection with no upper bound."""

    id: ClassVar[str] = "VG-PERF-002"
    category: ClassVar[Category] = Category.PERFORMANCE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "List endpoint without pagination"
    description: ClassVar[str] = (
        "A read handler returns an unbounded collection — .all(), .find({}), findMany(), or "
        "a SELECT with no LIMIT — and takes no limit, offset, cursor, or page parameter."
    )
    why_it_matters: ClassVar[str] = (
        "The endpoint is fast in development with fifty rows and fatal in production with "
        "five hundred thousand: the database streams every row, the process serialises them "
        "all into memory at once, and the response can be hundreds of megabytes. One such "
        "request can exhaust the container's memory and take the whole instance down, and "
        "the egress for those payloads is billed to you."
    )
    references: ClassVar[list[str]] = [
        "https://www.django-rest-framework.org/api-guide/pagination/",
        "https://use-the-index-luke.com/no-offset",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "performance.large-payloads",
        "performance.excessive-serialization",
        "cost.expensive-network-transfers",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for handler in handlers(ctx):
            if len(findings) >= _MAX_FINDINGS:
                break
            if not handler.accepts("get"):
                continue
            body = handler.text
            if not body:
                continue
            if _SINGLE_ROW.search(body):
                continue
            match = _UNBOUNDED.search(body)
            if match is None and _DRAINS_CURSOR.search(body):
                match = _RAW_SELECT.search(body)
            if match is None:
                continue
            if _PAGINATED.search(body):
                continue
            findings.append(
                self.make_finding(
                    file=handler.file,
                    line=handler.line,
                    snippet=match.group(0).strip()[:400],
                    description=(
                        f"Handler {handler.name}() at {handler.file}:{handler.line} returns "
                        f"`{match.group(0).strip()}` with no limit, offset, cursor, or page "
                        "parameter."
                    ),
                    recommended_followup=(
                        "Accept `limit` (with a sane maximum) and a `cursor`/`offset`, apply "
                        "them in the query itself — e.g. `.limit(limit).offset(offset)` — and "
                        "return the next cursor alongside the page."
                    ),
                )
            )
        return findings
