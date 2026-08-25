"""VG-SEC-001 / VG-SEC-002 — SQL injection via interpolated queries."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

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
    js_calls,
    node_text,
    py_calls,
    source_files,
)
from vibeguard.rules.security._taint import (
    arg_nodes,
    first_arg,
    is_interpolated_js,
    is_interpolated_py,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["SqlInjectionJavaScriptRule", "SqlInjectionPythonRule"]

#: Only treat an interpolated argument as a query when it reads like SQL.
SQL_KEYWORDS = re.compile(
    r"\b(select|insert\s+into|update|delete\s+from|drop\s+table|alter\s+table|"
    r"create\s+table|truncate|union\s+all|union\s+select|from|where|values)\b",
    re.IGNORECASE,
)

_PY_CALLEES = {"execute", "executemany", "executescript", "raw", "text", "execute_sql"}
_JS_CALLEES = {"query", "execute", "raw", "unsafe"}
_JS_QUALIFIED = ("sequelize.query", "knex.raw", "db.query", "pool.query", "connection.query")

_MAX = 8

_WHY = (
    "An attacker who controls any part of the query text can rewrite the statement: "
    "read every row of every table, forge a login, or drop the database outright. SQL "
    "injection is consistently one of the most exploited web vulnerabilities because a "
    "single reachable query is enough to lose the whole datastore."
)


class SqlInjectionPythonRule(Rule):
    """Interpolated SQL handed to a Python cursor/ORM execution method."""

    id: ClassVar[str] = "VG-SEC-001"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "SQL injection via interpolated query"
    description: ClassVar[str] = (
        "A SQL statement is built with string interpolation and passed straight to a "
        "database execution method instead of being parameterised."
    )
    why_it_matters: ClassVar[str] = _WHY
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.sql-injection"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): rewrite to parameter binding.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in py_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if call.base not in _PY_CALLEES:
                    continue
                arg = first_arg(call.node)
                if arg is None or not is_interpolated_py(source, arg):
                    continue
                text = node_text(source, arg)
                if not SQL_KEYWORDS.search(text):
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{call.name}({text.strip()[:200]})",
                        description=(
                            f"`{call.name}(...)` at {rel}:{call.line} receives a query built "
                            "by string interpolation rather than a parameterised statement."
                        ),
                        recommended_followup=(
                            "Keep the SQL text a constant and bind the values: "
                            "`cur.execute('SELECT ... WHERE id = %s', (user_id,))`. Use "
                            "SQLAlchemy `text(...).bindparams()` or the ORM query API for "
                            "dynamic filters."
                        ),
                    )
                )
        return findings


def _js_arg_is_interpolated(source: bytes, call_node: Any) -> Any | None:
    """First argument of a JS call when it is interpolated, else None."""
    args = arg_nodes(call_node)
    if not args:
        # Tagged templates (``sql`...` ``, ``prisma.$queryRaw`...` ``) parameterise.
        return None
    return args[0] if is_interpolated_js(source, args[0]) else None


class SqlInjectionJavaScriptRule(Rule):
    """Interpolated SQL handed to a JavaScript/TypeScript database driver."""

    id: ClassVar[str] = "VG-SEC-002"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "SQL injection via interpolated query"
    description: ClassVar[str] = (
        "A SQL statement is assembled with a template literal or string concatenation "
        "and passed to a database driver instead of using placeholders."
    )
    why_it_matters: ClassVar[str] = _WHY
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.sql-injection"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): rewrite to a placeholder query with a values array.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                name = call.name
                if call.base not in _JS_CALLEES and not name.endswith(_JS_QUALIFIED):
                    continue
                arg = _js_arg_is_interpolated(source, call.node)
                if arg is None:
                    continue
                text = node_text(source, arg)
                if not SQL_KEYWORDS.search(text):
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{name}({text.strip()[:200]})",
                        description=(
                            f"`{name}(...)` at {rel}:{call.line} builds its SQL with a "
                            "template literal or concatenation instead of placeholders."
                        ),
                        recommended_followup=(
                            "Use driver placeholders and a values array: "
                            "`db.query('SELECT ... WHERE id = $1', [id])`, `knex('users')"
                            ".where({ id })`, or a parameterising tagged template such as "
                            "`sql`...`` / `prisma.$queryRaw`...``."
                        ),
                    )
                )
        return findings
