"""VG-SEC-001 / VG-SEC-002 — SQL injection via interpolated queries."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    Patch,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._fixes import locate_call, replace_node, whole_file_patch
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

#: A parameterised rewrite is only possible when we know the driver's placeholder
#: style; guessing would produce a query that fails at runtime.
_PY_PLACEHOLDERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?m)^\s*(?:import\s+sqlite3\b|from\s+sqlite3\b)"), "?"),
    (
        re.compile(
            r"(?m)^\s*(?:import|from)\s+(?:psycopg2?|pymysql|MySQLdb|mysql\.connector)\b"
        ),
        "%s",
    ),
)
_JS_PLACEHOLDERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"""(?:require\(\s*['"]pg['"]|from\s+['"]pg['"])"""), "$1"),
    (re.compile(r"""(?:require\(\s*['"]mysql2?['"]|from\s+['"]mysql2?['"])"""), "?"),
)
#: Only a bare name or dotted attribute is bound; an expression could have side
#: effects or a different evaluation order once it moves into the parameter tuple.
_SIMPLE_EXPR = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


def _placeholder(text: str, table: tuple[tuple[re.Pattern[str], str], ...]) -> str | None:
    for pattern, style in table:
        if pattern.search(text):
            return style
    return None


def _single_hole(body: str, hole: re.Pattern[str]) -> str | None:
    """The one interpolated expression in ``body``, when there is exactly one and it
    is a plain name."""
    holes = hole.findall(body)
    if len(holes) != 1:
        return None
    expr = holes[0].strip()
    return expr if _SIMPLE_EXPR.fullmatch(expr) else None


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

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Bind the interpolated value as a query parameter — simple cases only.

        Every one of these must hold, or the finding is reported without a patch:
        the file makes the driver (and therefore the placeholder style) obvious; the
        reported line holds exactly one ``execute``-style call with a single argument;
        that argument is an f-string with exactly one interpolation; and the
        interpolated expression is a plain name or attribute. Anything else — two
        holes, a computed expression, a query assembled across statements — is a
        rewrite whose behaviour we cannot prove, so it stays a manual repair.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no:
            return None
        text = ctx.read(rel)
        placeholder = _placeholder(text, _PY_PLACEHOLDERS)
        if placeholder is None:
            return None
        call = locate_call(
            [c for c in py_calls(ctx, rel) if c.base in {"execute", "executemany"}], line_no
        )
        if call is None:
            return None
        line_no = call.line
        args = arg_nodes(call.node)
        args_node = call.node.child_by_field_name("arguments")
        if len(args) != 1 or args_node is None:
            return None
        source = text.encode("utf-8")
        rewritten = _rewrite_fstring(node_text(source, args[0]), placeholder)
        if rewritten is None:
            return None
        sql, expr = rewritten
        new_text = replace_node(text, args_node, f"({sql}, ({expr},))")
        if new_text is None:  # pragma: no cover - defensive
            return None
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=(
                f"Parameterise the query at {rel}:{line_no}: the SQL text becomes a "
                f"constant and `{expr}` is bound as a value."
            ),
            scope="security",
            summary="parameterise the SQL query",
        )


def _rewrite_fstring(raw: str, placeholder: str) -> tuple[str, str] | None:
    """``f"… {x} …"`` → ``("… ? …", "x")``; None when the shape is not provable."""
    match = re.fullmatch(r"[fF](['\"])(.*)\1", raw, re.S)
    if match is None:
        return None
    quote, body = match.group(1), match.group(2)
    if "{{" in body or "}}" in body:
        return None
    expr = _single_hole(body, re.compile(r"\{([^{}]*)\}"))
    if expr is None:
        return None
    # Any quotes wrapped around the interpolation go too: a bound parameter is not
    # quoted in the SQL text.
    new_body = re.sub(r"['\"]?\{[^{}]*\}['\"]?", placeholder, body)
    if quote in new_body:
        return None
    return f"{quote}{new_body}{quote}", expr


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

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Move the interpolated value into the driver's values array.

        Same conservatism as the Python rule: the driver must be identifiable (``pg``
        → ``$1``, ``mysql``/``mysql2`` → ``?``), the call must take exactly one
        template-literal argument, and that literal must contain exactly one
        ``${name}``. Concatenated strings and multi-hole templates are reported only.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no:
            return None
        text = ctx.read(rel)
        placeholder = _placeholder(text, _JS_PLACEHOLDERS)
        if placeholder is None:
            return None
        call = locate_call(
            [
                c
                for c in js_calls(ctx, rel)
                if c.base in _JS_CALLEES or c.name.endswith(_JS_QUALIFIED)
            ],
            line_no,
        )
        if call is None:
            return None
        line_no = call.line
        args = arg_nodes(call.node)
        args_node = call.node.child_by_field_name("arguments")
        if len(args) != 1 or args_node is None:
            return None
        source = text.encode("utf-8")
        rewritten = _rewrite_template(node_text(source, args[0]), placeholder)
        if rewritten is None:
            return None
        sql, expr = rewritten
        new_text = replace_node(text, args_node, f"({sql}, [{expr}])")
        if new_text is None:  # pragma: no cover - defensive
            return None
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=(
                f"Parameterise the query at {rel}:{line_no}: the SQL text becomes a "
                f"constant and `{expr}` moves into the values array."
            ),
            scope="security",
            summary="parameterise the SQL query",
        )


def _rewrite_template(raw: str, placeholder: str) -> tuple[str, str] | None:
    """`` `… ${x} …` `` → ``("'… ? …'", "x")``; None when the shape is not provable."""
    match = re.fullmatch(r"`(.*)`", raw, re.S)
    if match is None:
        return None
    body = match.group(1)
    expr = _single_hole(body, re.compile(r"\$\{([^{}]*)\}"))
    if expr is None:
        return None
    new_body = re.sub(r"['\"]?\$\{[^{}]*\}['\"]?", placeholder, body)
    if "`" in new_body or "\n" in new_body:
        return None
    quote = "'" if "'" not in new_body else ('"' if '"' not in new_body else "")
    if not quote:
        return None
    return f"{quote}{new_body}{quote}", expr
