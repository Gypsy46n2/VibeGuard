"""VG-REL-001 and VG-REL-002 — failures and resources that go unhandled.

* **VG-REL-001** an exception caught and discarded.
* **VG-REL-002** a file, cursor, or connection opened with no guaranteed release.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

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
from vibeguard.rules._fixes import locate_line, whole_file_patch
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    ancestors,
    calls,
    enclosing_function,
    line_at,
    node_text,
    source_files,
    walk,
)
from vibeguard.rules.reliability._common import (
    CODE_SUFFIXES,
    MAX_FINDINGS,
    function_name,
    root_of,
    statements,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["SwallowedExceptionRule", "UnreleasedResourceRule"]

_BROAD_EXCEPT = re.compile(r"^except\s*(\(?\s*(Exception|BaseException)\s*\)?)?\s*(as\s+\w+)?\s*:")
_SWALLOW_STATEMENTS = {"pass_statement", "continue_statement"}

_JS_EMPTY_CATCH = (
    re.compile(r"catch\s*(\([^)]*\))?\s*\{\s*\}"),
    re.compile(r"\.catch\s*\(\s*(\([^)]*\)|\w+)\s*=>\s*\{\s*\}\s*\)"),
    re.compile(r"\.catch\s*\(\s*(\([^)]*\)|\w+)\s*=>\s*(null|undefined|void 0)\s*\)"),
    re.compile(r"\.catch\s*\(\s*\(\s*\)\s*=>\s*\{?\s*\}?\s*\)"),
)


def _is_swallowed(source: bytes, clause: object) -> bool:
    """True when an ``except_clause`` body only discards the error."""
    header = node_text(source, clause).strip()
    if not _BROAD_EXCEPT.match(header.splitlines()[0] if header else ""):
        return False
    body = None
    try:
        for child in clause.children:  # type: ignore[attr-defined]
            if child.type == "block":
                body = child
    except Exception:  # pragma: no cover - defensive
        return False
    stmts = statements(body)
    if not stmts:
        return False
    for stmt in stmts:
        if stmt.type in _SWALLOW_STATEMENTS:
            continue
        if stmt.type == "return_statement":
            text = node_text(source, stmt).strip()
            if text in {"return", "return None"}:
                continue
        return False
    return True


class SwallowedExceptionRule(Rule):
    """A broad ``except`` (or an empty JS ``catch``) that discards the error."""

    id: ClassVar[str] = "VG-REL-001"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Exception swallowed without handling"
    description: ClassVar[str] = (
        "An exception is caught and then discarded — the handler body only passes, "
        "continues, or returns None — so the failure leaves no trace at all."
    )
    why_it_matters: ClassVar[str] = (
        "The code keeps running as if nothing went wrong, so a failed database write or a "
        "failed payment call looks like a success to the caller and to every dashboard. "
        "When users eventually report the missing data there is no log line, no stack "
        "trace, and no error-tracker event to work from, which turns a five-minute fix "
        "into a multi-day investigation."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/tutorial/errors.html#handling-exceptions",
        "https://docs.python.org/3/library/logging.html#logging.Logger.exception",
    ]
    topics: ClassVar[set[str]] = {"observability.error-tracking", "jobs.worker-crashes"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    _FOLLOWUP = (
        "Log the exception with context and then re-raise or handle it explicitly: "
        "`log.exception(\"failed to sync order %s\", order_id)` followed by `raise` — or "
        "narrow the except to the one error you genuinely expect and comment why it is "
        "safe to ignore."
    )

    # M3 fix(): log the exception with context and re-raise or handle explicitly.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text:
                continue
            suffix = PurePosixPath(rel).suffix.lower()
            if suffix in PY_SUFFIXES:
                findings.extend(self._python(ctx, rel, text))
            elif suffix in JS_SUFFIXES:
                findings.extend(self._javascript(rel, text))
        return findings[:MAX_FINDINGS]

    def _python(self, ctx: ScanContext, rel: str, text: str) -> list[Finding]:
        root = root_of(ctx, rel)
        if root is None:
            return []
        source = text.encode("utf-8")
        out: list[Finding] = []
        for node in walk(root):
            if node.type != "except_clause" or not _is_swallowed(source, node):
                continue
            line_no = node.start_point[0] + 1
            out.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=node_text(source, node)[:200],
                    description=(
                        f"{rel}:{line_no} catches a broad exception and discards it; the "
                        "handler body neither logs nor re-raises."
                    ),
                    recommended_followup=self._FOLLOWUP,
                )
            )
            if len(out) >= MAX_FINDINGS:
                break
        return out

    def _javascript(self, rel: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        for pattern in _JS_EMPTY_CATCH:
            for match in pattern.finditer(text):
                line_no = line_at(text, match.start())
                out.append(
                    self.make_finding(
                        file=rel,
                        line=line_no,
                        snippet=match.group(0)[:200],
                        description=(
                            f"{rel}:{line_no} catches a rejected promise or a thrown error "
                            "with an empty handler, so the failure disappears."
                        ),
                        recommended_followup=self._FOLLOWUP,
                    )
                )
                if len(out) >= MAX_FINDINGS:
                    return out
        return out


_FILE_OPENERS = {"open", "codecs.open", "io.open", "gzip.open", "tempfile.namedtemporaryfile"}
_HANDLE_OPENERS = {"cursor", "connect", "connection", "acquire", "checkout"}
_JS_OPENERS = {
    "fs.open",
    "fs.opensync",
    "fs.createreadstream",
    "fs.createwritestream",
    "createreadstream",
    "createwritestream",
}
#: ``fh = open(...)`` on a single line — the only shape VG-REL-002 repairs.
_OPEN_ASSIGNMENT = re.compile(r"(\s*)([A-Za-z_]\w*)\s*=\s*(open\(.*\))\s*")
_RELEASE = re.compile(r"\.close\s*\(|\.destroy\s*\(|\.release\s*\(|\.dispose\s*\(|closing\s*\(")
_WITHISH = {"with_statement", "with_clause", "with_item", "as_pattern", "resource"}


def _guarded_by_with(node: object) -> bool:
    """True when the call is the subject of a ``with`` statement."""
    for depth, parent in enumerate(ancestors(node)):
        if depth > 4:
            return False
        if parent.type in _WITHISH:
            return True
    return False


def _is_assigned(node: object) -> bool:
    for depth, parent in enumerate(ancestors(node)):
        if depth > 3:
            return False
        if parent.type in {"assignment", "variable_declarator", "augmented_assignment"}:
            return True
    return False


class UnreleasedResourceRule(Rule):
    """A handle opened outside ``with``/``try…finally`` and never closed."""

    id: ClassVar[str] = "VG-REL-002"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Resource opened without guaranteed release"
    description: ClassVar[str] = (
        "A file handle, cursor, or connection is opened and assigned to a variable, but "
        "nothing in the enclosing function guarantees it is released."
    )
    why_it_matters: ClassVar[str] = (
        "Every unreleased handle is one fewer the process can open. In a long-running "
        "server the leak accumulates request by request until the process hits its file "
        "descriptor limit and every subsequent operation — including accepting new "
        "connections — fails with 'too many open files'. A leaked database connection is "
        "worse: it holds a slot on the server and can keep a transaction open, blocking "
        "other writers."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/reference/compound_stmts.html#the-with-statement",
        "https://docs.python.org/3/library/contextlib.html#contextlib.closing",
    ]
    topics: ClassVar[set[str]] = {
        "concurrency.resource-leaks",
        "concurrency.file-handle-leaks",
        "concurrency.connection-leaks",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text:
                continue
            source = text.encode("utf-8")
            for site in calls(ctx, rel):
                if len(findings) >= MAX_FINDINGS:
                    break
                lowered = site.name.lower()
                kind = self._opener_kind(lowered)
                if kind is None:
                    continue
                if _guarded_by_with(site.node) or not _is_assigned(site.node):
                    continue
                func = enclosing_function(site.node)
                scope = node_text(source, func) if func is not None else text
                if _RELEASE.search(scope) or "finally" in scope:
                    continue
                line_no = site.line
                where = function_name(source, func) or "module scope"
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=line_no,
                        snippet=node_text(source, site.node)[:200],
                        description=(
                            f"{site.name}(...) opens a {kind} in {where} ({rel}:{line_no}) "
                            "outside a `with`/`try…finally`, and nothing in that scope "
                            "closes it."
                        ),
                        recommended_followup=(
                            "Use a context manager — `with open(path) as fh:`, "
                            "`with conn.cursor() as cur:`, `with closing(resource):` — or "
                            "close the handle in a `finally:` block so it is released even "
                            "when the body raises."
                        ),
                    )
                )
        return findings

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Wrap ``f = open(...)`` in a ``with`` statement — single-use case only.

        The pattern this repairs is the one that actually appears in vibe-coded apps::

            data = None
            fh = open(path)
            data = fh.read()

        It requires: a builtin ``open(...)`` assigned to a name on one line, exactly one
        following statement at the same indentation that uses the name, and no other
        use of that name anywhere later in the file. Under those conditions the
        with-block covers exactly the same statements, so the rewrite cannot change
        control flow. Anything longer needs re-indenting a block whose extent this rule
        cannot prove, and is left to a human.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no or PurePosixPath(rel).suffix.lower() != ".py":
            return None
        text = ctx.read(rel)
        target = locate_line(
            text,
            line_no,
            matches=lambda candidate: bool(_OPEN_ASSIGNMENT.fullmatch(candidate)),
        )
        if target is None:
            return None
        line_no = target
        lines = text.splitlines()
        match = _OPEN_ASSIGNMENT.fullmatch(lines[line_no - 1])
        if match is None:  # pragma: no cover - guaranteed by locate_line
            return None
        indent, var, call = match.group(1), match.group(2), match.group(3)
        if call.count("(") != call.count(")"):
            return None

        follow = line_no  # 0-based index of the next line
        while follow < len(lines) and not lines[follow].strip():
            follow += 1
        if follow >= len(lines):
            return None
        user = lines[follow]
        used = re.compile(rf"\b{re.escape(var)}\b")
        if (
            user[: len(indent) + 1] != indent + user.strip()[:1]
            or not used.search(user)
            or user.rstrip().endswith(":")
            or user.strip().startswith(("with ", "for ", "while ", "if ", "try", "@"))
        ):
            return None
        if any(used.search(rest) for rest in lines[follow + 1 :]):
            return None

        rebuilt = (
            lines[: line_no - 1]
            + [f"{indent}with {call} as {var}:", f"{indent}    {user.strip()}"]
            + lines[follow + 1 :]
        )
        new_text = "\n".join(rebuilt) + ("\n" if text.endswith("\n") else "")
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=(
                f"Wrap the handle opened at {rel}:{line_no} in a `with` statement so it is "
                "closed even when the body raises."
            ),
            scope="reliability",
            summary="close the file handle with a context manager",
        )

    @staticmethod
    def _opener_kind(lowered: str) -> str | None:
        if lowered in _FILE_OPENERS or lowered in _JS_OPENERS:
            return "file handle"
        base = lowered.rsplit(".", 1)[-1]
        if base in _HANDLE_OPENERS and "." in lowered:
            return "database handle"
        return None
