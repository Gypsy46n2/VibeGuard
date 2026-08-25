"""Shared helpers for built-in rule packs.

Four things live here:

* **Path filters** — test files, fixtures, vendored trees and migrations are skipped
  by default so regex rules do not drown the report in false positives.
* **String/comment awareness** — :func:`is_non_code_line` and :func:`non_code_lines`
  (implemented in ``_literals``) let any text rule ask whether a match landed inside
  a docstring, comment, or prose string literal rather than in executing code.
* **Base classes** — :class:`RegexRule` (regex with context, comment-aware) and
  :class:`ProjectRule` (one project-level finding) carry the boilerplate.
* **tree-sitter helpers** — defensive wrappers around the cached parse in
  :class:`~vibeguard.discovery.context.ScanContext`, used by the AST rules. Every
  helper returns an empty result rather than raising: a malformed source file must
  never break a scan.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.fingerprint import PROJECT_PATH
from vibeguard.core.models import Evidence, Finding
from vibeguard.core.rule import Rule
from vibeguard.rules._literals import (
    is_non_code_line,
    is_non_code_span,
    non_code_lines,
    non_code_lines_of_text,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "CallSite",
    "JS_SUFFIXES",
    "ProjectRule",
    "PY_SUFFIXES",
    "RegexRule",
    "ancestors",
    "block_of",
    "calls",
    "enclosing_function",
    "in_loop",
    "is_generated_path",
    "is_non_code_line",
    "is_non_code_span",
    "is_test_path",
    "js_calls",
    "line_at",
    "node_text",
    "non_code_lines",
    "non_code_lines_of_text",
    "py_calls",
    "source_files",
    "strip_quotes",
    "walk",
]

log = logging.getLogger(__name__)

PY_SUFFIXES: tuple[str, ...] = (".py",)
JS_SUFFIXES: tuple[str, ...] = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

_TEST_DIR_PARTS = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "e2e",
    "fixtures",
    "fixture",
    "testdata",
    "__mocks__",
    "mocks",
    "examples",
    "example",
    "samples",
}
_TEST_NAME_HINTS = ("test_", "_test.", ".test.", ".spec.", "_spec.", "conftest.py")

_GENERATED_DIR_PARTS = {
    "node_modules",
    "vendor",
    "vendored",
    "third_party",
    "site-packages",
    "dist",
    "build",
    "public",
    ".next",
    ".venv",
    "venv",
    "migrations",
    "__pycache__",
    "generated",
    "static",
}
_MINIFIED = re.compile(r"\.min\.(js|css)$", re.IGNORECASE)


def is_test_path(relpath: str) -> bool:
    """True for test, spec, fixture, and example files."""
    path = PurePosixPath(relpath)
    if any(part.lower() in _TEST_DIR_PARTS for part in path.parts[:-1]):
        return True
    name = path.name.lower()
    return any(hint in name for hint in _TEST_NAME_HINTS)


def is_generated_path(relpath: str) -> bool:
    """True for vendored, generated, build-output, and minified files."""
    path = PurePosixPath(relpath)
    if any(part.lower() in _GENERATED_DIR_PARTS for part in path.parts[:-1]):
        return True
    return bool(_MINIFIED.search(path.name))


def source_files(
    ctx: ScanContext,
    suffixes: tuple[str, ...],
    *,
    skip_tests: bool = True,
    skip_generated: bool = True,
    limit: int = 2000,
) -> list[str]:
    """Scanned files with one of ``suffixes``, filtered and capped."""
    wanted = {s.lower() for s in suffixes}
    out: list[str] = []
    for rel in ctx.files:
        if PurePosixPath(rel).suffix.lower() not in wanted:
            continue
        if skip_tests and is_test_path(rel):
            continue
        if skip_generated and is_generated_path(rel):
            continue
        out.append(rel)
        if len(out) >= limit:
            break
    return out


def strip_quotes(value: str) -> str:
    """Drop one layer of matching quotes."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def line_at(text: str, offset: int) -> int:
    """1-based line number of a character offset."""
    return text.count("\n", 0, max(0, offset)) + 1


def _is_comment(line: str, suffix: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if suffix in PY_SUFFIXES:
        return stripped.startswith("#")
    if suffix in JS_SUFFIXES:
        return stripped.startswith(("//", "*", "/*"))
    if suffix in {".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".sh"}:
        return stripped.startswith("#")
    return False


# --------------------------------------------------------------------- bases


class RegexRule(Rule):
    """Line-oriented regex rule with comment, test, and context filtering.

    Subclasses set :attr:`patterns` and :attr:`suffixes`; matches on comment lines,
    test files, and vendored trees are dropped, and a match is discarded when
    :attr:`negative` matches the surrounding context window.
    """

    #: Compiled patterns; the first match on a line wins.
    patterns: ClassVar[tuple[re.Pattern[str], ...]] = ()
    #: File suffixes to scan.
    suffixes: ClassVar[tuple[str, ...]] = PY_SUFFIXES
    #: Skip a match whose context window matches this (false-positive guard).
    negative: ClassVar[re.Pattern[str] | None] = None
    #: Lines of context either side considered by :attr:`negative`.
    context_lines: ClassVar[int] = 2
    skip_tests: ClassVar[bool] = True
    skip_generated: ClassVar[bool] = True
    skip_comments: ClassVar[bool] = True
    #: Drop matches on lines that are pure string or comment content (docstrings,
    #: wrapped prose strings, block comments). Opt-in per rule, and deliberately so:
    #: a rule whose whole subject *is* a string value — a hardcoded secret, a
    #: connection string, a CORS header assigned as a literal — must keep matching
    #: them. Those all live on lines that carry executable tokens too, so enabling
    #: this only ever removes prose. See ``rules/_literals``.
    skip_non_code: ClassVar[bool] = False
    #: Cap per file so one pathological file cannot flood the report.
    max_per_file: ClassVar[int] = 10
    #: Cap across the repository.
    max_total: ClassVar[int] = 50
    #: Redact evidence snippets even outside the SECRETS category.
    redact_evidence: ClassVar[bool] = False

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        """Per-occurrence description; override for something more specific."""
        return f"{self.description} ({relpath}:{line_no})"

    def followup(self, ctx: ScanContext, relpath: str, line: str) -> str:
        """Per-occurrence remediation hint."""
        return self.recommended_followup

    #: Default remediation text (class attribute so ``followup`` has something to use).
    recommended_followup: ClassVar[str] = ""

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(
            ctx, self.suffixes, skip_tests=self.skip_tests, skip_generated=self.skip_generated
        ):
            if len(findings) >= self.max_total:
                break
            text = ctx.read(rel)
            if not text:
                continue
            suffix = PurePosixPath(rel).suffix.lower()
            lines = text.splitlines()
            per_file = 0
            for index, line in enumerate(lines):
                if per_file >= self.max_per_file or len(findings) >= self.max_total:
                    break
                if len(line) > 2000:
                    continue
                if self.skip_comments and _is_comment(line, suffix):
                    continue
                if not any(pattern.search(line) for pattern in self.patterns):
                    continue
                if self.skip_non_code and is_non_code_line(ctx, rel, index + 1):
                    continue
                if self.negative is not None:
                    lo = max(0, index - self.context_lines)
                    hi = min(len(lines), index + self.context_lines + 1)
                    if self.negative.search("\n".join(lines[lo:hi])):
                        continue
                line_no = index + 1
                per_file += 1
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=line_no,
                        snippet=line.strip()[:400],
                        description=self.describe(ctx, rel, line_no, line),
                        recommended_followup=self.followup(ctx, rel, line),
                        redact_evidence=self.redact_evidence,
                    )
                )
        return findings


class ProjectRule(Rule):
    """A rule that emits at most one project-level finding.

    Subclasses implement :meth:`check`, returning ``None`` when the project is fine
    or ``(description, note)`` describing the gap.
    """

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        raise NotImplementedError

    #: Default remediation text.
    recommended_followup: ClassVar[str] = ""

    def detect(self, ctx: ScanContext) -> list[Finding]:
        result = self.check(ctx)
        if result is None:
            return []
        description, note = result
        return [
            self.make_finding(
                file=None,
                description=description,
                evidence=[Evidence(file=PROJECT_PATH, note=note)],
                recommended_followup=self.recommended_followup,
            )
        ]


# ---------------------------------------------------------------- tree-sitter


@dataclass(frozen=True)
class CallSite:
    """One call expression found in a parsed source file."""

    name: str
    args: str
    line: int
    node: Any
    file: str = ""

    @property
    def base(self) -> str:
        """Last dotted component: ``requests.get`` -> ``get``."""
        return self.name.rsplit(".", 1)[-1]


def walk(node: Any) -> Iterator[Any]:
    """Depth-first iteration over a tree-sitter subtree."""
    if node is None:
        return
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            stack.extend(reversed(current.children))
        except (AttributeError, TypeError):  # pragma: no cover - binding quirk
            # A node whose children the installed binding will not expose is skipped.
            # Narrow rather than broad, and silent rather than logged: this is the
            # innermost loop of every AST rule.
            continue


def node_text(source: bytes, node: Any) -> str:
    """UTF-8 slice of ``source`` covered by ``node``."""
    if node is None:
        return ""
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def ancestors(node: Any) -> Iterator[Any]:
    """Yield each parent up to the root."""
    current = getattr(node, "parent", None)
    seen = 0
    while current is not None and seen < 200:
        yield current
        current = getattr(current, "parent", None)
        seen += 1


_LOOP_TYPES = {"for_statement", "while_statement", "for_in_statement", "for_of_statement"}
_FUNC_TYPES = {
    "function_definition",
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
}


def in_loop(node: Any) -> bool:
    """True when ``node`` sits inside a for/while loop body."""
    return any(parent.type in _LOOP_TYPES for parent in ancestors(node))


def enclosing_function(node: Any) -> Any | None:
    """Nearest enclosing function-like node, or None."""
    for parent in ancestors(node):
        if parent.type in _FUNC_TYPES:
            return parent
    return None


def block_of(source: bytes, node: Any) -> str:
    """Text of the nearest enclosing function, else of the node itself."""
    func = enclosing_function(node)
    return node_text(source, func if func is not None else node)


def _calls(ctx: ScanContext, relpath: str, call_types: set[str]) -> list[CallSite]:
    tree = ctx.ast(relpath)
    if tree is None:
        return []
    source = ctx.read(relpath).encode("utf-8")
    out: list[CallSite] = []
    try:
        root = tree.root_node
    except Exception:  # pragma: no cover - defensive
        return []
    for node in walk(root):
        if node.type not in call_types:
            continue
        try:
            func = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            out.append(
                CallSite(
                    name=node_text(source, func).replace("\n", "").strip(),
                    args=node_text(source, args),
                    line=node.start_point[0] + 1,
                    node=node,
                    file=relpath,
                )
            )
        except (AttributeError, TypeError, ValueError):  # pragma: no cover - defensive
            # Per-node boundary: narrow, and silent for the same reason as `walk`.
            continue
    return out


def py_calls(ctx: ScanContext, relpath: str) -> list[CallSite]:
    """Every Python call expression in ``relpath`` (empty when unparsable)."""
    return _calls(ctx, relpath, {"call"})


def js_calls(ctx: ScanContext, relpath: str) -> list[CallSite]:
    """Every JS/TS call and ``new`` expression in ``relpath``."""
    return _calls(ctx, relpath, {"call_expression", "new_expression"})


def calls(ctx: ScanContext, relpath: str) -> list[CallSite]:
    """Language-dispatching call extraction."""
    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix in PY_SUFFIXES:
        return py_calls(ctx, relpath)
    if suffix in JS_SUFFIXES:
        return js_calls(ctx, relpath)
    return []
