"""Shared helpers for rule ``fix()`` implementations — INTERFACES.md §2 (Patch).

Every built-in repair is a **deterministic, whole-file edit**: the rule recomputes the
new file content from the file as it is on disk right now, and hands back a
:class:`~vibeguard.core.models.Patch` carrying the sha256 of the content it read. The
fixer engine re-checks that sha immediately before writing, so a file that changed
underneath us aborts its own fix instead of being clobbered.

The house rules for a built-in fix:

* **Provable or nothing.** If the preconditions for a safe edit are not met, return
  ``None``. Detection still reports the finding; we simply do not guess.
* **Nothing beyond the remediation.** No reformatting, no import sorting, no
  drive-by cleanups — the diff must contain only the fix.
* **Idempotent.** Re-running a fix on already-fixed content produces no patch.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Sequence
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from vibeguard.core.models import FileEdit, Finding, Patch

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "append_arguments",
    "append_object_properties",
    "commit_subject",
    "ensure_python_import",
    "file_text",
    "finding_snippet",
    "locate_call",
    "locate_line",
    "has_python_import",
    "indent_of",
    "insert_lines",
    "is_javascript",
    "is_python",
    "line_at",
    "python_import_anchor",
    "replace_line",
    "replace_node",
    "sha256_text",
    "whole_file_patch",
]


def sha256_text(text: str) -> str:
    """Hex sha256 of ``text`` encoded as UTF-8 — the ``FileEdit`` contract."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_text(ctx: ScanContext, relpath: str) -> str:
    """Current content of ``relpath`` as the fixer engine will see it."""
    return ctx.read(relpath)


def commit_subject(scope: str, summary: str, rule_id: str) -> str:
    """Conventional-commit subject ending in ``[RULE-ID]`` (INTERFACES.md §2)."""
    return f"fix({scope}): {summary} [{rule_id}]"


def whole_file_patch(
    finding: Finding,
    relpath: str,
    old_text: str,
    new_text: str,
    *,
    description: str,
    scope: str,
    summary: str,
) -> Patch | None:
    """Build a single-file whole-content patch, or ``None`` when nothing changed."""
    if new_text == old_text:
        return None
    return Patch(
        finding_id=finding.id,
        file_edits=[
            FileEdit(
                path=relpath,
                old_content_sha256=sha256_text(old_text),
                new_content=new_text,
            )
        ],
        description=description,
        commit_message=commit_subject(scope, summary, finding.rule_id),
    )


def line_at(text: str, line_no: int | None) -> str | None:
    """1-based line lookup; ``None`` when the line does not exist."""
    if not line_no or line_no < 1:
        return None
    lines = text.splitlines()
    if line_no > len(lines):
        return None
    return lines[line_no - 1]


def _join(lines: list[str], original: str) -> str:
    text = "\n".join(lines)
    return text + "\n" if original.endswith("\n") else text


def replace_line(text: str, line_no: int, new_line: str) -> str:
    """Return ``text`` with line ``line_no`` replaced, preserving the trailing newline."""
    lines = text.splitlines()
    lines[line_no - 1] = new_line
    return _join(lines, text)


def insert_lines(text: str, index: int, new_lines: list[str]) -> str:
    """Return ``text`` with ``new_lines`` inserted before 0-based ``index``."""
    lines = text.splitlines()
    lines[index:index] = new_lines
    return _join(lines, text)


_PY_IMPORT = re.compile(r"^(?:import\s+\S|from\s+\S+\s+import\s)")
_PY_DOCSTRING = re.compile(r"^\s*[rubRUB]*(\"\"\"|''')")


def _module_body_start(lines: list[str]) -> int:
    """0-based index of the first line after the shebang, comments, and docstring."""
    index = 0
    while index < len(lines) and (lines[index].startswith("#") or not lines[index].strip()):
        index += 1
    if index < len(lines) and _PY_DOCSTRING.match(lines[index]):
        quote = '"""' if '"""' in lines[index] else "'''"
        body = lines[index].split(quote, 1)[1]
        if quote not in body:
            index += 1
            while index < len(lines) and quote not in lines[index]:
                index += 1
        index += 1
    return index


def python_import_anchor(text: str, *, before: bool = False) -> int:
    """0-based line index at which a new top-level ``import`` should be inserted.

    Lands after the module docstring and never inside a function. With
    ``before=True`` the insertion point is the *top* of the import block (after any
    ``from __future__`` import), which is where a standard-library import belongs and
    keeps import-order linters quiet; otherwise it is the end of the block.
    """
    lines = text.splitlines()
    index = _module_body_start(lines)
    while index < len(lines) and not lines[index].strip():
        index += 1
    if before:
        first = index
        while first < len(lines) and lines[first].startswith("from __future__"):
            first += 1
        return first
    last_import = index
    for offset in range(index, min(len(lines), index + 100)):
        line = lines[offset]
        if _PY_IMPORT.match(line):
            last_import = offset + 1
        elif line.strip() and not line.startswith(("#", " ", ")")) and last_import > index:
            break
    return last_import


def has_python_import(text: str, module: str) -> bool:
    """True when ``module`` is already imported at module level."""
    name = re.escape(module)
    pattern = re.compile(rf"(?m)^\s*(?:import\s+{name}\b|from\s+{name}\s)")
    return bool(pattern.search(text))


def ensure_python_import(text: str, statement: str, module: str) -> str:
    """Add ``statement`` (e.g. ``import secrets``) unless ``module`` is already imported.

    Standard-library imports go at the top of the import block, where isort-style
    linters expect them, so the repair does not trade one lint error for another.
    """
    if has_python_import(text, module):
        return text
    return insert_lines(text, python_import_anchor(text, before=True), [statement])


def locate_line(
    text: str,
    line_no: int | None,
    *,
    matches: Callable[[str], bool],
    snippet: str = "",
    window: int = 12,
) -> int | None:
    """Re-find the line a finding refers to, tolerating drift from earlier fixes.

    Line numbers are recorded during detection; by the time a later fix runs, an
    earlier patch to the same file may have shifted them. The recorded line is used
    when it still matches, otherwise a unique match within ``window`` lines wins. If
    the target is ambiguous, ``None`` — editing the wrong line is far worse than
    reporting the finding unfixed.
    """
    if not line_no:
        return None
    lines = text.splitlines()
    head = snippet.strip().splitlines()[0].strip() if snippet.strip() else ""

    def fits(index: int) -> bool:
        line = lines[index - 1]
        if not matches(line):
            return False
        return not head or line.strip().startswith(head[:60])

    if 1 <= line_no <= len(lines) and fits(line_no):
        return line_no
    low, high = max(1, line_no - window), min(len(lines), line_no + window)
    hits = [index for index in range(low, high + 1) if fits(index)]
    return hits[0] if len(hits) == 1 else None


def locate_call(candidates: Sequence[Any], line_no: int | None, window: int = 12) -> Any | None:
    """Pick the one call a finding refers to from already-filtered ``candidates``.

    Same contract as :func:`locate_line`: the recorded line wins when it is
    unambiguous, a single nearby candidate is accepted when an earlier fix shifted the
    file, and anything ambiguous yields ``None``.
    """
    if not line_no or not candidates:
        return None
    exact = [call for call in candidates if call.line == line_no]
    if exact:
        return exact[0] if len(exact) == 1 else None
    near = [call for call in candidates if abs(call.line - line_no) <= window]
    return near[0] if len(near) == 1 else None


def finding_snippet(finding: Finding) -> str:
    """The evidence snippet a finding was created with (empty when it has none)."""
    return finding.evidence[0].snippet if finding.evidence else ""


def replace_node(text: str, node: object, new_text: str) -> str | None:
    """Return ``text`` with the byte range covered by a tree-sitter ``node`` replaced."""
    if node is None:
        return None
    start = getattr(node, "start_byte", None)
    end = getattr(node, "end_byte", None)
    if start is None or end is None:
        return None
    source = text.encode("utf-8")
    return source[:start].decode("utf-8") + new_text + source[end:].decode("utf-8")


def append_arguments(args_text: str, additions: Sequence[str]) -> str | None:
    """Append ``additions`` to a parenthesised argument list, preserving its layout.

    ``("a")`` + ``["timeout=30"]`` → ``("a", timeout=30)``; a trailing comma or a
    multi-line call keeps its shape because the text after the last argument (the
    newline and indentation before ``)``) is left where it was.
    """
    if not additions:
        return None
    if not (args_text.startswith("(") and args_text.endswith(")")):
        return None
    joined = ", ".join(additions)
    inner = args_text[1:-1]
    if not inner.strip():
        return f"({joined})"
    stripped = inner.rstrip()
    separator = " " if stripped.endswith(",") else ", "
    cut = len(stripped)
    return f"({inner[:cut]}{separator}{joined}{inner[cut:]})"


def append_object_properties(object_text: str, additions: Sequence[str]) -> str | None:
    """Append properties to a JS object literal, preserving its layout."""
    if not additions:
        return None
    if not (object_text.startswith("{") and object_text.endswith("}")):
        return None
    joined = ", ".join(additions)
    inner = object_text[1:-1]
    if not inner.strip():
        return "{ " + joined + " }"
    stripped = inner.rstrip()
    separator = " " if stripped.endswith(",") else ", "
    cut = len(stripped)
    return "{" + inner[:cut] + separator + joined + inner[cut:] + "}"


def indent_of(line: str) -> str:
    """Leading whitespace of ``line``."""
    return line[: len(line) - len(line.lstrip())]


def is_python(relpath: str) -> bool:
    return PurePosixPath(relpath).suffix.lower() == ".py"


def is_javascript(relpath: str) -> bool:
    return PurePosixPath(relpath).suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
