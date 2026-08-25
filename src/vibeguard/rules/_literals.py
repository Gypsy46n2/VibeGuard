"""Telling *doing* a dangerous thing apart from *mentioning* one.

Text and regex rules match on source lines, which means they also match the same
text inside a docstring, a comment, or a prose string literal. VibeGuard's own rule
sources are the extreme case — ``VG-SEC-018``'s ``description`` has to contain the
literal words ``verify=False`` — but the problem is general: a README-ish docstring,
a help string, a changelog entry in a comment, or a test's explanatory prose are all
places where a dangerous pattern is being *described*, not executed.

The helper here answers one question:

    Is line *n* of this file made of nothing but string and comment content?

That phrasing is deliberate and is what keeps the check surgical. A line inside a
docstring or a wrapped prose string has no executable tokens on it at all, so it is
"non-code". A line like ``response.headers["Access-Control-Allow-Origin"] = "*"``
*does* have executable tokens, so it stays in scope — rules that genuinely care about
string content (hardcoded secrets, connection strings, a CORS header value) keep
working unchanged.

Backends, in order of reliability:

* **Python** — :mod:`tokenize`. Exact, including implicit concatenation, f-strings
  (whose interpolations are separate tokens and stay "code"), and raw/byte strings.
* **JS/TS** — tree-sitter when the cached parse is available, masking ``comment``,
  ``string``, and ``template_string`` nodes but *un*-masking ``template_substitution``
  so ``${dangerous()}`` is still code.
* **Fallback** — a conservative hand lexer that tracks quotes, template literals, and
  ``//`` / ``/* */`` comments.

Everything is total: an unparsable file yields an empty set, i.e. "every line is
code", which is the pre-existing behaviour.
"""

from __future__ import annotations

import io
import logging
import tokenize
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "is_non_code_line",
    "is_non_code_span",
    "non_code_lines",
    "non_code_lines_of_text",
    "non_code_spans_of_text",
]

log = logging.getLogger(__name__)

_PY_SUFFIXES = {".py", ".pyi"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_MAX_CHARS = 400_000
#: Stands in for "to the end of the line" in a column interval.
_INF = 1 << 30


# --------------------------------------------------------------------- masking


class _Mask:
    """Per-line intervals of characters that belong to a string or comment."""

    def __init__(self, line_count: int) -> None:
        self.spans: list[list[tuple[int, int]]] = [[] for _ in range(line_count + 2)]

    def add(self, line_no: int, start: int, end: int) -> None:
        if 1 <= line_no < len(self.spans) and end > start:
            self.spans[line_no].append((start, end))

    def add_full(self, line_no: int) -> None:
        self.add(line_no, 0, _INF)

    def covers(self, line_no: int, index: int) -> bool:
        if not (1 <= line_no < len(self.spans)):
            return False
        return any(start <= index < end for start, end in self.spans[line_no])

    def non_code_lines(self, lines: list[str]) -> frozenset[int]:
        out: set[int] = set()
        for offset, line in enumerate(lines):
            line_no = offset + 1
            if line_no >= len(self.spans) or not self.spans[line_no]:
                continue
            columns = [i for i, char in enumerate(line) if not char.isspace()]
            if columns and all(self.covers(line_no, i) for i in columns):
                out.add(line_no)
        return frozenset(out)


def _mask_multiline(
    mask: _Mask, start_line: int, start_col: int, end_line: int, end_col: int
) -> None:
    if end_line == start_line:
        mask.add(start_line, start_col, end_col)
        return
    mask.add(start_line, start_col, _INF)
    for line_no in range(start_line + 1, end_line):
        mask.add_full(line_no)
    mask.add(end_line, 0, end_col)


# ---------------------------------------------------------------------- python

_PY_MASKED_TYPES = {tokenize.COMMENT, tokenize.STRING}
# 3.12+ splits f-strings; the MIDDLE pieces are literal text, the interpolations are
# ordinary tokens and must stay "code".
for _name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
    _value = getattr(tokenize, _name, None)
    if _value is not None:  # pragma: no branch - version dependent
        _PY_MASKED_TYPES.add(_value)


def _python_mask(text: str, lines: list[str]) -> _Mask | None:
    mask = _Mask(len(lines))
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type not in _PY_MASKED_TYPES:
                continue
            _mask_multiline(
                mask, token.start[0], token.start[1], token.end[0], token.end[1]
            )
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        log.debug("tokenize failed; falling back to the lexer", exc_info=True)
        return None
    return mask


# ------------------------------------------------------------------ javascript

_TS_STRING_TYPES = {"string", "template_string", "comment", "regex"}


def _javascript_mask_treesitter(tree: Any, text: str, lines: list[str]) -> _Mask | None:
    try:
        root = tree.root_node
    except Exception:  # pragma: no cover - defensive
        # Parser-binding boundary: an unusable tree means "no mask", never a crash.
        log.debug("tree-sitter tree has no root node", exc_info=True)
        return None
    source = text.encode("utf-8")
    line_starts = [0]
    for index, byte in enumerate(source):
        if byte == 0x0A:
            line_starts.append(index + 1)

    def position(offset: int) -> tuple[int, int]:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - line_starts[lo]

    mask = _Mask(len(lines))
    holes: list[tuple[int, int]] = []
    stack = [root]
    seen = 0
    while stack and seen < 200_000:
        node = stack.pop()
        seen += 1
        try:
            node_type = node.type
            children = list(node.children)
        except (AttributeError, TypeError):  # pragma: no cover - binding quirk
            # Narrow, and silent: this runs once per node of every parsed file.
            continue
        if node_type == "template_substitution":
            holes.append((node.start_byte, node.end_byte))
            stack.extend(children)
            continue
        if node_type in _TS_STRING_TYPES:
            start_line, start_col = position(node.start_byte)
            end_line, end_col = position(node.end_byte)
            _mask_multiline(mask, start_line, start_col, end_line, end_col)
            stack.extend(children)
            continue
        stack.extend(children)

    # ``${ ... }`` inside a template literal is executable again.
    for start, end in holes:
        start_line, start_col = position(start)
        end_line, end_col = position(end)
        _unmask(mask, start_line, start_col, end_line, end_col)
    return mask


def _unmask(mask: _Mask, start_line: int, start_col: int, end_line: int, end_col: int) -> None:
    """Punch a hole through the mask (template interpolations are code)."""
    for line_no in range(start_line, end_line + 1):
        if not 1 <= line_no < len(mask.spans):
            continue
        lo = start_col if line_no == start_line else 0
        hi = end_col if line_no == end_line else _INF
        mask.spans[line_no] = [
            piece for span in mask.spans[line_no] for piece in _subtract(span, (lo, hi))
        ]


def _subtract(span: tuple[int, int], hole: tuple[int, int]) -> list[tuple[int, int]]:
    (start, end), (lo, hi) = span, hole
    if hi <= start or lo >= end:
        return [span]
    out: list[tuple[int, int]] = []
    if start < lo:
        out.append((start, lo))
    if hi < end:
        out.append((hi, end))
    return out


def _lexer_mask(lines: list[str], *, js: bool) -> _Mask:
    """Conservative quote/comment tracker used when no parser is available."""
    mask = _Mask(len(lines))
    block_comment = False
    quote: str | None = None
    for offset, line in enumerate(lines):
        line_no = offset + 1
        index = 0
        length = len(line)
        while index < length:
            char = line[index]
            if block_comment:
                mask.add(line_no, index, index + 1)
                if js and char == "*" and index + 1 < length and line[index + 1] == "/":
                    mask.add(line_no, index + 1, index + 2)
                    index += 2
                    block_comment = False
                    continue
                index += 1
                continue
            if quote is not None:
                mask.add(line_no, index, index + 1)
                if char == "\\":
                    mask.add(line_no, index + 1, index + 2)
                    index += 2
                    continue
                if char == quote:
                    quote = None
                index += 1
                continue
            if js and char == "/" and index + 1 < length and line[index + 1] == "/":
                mask.add(line_no, index, length)
                break
            if not js and char == "#":
                mask.add(line_no, index, length)
                break
            if js and char == "/" and index + 1 < length and line[index + 1] == "*":
                block_comment = True
                mask.add(line_no, index, index + 2)
                index += 2
                continue
            if char in "\"'" or (js and char == "`"):
                quote = char
                mask.add(line_no, index, index + 1)
                index += 1
                continue
            index += 1
        if quote is not None and not (js and quote == "`"):
            # An unterminated single-line quote is a lexer artefact, not a string.
            quote = None
    return mask


# ------------------------------------------------------------------ public API


def _build_mask(text: str, suffix: str, tree: Any | None) -> _Mask | None:
    lines = text.splitlines()
    if not lines:
        return None
    if suffix in _PY_SUFFIXES:
        return _python_mask(text, lines) or _lexer_mask(lines, js=False)
    if suffix in _JS_SUFFIXES:
        mask = _javascript_mask_treesitter(tree, text, lines) if tree is not None else None
        return mask if mask is not None else _lexer_mask(lines, js=True)
    return None


def non_code_lines_of_text(text: str, suffix: str, tree: Any | None = None) -> frozenset[int]:
    """1-based line numbers made up entirely of string or comment content."""
    if not text or len(text) > _MAX_CHARS:
        return frozenset()
    mask = _build_mask(text, suffix.lower(), tree)
    if mask is None:
        return frozenset()
    return mask.non_code_lines(text.splitlines())


def non_code_spans_of_text(
    text: str, suffix: str, tree: Any | None = None
) -> dict[int, list[tuple[int, int]]]:
    """Per-line ``[start, end)`` column intervals covered by strings and comments."""
    if not text or len(text) > _MAX_CHARS:
        return {}
    mask = _build_mask(text, suffix.lower(), tree)
    if mask is None:
        return {}
    return {
        line_no: list(spans)
        for line_no, spans in enumerate(mask.spans)
        if line_no >= 1 and spans
    }


def non_code_lines(ctx: ScanContext, relpath: str) -> frozenset[int]:
    """Cached :func:`non_code_lines_of_text` for a file in the scanned repository.

    Languages without a backend (YAML, TOML, Dockerfiles, ``.env`` …) return an empty
    set: every line stays in scope, exactly as before this helper existed.
    """
    cache = getattr(ctx, "_non_code_cache", None)
    if cache is None:  # pragma: no cover - ScanContext always defines it
        cache = {}
    key = str(relpath)
    cached = cache.get(key)
    if cached is not None:
        return cached
    suffix = PurePosixPath(key).suffix.lower()
    tree = ctx.ast(key) if suffix in _JS_SUFFIXES else None
    result = non_code_lines_of_text(ctx.read(key), suffix, tree)
    cache[key] = result
    return result


def is_non_code_line(ctx: ScanContext, relpath: str, line_no: int) -> bool:
    """True when line ``line_no`` of ``relpath`` is only string or comment content.

    This is the check a text rule should apply before reporting a match: a *mention*
    of a dangerous pattern in a docstring, comment, or prose string is not the same
    as *doing* it.
    """
    return line_no in non_code_lines(ctx, relpath)


def is_non_code_span(ctx: ScanContext, relpath: str, line_no: int, start: int, end: int) -> bool:
    """True when columns ``[start, end)`` of ``line_no`` sit inside one string or comment.

    Stricter than :func:`is_non_code_line` and reserved for patterns whose meaning is
    unambiguous: ``print(`` appearing *inside a string literal* is the word "print",
    never a call. Rules whose subject is itself a string value must not use this.
    """
    cache = getattr(ctx, "_non_code_cache", None)
    key = f"spans::{relpath}"
    spans = cache.get(key) if cache is not None else None
    if spans is None:
        suffix = PurePosixPath(str(relpath)).suffix.lower()
        tree = ctx.ast(str(relpath)) if suffix in _JS_SUFFIXES else None
        spans = non_code_spans_of_text(ctx.read(str(relpath)), suffix, tree)
        if cache is not None:
            cache[key] = spans
    return any(lo <= start and end <= hi for lo, hi in spans.get(line_no, ()))
