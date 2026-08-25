"""Private helpers for the reliability rule pack.

Deliberately self-contained: cross-pack helpers belong in
:mod:`vibeguard.rules._support`, and this pack must not depend on another pack's
internals. Every helper swallows parser quirks and returns an empty/False result
rather than raising — a rule that crashes silently loses coverage.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    ancestors,
    is_test_path,
    node_text,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

#: Hard cap on findings per rule per repository.
MAX_FINDINGS = 6

CODE_SUFFIXES: tuple[str, ...] = PY_SUFFIXES + JS_SUFFIXES

_HANDLER_DECORATOR = re.compile(
    r"@[\w\.]*\b(route|get|post|put|patch|delete|head|options|websocket|api_route|"
    r"before_request|after_request|on_event|middleware|task|actor|job|shared_task)\s*[\(\n]",
    re.IGNORECASE,
)
_HANDLER_NAME = re.compile(
    r"^(handle|view|index|list|create|update|delete|show|detail|search|process|run|"
    r"consume|worker)_|_(view|handler|route|endpoint|api|task|job|worker)$",
    re.IGNORECASE,
)
_JS_HANDLER_PARAMS = re.compile(r"\(\s*(req|request|ctx|context)\b")


def root_of(ctx: ScanContext, relpath: str) -> Any | None:
    """Root node of the cached parse for ``relpath``, or None."""
    tree = ctx.ast(relpath)
    if tree is None:
        return None
    try:
        return tree.root_node
    except Exception:  # pragma: no cover - defensive
        return None


def function_name(source: bytes, func: Any) -> str:
    """Name of a function-like node ("" when anonymous or unparsable)."""
    if func is None:
        return ""
    try:
        return node_text(source, func.child_by_field_name("name"))
    except Exception:  # pragma: no cover - defensive
        return ""


def decorator_text(source: bytes, func: Any) -> str:
    """Text of the decorators attached to a Python ``function_definition``."""
    parent = getattr(func, "parent", None)
    if parent is None or getattr(parent, "type", "") != "decorated_definition":
        return ""
    try:
        return source[parent.start_byte : func.start_byte].decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def is_handler(source: bytes, func: Any) -> bool:
    """Heuristic: does this function run per request or per queued job?"""
    if func is None:
        return False
    if _HANDLER_DECORATOR.search(decorator_text(source, func)):
        return True
    name = function_name(source, func)
    if name and _HANDLER_NAME.search(name):
        return True
    return bool(_JS_HANDLER_PARAMS.search(node_text(source, func)[:200]))


def is_async(source: bytes, func: Any) -> bool:
    """True for ``async def`` / ``async function`` / ``async (…) => …``."""
    if func is None:
        return False
    return node_text(source, func).lstrip().startswith("async")


def statements(block: Any) -> list[Any]:
    """Non-trivial statement children of a block (comments and punctuation dropped)."""
    if block is None:
        return []
    try:
        children = list(block.children)
    except Exception:  # pragma: no cover - defensive
        return []
    return [
        child
        for child in children
        if child.type not in {"comment", ":", "{", "}", ";", "block_comment", "line_comment"}
    ]


def module_level(node: Any) -> bool:
    """True when ``node`` is not nested inside any function or class body."""
    return not any(
        parent.type
        in {
            "function_definition",
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
            "class_definition",
            "class_declaration",
        }
        for parent in ancestors(node)
    )


def probe_files(
    ctx: ScanContext,
    suffixes: tuple[str, ...] | None = None,
    *,
    limit: int = 1200,
) -> list[str]:
    """Files for a repo-wide text probe (tests dropped, everything else kept)."""
    wanted = {s.lower() for s in suffixes} if suffixes else None
    out: list[str] = []
    for rel in ctx.files:
        if wanted is not None and PurePosixPath(rel).suffix.lower() not in wanted:
            continue
        if is_test_path(rel):
            continue
        out.append(rel)
        if len(out) >= limit:
            break
    return out


def find_in_repo(
    ctx: ScanContext,
    pattern: re.Pattern[str],
    suffixes: tuple[str, ...] | None = None,
) -> str | None:
    """First non-test file whose text matches ``pattern``, else None."""
    for rel in probe_files(ctx, suffixes):
        text = ctx.read(rel)
        if text and pattern.search(text):
            return rel
    return None


def has_long_running_process(ctx: ScanContext) -> bool:
    """True when the repo ships a server or a worker rather than a one-shot script."""
    return bool(ctx.tech.backend or ctx.tech.workers or ctx.tech.brokers or ctx.tech.realtime)
