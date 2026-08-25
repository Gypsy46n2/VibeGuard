"""Private tree-sitter helpers for loop-body analysis in the cost pack."""

from __future__ import annotations

import re
from typing import Any

from vibeguard.rules._support import ancestors, node_text

__all__ = ["UNBOUNDED_ITERABLE", "enclosing_loop", "in_request_handler", "loop_iterable"]

_LOOP_TYPES = {"for_statement", "while_statement", "for_in_statement", "for_of_statement"}

#: Iterables whose length is driven by data volume rather than a literal.
UNBOUNDED_ITERABLE = re.compile(
    r"\.all\(\)|\.fetchall\(|\.fetchmany\(|\bcursor\b|\bquery\b|\.filter\(|\.find\(|"
    r"\.findAll\(|\.scan\(|\bselect\b|\brows\b|\brecords\b|\bresults\b|\bentries\b|"
    r"\bpayload\b|\.json\(\)|\.readlines\(\)|\bdataset\b|"
    r"\busers\b|\borders\b|\bevents\b|\bmessages\b",
    re.IGNORECASE,
)

_HANDLER_DECORATOR = re.compile(
    r"@(?:app|api|router|bp|blueprint|routes)\.(?:route|get|post|put|patch|delete)\s*\(",
    re.IGNORECASE,
)


def enclosing_loop(node: Any) -> Any | None:
    """Nearest enclosing for/while node, or None."""
    for parent in ancestors(node):
        if parent.type in _LOOP_TYPES:
            return parent
    return None


def loop_iterable(source: bytes, loop: Any) -> str:
    """Text of the loop's iterable/condition — ``""`` when it cannot be read."""
    if loop is None:
        return ""
    try:
        if loop.type == "while_statement":
            return node_text(source, loop.child_by_field_name("condition"))
        right = loop.child_by_field_name("right")
        if right is not None:
            return node_text(source, right)
        return node_text(source, loop.child_by_field_name("condition"))
    except Exception:  # pragma: no cover - defensive against binding quirks
        return ""


def in_request_handler(source: bytes, node: Any) -> bool:
    """True when ``node`` sits inside a decorated route handler."""
    for parent in ancestors(node):
        if parent.type != "decorated_definition":
            continue
        if _HANDLER_DECORATOR.search(node_text(source, parent)[:400]):
            return True
    return False
