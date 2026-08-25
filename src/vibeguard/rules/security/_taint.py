"""Private taint and interpolation heuristics for the security pack.

Two questions recur across almost every rule in this pack:

* *Is this expression derived from request input?* — :func:`is_tainted` answers it
  from the expression text, from local assignments inside the enclosing function,
  and from the parameters of a function carrying a route decorator.
* *Is this expression built by string interpolation?* — :func:`is_interpolated_py`
  and :func:`is_interpolated_js` answer it from the tree-sitter node.

Everything here is defensive: a malformed node yields ``False``/``set()``, never an
exception. These helpers are private to the security pack (see the pack contract:
new shared helpers live in the owning pack, not in ``rules/_support``).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from vibeguard.rules._support import (
    enclosing_function,
    is_generated_path,
    is_test_path,
    node_text,
    walk,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "REQUEST_SOURCE",
    "arg_nodes",
    "block_text",
    "config_files",
    "contains",
    "first_arg",
    "has_literal_only",
    "is_interpolated_js",
    "is_interpolated_py",
    "is_tainted",
    "looks_interpolated",
    "route_param_names",
    "tainted_names",
]

#: Expression text that names a request-derived value.
REQUEST_SOURCE = re.compile(
    r"""
      \brequest\s*\.
    | \bflask\.request\b
    | \bself\.request\b
    | \breq\s*\.\s*(query|params|body|headers|cookies|url|originalUrl|files)\b
    | \bevent\s*\[\s*['"](queryStringParameters|body|pathParameters|headers)
    | \bevent\s*\.\s*(queryStringParameters|pathParameters)\b
    | \bparams\s*\[
    | \bargs\s*\.\s*get\s*\(
    | \bform\s*\[
    | \bform\s*\.\s*get\s*\(
    | \bquery_params\b
    | \bpath_params\b
    | \binput\s*\(
    """,
    re.VERBOSE,
)

_ASSIGN = re.compile(
    r"^[ \t]*(?:const |let |var )?([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*([^\n]+)$",
    re.MULTILINE,
)
_DESTRUCTURE = re.compile(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*([^;\n]+)")
_ROUTE_DECORATOR = re.compile(
    r"@[\w.]*\b(route|get|post|put|patch|delete|head|options)\s*\(", re.IGNORECASE
)
_INTERPOLATED_TEXT = re.compile(
    r"""(?x)
      \bf["']              # f-string
    | \.format\s*\(
    | %\s*[\(\w]           # %-formatting
    | \$\{                 # JS template substitution
    | ["']\s*\+\s*[A-Za-z_$]
    | [A-Za-z_$][\w$]*\s*\+\s*["']
    """
)

_PY_NON_LITERAL = {
    "identifier",
    "attribute",
    "subscript",
    "call",
    "conditional_expression",
    "binary_operator",
}
_JS_NON_LITERAL = {
    "identifier",
    "member_expression",
    "subscript_expression",
    "call_expression",
    "ternary_expression",
    "template_string",
}


# ------------------------------------------------------------------ node access


def arg_nodes(call_node: Any) -> list[Any]:
    """Named argument nodes of a call, or ``[]`` for tagged templates/oddities."""
    try:
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return []
        return [child for child in args.children if child.is_named and child.type != "comment"]
    except Exception:  # pragma: no cover - defensive
        return []


def first_arg(call_node: Any) -> Any | None:
    """First named argument node, or None."""
    nodes = arg_nodes(call_node)
    return nodes[0] if nodes else None


def block_text(source: bytes, node: Any) -> str:
    """Text of the enclosing function, falling back to the node itself."""
    func = enclosing_function(node)
    return node_text(source, func if func is not None else node)


# ------------------------------------------------------------------- taint


def tainted_names(text: str) -> set[str]:
    """Local variable names assigned from a request-derived expression."""
    names: set[str] = set()
    if not text:
        return names
    try:
        for match in _ASSIGN.finditer(text):
            if REQUEST_SOURCE.search(match.group(2)):
                names.add(match.group(1))
        for match in _DESTRUCTURE.finditer(text):
            if not REQUEST_SOURCE.search(match.group(2)):
                continue
            for part in match.group(1).split(","):
                name = part.split(":")[-1].strip().strip(".")
                if name.isidentifier():
                    names.add(name)
    except Exception:  # pragma: no cover - defensive
        return names
    return names


def route_param_names(source: bytes, node: Any) -> set[str]:
    """Parameters of the enclosing function when it carries a route decorator.

    A Flask/FastAPI path parameter is request input even though its name says
    nothing about where it came from, so handlers get their parameters tainted.
    """
    func = enclosing_function(node)
    if func is None:
        return set()
    parent = getattr(func, "parent", None)
    if parent is None or parent.type != "decorated_definition":
        return set()
    if not _ROUTE_DECORATOR.search(node_text(source, parent)):
        return set()
    params = func.child_by_field_name("parameters")
    if params is None:
        return set()
    names: set[str] = set()
    for child in params.children:
        if child.type == "identifier":
            names.add(node_text(source, child))
        elif child.type in {"default_parameter", "typed_parameter", "typed_default_parameter"}:
            for sub in child.children:
                if sub.type == "identifier":
                    names.add(node_text(source, sub))
                    break
    names.discard("self")
    names.discard("cls")
    return names


def is_tainted(source: bytes, node: Any, expr_text: str | None = None) -> bool:
    """True when ``expr_text`` (default: the node's text) looks request-derived."""
    if node is None and not expr_text:
        return False
    text = expr_text if expr_text is not None else node_text(source, node)
    if not text:
        return False
    if REQUEST_SOURCE.search(text):
        return True
    if node is None:
        return False
    candidates = tainted_names(block_text(source, node)) | route_param_names(source, node)
    if not candidates:
        return False
    return any(word in candidates for word in re.findall(r"[A-Za-z_$][\w$]*", text))


# ------------------------------------------------------- interpolation (Python)


def _py_operator(node: Any) -> str:
    try:
        op = node.child_by_field_name("operator")
        if op is not None:
            return op.type
        for child in node.children:
            if not child.is_named:
                return child.type
    except Exception:  # pragma: no cover - defensive
        return ""
    return ""


def is_interpolated_py(source: bytes, node: Any, depth: int = 0) -> bool:
    """True for an f-string, ``%``/``+`` build, or ``.format(...)`` expression."""
    if node is None or depth > 6:
        return False
    kind = node.type
    if kind == "string":
        return any(child.type == "interpolation" for child in node.children)
    if kind == "concatenated_string":
        return any(is_interpolated_py(source, child, depth + 1) for child in node.children)
    if kind == "parenthesized_expression":
        return any(is_interpolated_py(source, child, depth + 1) for child in node.children)
    if kind == "binary_operator":
        if _py_operator(node) not in {"%", "+"}:
            return False
        parts = [child for child in node.children if child.is_named]
        has_string = any(
            child.type in {"string", "concatenated_string", "binary_operator"} for child in parts
        )
        has_dynamic = any(child.type in _PY_NON_LITERAL for child in parts)
        return has_string and has_dynamic
    if kind == "call":
        func = node.child_by_field_name("function")
        name = node_text(source, func)
        return name.endswith(".format") and bool(arg_nodes(node))
    return False


# ----------------------------------------------------------- interpolation (JS)


def is_interpolated_js(source: bytes, node: Any, depth: int = 0) -> bool:
    """True for a substituting template literal or a ``+`` build with a non-literal."""
    if node is None or depth > 6:
        return False
    kind = node.type
    if kind == "template_string":
        return any(child.type == "template_substitution" for child in node.children)
    if kind == "parenthesized_expression":
        return any(is_interpolated_js(source, child, depth + 1) for child in node.children)
    if kind == "binary_expression":
        if _py_operator(node) != "+":
            return False
        parts = [child for child in node.children if child.is_named]
        has_string = any(child.type in {"string", "template_string"} for child in parts)
        has_dynamic = any(child.type in _JS_NON_LITERAL for child in parts)
        if has_string and has_dynamic:
            return True
        return any(is_interpolated_js(source, child, depth + 1) for child in parts)
    if kind == "call_expression":
        func = node.child_by_field_name("function")
        return node_text(source, func).endswith(".concat")
    return False


def has_literal_only(node: Any) -> bool:
    """True when the node is a plain string literal with no dynamic part."""
    if node is None:
        return False
    if node.type != "string":
        return False
    dynamic = {"interpolation", "template_substitution"}
    return not any(child.type in dynamic for child in node.children)


def looks_interpolated(text: str) -> bool:
    """Text-level fallback used where no parse tree is available."""
    return bool(text) and bool(_INTERPOLATED_TEXT.search(text))


def contains(node: Any, types: set[str]) -> bool:
    """True when the subtree contains a node of one of ``types``."""
    return any(child.type in types for child in walk(node))


# --------------------------------------------------------------- file helpers


def config_files(
    ctx: ScanContext,
    *,
    suffixes: tuple[str, ...] = (),
    names: tuple[str, ...] = (),
    limit: int = 400,
) -> list[str]:
    """Scanned config-ish files matched by suffix or exact/prefix filename."""
    wanted = {suffix.lower() for suffix in suffixes}
    lowered_names = {name.lower() for name in names}
    out: list[str] = []
    for rel in ctx.files:
        if is_test_path(rel) or is_generated_path(rel):
            continue
        path = PurePosixPath(rel)
        name = path.name.lower()
        if path.suffix.lower() in wanted or name in lowered_names:
            out.append(rel)
        elif any(name.startswith(candidate) for candidate in lowered_names if candidate):
            out.append(rel)
        if len(out) >= limit:
            break
    return out
