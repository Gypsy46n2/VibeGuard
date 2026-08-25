"""Private HTTP-shape helpers for the api, network, and performance rule packs.

These are deliberately *not* in ``rules/_support.py`` (which the M2 contract freezes):
they are owned by, and only used from, the three packs implemented together here
(``api``, ``network``, ``performance``).

Everything in this module is defensive — a malformed or unparsable file yields an
empty result rather than an exception.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    js_calls,
    node_text,
    source_files,
    walk,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "Handler",
    "config_files",
    "first_string",
    "handlers",
    "has_routes",
    "js_handlers",
    "py_handlers",
    "repo_matches",
    "serves_http",
]

_ROUTE_METHOD_NAMES = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "websocket",
    "api_route",
    "add_url_rule",
    "sse",
}
_JS_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "all", "use"}
_JS_ROUTER_NAMES = {"app", "router", "server", "fastify", "api", "apiRouter", "r"}

_PY_ROUTE_DECORATOR = re.compile(
    r"^@\s*[\w\.]*\b(?:" + "|".join(sorted(_ROUTE_METHOD_NAMES)) + r")\s*\(",
)
_DECORATOR_BASE = re.compile(r"@\s*[\w\.]*?(\w+)\s*\(")
_STRING = re.compile(r"""['"]([^'"\n]*)['"]""")
_METHODS_KW = re.compile(r"methods\s*=\s*[\[\(]([^\]\)]*)[\]\)]")

#: Text/config suffixes worth grepping for infrastructure posture.
_CONFIG_SUFFIXES = (
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".tf",
    ".env",
    ".txt",
    ".md",
    ".sh",
    ".xml",
    ".properties",
)


@dataclass(frozen=True)
class Handler:
    """One HTTP route handler discovered in a source file."""

    file: str
    name: str
    path: str
    methods: frozenset[str] = field(default_factory=frozenset)
    line: int = 1
    text: str = ""
    decorator: str = ""
    node: Any = None

    @property
    def signature(self) -> str:
        """Path plus handler name — what the money/webhook heuristics match on."""
        return f"{self.path} {self.name}".lower()

    def accepts(self, method: str) -> bool:
        """True when the route takes ``method`` (unknown method sets count as yes)."""
        return not self.methods or method.lower() in self.methods


def first_string(text: str) -> str:
    """First quoted literal in ``text`` (``""`` when there is none)."""
    match = _STRING.search(text or "")
    return match.group(1) if match else ""


def _decorator_methods(decorator: str) -> frozenset[str]:
    kw = _METHODS_KW.search(decorator)
    if kw:
        found = {value.strip().strip("\"'").lower() for value in kw.group(1).split(",")}
        found.discard("")
        if found:
            return frozenset(found)
    base = _DECORATOR_BASE.search(decorator)
    name = base.group(1).lower() if base else ""
    if name in {"route", "add_url_rule", "api_route"}:
        return frozenset({"get"})
    if name in _ROUTE_METHOD_NAMES:
        return frozenset({name})
    return frozenset()


def _py_function_children(node: Any) -> Any | None:
    try:
        for child in node.children:
            if child.type == "function_definition":
                return child
    except Exception:  # pragma: no cover - defensive
        return None
    return None


def _is_django_view(source: bytes, func: Any) -> bool:
    try:
        params = func.child_by_field_name("parameters")
    except Exception:  # pragma: no cover - defensive
        return False
    if params is None:
        return False
    text = node_text(source, params).lstrip("( ")
    return text.startswith("request") or text.startswith("self, request")


def py_handlers(ctx: ScanContext, relpath: str) -> list[Handler]:
    """Route handlers declared in a Python file (decorators plus Django views)."""
    tree = ctx.ast(relpath)
    if tree is None:
        return []
    source = ctx.read(relpath).encode("utf-8")
    try:
        root = tree.root_node
    except Exception:  # pragma: no cover - defensive
        return []

    is_views_module = "views" in PurePosixPath(relpath).stem.lower() or "/views/" in relpath
    out: list[Handler] = []
    decorated: set[int] = set()

    for node in walk(root):
        if node.type != "decorated_definition":
            continue
        func = _py_function_children(node)
        if func is None:
            continue
        try:
            decorators = [
                node_text(source, child) for child in node.children if child.type == "decorator"
            ]
        except Exception:  # pragma: no cover - defensive
            continue
        route = next((d for d in decorators if _PY_ROUTE_DECORATOR.match(d.strip())), None)
        decorated.add(func.start_byte)
        if route is None:
            continue
        out.append(
            Handler(
                file=relpath,
                name=node_text(source, func.child_by_field_name("name")),
                path=first_string(route),
                methods=_decorator_methods(route),
                line=func.start_point[0] + 1,
                text=node_text(source, func),
                decorator=route.strip(),
                node=func,
            )
        )

    if is_views_module:
        for node in walk(root):
            if node.type != "function_definition" or node.start_byte in decorated:
                continue
            if not _is_django_view(source, node):
                continue
            name = node_text(source, node.child_by_field_name("name"))
            if name.startswith("_"):
                continue
            out.append(
                Handler(
                    file=relpath,
                    name=name,
                    path="",
                    methods=frozenset(),
                    line=node.start_point[0] + 1,
                    text=node_text(source, node),
                    node=node,
                )
            )
    return out


def js_handlers(ctx: ScanContext, relpath: str) -> list[Handler]:
    """Express/Fastify-style route registrations in a JS/TS file."""
    out: list[Handler] = []
    for call in js_calls(ctx, relpath):
        if "." not in call.name:
            continue
        base, _, method = call.name.rpartition(".")
        method = method.lower()
        if method not in _JS_ROUTE_METHODS or base.split(".")[-1] not in _JS_ROUTER_NAMES:
            continue
        path = first_string(call.args)
        if not path.startswith("/"):
            continue
        out.append(
            Handler(
                file=relpath,
                name=path.strip("/").replace("/", "_") or "root",
                path=path,
                methods=frozenset({method}) if method != "use" else frozenset(),
                line=call.line,
                text=call.args,
                node=call.node,
            )
        )
    return out


def handlers(ctx: ScanContext, *, limit: int = 400) -> list[Handler]:
    """Every route handler in the repository, capped."""
    found: list[Handler] = []
    for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
        if len(found) >= limit:
            break
        suffix = PurePosixPath(rel).suffix.lower()
        try:
            if suffix in PY_SUFFIXES:
                found.extend(py_handlers(ctx, rel))
            else:
                found.extend(js_handlers(ctx, rel))
        except Exception:  # pragma: no cover - defensive
            continue
    return found[:limit]


def has_routes(ctx: ScanContext) -> bool:
    """True when the repo registers HTTP routes (decorators, express, or urls.py)."""
    if handlers(ctx, limit=1):
        return True
    for rel in source_files(ctx, PY_SUFFIXES):
        if PurePosixPath(rel).name == "urls.py" and "urlpatterns" in ctx.read(rel):
            return True
    return False


def serves_http(ctx: ScanContext) -> bool:
    """True when a server framework is present *and* routes exist."""
    return bool(ctx.tech.backend) and has_routes(ctx)


def config_files(ctx: ScanContext, *, limit: int = 600) -> list[str]:
    """Config-ish and source files worth grepping for infrastructure posture."""
    out: list[str] = []
    for rel in ctx.files:
        name = PurePosixPath(rel).name.lower()
        suffix = PurePosixPath(rel).suffix.lower()
        if (
            suffix in _CONFIG_SUFFIXES
            or suffix in PY_SUFFIXES
            or suffix in JS_SUFFIXES
            or name.startswith(".")
            or "docker" in name
            or "nginx" in name
            or "caddyfile" in name
            or "procfile" in name
        ):
            out.append(rel)
        if len(out) >= limit:
            break
    return out


def repo_matches(ctx: ScanContext, pattern: re.Pattern[str], *, limit: int = 600) -> str:
    """First path whose *name or content* matches ``pattern`` (``""`` when none)."""
    for rel in config_files(ctx, limit=limit):
        if pattern.search(rel):
            return rel
        text = ctx.read(rel)
        if text and pattern.search(text):
            return rel
    return ""
