"""Private helpers for the database rule pack.

Nothing here is public API — the shared, cross-pack helpers live in
:mod:`vibeguard.rules._support`. These are database-specific conveniences
(migration-path recognition, request-handler recognition, repo-wide text probes)
that only this pack needs.

Every helper is defensive: a malformed file yields an empty/False result rather
than an exception, because a crashing rule silently loses coverage.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from vibeguard.rules._support import ancestors, is_generated_path, is_test_path, node_text

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

#: Hard cap on findings per rule per repository — report the pattern, not every line.
MAX_FINDINGS = 5

SQL_SUFFIXES: tuple[str, ...] = (".sql",)

_HANDLER_DECORATOR = re.compile(
    r"@[\w\.]*\b(route|get|post|put|patch|delete|head|options|websocket|api_route|"
    r"before_request|after_request|endpoint|handler|on_event|middleware)\s*[\(\n]",
    re.IGNORECASE,
)
_HANDLER_NAME = re.compile(
    r"^(handle|view|index|list|create|update|delete|show|detail|search)_|"
    r"_(view|handler|route|endpoint|api)$",
    re.IGNORECASE,
)
_JS_HANDLER_PARAMS = re.compile(r"\(\s*(req|request|ctx|context)\b")


_NEW_EXPRESSION = re.compile(r"^new\s+([\w$.]+)")


def call_name(source: bytes, site: Any) -> str:
    """Callee name for a call site, including ``new Foo(...)`` constructors.

    ``_support.js_calls`` reads the ``function`` field, which tree-sitter leaves unset
    on ``new_expression`` nodes; recover the constructor name from the node text.
    """
    name = getattr(site, "name", "") or ""
    if name:
        return name
    if getattr(getattr(site, "node", None), "type", "") == "new_expression":
        match = _NEW_EXPRESSION.match(node_text(source, site.node).strip())
        if match:
            return match.group(1)
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


def function_name(source: bytes, func: Any) -> str:
    """Name of a function-like node ("" when anonymous or unparsable)."""
    if func is None:
        return ""
    try:
        ident = func.child_by_field_name("name")
    except Exception:  # pragma: no cover - defensive
        return ""
    return node_text(source, ident)


def is_request_handler(source: bytes, func: Any) -> bool:
    """Heuristic: does this function run once per inbound HTTP request?"""
    if func is None:
        return False
    if _HANDLER_DECORATOR.search(decorator_text(source, func)):
        return True
    name = function_name(source, func)
    if name and _HANDLER_NAME.search(name):
        return True
    text = node_text(source, func)
    return bool(_JS_HANDLER_PARAMS.search(text[:200]))


def is_async_function(source: bytes, func: Any) -> bool:
    """True for ``async def`` / ``async function`` / ``async (…) =>``."""
    if func is None:
        return False
    return node_text(source, func).lstrip().startswith("async")


def in_function(node: Any) -> bool:
    """True when ``node`` sits inside any function body."""
    return any(
        parent.type
        in {
            "function_definition",
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        }
        for parent in ancestors(node)
    )


# ------------------------------------------------------------------ migrations

_MIGRATION_DIR_PARTS = {"migrations", "migration", "migrate", "versions"}


def is_migration_path(relpath: str) -> bool:
    """True for alembic ``versions/``, django/prisma/knex ``migrations/`` files."""
    path = PurePosixPath(relpath)
    parts = [part.lower() for part in path.parts]
    if not any(part in _MIGRATION_DIR_PARTS for part in parts[:-1]):
        return False
    if "versions" in parts[:-1]:
        # ``versions/`` alone is ambiguous; require an alembic-ish neighbourhood.
        return "alembic" in parts or "migrations" in parts or "migration" in parts
    return True


def migration_files(ctx: ScanContext, limit: int = 400) -> list[str]:
    """Every scanned file that looks like a schema migration."""
    out: list[str] = []
    for rel in ctx.files:
        if not is_migration_path(rel):
            continue
        if PurePosixPath(rel).suffix.lower() not in {".py", ".sql", ".js", ".ts", ".rb"}:
            continue
        out.append(rel)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- repo probes


def scannable(
    ctx: ScanContext,
    suffixes: tuple[str, ...] | None = None,
    *,
    skip_tests: bool = True,
    skip_generated: bool = False,
    limit: int = 1200,
) -> list[str]:
    """Files to probe with a repo-wide text search.

    Unlike :func:`vibeguard.rules._support.source_files` this keeps ``migrations/``
    by default — several database rules must look *inside* migrations.
    """
    wanted = {s.lower() for s in suffixes} if suffixes else None
    out: list[str] = []
    for rel in ctx.files:
        if wanted is not None and PurePosixPath(rel).suffix.lower() not in wanted:
            continue
        if skip_tests and is_test_path(rel):
            continue
        if skip_generated and is_generated_path(rel):
            continue
        out.append(rel)
        if len(out) >= limit:
            break
    return out


def find_in_repo(
    ctx: ScanContext,
    pattern: re.Pattern[str],
    suffixes: tuple[str, ...] | None = None,
    *,
    skip_tests: bool = True,
    skip_generated: bool = True,
) -> str | None:
    """First scanned file whose text matches ``pattern``, else None."""
    for rel in scannable(ctx, suffixes, skip_tests=skip_tests, skip_generated=skip_generated):
        text = ctx.read(rel)
        if text and pattern.search(text):
            return rel
    return None


def has_database(ctx: ScanContext) -> bool:
    """True when discovery found a datastore or an ORM."""
    return bool(ctx.tech.databases) or bool(ctx.tech.orms)


SCHEMA_DEFINITION = re.compile(
    r"CREATE\s+TABLE|"
    r"\bdb\.Model\b|\bmodels\.Model\b|declarative_base\s*\(|\bDeclarativeBase\b|"
    r"\bTable\s*\(|\bmapped_column\s*\(|\bColumn\s*\(|"
    r"\bmongoose\.Schema\b|\bnew\s+Schema\s*\(|@Entity\b|"
    r"\bsequelize\.define\s*\(|\bmodel\s+\w+\s*\{",
    re.IGNORECASE,
)
