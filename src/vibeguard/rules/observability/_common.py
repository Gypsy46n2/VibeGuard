"""Helpers private to the observability rule pack."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, source_files

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "CODE_SUFFIXES",
    "CONFIG_SUFFIXES",
    "has_server",
    "haystack",
    "matched_tokens",
]

CODE_SUFFIXES: tuple[str, ...] = PY_SUFFIXES + JS_SUFFIXES
CONFIG_SUFFIXES: tuple[str, ...] = (
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".json",
    ".txt",
    ".md",
    ".tf",
    ".go",
    ".rb",
    ".java",
)

_SCAN_LIMIT = 300
_MAX_FILE_CHARS = 400_000


def haystack(ctx: ScanContext, *, include_tests: bool = False) -> str:
    """Lowercased concatenation of the project's source, config, and manifest files.

    Cheap because :meth:`ScanContext.read` caches; capped so a huge repository cannot
    turn a project-level rule into a full-text search.
    """
    rels = source_files(
        ctx,
        CODE_SUFFIXES + CONFIG_SUFFIXES,
        skip_tests=not include_tests,
        limit=_SCAN_LIMIT,
    )
    seen = set(rels)
    for extra in list(ctx.tech.manifest_files) + [".env", "Makefile", "Procfile"]:
        if extra not in seen and extra in set(ctx.files):
            rels.append(extra)
            seen.add(extra)
    chunks: list[str] = []
    for rel in rels[:_SCAN_LIMIT]:
        text = ctx.read(rel)
        if text:
            chunks.append(text[:_MAX_FILE_CHARS].lower())
    return "\n".join(chunks)


def matched_tokens(text: str, tokens: tuple[str, ...]) -> list[str]:
    """Which ``tokens`` (already lowercase) appear in ``text``."""
    return [token for token in tokens if token in text]


def has_server(ctx: ScanContext) -> bool:
    """True when discovery found a backend/server framework."""
    return bool(ctx.tech.backend) or bool(ctx.tech.serverless)


def source_file_count(ctx: ScanContext) -> int:
    """Number of non-test, non-generated first-party source files."""
    return len(source_files(ctx, CODE_SUFFIXES, limit=_SCAN_LIMIT))


def is_frontend_path(relpath: str) -> bool:
    """True for paths that live in a browser-side tree."""
    path = PurePosixPath(str(relpath))
    parts = {part.lower() for part in path.parts[:-1]}
    if parts & {"frontend", "client", "ui", "www", "webapp", "components", "views"}:
        return True
    return path.suffix.lower() in {".jsx", ".tsx", ".vue", ".svelte"}
