"""Helpers private to the testing rule pack.

Every rule in this pack is a *gap* rule: it reports a kind of test the project is
missing. That only makes sense once a test suite exists — a project with no tests
at all is already reported once by ``VG-MAINT-001``, and repeating the point five
more times would bury it. :func:`has_test_suite` is the shared gate that keeps the
report to one clear finding.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "has_test_suite",
    "test_files",
    "test_text",
]

_TEST_DIR_NAMES = {
    "tests",
    "test",
    "__tests__",
    "spec",
    "specs",
    "e2e",
    "integration",
    "cypress",
    "playwright",
}
_TEST_FILE_HINTS = ("test_", "_test.", ".test.", ".spec.", "_spec.")
_TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rb",
    ".java",
    ".feature",
}
_MAX_TEST_FILES = 200
_MAX_FILE_CHARS = 200_000


def test_files(ctx: ScanContext) -> list[str]:
    """Scanned files that look like tests (directory or filename convention)."""
    out: list[str] = []
    for rel in ctx.files:
        path = PurePosixPath(rel)
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        name = path.name.lower()
        in_test_dir = any(part.lower() in _TEST_DIR_NAMES for part in path.parts[:-1])
        if in_test_dir or any(hint in name for hint in _TEST_FILE_HINTS):
            out.append(rel)
        if len(out) >= _MAX_TEST_FILES:
            break
    return out


def has_test_suite(ctx: ScanContext) -> bool:
    """Mirror of ``VG-MAINT-001``'s gate, inverted.

    True when *anything* resembling a test suite exists, so the gap rules stay quiet
    on a project that has no tests at all.
    """
    if ctx.tech.test_frameworks:
        return True
    if any(ctx.exists(name) for name in sorted(_TEST_DIR_NAMES)):
        return True
    return bool(test_files(ctx))


def test_text(ctx: ScanContext) -> str:
    """Lowercased concatenation of every test file's contents."""
    chunks: list[str] = []
    for rel in test_files(ctx):
        text = ctx.read(rel)
        if text:
            chunks.append(text[:_MAX_FILE_CHARS].lower())
    return "\n".join(chunks)


def test_paths_text(ctx: ScanContext) -> str:
    """Lowercased newline-joined list of test file paths (for path-shaped signals)."""
    return "\n".join(rel.lower() for rel in test_files(ctx))
