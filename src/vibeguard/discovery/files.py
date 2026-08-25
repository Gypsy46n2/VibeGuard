"""Repository file walking: gitignore-aware, binary-excluding, config-excluded."""

from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath

__all__ = ["collect_files", "is_probably_binary", "load_gitignore_patterns", "SOURCE_EXTENSIONS"]

#: Extension -> language name, used for both language counts and LOC.
SOURCE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".sh": "shell",
    ".sql": "sql",
    ".vue": "vue",
    ".svelte": "svelte",
}

_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz",
    ".bz2", ".xz", ".tar", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class",
    ".jar", ".war", ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3",
    ".mp4", ".mov", ".avi", ".wav", ".ogg", ".webm", ".db", ".sqlite", ".sqlite3",
    ".bin", ".dat", ".wasm", ".node",
}

_MAX_FILE_BYTES = 2_000_000
_ALWAYS_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}


def is_probably_binary(path: Path) -> bool:
    """Cheap binary sniff: known extension, or a NUL byte in the first 4 KiB."""
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(4096)
    except OSError:  # pragma: no cover - unreadable file
        return True


def load_gitignore_patterns(root: Path) -> list[str]:
    """Parse the root ``.gitignore`` into fnmatch-able patterns (best effort).

    Negations (``!pattern``) are honoured only insofar as they are dropped from the
    ignore set; nested .gitignore files are not walked (M1 scope).
    """
    patterns: list[str] = []
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return patterns
    try:
        lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:  # pragma: no cover
        return patterns
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        patterns.append(line)
    return patterns


def _pattern_variants(pattern: str) -> set[str]:
    """Expand a gitignore/config glob into fnmatch-able variants.

    ``fnmatch``'s ``*`` already spans ``/``, so ``a/**`` and ``a/*`` are equivalent;
    the anchored forms are what need generating (``**/vendor/**`` must also match
    ``vendor/lib.py``).
    """
    pat = pattern.strip().rstrip("/")
    if not pat:
        return set()
    variants = {pat}
    for candidate in list(variants):
        if candidate.startswith("**/"):
            variants.add(candidate[3:])
        if candidate.startswith("/"):
            variants.add(candidate.lstrip("/"))
    for candidate in list(variants):
        if candidate.endswith("/**"):
            variants.add(candidate[:-3] + "/*")
    return variants


def _matches(relpath: str, patterns: list[str]) -> bool:
    parts = PurePosixPath(relpath).parts
    for pattern in patterns:
        pat = pattern.strip().rstrip("/")
        if not pat:
            continue
        for variant in _pattern_variants(pattern):
            if fnmatch.fnmatchcase(relpath, variant) or fnmatch.fnmatchcase(
                relpath, f"*/{variant}"
            ):
                return True
        # Bare names ("node_modules", "*.log") match any path component.
        bare = pat[3:] if pat.startswith("**/") else pat
        if "/" not in bare and any(fnmatch.fnmatchcase(part, bare) for part in parts):
            return True
    return False


def collect_files(root: Path, exclude: list[str] | None = None) -> list[str]:
    """Return POSIX-relative paths of candidate text files under ``root``."""
    patterns = list(exclude or []) + load_gitignore_patterns(root)
    results: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:  # pragma: no cover - defensive
            continue
        if any(part in _ALWAYS_SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if _matches(rel, patterns):
            continue
        try:
            if path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:  # pragma: no cover
            continue
        if is_probably_binary(path):
            continue
        results.append(rel)
    return results
