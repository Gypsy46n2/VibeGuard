"""ScanContext — the read-only view of a repository handed to every rule.

Declared in INTERFACES.md §2; implemented here because it composes config and the
discovery profiles. ``vibeguard.core.models.ScanContext`` re-exports it.
"""

from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from vibeguard.ai.gateway import AIGateway
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.models import ArchitectureGraph, ScaleProfile, TechProfile

__all__ = ["ScanContext"]

log = logging.getLogger(__name__)

_TS_LANGUAGE_BY_EXT = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
}

_parser_cache: dict[str, Any] = {}


def _get_parser(language: str) -> Any | None:
    """Return a cached tree-sitter parser, or None when unavailable."""
    if language in _parser_cache:
        return _parser_cache[language]
    parser: Any | None = None
    try:
        import tree_sitter

        if language == "python":
            import tree_sitter_python as ts_lang
        else:
            import tree_sitter_javascript as ts_lang

        ts_language = tree_sitter.Language(ts_lang.language())
        try:
            parser = tree_sitter.Parser(ts_language)
        except TypeError:  # pragma: no cover - older binding API
            parser = tree_sitter.Parser()
            parser.set_language(ts_language)
    except Exception:  # pragma: no cover - missing/incompatible tree-sitter
        log.debug("tree-sitter unavailable for %s", language, exc_info=True)
        parser = None
    _parser_cache[language] = parser
    return parser


class ScanContext(BaseModel):
    """Everything a rule may look at. Rules must treat it as read-only."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    root: Path
    files: list[str] = Field(default_factory=list)
    tech: TechProfile
    graph: ArchitectureGraph
    scale: ScaleProfile
    config: VibeguardConfig
    #: The run's AI gateway (INTERFACES.md §10), or ``None`` when the engine did not
    #: build one. Rules declaring ``requires_ai`` are only run when
    #: :meth:`ai_available` is true, so a rule may use ``ctx.ai.complete(...)``
    #: directly; anything else should go through ``ctx.ai.try_complete(...)`` and fall
    #: back to a deterministic answer.
    ai: AIGateway | None = None

    _read_cache: dict[str, str] = PrivateAttr(default_factory=dict)
    _ast_cache: dict[str, Any] = PrivateAttr(default_factory=dict)

    # ------------------------------------------------------------------ files
    def read(self, relpath: str) -> str:
        """Cached text read; returns ``""`` for missing or unreadable files."""
        key = str(relpath)
        cached = self._read_cache.get(key)
        if cached is not None:
            return cached
        path = self.root / key
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            text = ""
        self._read_cache[key] = text
        return text

    def ast(self, relpath: str) -> Any | None:
        """Cached tree-sitter parse for py/js/ts files; None when unsupported."""
        key = str(relpath)
        if key in self._ast_cache:
            return self._ast_cache[key]
        tree: Any | None = None
        language = _TS_LANGUAGE_BY_EXT.get(PurePosixPath(key).suffix.lower())
        if language:
            parser = _get_parser(language)
            if parser is not None:
                try:
                    tree = parser.parse(self.read(key).encode("utf-8"))
                except Exception:  # pragma: no cover - parser failure is non-fatal
                    log.debug("tree-sitter parse failed for %s", key, exc_info=True)
                    tree = None
        self._ast_cache[key] = tree
        return tree

    # -------------------------------------------------------------- helpers
    def ai_available(self) -> bool:
        """True when an AI provider is configured, permitted, and usable."""
        return self.ai is not None and self.ai.available

    def exists(self, relpath: str) -> bool:
        """True when the path exists on disk under the repo root."""
        return (self.root / relpath).exists()

    def files_matching(self, *suffixes: str) -> list[str]:
        """Scanned files whose suffix matches any of ``suffixes`` (case-insensitive)."""
        wanted = {s.lower() for s in suffixes}
        return [f for f in self.files if PurePosixPath(f).suffix.lower() in wanted]
