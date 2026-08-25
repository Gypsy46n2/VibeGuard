from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from vibeguard.core.config import VibeguardConfig
from vibeguard.discovery.context import ScanContext
from vibeguard.discovery.files import collect_files
from vibeguard.discovery.graph import build_graph
from vibeguard.discovery.scale import detect_scale
from vibeguard.discovery.tech import detect_tech

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_FLASK_APP = FIXTURES / "sample_flask_app"


def make_context(root: Path, config: VibeguardConfig | None = None) -> ScanContext:
    """Run discovery over ``root`` and return the resulting ScanContext."""
    config = config or VibeguardConfig()
    files = collect_files(root, config.exclude)

    def read(rel: str) -> str:
        try:
            return (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    tech = detect_tech(root, files, read)
    scale = detect_scale(root, files, read, tech)
    graph = build_graph(root, files, read, tech)
    return ScanContext(
        root=root, files=files, tech=tech, graph=graph, scale=scale, config=config
    )


def write_repo(root: Path, files: Mapping[str, str]) -> Path:
    """Materialise ``{relpath: content}`` under ``root`` and return it."""
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def context_from(
    root: Path, files: Mapping[str, str], config: VibeguardConfig | None = None
) -> ScanContext:
    """Write ``files`` under ``root`` and run discovery over the result."""
    write_repo(root, files)
    return make_context(root, config)


def run_rule(rule_cls: type, root: Path, files: Mapping[str, str]) -> list:
    """Instantiate ``rule_cls``, gate it, and return its findings for ``files``.

    Returns ``[]`` when the rule's applicability gate rejects the fixture, which is
    exactly what a negative test wants to assert.
    """
    ctx = context_from(root, files)
    rule = rule_cls()
    if not rule.applicable(ctx):
        return []
    return rule.detect(ctx)


@pytest.fixture
def sample_app() -> Path:
    return SAMPLE_FLASK_APP


@pytest.fixture
def sample_ctx(sample_app: Path) -> ScanContext:
    return make_context(sample_app)
