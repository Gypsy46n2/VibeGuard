from __future__ import annotations

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


@pytest.fixture
def sample_app() -> Path:
    return SAMPLE_FLASK_APP


@pytest.fixture
def sample_ctx(sample_app: Path) -> ScanContext:
    return make_context(sample_app)
