from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vibeguard.core.config import VibeguardConfig
from vibeguard.core.models import (
    ArchitectureGraph,
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    FixRecord,
    ScaleClass,
    ScaleProfile,
    ScanReport,
    Severity,
    TechProfile,
)
from vibeguard.discovery.context import ScanContext
from vibeguard.discovery.files import collect_files
from vibeguard.discovery.graph import build_graph
from vibeguard.discovery.paths import split_primary
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

    # Mirror Engine.build_context exactly: profiles come from primary files only.
    primary, _ = split_primary(files, config.fixture_paths)
    tech = detect_tech(root, primary, read)
    scale = detect_scale(root, primary, read, tech)
    graph = build_graph(root, primary, read, tech)
    return ScanContext(
        root=root,
        files=files,
        primary_files=primary,
        tech=tech,
        graph=graph,
        scale=scale,
        config=config,
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


# ------------------------------------------------------- report/finding factories


def make_finding(
    fingerprint: str = "a" * 64,
    *,
    rule_id: str = "VG-SEC-001",
    category: Category = Category.SECURITY,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    title: str = "something is wrong",
    file: str | None = "app.py",
    line: int | None = 3,
    snippet: str = "x = 1",
    autofix_safety: AutofixSafety = AutofixSafety.SAFE_AUTOFIX,
    fix: FixRecord | None = None,
    references: list[str] | None = None,
) -> Finding:
    """A fully-populated Finding, for tests that care about reports rather than rules."""
    return Finding(
        id=f"{rule_id}:{fingerprint[:12]}",
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description="d",
        why_it_matters="w",
        evidence=[Evidence(file=file or ".", line=line, snippet=snippet)],
        file=file,
        line=line,
        autofix_safety=autofix_safety,
        fingerprint=fingerprint,
        references=references or [],
        recommended_followup="do the thing",
        fix=fix,
    )


def make_report(*findings: Finding, mode: str = "audit", **overrides) -> ScanReport:
    """A minimally valid ScanReport carrying ``findings``."""
    data = {
        "repo": "/repo",
        "scan_date": datetime.now(UTC),
        "vibeguard_version": "0.1.0",
        "mode": mode,
        "tech": TechProfile(),
        "graph": ArchitectureGraph(),
        "scale": ScaleProfile(
            scale=ScaleClass.SMALL,
            loc=100,
            service_count=1,
            has_sensitive_data=False,
            rationale="r",
        ),
        "findings": list(findings),
        "scores_before": [],
        "overall_before": 100,
    }
    data.update(overrides)
    return ScanReport(**data)


@pytest.fixture
def sample_app() -> Path:
    return SAMPLE_FLASK_APP


@pytest.fixture
def sample_ctx(sample_app: Path) -> ScanContext:
    return make_context(sample_app)
