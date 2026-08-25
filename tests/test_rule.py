from __future__ import annotations

import shutil
from pathlib import Path
from typing import ClassVar

from conftest import make_context
from vibeguard.core.fingerprint import fingerprint
from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule


class _Simple(Rule):
    id: ClassVar[str] = "VG-REL-001"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "no timeout"
    description: ClassVar[str] = "default description"
    why_it_matters: ClassVar[str] = "hangs forever"
    references: ClassVar[list[str]] = ["https://example.org/timeouts"]
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.SAFE_AUTOFIX

    def detect(self, ctx) -> list[Finding]:
        return [self.make_finding(file="app.py", line=7, snippet="requests.get(url)")]


def test_make_finding_populates_contract_fields(sample_ctx):
    finding = _Simple().detect(sample_ctx)[0]
    assert finding.rule_id == "VG-REL-001"
    assert finding.fingerprint == fingerprint("VG-REL-001", "app.py", "requests.get(url)")
    assert finding.id == f"VG-REL-001:{finding.fingerprint[:12]}"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.description == "default description"
    assert finding.references == ["https://example.org/timeouts"]
    assert finding.autofix_safety is AutofixSafety.SAFE_AUTOFIX
    assert finding.evidence[0].snippet == "requests.get(url)"
    assert finding.suppressed is False
    assert finding.fix is None


def test_make_finding_redacts_flagged_evidence(sample_ctx):
    rule = _Simple()
    finding = rule.make_finding(
        file="config.py",
        evidence=[
            Evidence(file="config.py", line=1, snippet="api_key = sk-live-abcdefgh12345678"),
        ],
        redact_evidence=True,
    )
    assert "[REDACTED]" in finding.evidence[0].snippet


def test_make_finding_redacts_per_evidence_flag(sample_ctx):
    finding = _Simple().make_finding(
        file="config.py",
        evidence=[
            Evidence(file="config.py", snippet="token = AKIAIOSFODNN7EXAMPLE", redact=True),
            Evidence(file="config.py", snippet="plain code"),
        ],
    )
    assert "[REDACTED]" in finding.evidence[0].snippet
    assert finding.evidence[1].snippet == "plain code"


def test_default_fix_returns_none(sample_ctx):
    rule = _Simple()
    assert rule.fix(sample_ctx, rule.detect(sample_ctx)[0]) is None


def test_applicable_default_gate(sample_ctx, sample_app: Path, tmp_path: Path):
    class Flaskish(_Simple):
        id: ClassVar[str] = "VG-REL-002"
        technologies: ClassVar[set[str]] = {"flask"}

    class Djangoish(_Simple):
        id: ClassVar[str] = "VG-REL-003"
        technologies: ClassVar[set[str]] = {"django"}

    class BigOnly(_Simple):
        id: ClassVar[str] = "VG-REL-004"
        min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM

    assert _Simple().applicable(sample_ctx) is True  # no technologies = any stack
    assert Flaskish().applicable(sample_ctx) is True
    assert Djangoish().applicable(sample_ctx) is False
    assert BigOnly().applicable(sample_ctx) is False

    big = tmp_path / "big"
    shutil.copytree(sample_app, big)
    (big / "bulk.py").write_text("x = 1\n" * 12_000, encoding="utf-8")
    assert BigOnly().applicable(make_context(big)) is True
