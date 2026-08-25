from __future__ import annotations

import shutil
from pathlib import Path
from typing import ClassVar

import pytest

from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    ScanReport,
    Severity,
)
from vibeguard.core.registry import RuleRegistry
from vibeguard.core.rule import Rule
from vibeguard.engine.orchestrator import EXIT_FINDINGS, EXIT_OK, Engine


class _Boom(Rule):
    id: ClassVar[str] = "VG-TEST-500"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "boom"
    description: ClassVar[str] = "boom"
    why_it_matters: ClassVar[str] = "boom"

    def detect(self, ctx) -> list[Finding]:
        raise RuntimeError("rule exploded")


class _Duplicate(Rule):
    id: ClassVar[str] = "VG-TEST-501"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "dup"
    description: ClassVar[str] = "dup"
    why_it_matters: ClassVar[str] = "dup"

    def detect(self, ctx) -> list[Finding]:
        return [
            self.make_finding(file="app.py", line=1, snippet="x = 1"),
            self.make_finding(file="app.py", line=99, snippet="x  =  1"),  # same fingerprint
        ]


class _ScaleGated(Rule):
    id: ClassVar[str] = "VG-TEST-502"
    category: ClassVar[Category] = Category.SCALABILITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "needs scale"
    description: ClassVar[str] = "needs scale"
    why_it_matters: ClassVar[str] = "needs scale"
    min_scale: ClassVar[ScaleClass] = ScaleClass.LARGE

    def detect(self, ctx) -> list[Finding]:  # pragma: no cover - must never run
        raise AssertionError("scale-gated rule ran")


class _TechGated(Rule):
    id: ClassVar[str] = "VG-TEST-503"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "django only"
    description: ClassVar[str] = "django only"
    why_it_matters: ClassVar[str] = "django only"
    technologies: ClassVar[set[str]] = {"django"}

    def detect(self, ctx) -> list[Finding]:  # pragma: no cover - must never run
        raise AssertionError("tech-gated rule ran")


class _Secretish(Rule):
    id: ClassVar[str] = "VG-SCR-900"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "hardcoded key"
    description: ClassVar[str] = "hardcoded key"
    why_it_matters: ClassVar[str] = "hardcoded key"

    def detect(self, ctx) -> list[Finding]:
        return [
            self.make_finding(
                file="app.py",
                line=2,
                evidence=[
                    Evidence(file="app.py", line=2, snippet="AWS_KEY = AKIAIOSFODNN7EXAMPLE")
                ],
            )
        ]


def test_audit_end_to_end_on_fixture(sample_app: Path):
    report = Engine(VibeguardConfig()).audit(sample_app)
    assert isinstance(report, ScanReport)
    assert report.schema_version == "1"
    assert report.mode == "audit"
    assert report.repo == str(sample_app.resolve())
    assert "flask" in report.tech.backend
    assert report.scale.scale is ScaleClass.SMALL

    maint = [f for f in report.findings if f.rule_id == "VG-MAINT-001"]
    assert len(maint) == 1
    finding = maint[0]
    assert finding.category is Category.TESTING
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH
    assert finding.id == f"VG-MAINT-001:{finding.fingerprint[:12]}"
    assert len(finding.fingerprint) == 64
    assert finding.recommended_followup

    testing = next(s for s in report.scores_before if s.category is Category.TESTING)
    assert testing.applicable is True
    assert testing.score == 90
    assert report.counts["medium"] == 1
    assert report.counts["total"] == len(report.findings)

    # report survives serialisation
    assert ScanReport.model_validate_json(report.model_dump_json()) == report


def test_no_tests_rule_is_silent_when_tests_exist(sample_app: Path, tmp_path: Path):
    target = tmp_path / "app"
    shutil.copytree(sample_app, target)
    (target / "tests").mkdir()
    (target / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n", "utf-8")

    report = Engine(VibeguardConfig()).audit(target)
    assert [f for f in report.findings if f.rule_id == "VG-MAINT-001"] == []


def test_events_are_emitted_in_order(sample_app: Path):
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe("*", lambda name, _p: seen.append(name))
    Engine(VibeguardConfig(), events=bus).audit(sample_app)
    assert seen[0] == "scan.started"
    assert seen[-1] == "scan.completed"
    assert "scan.issue_found" in seen
    assert any(name == "scan.stage" for name in seen)


def test_issue_found_payload_is_json_serialisable(sample_app: Path):
    import json

    bus = EventBus()
    payloads: list[dict] = []
    bus.subscribe("scan.issue_found", lambda _n, payload: payloads.append(payload))
    Engine(VibeguardConfig(), events=bus).audit(sample_app)
    assert payloads
    json.dumps(payloads[0])  # must not raise


def _engine_with(rules: list[type[Rule]], config: VibeguardConfig | None = None) -> Engine:
    registry = RuleRegistry()
    for cls in rules:
        registry.register("test", cls)
    return Engine(config or VibeguardConfig(), registry=registry)


def test_failing_rule_is_isolated(sample_app: Path):
    engine = _engine_with([_Boom, _Duplicate])
    report = engine.audit(sample_app)
    assert [f.rule_id for f in report.findings] == ["VG-TEST-501"]


def test_findings_are_deduped_by_fingerprint(sample_app: Path):
    report = _engine_with([_Duplicate]).audit(sample_app)
    assert len(report.findings) == 1


def test_applicability_gates_block_rules(sample_app: Path):
    report = _engine_with([_ScaleGated, _TechGated]).audit(sample_app)
    assert report.findings == []
    # blocked categories are not scored as applicable
    scalability = next(s for s in report.scores_before if s.category is Category.SCALABILITY)
    assert scalability.applicable is False


def test_secrets_evidence_is_redacted(sample_app: Path):
    report = _engine_with([_Secretish]).audit(sample_app)
    snippet = report.findings[0].evidence[0].snippet
    assert "AKIAIOSFODNN7EXAMPLE" not in snippet
    assert "[REDACTED]" in snippet


def test_ci_exit_codes(sample_app: Path):
    config = VibeguardConfig()
    report, code = Engine(config).ci(sample_app)
    assert report.mode == "ci"
    assert code == EXIT_OK  # only a MEDIUM finding, threshold is HIGH

    config_low = VibeguardConfig()
    config_low.ci.fail_on = Severity.MEDIUM
    _, code_low = Engine(config_low).ci(sample_app)
    assert code_low == EXIT_FINDINGS


def test_fix_raises_not_implemented(sample_app: Path):
    with pytest.raises(NotImplementedError, match="M3"):
        Engine(VibeguardConfig()).fix(sample_app, "safe")


def test_audit_rejects_non_directory(tmp_path: Path):
    target = tmp_path / "file.txt"
    target.write_text("hi", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        Engine(VibeguardConfig()).audit(target)


def test_pack_selection_limits_rules(sample_app: Path):
    config = VibeguardConfig(packs=["secrets"])
    report = Engine(config).audit(sample_app)
    assert report.findings == []
