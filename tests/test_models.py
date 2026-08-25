from __future__ import annotations

from datetime import UTC, datetime

from vibeguard.core.models import (
    ArchEdge,
    ArchitectureGraph,
    ArchNode,
    AutofixSafety,
    Category,
    CategoryScore,
    Confidence,
    Evidence,
    FileEdit,
    Finding,
    FixRecord,
    FixStatus,
    Patch,
    RegressionDiff,
    ScaleClass,
    ScaleProfile,
    ScanReport,
    Severity,
    SuppressionEntry,
    SuppressionReason,
    TechProfile,
    ValidationStep,
)


def _finding(**overrides) -> Finding:
    data = dict(
        id="VG-SEC-001:abc123abc123",
        rule_id="VG-SEC-001",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="t",
        description="d",
        why_it_matters="w",
        evidence=[Evidence(file="app.py", line=3, snippet="x = 1")],
        file="app.py",
        line=3,
        autofix_safety=AutofixSafety.REVIEW_RECOMMENDED,
        fingerprint="f" * 64,
    )
    data.update(overrides)
    return Finding(**data)


def test_enum_values_match_contract():
    assert Severity.CRITICAL.value == "critical"
    assert AutofixSafety.MANUAL_CHANGE_REQUIRED.value == "manual_change_required"
    assert FixStatus.PARTIALLY_FIXED.value == "partially_fixed"
    assert Category.DISASTER_RECOVERY.value == "disaster_recovery"
    assert SuppressionReason.ACCEPTED_RISK.value == "accepted_risk"


def test_scale_class_is_ordered():
    assert ScaleClass.TOY.order < ScaleClass.SMALL.order < ScaleClass.MEDIUM.order
    assert ScaleClass.LARGE.order == 3
    assert ScaleClass.MEDIUM >= ScaleClass.SMALL
    assert ScaleClass.TOY < ScaleClass.LARGE


def test_severity_is_ordered():
    assert Severity.CRITICAL.order > Severity.HIGH.order > Severity.INFO.order


def test_finding_roundtrip():
    finding = _finding()
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding


def test_scan_report_roundtrip():
    report = ScanReport(
        repo="/tmp/x",
        scan_date=datetime.now(UTC),
        vibeguard_version="0.1.0",
        mode="audit",
        tech=TechProfile(languages={"python": 2}),
        scale=ScaleProfile(scale=ScaleClass.SMALL, loc=120, service_count=1),
        graph=ArchitectureGraph(
            nodes=[ArchNode(id="app", kind="service", label="app")],
            edges=[ArchEdge(src="app", dst="db:sqlite", kind="reads_writes")],
        ),
        findings=[
            _finding(
                fix=FixRecord(
                    status=FixStatus.UNVERIFIED,
                    validation=[ValidationStep(name="syntax", passed=True)],
                ),
                suppression=SuppressionEntry(
                    fingerprint="f" * 64,
                    rule_id="VG-SEC-001",
                    reason=SuppressionReason.TEMPORARY,
                ),
            )
        ],
        scores_before=[
            CategoryScore(
                category=Category.SECURITY, score=75, applicable=True, finding_count=1
            )
        ],
        overall_before=75,
        counts={"high": 1, "total": 1},
        regression=RegressionDiff(new=["VG-SEC-001:abc"], unchanged=2),
    )
    restored = ScanReport.model_validate_json(report.model_dump_json())
    assert restored.schema_version == "1"
    assert restored == report


def test_patch_and_file_edit_roundtrip():
    patch = Patch(
        finding_id="VG-SEC-001:abc123abc123",
        file_edits=[FileEdit(path="app.py", old_content_sha256="a" * 64, new_content="x")],
        description="desc",
        commit_message="fix(security): quote input [VG-SEC-001]",
    )
    assert Patch.model_validate_json(patch.model_dump_json()) == patch
    assert patch.commit_message.endswith("[VG-SEC-001]")


def test_tech_profile_all_technologies_is_lowercased_union():
    tech = TechProfile(
        languages={"Python": 3}, backend=["Flask"], databases=["SQLite"], auth=["JWT"]
    )
    assert {"python", "flask", "sqlite", "jwt"} <= tech.all_technologies()


def test_scan_context_reexported_from_core_models():
    from vibeguard.core import models
    from vibeguard.discovery.context import ScanContext

    assert models.ScanContext is ScanContext
