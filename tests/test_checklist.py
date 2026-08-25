"""Master audit checklist derivation — INTERFACES.md §11 semantics."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import context_from
from vibeguard.core.models import (
    AutofixSafety,
    Category,
    ChecklistStatus,
    Confidence,
    Evidence,
    Finding,
    FixRecord,
    FixStatus,
    Severity,
    ValidationStep,
)
from vibeguard.engine.checklist import (
    NO_DETECTOR_NOTE,
    DetectorInfo,
    MissingTopicsError,
    derive_checklist,
    section_rollup,
)
from vibeguard.engine.orchestrator import Engine
from vibeguard.rules.topics import all_topics, topic_ids

TOPIC = "security.sql-injection"
OTHER = "security.xss"


def make_finding(
    rule_id: str = "VG-SEC-001",
    *,
    autofix: AutofixSafety = AutofixSafety.REVIEW_RECOMMENDED,
    fix: FixRecord | None = None,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        id=f"{rule_id}:abc123",
        rule_id=rule_id,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="t",
        description="d",
        why_it_matters="w",
        evidence=[Evidence(file="app.py", line=1, snippet="x")],
        file="app.py",
        line=1,
        autofix_safety=autofix,
        fingerprint="f" * 64,
        fix=fix,
        suppressed=suppressed,
    )


def item_for(checklist, topic_id):
    return next(item for item in checklist if item.topic_id == topic_id)


# ------------------------------------------------------------------ completeness


def test_checklist_covers_every_registry_topic():
    checklist = derive_checklist([], [])
    assert {item.topic_id for item in checklist} == set(topic_ids())
    assert len(checklist) == len(all_topics())


def test_checklist_preserves_registry_order_and_metadata():
    checklist = derive_checklist([], [])
    assert [item.topic_id for item in checklist] == [topic.id for topic in all_topics()]
    first = checklist[0]
    assert first.section and first.name and isinstance(first.category, Category)


def test_missing_topics_error_names_the_gap():
    error = MissingTopicsError({"security.xss", "api.timeouts"})
    assert error.missing == ["api.timeouts", "security.xss"]
    assert "security.xss" in str(error)


# -------------------------------------------------------------- status semantics


def test_topic_without_any_detector_is_review_required_not_pass():
    checklist = derive_checklist([], [])
    item = item_for(checklist, TOPIC)
    assert item.status is ChecklistStatus.REVIEW_REQUIRED
    assert item.note == NO_DETECTOR_NOTE
    assert item.detectors == []


def test_applicable_detector_without_findings_passes():
    detector = DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True)
    item = item_for(derive_checklist([detector], []), TOPIC)
    assert item.status is ChecklistStatus.PASS
    assert item.detectors == ["VG-SEC-001"]


def test_inapplicable_detector_makes_the_topic_not_applicable():
    detector = DetectorInfo(
        key="VG-CTR-009",
        topics=frozenset({"containers.liveness-probes"}),
        applicable=False,
        reason="requires k8s (not detected)",
    )
    item = item_for(derive_checklist([detector], []), "containers.liveness-probes")
    assert item.status is ChecklistStatus.NOT_APPLICABLE
    assert "requires k8s" in item.note


def test_open_finding_fails_the_topic():
    detector = DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True)
    item = item_for(derive_checklist([detector], [make_finding()]), TOPIC)
    assert item.status is ChecklistStatus.FAIL
    assert item.finding_ids == ["VG-SEC-001:abc123"]


def test_advisory_findings_are_review_required_not_fail():
    detector = DetectorInfo(key="VG-OBS-003", topics=frozenset({TOPIC}), applicable=True)
    finding = make_finding("VG-OBS-003", autofix=AutofixSafety.INFORMATIONAL)
    item = item_for(derive_checklist([detector], [finding]), TOPIC)
    assert item.status is ChecklistStatus.REVIEW_REQUIRED
    assert "judgement" in item.note


def test_fixed_findings_report_fixed_with_validation_evidence():
    detector = DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True)
    fix = FixRecord(
        status=FixStatus.FIXED,
        validation=[
            ValidationStep(name="syntax", passed=True),
            ValidationStep(name="tests:targeted", passed=True),
            ValidationStep(name="build", passed=False, skipped=True),
        ],
    )
    item = item_for(derive_checklist([detector], [make_finding(fix=fix)]), TOPIC)
    assert item.status is ChecklistStatus.FIXED
    assert item.fixes == ["VG-SEC-001:abc123"]
    assert "syntax=pass" in item.validation
    assert "build" not in item.validation  # skipped steps are not evidence


def test_partially_fixed_topic_still_fails_but_records_the_fix():
    detector = DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True)
    fixed = make_finding(fix=FixRecord(status=FixStatus.FIXED))
    fixed.id = "VG-SEC-001:fixed"
    still_open = make_finding()
    item = item_for(derive_checklist([detector], [fixed, still_open]), TOPIC)
    assert item.status is ChecklistStatus.FAIL
    assert item.fixes == ["VG-SEC-001:fixed"]


def test_attempted_fix_is_not_treated_as_fixed():
    detector = DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True)
    finding = make_finding(fix=FixRecord(status=FixStatus.ATTEMPTED))
    assert item_for(derive_checklist([detector], [finding]), TOPIC).status is ChecklistStatus.FAIL


def test_suppressed_findings_do_not_fail_a_topic():
    detector = DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True)
    finding = make_finding(suppressed=True)
    assert item_for(derive_checklist([detector], [finding]), TOPIC).status is ChecklistStatus.PASS


def test_all_five_statuses_are_reachable_in_one_derivation():
    detectors = [
        DetectorInfo(key="VG-A", topics=frozenset({"api.timeouts"}), applicable=True),
        DetectorInfo(key="VG-B", topics=frozenset({"api.retries"}), applicable=True),
        DetectorInfo(key="VG-C", topics=frozenset({"api.caching"}), applicable=True),
        DetectorInfo(
            key="VG-D", topics=frozenset({"api.webhooks"}), applicable=False, reason="no webhooks"
        ),
    ]
    findings = [
        make_finding("VG-B"),
        make_finding("VG-C", fix=FixRecord(status=FixStatus.FIXED)),
    ]
    checklist = derive_checklist(detectors, findings)
    statuses = {item.topic_id: item.status for item in checklist}
    assert statuses["api.timeouts"] is ChecklistStatus.PASS
    assert statuses["api.retries"] is ChecklistStatus.FAIL
    assert statuses["api.caching"] is ChecklistStatus.FIXED
    assert statuses["api.webhooks"] is ChecklistStatus.NOT_APPLICABLE
    assert statuses["api.idempotency"] is ChecklistStatus.REVIEW_REQUIRED


def test_adapter_findings_attach_by_rule_id_prefix():
    detector = DetectorInfo(
        key="bandit",
        topics=frozenset({TOPIC}),
        applicable=True,
        rule_id_prefix="VG-EXT-bandit-",
    )
    finding = make_finding("VG-EXT-bandit-B608")
    item = item_for(derive_checklist([detector], [finding]), TOPIC)
    assert item.status is ChecklistStatus.FAIL
    assert item.detectors == ["bandit"]


def test_one_finding_reaching_a_topic_twice_is_counted_once():
    detectors = [
        DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC, OTHER}), applicable=True),
        DetectorInfo(key="VG-SEC-001", topics=frozenset({TOPIC}), applicable=True),
    ]
    item = item_for(derive_checklist(detectors, [make_finding()]), TOPIC)
    assert item.finding_ids == ["VG-SEC-001:abc123"]


def test_unknown_topic_on_a_detector_is_ignored():
    detector = DetectorInfo(key="VG-X", topics=frozenset({"not-a.topic"}), applicable=True)
    checklist = derive_checklist([detector], [])
    assert all("not-a.topic" != item.topic_id for item in checklist)


def test_section_rollup_counts_by_status():
    rollup = dict(section_rollup(derive_checklist([], [])))
    assert set(rollup) == {section for section, _ in section_rollup(derive_checklist([], []))}
    security = rollup["security"]
    assert sum(security.values()) == len(
        [topic for topic in all_topics() if topic.section == "security"]
    )


# --------------------------------------------------------------- engine wiring


@pytest.fixture
def flask_repo(tmp_path: Path) -> Path:
    context_from(
        tmp_path,
        {
            "requirements.txt": "flask==3.0.0\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "Dockerfile": "FROM python:3.11-slim\nCMD [\"python\", \"app.py\"]\n",
        },
    )
    return tmp_path


def test_engine_report_carries_the_full_checklist(flask_repo: Path):
    report = Engine().audit(flask_repo)
    assert len(report.checklist) == len(all_topics())
    assert {item.topic_id for item in report.checklist} == set(topic_ids())


def test_kubernetes_topics_are_not_applicable_without_kubernetes(flask_repo: Path):
    report = Engine().audit(flask_repo)
    statuses = {item.topic_id: item for item in report.checklist}
    for topic_id in (
        "containers.liveness-probes",
        "containers.readiness-probes",
        "containers.startup-probes",
    ):
        item = statuses[topic_id]
        assert item.status in {
            ChecklistStatus.NOT_APPLICABLE,
            ChecklistStatus.REVIEW_REQUIRED,
        }, f"{topic_id} -> {item.status}"
        if item.status is ChecklistStatus.NOT_APPLICABLE:
            assert item.note


def test_large_scale_topics_are_gated_out_for_a_small_app(flask_repo: Path):
    report = Engine().audit(flask_repo)
    statuses = {item.topic_id: item.status for item in report.checklist}
    for topic_id in (
        "disaster-recovery.chaos-engineering",
        "distributed.leader-election",
        "database.sharding-readiness",
        "scaling.multi-region-deployment",
    ):
        assert statuses[topic_id] in {
            ChecklistStatus.NOT_APPLICABLE,
            ChecklistStatus.REVIEW_REQUIRED,
        }, f"{topic_id} -> {statuses[topic_id]}"


def test_checklist_never_silently_passes_an_undetected_topic(flask_repo: Path):
    report = Engine().audit(flask_repo)
    for item in report.checklist:
        if item.status is ChecklistStatus.PASS:
            assert item.detectors, item.topic_id


def test_report_json_roundtrips_the_checklist(flask_repo: Path):
    report = Engine().audit(flask_repo)
    payload = report.model_dump(mode="json")
    assert len(payload["checklist"]) == len(all_topics())
    assert set(payload["checklist"][0]) >= {
        "topic_id",
        "section",
        "name",
        "category",
        "status",
        "detectors",
        "technologies",
        "finding_ids",
        "fixes",
        "validation",
        "note",
    }
