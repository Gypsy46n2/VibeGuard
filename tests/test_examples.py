"""The shipped example apps, audited end to end.

This is the acceptance test for the whole pipeline: no fixtures, no mocks, no
hand-built ScanContext — the real engine over the real ``examples/vulnerable-app``.
Thresholds are deliberately tolerant floors rather than exact counts: rules get
added, and an example is not a golden file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.core.config import VibeguardConfig
from vibeguard.core.models import Category, ChecklistStatus, Severity
from vibeguard.engine.orchestrator import EXIT_FINDINGS, Engine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
VULNERABLE = EXAMPLES / "vulnerable-app"
REPAIRED = EXAMPLES / "repaired-app"


@pytest.fixture(scope="module")
def vulnerable_report():
    return Engine(VibeguardConfig()).audit(VULNERABLE)


def test_the_example_exists_and_is_not_empty():
    assert (VULNERABLE / "app.py").is_file()
    assert (VULNERABLE / "README.md").is_file()


def test_the_vulnerable_app_yields_a_broad_spread_of_findings(vulnerable_report):
    findings = [f for f in vulnerable_report.findings if not f.suppressed]
    categories = {f.category for f in findings}
    assert len(findings) >= 20, f"only {len(findings)} findings"
    assert len(categories) >= 6, sorted(c.value for c in categories)


def test_the_headline_defects_are_all_detected(vulnerable_report):
    """The specific things the example's README claims are wrong with it."""
    rules = {f.rule_id for f in vulnerable_report.findings}
    for rule_id in (
        "VG-SEC-001",  # SQL injection via f-string
        "VG-SEC-003",  # |safe in the template
        "VG-SEC-010",  # MD5 password hashing
        "VG-SEC-011",  # random-module session tokens
        "VG-SEC-012",  # debug=True
        "VG-SEC-015",  # CORS: *
        "VG-SEC-016",  # cookie without flags
        "VG-SEC-018",  # verify=False
        "VG-SCR-006",  # committed .env
        "VG-SCR-008",  # hardcoded signing secret
        "VG-API-001",  # no HTTP timeout
        "VG-API-003",  # no rate limiting
        "VG-DB-001",  # N+1
        "VG-CTR-001",  # container runs as root
        "VG-CTR-002",  # no HEALTHCHECK
        "VG-CTR-003",  # unpinned base image
        "VG-DEPS-002",  # unpinned dependencies
        "VG-DEP-002",  # deploy workflow with no tests
        "VG-DR-003",  # SQLite on the container filesystem
        "VG-OBS-001",  # print() instead of logging
        "VG-MAINT-001",  # no test suite
    ):
        assert rule_id in rules, f"{rule_id} no longer fires on the example app"


def test_the_example_is_severe_enough_to_fail_a_ci_gate():
    engine = Engine(VibeguardConfig())
    report, exit_code = engine.ci(VULNERABLE)
    assert exit_code == EXIT_FINDINGS
    assert any(f.severity is Severity.CRITICAL for f in engine.gating_findings(report))


def test_security_scores_reflect_the_damage(vulnerable_report):
    security = next(
        score for score in vulnerable_report.scores_before
        if score.category is Category.SECURITY
    )
    assert security.applicable
    assert security.score <= 20, "an app this broken must not score well on security"
    assert vulnerable_report.overall_before <= 80


def test_the_checklist_still_accounts_for_every_topic(vulnerable_report):
    assert len(vulnerable_report.checklist) >= 279
    assert {item.status for item in vulnerable_report.checklist} >= {
        ChecklistStatus.FAIL,
        ChecklistStatus.PASS,
    }


def test_proportionality_holds_even_here(vulnerable_report):
    """A small app is not told to adopt Kubernetes, meshes, or multi-region."""
    rules = {f.rule_id for f in vulnerable_report.findings}
    for rule_id in ("VG-CTR-009", "VG-CTR-010", "VG-CTR-011", "VG-DB-010", "VG-DR-006"):
        assert rule_id not in rules, f"{rule_id} is not proportional to this project"


# --------------------------------------------------------------------- repaired


@pytest.mark.skipif(not (REPAIRED / "app.py").is_file(), reason="repaired app not generated")
def test_the_repaired_app_is_measurably_better():
    before = Engine(VibeguardConfig()).audit(VULNERABLE)
    after = Engine(VibeguardConfig()).audit(REPAIRED)
    assert after.overall_before > before.overall_before
    assert len(after.findings) < len(before.findings)
    assert (REPAIRED / "vibeguard-report.md").is_file(), "ship the report we generated"
