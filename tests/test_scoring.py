from __future__ import annotations

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    CategoryScore,
    Confidence,
    Finding,
    Severity,
)
from vibeguard.reporting.scoring import (
    CONFIDENCE_FACTORS,
    SEVERITY_WEIGHTS,
    category_scores,
    overall_score,
    score_findings,
)


def _finding(
    category: Category,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        id="x",
        rule_id="VG-X-001",
        category=category,
        severity=severity,
        confidence=confidence,
        title="t",
        description="d",
        why_it_matters="w",
        autofix_safety=AutofixSafety.INFORMATIONAL,
        fingerprint="f" * 64,
        suppressed=suppressed,
    )


def test_weights_match_contract():
    assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 0.40
    assert SEVERITY_WEIGHTS[Severity.HIGH] == 0.25
    assert SEVERITY_WEIGHTS[Severity.MEDIUM] == 0.10
    assert SEVERITY_WEIGHTS[Severity.LOW] == 0.04
    assert SEVERITY_WEIGHTS[Severity.INFO] == 0.01
    assert CONFIDENCE_FACTORS == {
        Confidence.HIGH: 1.0,
        Confidence.MEDIUM: 0.7,
        Confidence.LOW: 0.4,
    }


def test_clean_category_scores_100():
    scores = category_scores([], [Category.SECURITY])
    security = next(s for s in scores if s.category is Category.SECURITY)
    assert security.score == 100
    assert security.applicable is True
    assert security.finding_count == 0


def test_single_finding_applies_weight_times_confidence():
    findings = [_finding(Category.SECURITY, Severity.HIGH, Confidence.MEDIUM)]
    scores = category_scores(findings, [Category.SECURITY])
    security = next(s for s in scores if s.category is Category.SECURITY)
    assert security.score == round(100 * (1 - 0.25 * 0.7))  # 82
    assert security.finding_count == 1


def test_findings_multiply():
    findings = [
        _finding(Category.SECURITY, Severity.CRITICAL),
        _finding(Category.SECURITY, Severity.MEDIUM),
    ]
    expected = round(100 * (1 - 0.40) * (1 - 0.10))  # 54
    scores = category_scores(findings, [Category.SECURITY])
    assert next(s for s in scores if s.category is Category.SECURITY).score == expected


def test_suppressed_findings_are_excluded():
    findings = [_finding(Category.SECURITY, Severity.CRITICAL, suppressed=True)]
    scores = category_scores(findings, [Category.SECURITY])
    security = next(s for s in scores if s.category is Category.SECURITY)
    assert security.score == 100
    assert security.finding_count == 0


def test_inapplicable_categories_are_marked_and_excluded_from_overall():
    scores = category_scores([], [Category.TESTING])
    assert all(s.applicable is (s.category is Category.TESTING) for s in scores)
    assert overall_score(scores) == 100


def test_overall_double_weights_security_and_secrets():
    scores = [
        CategoryScore(category=Category.SECURITY, score=50, applicable=True, finding_count=1),
        CategoryScore(category=Category.SECRETS, score=50, applicable=True, finding_count=1),
        CategoryScore(category=Category.TESTING, score=100, applicable=True, finding_count=0),
    ]
    # (50*2 + 50*2 + 100*1) / 5 = 60
    assert overall_score(scores) == 60


def test_overall_with_no_applicable_categories_is_100():
    assert overall_score([]) == 100


def test_score_findings_helper():
    findings = [_finding(Category.TESTING, Severity.MEDIUM)]
    scores, overall = score_findings(findings, [Category.TESTING])
    testing = next(s for s in scores if s.category is Category.TESTING)
    assert testing.score == 90
    assert overall == 90


def test_score_floors_at_zero():
    findings = [_finding(Category.SECURITY, Severity.CRITICAL) for _ in range(50)]
    scores = category_scores(findings, [Category.SECURITY])
    assert next(s for s in scores if s.category is Category.SECURITY).score == 0
