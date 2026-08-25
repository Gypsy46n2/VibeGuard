"""Scoring — INTERFACES.md §8.

``category_score = round(100 * Π_open_findings (1 − w·c))`` floored at 0, where
``w`` is the severity weight and ``c`` the confidence factor. Suppressed findings are
excluded. Categories with no applicable rules are excluded from the overall score;
``overall = round(mean(applicable category scores))`` with SECURITY and SECRETS
double-weighted. This is an explicit heuristic, not science.
"""

from __future__ import annotations

from collections.abc import Iterable

from vibeguard.core.models import Category, CategoryScore, Confidence, Finding, Severity

__all__ = [
    "SEVERITY_WEIGHTS",
    "CONFIDENCE_FACTORS",
    "DOUBLE_WEIGHTED",
    "category_scores",
    "overall_score",
    "score_findings",
]

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 0.40,
    Severity.HIGH: 0.25,
    Severity.MEDIUM: 0.10,
    Severity.LOW: 0.04,
    Severity.INFO: 0.01,
}

CONFIDENCE_FACTORS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}

#: Categories that count twice in the overall score.
DOUBLE_WEIGHTED: frozenset[Category] = frozenset({Category.SECURITY, Category.SECRETS})


def _score_for(findings: Iterable[Finding]) -> int:
    product = 1.0
    for finding in findings:
        if finding.suppressed:
            continue
        weight = SEVERITY_WEIGHTS[finding.severity]
        factor = CONFIDENCE_FACTORS[finding.confidence]
        product *= 1.0 - weight * factor
    return max(0, round(100 * product))


def category_scores(
    findings: Iterable[Finding], applicable_categories: Iterable[Category]
) -> list[CategoryScore]:
    """Score every category, marking those without applicable rules inapplicable."""
    applicable = set(applicable_categories)
    grouped: dict[Category, list[Finding]] = {category: [] for category in Category}
    for finding in findings:
        grouped[finding.category].append(finding)

    scores: list[CategoryScore] = []
    for category in Category:
        items = grouped[category]
        is_applicable = category in applicable
        open_items = [f for f in items if not f.suppressed]
        scores.append(
            CategoryScore(
                category=category,
                score=_score_for(open_items) if is_applicable else 100,
                applicable=is_applicable,
                finding_count=len(open_items),
            )
        )
    return scores


def overall_score(scores: Iterable[CategoryScore]) -> int:
    """Weighted mean of applicable category scores (SECURITY/SECRETS count double)."""
    total = 0.0
    weight_sum = 0.0
    for score in scores:
        if not score.applicable:
            continue
        weight = 2.0 if score.category in DOUBLE_WEIGHTED else 1.0
        total += score.score * weight
        weight_sum += weight
    if weight_sum == 0:
        return 100
    return round(total / weight_sum)


def score_findings(
    findings: Iterable[Finding], applicable_categories: Iterable[Category]
) -> tuple[list[CategoryScore], int]:
    """Convenience: category scores plus the overall score."""
    scores = category_scores(list(findings), applicable_categories)
    return scores, overall_score(scores)
