"""Master audit checklist derivation — INTERFACES.md §11.

Every topic in ``rules/topics.yaml`` must appear in every report with an explicit
status. Statuses are derived from what actually ran:

``NOT_APPLICABLE``
    Detectors exist for the topic but none of them applied to this stack/scale.
``PASS``
    ≥1 mapped detector ran and produced no open findings.
``FAIL``
    Open, unfixed findings are attributed to the topic.
``FIXED``
    Every attributed finding carries ``FixRecord.status == FIXED``.
``REVIEW_REQUIRED``
    The open findings are advisory (they need a human judgement call), **or** the
    topic has no automated detector at all. The honest fallback: never converted
    to ``PASS``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from vibeguard.core.models import (
    AutofixSafety,
    ChecklistItem,
    ChecklistStatus,
    Finding,
    FixStatus,
)
from vibeguard.rules.topics import Topic, all_topics

__all__ = [
    "DetectorInfo",
    "MissingTopicsError",
    "NO_DETECTOR_NOTE",
    "derive_checklist",
    "section_rollup",
]

NO_DETECTOR_NOTE = "no automated detector — manual review required"

#: Findings whose remediation is a judgement call rather than a defect to fix.
_ADVISORY = frozenset({AutofixSafety.INFORMATIONAL, AutofixSafety.NOT_APPLICABLE})


class MissingTopicsError(RuntimeError):
    """Raised when a produced checklist does not account for every topic."""

    def __init__(self, missing: Iterable[str]) -> None:
        self.missing = sorted(missing)
        super().__init__(
            "checklist is incomplete — topics.yaml topics missing from the report: "
            + ", ".join(self.missing)
        )


@dataclass(frozen=True)
class DetectorInfo:
    """A rule or adapter as far as the checklist is concerned."""

    #: Rule id ("VG-SEC-001") or adapter name ("bandit").
    key: str
    topics: frozenset[str]
    technologies: tuple[str, ...] = ()
    applicable: bool = False
    #: Why an inapplicable detector was gated out (shown in NOT_APPLICABLE notes).
    reason: str = ""
    #: Prefix that adapter-produced rule_ids carry, for finding attribution.
    rule_id_prefix: str = ""


@dataclass
class _Bucket:
    detectors: list[DetectorInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _is_open(finding: Finding) -> bool:
    if finding.suppressed:
        return False
    return finding.fix is None or finding.fix.status is not FixStatus.FIXED


def _is_fixed(finding: Finding) -> bool:
    return finding.fix is not None and finding.fix.status is FixStatus.FIXED


def _validation_summary(findings: Sequence[Finding]) -> str:
    """One line describing the validation evidence behind the fixes."""
    steps: list[str] = []
    for finding in findings:
        if finding.fix is None:
            continue
        for step in finding.fix.validation:
            if step.skipped:
                continue
            steps.append(f"{step.name}={'pass' if step.passed else 'fail'}")
    if not steps:
        return "fixes recorded without validation evidence"
    ordered = list(dict.fromkeys(steps))
    return "validated: " + ", ".join(ordered)


def _attribute(
    topics: Sequence[Topic],
    detectors: Sequence[DetectorInfo],
    findings: Sequence[Finding],
) -> dict[str, _Bucket]:
    buckets: dict[str, _Bucket] = {topic.id: _Bucket() for topic in topics}
    known = set(buckets)

    by_rule_id: dict[str, list[DetectorInfo]] = {}
    prefixed: list[DetectorInfo] = []
    for detector in detectors:
        for topic_id in sorted(detector.topics):
            if topic_id in known:
                buckets[topic_id].detectors.append(detector)
        if detector.rule_id_prefix:
            prefixed.append(detector)
        else:
            by_rule_id.setdefault(detector.key, []).append(detector)

    for finding in findings:
        owners = list(by_rule_id.get(finding.rule_id, ()))
        if not owners:
            owners = [d for d in prefixed if finding.rule_id.startswith(d.rule_id_prefix)]
        for owner in owners:
            for topic_id in sorted(owner.topics):
                if topic_id in known:
                    buckets[topic_id].findings.append(finding)
    return buckets


def derive_checklist(
    detectors: Sequence[DetectorInfo],
    findings: Sequence[Finding],
) -> list[ChecklistItem]:
    """Produce one :class:`ChecklistItem` per topic in ``topics.yaml``.

    Raises :class:`MissingTopicsError` if the derivation would drop a topic — the
    self-check INTERFACES.md §11 requires.
    """
    topics = all_topics()
    buckets = _attribute(topics, detectors, findings)

    items: list[ChecklistItem] = []
    for topic in topics:
        bucket = buckets[topic.id]
        mapped = bucket.detectors
        applicable_detectors = [d for d in mapped if d.applicable]
        # Deduplicate findings while preserving order (a topic can be claimed by
        # several detectors, and one finding can reach it through more than one).
        seen: set[str] = set()
        attributed: list[Finding] = []
        for finding in bucket.findings:
            if finding.id in seen:
                continue
            seen.add(finding.id)
            attributed.append(finding)

        open_findings = [f for f in attributed if _is_open(f)]
        fixed_findings = [f for f in attributed if _is_fixed(f)]

        note = ""
        validation = ""
        if not mapped:
            status = ChecklistStatus.REVIEW_REQUIRED
            note = NO_DETECTOR_NOTE
        elif not applicable_detectors and not attributed:
            status = ChecklistStatus.NOT_APPLICABLE
            reasons = sorted({d.reason for d in mapped if d.reason})
            detail = "; ".join(reasons) if reasons else "detectors gated out for this project"
            note = f"{len(mapped)} detector(s) mapped, none applicable — {detail}"
        elif open_findings:
            advisory = all(f.autofix_safety in _ADVISORY for f in open_findings)
            status = ChecklistStatus.REVIEW_REQUIRED if advisory else ChecklistStatus.FAIL
            if advisory:
                note = "advisory findings — human judgement required"
            if fixed_findings:
                validation = _validation_summary(fixed_findings)
        elif fixed_findings:
            status = ChecklistStatus.FIXED
            validation = _validation_summary(fixed_findings)
        else:
            status = ChecklistStatus.PASS
            note = f"checked by {len(applicable_detectors)} detector(s), no findings"

        technologies = sorted({t for d in mapped for t in d.technologies})
        items.append(
            ChecklistItem(
                topic_id=topic.id,
                section=topic.section,
                name=topic.name,
                category=topic.category,
                status=status,
                detectors=sorted({d.key for d in mapped}),
                technologies=technologies,
                finding_ids=[f.id for f in attributed],
                fixes=[f.id for f in fixed_findings],
                validation=validation,
                note=note,
            )
        )

    produced = {item.topic_id for item in items}
    missing = {topic.id for topic in topics} - produced
    if missing:  # pragma: no cover - guarded by construction, kept as the §11 self-check
        raise MissingTopicsError(missing)
    return items


def section_rollup(
    checklist: Sequence[ChecklistItem],
) -> list[tuple[str, dict[ChecklistStatus, int]]]:
    """Per-section counts by status, in checklist order — used by the CLI summary."""
    order: list[str] = []
    counts: dict[str, dict[ChecklistStatus, int]] = {}
    for item in checklist:
        if item.section not in counts:
            order.append(item.section)
            counts[item.section] = dict.fromkeys(ChecklistStatus, 0)
        counts[item.section][item.status] += 1
    return [(section, counts[section]) for section in order]
