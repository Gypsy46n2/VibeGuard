"""Shared report-shaping helpers used by every renderer.

The markdown and HTML renderers must not disagree about what a report *says* — only
about how it looks. Everything either of them summarises, counts, or labels is
computed here, once.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from vibeguard.core.models import (
    ChecklistItem,
    ChecklistStatus,
    Finding,
    FixStatus,
    ScanReport,
    Severity,
)
from vibeguard.engine.checklist import section_rollup
from vibeguard.validation.engine import ValidationEngine

__all__ = [
    "Field",
    "NO_RECORD",
    "SEVERITY_ORDER",
    "checklist_by_section",
    "counts_by_severity",
    "executive_summary",
    "finding_fields",
    "findings_by_severity",
    "open_findings",
    "readiness_line",
    "repair_counts",
    "repair_summary",
    "section_rollup",
    "stack_summary",
    "suppressed_findings",
]

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

#: Key used for findings the repair loop never produced a :class:`FixRecord` for —
#: audit mode, or advisory findings it deliberately skips (DECISIONS.md D28).
NO_RECORD = "no_repair_record"


@dataclass(frozen=True)
class Field:
    """One labelled field of a per-finding detail section."""

    label: str
    value: str
    #: ``"text"`` renders inline, ``"code"`` renders in a preformatted block.
    kind: str = "text"


# ------------------------------------------------------------------ selections


def open_findings(report: ScanReport) -> list[Finding]:
    """Findings that count: not suppressed. Baselined ones still count."""
    return [f for f in report.findings if not f.suppressed]


def suppressed_findings(report: ScanReport) -> list[Finding]:
    return [f for f in report.findings if f.suppressed]


def findings_by_severity(findings: Iterable[Finding]) -> list[tuple[Severity, list[Finding]]]:
    """Group findings by severity, most severe first, skipping empty severities."""
    grouped: dict[Severity, list[Finding]] = {severity: [] for severity in SEVERITY_ORDER}
    for finding in findings:
        grouped[finding.severity].append(finding)
    return [(severity, grouped[severity]) for severity in SEVERITY_ORDER if grouped[severity]]


def counts_by_severity(findings: Iterable[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def checklist_by_section(
    checklist: Sequence[ChecklistItem],
) -> list[tuple[str, list[ChecklistItem]]]:
    """Checklist items grouped by section, in registry order."""
    order: list[str] = []
    grouped: dict[str, list[ChecklistItem]] = {}
    for item in checklist:
        if item.section not in grouped:
            order.append(item.section)
            grouped[item.section] = []
        grouped[item.section].append(item)
    return [(section, grouped[section]) for section in order]


# --------------------------------------------------------------------- summary


def stack_summary(report: ScanReport) -> str:
    """One line naming the detected stack, or an honest admission that we found none."""
    tech = report.tech
    bits: list[str] = []
    if tech.languages:
        bits.append(
            ", ".join(
                f"{name} ({count} file{'s' if count != 1 else ''})"
                for name, count in sorted(tech.languages.items(), key=lambda kv: -kv[1])
            )
        )
    for label, values in (
        ("frameworks", tech.frameworks),
        ("databases", tech.databases),
        ("ORMs", tech.orms),
        ("containers", tech.containers),
        ("CI/CD", tech.ci_cd),
        ("tests", tech.test_frameworks),
    ):
        if values:
            bits.append(f"{label}: {', '.join(values)}")
    return " · ".join(bits) or "no recognised stack detected"


def repair_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Repair outcomes across the findings, one bucket per :class:`FixStatus`.

    Every status is present even at zero, so a reader can tell "no finding failed"
    apart from "the report forgot to mention failures". Findings the repair loop never
    considered land in :data:`NO_RECORD` rather than being counted as a fix outcome.
    """
    counts: dict[str, int] = {status.value: 0 for status in FixStatus}
    counts[NO_RECORD] = 0
    for finding in findings:
        record = finding.fix
        if record is None:
            counts[NO_RECORD] += 1
        else:
            counts[record.status.value] += 1
    return counts


def repair_summary(findings: Iterable[Finding]) -> str:
    """One line naming every non-zero repair outcome, or saying there were none."""
    counts = repair_counts(findings)
    parts = [
        f"{status.value.replace('_', ' ')} {counts[status.value]}"
        for status in FixStatus
        if counts[status.value]
    ]
    if counts[NO_RECORD]:
        parts.append(f"no automated repair attempted {counts[NO_RECORD]}")
    return " · ".join(parts) or "no repairs attempted"


def readiness_line(report: ScanReport) -> str:
    """Overall readiness, before and (for fix runs) after."""
    if report.overall_after is None:
        return f"{report.overall_before}/100"
    return f"{report.overall_before}/100 → {report.overall_after}/100"


def executive_summary(report: ScanReport) -> list[tuple[str, str]]:
    """The executive summary block: label/value rows, in brief order."""
    live = open_findings(report)
    severities = counts_by_severity(live)
    suppressed = suppressed_findings(report)
    baselined = [f for f in live if f.baselined]
    checklist_counts = dict.fromkeys(ChecklistStatus, 0)
    for item in report.checklist:
        checklist_counts[item.status] += 1

    rows: list[tuple[str, str]] = [
        ("Repository", report.repo),
        ("Stack", stack_summary(report)),
        (
            "Scale",
            f"{report.scale.scale.value} — {report.scale.loc} LOC, "
            f"{report.scale.service_count} service(s), sensitive data: "
            f"{'yes' if report.scale.has_sensitive_data else 'no'}",
        ),
        ("Scan date", report.scan_date.isoformat(timespec="seconds")),
        ("Mode", report.mode),
        ("VibeGuard version", report.vibeguard_version),
        ("Production readiness", readiness_line(report)),
        (
            "Issues by severity",
            ", ".join(f"{severity.value} {severities[severity]}" for severity in SEVERITY_ORDER)
            + f" — {len(live)} open in total",
        ),
        ("Repair outcomes", repair_summary(live)),
        (
            "Checklist",
            f"{len(report.checklist)} topics — "
            + " · ".join(
                f"{status.value} {checklist_counts[status]}" for status in ChecklistStatus
            ),
        ),
    ]
    rows.append(
        (
            "Suppressed",
            f"{len(suppressed)} finding(s), listed with reasons below"
            if suppressed
            else "0 — nothing waived",
        )
    )
    if baselined:
        rows.append(
            ("Baselined", f"{len(baselined)} finding(s) accepted by .vibeguard/baseline.json")
        )
    if report.regression is not None:
        diff = report.regression
        rows.append(
            (
                "Since last scan",
                f"{len(diff.new)} new · {len(diff.resolved)} resolved · "
                f"{len(diff.regressed)} regressed · {diff.unchanged} unchanged",
            )
        )
    rows.append(("AI assistance", "used" if report.ai_used else "none — deterministic only"))
    rows.append(("Local only", "yes" if report.local_only else "no"))
    return rows


# ------------------------------------------------------------- finding detail


def _evidence_block(finding: Finding) -> str:
    parts: list[str] = []
    for item in finding.evidence:
        location = item.file
        if item.line:
            location = f"{location}:{item.line}"
            if item.end_line and item.end_line != item.line:
                location = f"{location}-{item.end_line}"
        header = location
        if item.note:
            header = f"{header}  # {item.note}"
        parts.append(header if not item.snippet else f"{header}\n{item.snippet}")
    return "\n\n".join(parts)


def _tests_performed(finding: Finding) -> str:
    record = finding.fix
    if record is None:
        return ""
    bits: list[str] = []
    if record.repro_test:
        bits.append(f"repro test: {record.repro_test}")
    ran = [step.name for step in record.validation if not step.skipped]
    if ran:
        bits.append("validators run: " + ", ".join(ran))
    skipped = [f"{step.name} ({step.detail})" for step in record.validation if step.skipped]
    if skipped:
        bits.append("skipped: " + "; ".join(skipped))
    return " · ".join(bits)


def finding_fields(finding: Finding) -> list[Field]:
    """Every brief-mandated field for one finding; empty fields are omitted."""
    record = finding.fix
    location = finding.file or "—"
    candidates: list[Field] = [
        Field("Issue ID", finding.id),
        Field("Rule", finding.rule_id),
        Field("Category", finding.category.value),
        Field("Severity", finding.severity.value),
        Field("Confidence", finding.confidence.value),
        Field("File", location),
        Field("Line", str(finding.line) if finding.line else ""),
        Field("Description", finding.description),
        Field("Why It Matters", finding.why_it_matters),
        Field("Evidence", _evidence_block(finding), "code"),
        Field("Original Code", record.original_snippet if record else "", "code"),
        Field("Corrected Code", record.repaired_snippet if record else "", "code"),
        Field(
            "Repair Performed",
            ""
            if record is None
            else " · ".join(
                bit
                for bit in (
                    f"status: {record.status.value}",
                    record.patch_summary,
                    f"commit: {record.commit_sha[:12]}" if record.commit_sha else "",
                )
                if bit
            ),
        ),
        Field("Tests Performed", _tests_performed(finding)),
        Field(
            "Validation Result",
            ValidationEngine.summarise(record.validation)
            if record and record.validation
            else ("no validators ran" if record else ""),
        ),
        Field("Residual Risk", record.residual_risk if record else ""),
        Field("Recommended Follow-Up", finding.recommended_followup),
        Field("Autofix Safety", finding.autofix_safety.value),
        Field("References", "\n".join(finding.references)),
        Field("Fingerprint", finding.fingerprint),
    ]
    if finding.baselined:
        candidates.append(
            Field("Baselined", "in .vibeguard/baseline.json — reported, not gated on")
        )
    if finding.suppressed and finding.suppression is not None:
        entry = finding.suppression
        detail = f"{entry.reason.value} — {entry.author or 'unknown author'}"
        if entry.note:
            detail = f"{detail}: {entry.note}"
        if entry.expires:
            detail = f"{detail} (expires {entry.expires:%Y-%m-%d})"
        candidates.append(Field("Suppressed", detail))
    return [field for field in candidates if field.value.strip()]
