"""Markdown renderer — ``vibeguard-report.md``.

The document is written for a human deciding whether to ship: executive summary, the
category dashboard, what changed since last time, the coverage we actually had, the
full 279-topic master checklist, and then one detail section per finding carrying
every field the product brief mandates.

Nothing is quietly omitted. Adapters and validators are listed verbatim *including
their skip reasons*, suppressed findings get their own auditable section, and
validators excluded by the baseline rule (DECISIONS.md D21) are named.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from vibeguard.core.models import (
    CategoryScore,
    ChecklistStatus,
    Finding,
    ScanReport,
)
from vibeguard.reporting.common import (
    checklist_by_section,
    executive_summary,
    finding_fields,
    findings_by_severity,
    open_findings,
    section_rollup,
    suppressed_findings,
)
from vibeguard.reporting.diagram import graph_is_trivial, mermaid_architecture

__all__ = ["MARKDOWN_FILENAME", "render_markdown", "write_markdown"]

MARKDOWN_FILENAME = "vibeguard-report.md"

_BAR_WIDTH = 20


def _cell(text: str) -> str:
    """Make ``text`` safe for a markdown table cell."""
    return text.replace("|", "\\|").replace("\n", "<br>").strip() or "—"


def _inline(text: str) -> str:
    """Fold ``text`` onto one line, so a multi-value field stays one bullet."""
    return "<br>".join(line.strip() for line in text.splitlines() if line.strip())


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(str(value)) for value in row) + " |")
    lines.append("")
    return lines


def _bar(score: int) -> str:
    filled = round(score / 100 * _BAR_WIDTH)
    return "█" * filled + "·" * (_BAR_WIDTH - filled)


def _code(text: str) -> list[str]:
    return ["```", *text.splitlines(), "```", ""]


# ------------------------------------------------------------------- sections


def _architecture_section(report: ScanReport) -> list[str]:
    """The inferred architecture as a mermaid block — GitHub and GitLab render it."""
    graph = report.graph
    lines = ["## Architecture", ""]
    if graph_is_trivial(graph):
        lines.append(
            "Discovery inferred a single-node architecture: no datastore, broker or "
            "external service was detected alongside the application, so there is no "
            "graph worth drawing. That is a statement about what was *found*, not a "
            "guarantee that nothing else is deployed."
        )
        lines.append("")
        return lines
    lines.append(
        f"{len(graph.nodes)} node(s) and {len(graph.edges)} edge(s) were inferred from "
        "the manifests, configuration and code. Node colour is the category score that "
        "governs that node — green ≥85, amber 60–84, red <60, grey unscored."
    )
    lines.append("")
    lines.append("```mermaid")
    lines.append(mermaid_architecture(report))
    lines.append("```")
    lines.append("")
    return lines


def _summary_section(report: ScanReport) -> list[str]:
    lines = ["## Executive summary", ""]
    lines.extend(_table(("", ""), [(label, value) for label, value in executive_summary(report)]))
    return lines


def _dashboard(report: ScanReport) -> list[str]:
    after = {score.category: score for score in (report.scores_after or [])}
    has_after = bool(after)
    headers = ["category", "score", ""] + (["after", ""] if has_after else []) + [
        "open findings",
        "applicable",
    ]
    rows: list[list[str]] = []
    for score in report.scores_before:
        row: list[str] = [score.category.value, str(score.score), _bar(score.score)]
        if has_after:
            later: CategoryScore | None = after.get(score.category)
            row += [str(later.score) if later else "—", _bar(later.score) if later else ""]
        row += [
            str(score.finding_count),
            "yes" if score.applicable else "no — no applicable rules for this project",
        ]
        rows.append(row)

    lines = [
        "## Category dashboard",
        "",
        f"Overall readiness **{report.overall_before}/100**"
        + (
            f" → **{report.overall_after}/100** after repairs"
            if report.overall_after is not None
            else ""
        )
        + ".",
        "",
    ]
    lines.extend(_table(headers, rows))
    lines.append(
        "> Scores are a heuristic (docs/SCORING.md), not a certification. Categories "
        "without applicable rules are excluded from the overall score rather than "
        "counted as perfect."
    )
    lines.append("")
    return lines


def _regression_section(report: ScanReport) -> list[str]:
    diff = report.regression
    if diff is None:
        return []
    resolved = ", ".join(fp[:12] for fp in diff.resolved[:20]) or "—"
    lines = ["## Since the last scan", ""]
    lines.extend(
        _table(
            ("change", "count", "detail"),
            [
                ("new", str(len(diff.new)), ", ".join(diff.new[:20]) or "—"),
                ("resolved", str(len(diff.resolved)), resolved),
                ("regressed", str(len(diff.regressed)), ", ".join(diff.regressed[:20]) or "—"),
                ("unchanged", str(diff.unchanged), "—"),
            ],
        )
    )
    if diff.regressed:
        lines.append(
            "> **Regressed** means the finding was resolved in the previous scan and is "
            "back now — a process failure, not just a defect."
        )
        lines.append("")
    return lines


def _coverage_section(report: ScanReport) -> list[str]:
    lines = ["## Coverage", "", "### Adapters", ""]
    if report.adapters_used:
        lines.extend(f"- {entry}" for entry in report.adapters_used)
    else:
        lines.append("- none — built-in rules only")
    lines.append("")
    lines.append("### Validators")
    lines.append("")
    if report.validators_used:
        lines.extend(f"- {name}" for name in report.validators_used)
    else:
        lines.append("- none ran (audit mode performs no repairs to validate)")
    lines.append("")
    if report.baseline_validation:
        lines.append("### Validation baseline (pre-existing failures)")
        lines.append("")
        lines.extend(
            _table(
                ("step", "result", "detail"),
                [
                    (
                        step.name,
                        "skipped" if step.skipped else ("pass" if step.passed else "FAIL"),
                        step.detail,
                    )
                    for step in report.baseline_validation
                ],
            )
        )
        failures = [s.name for s in report.baseline_validation if not s.passed and not s.skipped]
        if failures:
            lines.append(
                "> These validators already failed on the untouched repository, so their "
                "post-fix results are **excluded** from every verdict: "
                + ", ".join(failures)
                + "."
            )
            lines.append("")
    lines.append(
        "> A skipped adapter or validator is listed with its reason. This report never "
        "implies coverage it did not have."
    )
    lines.append("")
    return lines


def _warnings_section(report: ScanReport) -> list[str]:
    if not report.warnings:
        return []
    lines = ["## Warnings", ""]
    lines.extend(f"- {warning}" for warning in report.warnings)
    lines.append("")
    return lines


def _checklist_section(report: ScanReport) -> list[str]:
    if not report.checklist:
        return []
    grouped = checklist_by_section(report.checklist)
    rollup = dict(section_rollup(report.checklist))
    lines = [
        "## Master audit checklist",
        "",
        f"All {len(report.checklist)} topics across {len(grouped)} sections. Every topic "
        "carries an explicit status; none is silently skipped.",
        "",
    ]
    lines.extend(
        _table(
            ("section", *[status.value for status in ChecklistStatus]),
            [
                (section, *[str(rollup[section][status]) for status in ChecklistStatus])
                for section, _ in grouped
            ],
        )
    )
    for section, items in grouped:
        lines.append(f"### {section} ({len(items)} topics)")
        lines.append("")
        lines.extend(
            _table(
                ("topic", "status", "detectors", "findings", "validation"),
                [
                    (
                        item.name,
                        item.status.value,
                        ", ".join(item.detectors) or "—",
                        ", ".join(item.finding_ids) or "—",
                        item.validation or item.note,
                    )
                    for item in items
                ],
            )
        )
    lines.append(
        "> `review_required` includes topics that have no automated detector yet. That is "
        "the honest fallback and is never converted to `pass`."
    )
    lines.append("")
    return lines


def _finding_detail(finding: Finding) -> list[str]:
    location = finding.file or "."
    if finding.line:
        location = f"{location}:{finding.line}"
    lines = [f"#### {finding.rule_id} — {finding.title}", "", f"`{location}`", ""]
    for field in finding_fields(finding):
        if field.kind == "code":
            # A blank line first, or the bold label is swallowed by the bullet list
            # that precedes it and the fenced block never opens.
            lines.extend(["", f"**{field.label}**", ""])
            lines.extend(_code(field.value))
        else:
            lines.append(f"- **{field.label}:** {_inline(field.value)}")
    lines.append("")
    return lines


def _findings_section(report: ScanReport) -> list[str]:
    live = open_findings(report)
    lines = ["## Findings", ""]
    if not live:
        lines.append("No open findings. (Suppressed findings, if any, are listed below.)")
        lines.append("")
        return lines
    for severity, items in findings_by_severity(live):
        lines.append(f"### {severity.value} ({len(items)})")
        lines.append("")
        for finding in items:
            lines.extend(_finding_detail(finding))
    return lines


def _suppressed_section(report: ScanReport) -> list[str]:
    suppressed = suppressed_findings(report)
    if not suppressed and not report.suppressions:
        return []
    lines = [
        "## Suppressed findings",
        "",
        "Suppressed findings are excluded from scores and from the CI gate, and listed "
        "here so the decision stays auditable.",
        "",
    ]
    rows: list[tuple[str, ...]] = []
    for finding in suppressed:
        entry = finding.suppression
        rows.append(
            (
                finding.rule_id,
                f"{finding.file or '.'}:{finding.line or '-'}",
                finding.severity.value,
                entry.reason.value if entry else "—",
                entry.author if entry else "—",
                (entry.note if entry else "") or finding.title,
                f"{entry.expires:%Y-%m-%d}" if entry and entry.expires else "—",
            )
        )
    if rows:
        lines.extend(
            _table(
                ("rule", "location", "severity", "reason", "author", "note", "expires"), rows
            )
        )
    unmatched = [
        entry
        for entry in report.suppressions
        if not any(f.suppression == entry for f in suppressed)
    ]
    if unmatched:
        lines.append("Configured suppressions that matched nothing in this scan:")
        lines.append("")
        lines.extend(
            _table(
                ("rule", "fingerprint", "reason", "author", "note"),
                [
                    (
                        entry.rule_id or "—",
                        entry.fingerprint[:12] or "—",
                        entry.reason.value,
                        entry.author or "—",
                        entry.note,
                    )
                    for entry in unmatched
                ],
            )
        )
    return lines


# --------------------------------------------------------------------- render


def render_markdown(report: ScanReport) -> str:
    """Render the whole report as markdown."""
    lines: list[str] = [
        "# VibeGuard report",
        "",
        f"_{report.mode} scan of `{report.repo}` on "
        f"{report.scan_date.isoformat(timespec='seconds')} by vibeguard "
        f"{report.vibeguard_version}._",
        "",
    ]
    lines += _architecture_section(report)
    lines += _summary_section(report)
    lines += _dashboard(report)
    lines += _regression_section(report)
    lines += _warnings_section(report)
    lines += _coverage_section(report)
    lines += _checklist_section(report)
    lines += _findings_section(report)
    lines += _suppressed_section(report)
    lines.append("")
    lines.append(
        "_Generated by VibeGuard. Secrets are redacted at detection time; no renderer "
        "can reveal them._"
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown(report: ScanReport, root: str | Path) -> Path:
    """Write ``vibeguard-report.md`` under ``root`` and return the path."""
    destination = Path(root) / MARKDOWN_FILENAME
    destination.write_text(render_markdown(report), encoding="utf-8")
    return destination
