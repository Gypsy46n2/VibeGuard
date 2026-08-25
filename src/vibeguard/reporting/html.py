"""HTML renderer — ``vibeguard-report.html``.

Fully self-contained: inline CSS, inline JS, no external stylesheet, script, font, or
image, and no ``href`` off the page. A report is often read from a CI artifact store or
an air-gapped machine; it must render identically there. Reference URLs are therefore
printed as text rather than links — the document makes zero network requests, by
construction rather than by promise.

Light and dark are handled with ``prefers-color-scheme`` over CSS custom properties,
sections and findings collapse with ``<details>``, and a ~20-line filter script hides
non-matching rows without any library.
"""

from __future__ import annotations

from collections.abc import Sequence
from html import escape
from pathlib import Path

from vibeguard.core.models import ChecklistStatus, Finding, ScanReport, Severity
from vibeguard.reporting.common import (
    checklist_by_section,
    executive_summary,
    finding_fields,
    findings_by_severity,
    open_findings,
    section_rollup,
    suppressed_findings,
)

__all__ = ["HTML_FILENAME", "render_html", "write_html"]

HTML_FILENAME = "vibeguard-report.html"

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1b1f24; --muted: #5b6570; --line: #e2e6ea;
  --panel: #f7f9fb; --accent: #2f6feb;
  --critical: #b21b1b; --high: #d1541f; --medium: #b8860b; --low: #2f6feb; --info: #5b6570;
  --pass: #1a7f4b; --fail: #b21b1b; --fixed: #1a7f4b; --review: #b8860b; --na: #7a838d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12161a; --fg: #e6eaee; --muted: #9aa4ae; --line: #262c33;
    --panel: #171c22; --accent: #6ea8fe;
    --critical: #ff6b6b; --high: #ffa657; --medium: #e3b341; --low: #6ea8fe; --info: #9aa4ae;
    --pass: #56d364; --fail: #ff6b6b; --fixed: #56d364; --review: #e3b341; --na: #7d8590;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial,
        sans-serif;
}
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 1.7rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 { font-size: 1.2rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1rem; margin: 1.5rem 0 .5rem; }
h4 { font-size: .95rem; margin: 0; }
p.sub { color: var(--muted); margin: 0 0 1.5rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .88rem; }
th, td { text-align: left; padding: .4rem .55rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
pre { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
      padding: .6rem .7rem; overflow-x: auto; font-size: .82rem; margin: .35rem 0 .8rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
details { border: 1px solid var(--line); border-radius: 8px; margin: .5rem 0;
          background: var(--panel); }
details > summary { cursor: pointer; padding: .55rem .75rem; font-weight: 600;
                    list-style: none; display: flex; gap: .6rem; align-items: baseline; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "▸"; color: var(--muted); }
details[open] > summary::before { content: "▾"; }
details > div.body { padding: 0 .75rem .75rem; }
.summary-grid { display: grid; grid-template-columns: minmax(9rem, 14rem) 1fr; gap: .1rem .9rem; }
.summary-grid dt { color: var(--muted); }
.summary-grid dd { margin: 0; }
.bar { display: inline-block; width: 140px; height: 9px; border-radius: 5px;
       background: var(--line); overflow: hidden; vertical-align: middle; }
.bar > span { display: block; height: 100%; background: var(--accent); }
.badge { display: inline-block; padding: .05rem .45rem; border-radius: 999px;
         font-size: .74rem; font-weight: 600; border: 1px solid currentColor; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
.sev-medium { color: var(--medium); } .sev-low { color: var(--low); }
.sev-info { color: var(--info); }
.st-pass { color: var(--pass); } .st-fail { color: var(--fail); }
.st-fixed { color: var(--fixed); } .st-review_required { color: var(--review); }
.st-not_applicable { color: var(--na); }
.note { color: var(--muted); font-size: .85rem; border-left: 3px solid var(--line);
        padding-left: .7rem; margin: .6rem 0; }
#filter { width: 100%; padding: .5rem .65rem; font: inherit; color: var(--fg);
          background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
          margin: 1rem 0 .25rem; }
.hidden { display: none !important; }
ul.plain { margin: .3rem 0 1rem; padding-left: 1.1rem; }
"""

_JS = """
(function () {
  var box = document.getElementById('filter');
  if (!box) return;
  var items = Array.prototype.slice.call(document.querySelectorAll('[data-search]'));
  box.addEventListener('input', function () {
    var q = box.value.trim().toLowerCase();
    items.forEach(function (el) {
      var hit = !q || el.getAttribute('data-search').indexOf(q) !== -1;
      el.classList.toggle('hidden', !hit);
      if (hit && q) {
        var p = el.parentElement;
        while (p) { if (p.tagName === 'DETAILS') p.open = true; p = p.parentElement; }
      }
    });
  });
})();
"""

_SEVERITY_CLASS = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH: "sev-high",
    Severity.MEDIUM: "sev-medium",
    Severity.LOW: "sev-low",
    Severity.INFO: "sev-info",
}


def _search_key(*parts: object) -> str:
    return escape(" ".join(str(part) for part in parts if part).lower(), quote=True)


def _badge(text: str, css_class: str) -> str:
    return f'<span class="badge {css_class}">{escape(text)}</span>'


def _rollup_badges(counts: dict[ChecklistStatus, int]) -> str:
    """The section's per-status rollup, rendered inline next to its name."""
    return " " + " ".join(
        _badge(f"{status.value} {counts[status]}", f"st-{status.value}")
        for status in ChecklistStatus
        if counts[status]
    )


def _bar(score: int) -> str:
    return f'<span class="bar"><span style="width:{max(0, min(100, score))}%"></span></span>'


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]], *, searchable: bool = False,
           keys: Sequence[str] = ()) -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body: list[str] = []
    for index, row in enumerate(rows):
        attr = f' data-search="{keys[index]}"' if searchable and index < len(keys) else ""
        cells = "".join(f"<td>{cell}</td>" for cell in row)
        body.append(f"<tr{attr}>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


# ------------------------------------------------------------------- sections


def _summary(report: ScanReport) -> str:
    rows = "".join(
        f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>"
        for label, value in executive_summary(report)
    )
    return f"<h2>Executive summary</h2><dl class='summary-grid'>{rows}</dl>"


def _dashboard(report: ScanReport) -> str:
    after = {score.category: score for score in (report.scores_after or [])}
    headers = ["category", "score", ""]
    if after:
        headers += ["after", ""]
    headers += ["open findings", "applicable"]
    rows: list[list[str]] = []
    for score in report.scores_before:
        row = [escape(score.category.value), str(score.score), _bar(score.score)]
        if after:
            later = after.get(score.category)
            row += [str(later.score) if later else "—", _bar(later.score) if later else ""]
        row += [
            str(score.finding_count),
            "yes" if score.applicable else "<span class='st-not_applicable'>no rules</span>",
        ]
        rows.append(row)
    heading = f"Overall readiness <strong>{report.overall_before}/100</strong>"
    if report.overall_after is not None:
        heading += f" → <strong>{report.overall_after}/100</strong> after repairs"
    return (
        "<h2>Category dashboard</h2>"
        f"<p>{heading}.</p>"
        + _table(headers, rows)
        + "<p class='note'>Scores are a heuristic (docs/SCORING.md), not a certification. "
        "Categories with no applicable rules are excluded from the overall score rather "
        "than counted as perfect.</p>"
    )


def _regression(report: ScanReport) -> str:
    diff = report.regression
    if diff is None:
        return ""
    rows = [
        ["new", str(len(diff.new)), escape(", ".join(diff.new[:20]) or "—")],
        [
            "resolved",
            str(len(diff.resolved)),
            escape(", ".join(fp[:12] for fp in diff.resolved[:20]) or "—"),
        ],
        ["regressed", str(len(diff.regressed)), escape(", ".join(diff.regressed[:20]) or "—")],
        ["unchanged", str(diff.unchanged), "—"],
    ]
    note = (
        "<p class='note'><strong>Regressed</strong> means the finding was resolved in the "
        "previous scan and is back now.</p>"
        if diff.regressed
        else ""
    )
    return "<h2>Since the last scan</h2>" + _table(["change", "count", "detail"], rows) + note


def _warnings(report: ScanReport) -> str:
    if not report.warnings:
        return ""
    items = "".join(f"<li>{escape(warning)}</li>" for warning in report.warnings)
    return f"<h2>Warnings</h2><ul class='plain'>{items}</ul>"


def _coverage(report: ScanReport) -> str:
    adapters = report.adapters_used or ["none — built-in rules only"]
    validators = report.validators_used or [
        "none ran (audit mode performs no repairs to validate)"
    ]
    parts = [
        "<h2>Coverage</h2><h3>Adapters</h3><ul class='plain'>",
        "".join(f"<li>{escape(entry)}</li>" for entry in adapters),
        "</ul><h3>Validators</h3><ul class='plain'>",
        "".join(f"<li>{escape(name)}</li>" for name in validators),
        "</ul>",
    ]
    if report.baseline_validation:
        rows = [
            [
                escape(step.name),
                "skipped" if step.skipped else ("pass" if step.passed else "FAIL"),
                escape(step.detail),
            ]
            for step in report.baseline_validation
        ]
        parts.append("<h3>Validation baseline (pre-existing failures)</h3>")
        parts.append(_table(["step", "result", "detail"], rows))
        failures = [s.name for s in report.baseline_validation if not s.passed and not s.skipped]
        if failures:
            parts.append(
                "<p class='note'>These validators already failed on the untouched "
                "repository, so their post-fix results are <strong>excluded</strong> from "
                f"every verdict: {escape(', '.join(failures))}.</p>"
            )
    parts.append(
        "<p class='note'>A skipped adapter or validator is listed with its reason. This "
        "report never implies coverage it did not have.</p>"
    )
    return "".join(parts)


def _checklist(report: ScanReport) -> str:
    if not report.checklist:
        return ""
    grouped = checklist_by_section(report.checklist)
    rollup = dict(section_rollup(report.checklist))
    summary_rows = [
        [escape(section)] + [str(rollup[section][status]) for status in ChecklistStatus]
        for section, _ in grouped
    ]
    parts = [
        "<h2>Master audit checklist</h2>",
        f"<p>All {len(report.checklist)} topics across {len(grouped)} sections. Every topic "
        "carries an explicit status; none is silently skipped.</p>",
        _table(["section", *[s.value for s in ChecklistStatus]], summary_rows),
    ]
    for section, items in grouped:
        rows = []
        keys = []
        for item in items:
            rows.append(
                [
                    escape(item.name),
                    _badge(item.status.value, f"st-{item.status.value}"),
                    escape(", ".join(item.detectors) or "—"),
                    escape(", ".join(item.finding_ids) or "—"),
                    escape(item.validation or item.note),
                ]
            )
            keys.append(
                _search_key(item.topic_id, item.name, item.status.value, *item.detectors)
            )
        parts.append(
            f"<details><summary>{escape(section)} "
            f"<span class='badge st-not_applicable'>{len(items)} topics</span>"
            f"{_rollup_badges(rollup[section])}</summary><div class='body'>"
            + _table(
                ["topic", "status", "detectors", "findings", "validation"],
                rows,
                searchable=True,
                keys=keys,
            )
            + "</div></details>"
        )
    parts.append(
        "<p class='note'><code>review_required</code> includes topics with no automated "
        "detector yet. That is the honest fallback and is never converted to "
        "<code>pass</code>.</p>"
    )
    return "".join(parts)


def _finding_block(finding: Finding) -> str:
    location = finding.file or "."
    if finding.line:
        location = f"{location}:{finding.line}"
    body: list[str] = []
    for field in finding_fields(finding):
        if field.kind == "code":
            body.append(
                f"<h4>{escape(field.label)}</h4><pre><code>{escape(field.value)}</code></pre>"
            )
        else:
            body.append(
                f"<p><strong>{escape(field.label)}:</strong> {escape(field.value)}</p>"
            )
    key = _search_key(
        finding.rule_id, finding.id, finding.title, location, finding.category.value,
        finding.severity.value, finding.description,
    )
    marks = ""
    if finding.baselined:
        marks += " " + _badge("baselined", "st-not_applicable")
    return (
        f"<details data-search=\"{key}\"><summary>"
        f"{_badge(finding.severity.value, _SEVERITY_CLASS[finding.severity])} "
        f"<span>{escape(finding.rule_id)} — {escape(finding.title)}</span> "
        f"<span class='st-not_applicable'>{escape(location)}</span>{marks}"
        f"</summary><div class='body'>{''.join(body)}</div></details>"
    )


def _findings(report: ScanReport) -> str:
    live = open_findings(report)
    parts = ["<h2>Findings</h2>"]
    if not live:
        parts.append("<p>No open findings. Suppressed findings, if any, are listed below.</p>")
        return "".join(parts)
    parts.append(
        "<input id='filter' type='search' placeholder='filter findings and checklist "
        "topics…' autocomplete='off'>"
    )
    for severity, items in findings_by_severity(live):
        parts.append(
            f"<h3>{_badge(severity.value, _SEVERITY_CLASS[severity])} {len(items)}</h3>"
        )
        parts.extend(_finding_block(finding) for finding in items)
    return "".join(parts)


def _suppressed(report: ScanReport) -> str:
    suppressed = suppressed_findings(report)
    if not suppressed and not report.suppressions:
        return ""
    parts = [
        "<h2>Suppressed findings</h2>",
        "<p>Suppressed findings are excluded from scores and from the CI gate, and listed "
        "here so the decision stays auditable.</p>",
    ]
    if suppressed:
        rows = []
        for finding in suppressed:
            entry = finding.suppression
            rows.append(
                [
                    escape(finding.rule_id),
                    escape(f"{finding.file or '.'}:{finding.line or '-'}"),
                    _badge(finding.severity.value, _SEVERITY_CLASS[finding.severity]),
                    escape(entry.reason.value if entry else "—"),
                    escape((entry.author if entry else "") or "—"),
                    escape((entry.note if entry else "") or finding.title),
                    escape(f"{entry.expires:%Y-%m-%d}" if entry and entry.expires else "—"),
                ]
            )
        parts.append(
            _table(
                ["rule", "location", "severity", "reason", "author", "note", "expires"], rows
            )
        )
    unmatched = [
        entry for entry in report.suppressions
        if not any(f.suppression == entry for f in suppressed)
    ]
    if unmatched:
        parts.append("<h3>Configured suppressions that matched nothing in this scan</h3>")
        parts.append(
            _table(
                ["rule", "fingerprint", "reason", "author", "note"],
                [
                    [
                        escape(entry.rule_id or "—"),
                        escape(entry.fingerprint[:12] or "—"),
                        escape(entry.reason.value),
                        escape(entry.author or "—"),
                        escape(entry.note),
                    ]
                    for entry in unmatched
                ],
            )
        )
    return "".join(parts)


# --------------------------------------------------------------------- render


def render_html(report: ScanReport) -> str:
    """Render the whole report as a single self-contained HTML document."""
    title = f"VibeGuard report — {Path(report.repo).name or report.repo}"
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title>",
        f"<style>{_CSS}</style>",
        # Without JS the filter box cannot do anything, so it is not offered. Every
        # other affordance (collapsible sections, tables, colours) is pure CSS/HTML.
        "<noscript><style>#filter{display:none}details{border-color:var(--line)}</style>"
        "</noscript></head><body><main>",
        f"<h1>{escape(title)}</h1>",
        f"<p class='sub'>{escape(report.mode)} scan of {escape(report.repo)} on "
        f"{escape(report.scan_date.isoformat(timespec='seconds'))} · vibeguard "
        f"{escape(report.vibeguard_version)}</p>",
        _summary(report),
        _dashboard(report),
        _regression(report),
        _warnings(report),
        _coverage(report),
        _checklist(report),
        _findings(report),
        _suppressed(report),
        "<p class='note'>Generated by VibeGuard. Secrets are redacted at detection time; "
        "no renderer can reveal them. Reference URLs are printed as text so this document "
        "makes no network requests.</p>",
        f"</main><script>{_JS}</script></body></html>",
    ]
    return "\n".join(parts)


def write_html(report: ScanReport, root: str | Path) -> Path:
    """Write ``vibeguard-report.html`` under ``root`` and return the path."""
    destination = Path(root) / HTML_FILENAME
    destination.write_text(render_html(report), encoding="utf-8")
    return destination
