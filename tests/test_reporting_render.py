"""Markdown and HTML renderers — ARCHITECTURE.md §8, INTERFACES.md §8 and §11.

The renderers carry two obligations that are worth testing before anything cosmetic:

1. **Completeness.** Every one of the ~279 checklist topics must appear, in its
   section, with an explicit status. A report that quietly drops a section would let
   a category be silently skipped, which §11 forbids.
2. **Confidentiality.** Secrets are redacted at Finding construction, so no renderer
   is *supposed* to be able to leak one. That is exactly the kind of guarantee that
   should be tested rather than assumed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from conftest import context_from, make_finding, make_report
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.models import (
    Category,
    CategoryScore,
    ChecklistStatus,
    Confidence,
    Evidence,
    FixRecord,
    FixStatus,
    RegressionDiff,
    Severity,
    SuppressionEntry,
    SuppressionReason,
    ValidationStep,
)
from vibeguard.core.redact import redact
from vibeguard.core.rule import Rule
from vibeguard.engine.orchestrator import Engine
from vibeguard.reporting import (
    HTML_FILENAME,
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    render_html,
    render_markdown,
    write_reports,
)
from vibeguard.reporting.common import (
    NO_RECORD,
    executive_summary,
    repair_counts,
    repair_summary,
)


def both(report) -> dict[str, str]:
    """Both rendered formats, so a test can assert the same fact about each."""
    return {"markdown": render_markdown(report), "html": render_html(report)}


# ------------------------------------------------------------------- headers


def test_header_carries_repo_stack_date_and_mode():
    report = make_report(mode="fix-safe")
    report.tech.languages = {"python": 12}
    report.tech.frameworks = ["flask"]
    for name, text in both(report).items():
        assert "/repo" in text, name
        assert "fix-safe" in text, name
        assert "python" in text and "flask" in text, name
        assert str(report.scan_date.year) in text, name


def test_before_and_after_scores_are_both_shown_for_a_fix_run():
    report = make_report(
        mode="fix-safe",
        overall_before=40,
        overall_after=85,
        scores_before=[
            CategoryScore(category=Category.SECURITY, score=40, applicable=True,
                          finding_count=3)
        ],
        scores_after=[
            CategoryScore(category=Category.SECURITY, score=85, applicable=True,
                          finding_count=1)
        ],
    )
    for name, text in both(report).items():
        assert "40" in text and "85" in text, name
        assert "after" in text.lower(), name


def test_an_audit_shows_a_single_score_and_no_after_column():
    report = make_report(overall_before=72)
    assert "72/100" in render_markdown(report)
    assert "after repairs" not in render_markdown(report)


def test_severity_counts_and_suppressed_count_are_in_the_summary():
    high = make_finding("a" * 64, severity=Severity.HIGH)
    low = make_finding("b" * 64, severity=Severity.LOW)
    waived = make_finding("c" * 64)
    waived.suppressed = True
    waived.suppression = SuppressionEntry(
        fingerprint="c" * 64, rule_id="VG-SEC-001",
        reason=SuppressionReason.ACCEPTED_RISK, author="alice",
    )
    rows = dict(executive_summary(make_report(high, low, waived)))
    assert "high 1" in rows["Issues by severity"]
    assert "low 1" in rows["Issues by severity"]
    assert "2 open in total" in rows["Issues by severity"]
    assert rows["Suppressed"].startswith("1 finding(s)")


def test_a_clean_report_still_states_the_suppressed_count():
    rows = dict(executive_summary(make_report()))
    assert rows["Suppressed"] == "0 — nothing waived"


# ------------------------------------------------------------- repair counts


def test_repair_counts_seed_every_status():
    counts = repair_counts([])
    for status in FixStatus:
        assert counts[status.value] == 0
    assert counts[NO_RECORD] == 0


def test_repair_counts_bucket_each_outcome():
    findings = [
        make_finding("a" * 64, fix=FixRecord(status=FixStatus.FIXED)),
        make_finding("b" * 64, fix=FixRecord(status=FixStatus.FAILED)),
        make_finding("c" * 64, fix=FixRecord(status=FixStatus.UNVERIFIED)),
        make_finding("d" * 64, fix=FixRecord(status=FixStatus.REQUIRES_REVIEW)),
        make_finding("e" * 64, fix=FixRecord(status=FixStatus.NOT_ATTEMPTED)),
        make_finding("f" * 64, fix=FixRecord(status=FixStatus.ATTEMPTED)),
        make_finding("g" * 64),
    ]
    counts = repair_counts(findings)
    assert counts["fixed"] == 1
    assert counts["failed"] == 1
    assert counts["unverified"] == 1
    assert counts["requires_review"] == 1
    assert counts["not_attempted"] == 1
    assert counts["attempted"] == 1
    assert counts[NO_RECORD] == 1

    summary = repair_summary(findings)
    for word in ("fixed", "failed", "unverified", "requires review", "not attempted"):
        assert word in summary


def test_every_repair_outcome_reaches_both_renderers():
    findings = [
        make_finding("a" * 64, fix=FixRecord(status=FixStatus.FIXED)),
        make_finding("b" * 64, fix=FixRecord(status=FixStatus.FAILED)),
    ]
    for name, text in both(make_report(*findings, mode="fix-safe")).items():
        assert "fixed 1" in text, name
        assert "failed 1" in text, name


# ---------------------------------------------------------------- checklist


def checklist_report(tmp_path: Path):
    """A real report over a real repository — the checklist must be genuine."""
    context_from(
        tmp_path,
        {
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "requirements.txt": "flask\n",
            "Dockerfile": "FROM python:3.11\nCMD python app.py\n",
        },
    )
    return Engine(VibeguardConfig()).audit(tmp_path)


def test_markdown_renders_every_checklist_section_and_topic(tmp_path: Path):
    report = checklist_report(tmp_path)
    text = render_markdown(report)

    assert f"All {len(report.checklist)} topics" in text
    sections = {item.section for item in report.checklist}
    for section in sections:
        assert f"### {section} (" in text, f"section {section} is missing from the markdown"
    for item in report.checklist:
        assert item.name in text, f"topic {item.topic_id} is missing from the markdown"


def test_html_renders_every_checklist_section_and_topic(tmp_path: Path):
    report = checklist_report(tmp_path)
    text = render_html(report)
    for item in report.checklist:
        assert item.topic_id in text or item.name in text, item.topic_id


def test_checklist_rollup_counts_add_up_to_the_topic_total(tmp_path: Path):
    report = checklist_report(tmp_path)
    text = render_markdown(report)
    table = text.split("## Master audit checklist", 1)[1].split("### ", 1)[0]

    total = 0
    for row in table.splitlines():
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        if len(cells) != len(ChecklistStatus) + 1 or not cells[1].isdigit():
            continue
        total += sum(int(cell) for cell in cells[1:])
    assert total == len(report.checklist)


def test_every_checklist_status_is_a_column_in_the_rollup(tmp_path: Path):
    text = render_markdown(checklist_report(tmp_path))
    header = text.split("## Master audit checklist", 1)[1].splitlines()[4]
    for status in ChecklistStatus:
        assert status.value in header


# ------------------------------------------------------------ finding detail


def test_finding_detail_carries_every_mandated_field():
    finding = make_finding(
        fix=FixRecord(
            status=FixStatus.FIXED,
            patch_summary="added a timeout",
            original_snippet="requests.get(url)",
            repaired_snippet="requests.get(url, timeout=10)",
            commit_sha="0123456789abcdef",
            validation=[ValidationStep(name="syntax", passed=True)],
            residual_risk="the timeout value is a guess",
        ),
        references=["https://example.invalid/docs"],
    )
    for name, text in both(make_report(finding, mode="fix-safe")).items():
        for label in (
            "Issue ID", "Rule", "Category", "Severity", "Confidence", "File",
            "Description", "Why It Matters", "Evidence", "Original Code",
            "Corrected Code", "Repair Performed", "Validation Result",
            "Residual Risk", "Recommended Follow-Up", "References", "Fingerprint",
        ):
            assert label in text, f"{label} missing from {name}"
        assert "requests.get(url, timeout=10)" in text, name
        assert "syntax=pass" in text, name
        assert "the timeout value is a guess" in text, name


def test_findings_are_grouped_by_severity_most_severe_first():
    text = render_markdown(
        make_report(
            make_finding("a" * 64, severity=Severity.LOW),
            make_finding("b" * 64, severity=Severity.CRITICAL),
        )
    )
    assert text.index("### critical") < text.index("### low")


def test_a_clean_report_says_so_rather_than_rendering_an_empty_table():
    for name, text in both(make_report()).items():
        assert "No open findings" in text, name


# ------------------------------------------------------------- REDACTION


SECRET = "sk-live-abcdefghijklmnop0123456789"


class _SecretRule(Rule):
    """A minimal SECRETS-category rule, used only to reach the redaction boundary."""

    id = "VG-SCR-999"
    category = Category.SECRETS
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    title = "Hardcoded API key"
    description = "an API key is committed to the repository"
    why_it_matters = "a committed key is a live credential in every clone"

    def detect(self, ctx):  # pragma: no cover - constructed directly by the tests
        return []


def secret_report():
    """A secrets finding built through the real rule boundary, so it is redacted."""
    rule = _SecretRule()
    finding = rule.make_finding(
        file="settings.py",
        line=4,
        evidence=[
            Evidence(file="settings.py", line=4, snippet=f'API_KEY = "{SECRET}"'),
            Evidence(file=".env", line=1, snippet=f"API_KEY={SECRET}", note="also here"),
        ],
    )
    # The fixer redacts its own hunks the same way (fixers/engine.py); a FixRecord
    # built by hand must not be able to smuggle the raw value back into the report.
    finding.fix = FixRecord(
        status=FixStatus.REQUIRES_REVIEW,
        original_snippet=redact(f'API_KEY = "{SECRET}"'),
        repaired_snippet='API_KEY = os.environ["API_KEY"]',
    )
    return make_report(finding)


def test_the_rule_boundary_actually_redacts_the_secret():
    """Guard the guard: if this fails, the leak tests below prove nothing."""
    report = secret_report()
    finding = report.findings[0]
    assert "[REDACTED]" in finding.evidence[0].snippet
    assert SECRET not in finding.evidence[0].snippet


def test_no_renderer_can_leak_a_secret(tmp_path: Path):
    report = secret_report()
    rendered = {
        "markdown": render_markdown(report),
        "html": render_html(report),
        "json": report.model_dump_json(),
    }
    for name, text in rendered.items():
        assert SECRET not in text, f"the raw secret leaked into the {name} report"
        assert "[REDACTED]" in text, f"the {name} report lost the redaction marker"

    # And the same holds for what actually lands on disk.
    for path in write_reports(report, tmp_path, ("json", "md", "html")):
        assert SECRET not in path.read_text(encoding="utf-8"), path.name


def test_redaction_survives_html_escaping():
    """HTML-escaping must not reconstruct a secret out of an escaped redaction."""
    text = render_html(secret_report())
    assert SECRET not in text
    assert not re.search(re.escape(SECRET[:12]) + r"[^<]", text)


# ----------------------------------------------------------- regression etc.


def test_regression_section_reports_all_four_buckets():
    report = make_report(
        regression=RegressionDiff(
            new=["VG-SEC-001:aaaa"], resolved=["b" * 64],
            regressed=["VG-SEC-002:cccc"], unchanged=7,
        )
    )
    for name, text in both(report).items():
        assert "Since the last scan" in text, name
        assert "new" in text and "resolved" in text and "regressed" in text, name
        assert "7" in text, name
        assert "VG-SEC-001:aaaa" in text, name


def test_no_regression_section_without_history():
    for text in both(make_report()).values():
        assert "Since the last scan" not in text


def test_adapters_and_validators_are_reproduced_verbatim_with_their_reasons():
    report = make_report(
        adapters_used=[
            "bandit (skipped: not installed)",
            "trivy (skipped: local_only: tool contacts a remote service)",
            "semgrep (3 finding(s))",
        ],
        validators_used=["syntax", "lint", "tests:targeted"],
    )
    for name, text in both(report).items():
        assert "bandit (skipped: not installed)" in text, name
        assert "local_only: tool contacts a remote service" in text, name
        assert "semgrep (3 finding(s))" in text, name
        assert "tests:targeted" in text, name


def test_ai_and_local_only_flags_are_stated():
    rows = dict(executive_summary(make_report(ai_used=False, local_only=True)))
    assert "deterministic only" in rows["AI assistance"]
    assert rows["Local only"] == "yes"

    rows = dict(executive_summary(make_report(ai_used=True, local_only=False)))
    assert rows["AI assistance"] == "used"
    assert rows["Local only"] == "no"


def test_baseline_validation_is_serialised_and_rendered():
    report = make_report(
        mode="fix-safe",
        baseline_validation=[
            ValidationStep(name="lint", passed=False, detail="17 pre-existing errors"),
            ValidationStep(name="syntax", passed=True),
        ],
    )
    assert report.model_dump()["baseline_validation"][0]["name"] == "lint"
    for name, text in both(report).items():
        assert "17 pre-existing errors" in text, name
        assert "excluded" in text.lower(), name


def test_warnings_are_surfaced():
    report = make_report(warnings=["suppression for VG-SEC-001 (alice) expired on 2026-01-01"])
    for name, text in both(report).items():
        assert "expired on 2026-01-01" in text, name


# ------------------------------------------------------------- suppressions


def suppressed_report():
    finding = make_finding("a" * 64)
    finding.suppressed = True
    finding.suppression = SuppressionEntry(
        fingerprint="a" * 64,
        rule_id="VG-SEC-001",
        reason=SuppressionReason.FALSE_POSITIVE,
        author="alice@example.invalid",
        created=datetime(2026, 1, 1, tzinfo=UTC),
        expires=datetime(2026, 12, 31, tzinfo=UTC),
        note="the sink is a test double",
    )
    return make_report(finding, suppressions=[finding.suppression])


def test_suppressed_findings_stay_in_the_report_with_their_justification():
    for name, text in both(suppressed_report()).items():
        assert "Suppressed findings" in text, name
        assert "false_positive" in text, name
        assert "alice@example.invalid" in text, name
        assert "the sink is a test double" in text, name
        assert "2026-12-31" in text, name


def test_suppressed_findings_are_not_listed_among_the_open_ones():
    for name, text in both(suppressed_report()).items():
        assert "No open findings" in text, name


def test_configured_suppressions_that_matched_nothing_are_still_listed():
    orphan = SuppressionEntry(
        fingerprint="f" * 64, rule_id="VG-SEC-042",
        reason=SuppressionReason.NOT_APPLICABLE, author="bob", note="k8s only",
    )
    for name, text in both(make_report(suppressions=[orphan])).items():
        assert "VG-SEC-042" in text, name
        assert "k8s only" in text, name


def test_baselined_findings_are_marked_as_such():
    finding = make_finding()
    finding.baselined = True
    for name, text in both(make_report(finding)).items():
        assert "baseline" in text.lower(), name


# -------------------------------------------------------------------- HTML


def test_html_is_self_contained():
    text = render_html(
        make_report(make_finding(references=["https://example.invalid/a"]))
    )
    assert "<script src=" not in text
    assert "<link " not in text
    assert "<img" not in text
    assert "@import" not in text
    # Reference URLs appear as text, never as a link that would phone home.
    assert "https://example.invalid/a" in text
    assert 'href="https://' not in text


def test_html_is_a_single_well_formed_document():
    from html.parser import HTMLParser

    class _Parser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags: list[str] = []

        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)

    parser = _Parser()
    parser.feed(render_html(checklist_report_stub()))
    assert parser.tags[0] == "html"
    assert "table" in parser.tags
    assert "details" in parser.tags


def checklist_report_stub():
    return make_report(make_finding())


def test_html_degrades_without_javascript():
    """No JS: the filter box hides itself, and nothing else depends on scripting."""
    text = render_html(make_report(make_finding()))
    assert "<noscript>" in text
    assert "#filter{display:none}" in text
    # Collapsing is <details>, which is pure HTML.
    assert "<details" in text


def test_html_handles_both_colour_schemes():
    text = render_html(make_report())
    assert "prefers-color-scheme: dark" in text


def test_html_escapes_hostile_content():
    finding = make_finding(title="<script>alert(1)</script>", snippet="</pre><script>x")
    text = render_html(make_report(finding))
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


# ------------------------------------------------------------------- writer


def test_write_reports_always_writes_json_and_only_what_was_asked(tmp_path: Path):
    report = make_report(make_finding())

    paths = write_reports(report, tmp_path, ("md",))
    assert [p.name for p in paths] == [JSON_FILENAME, MARKDOWN_FILENAME]
    assert not (tmp_path / HTML_FILENAME).exists()

    paths = write_reports(report, tmp_path, ("html",))
    assert [p.name for p in paths] == [JSON_FILENAME, HTML_FILENAME]


def test_write_reports_understands_all(tmp_path: Path):
    paths = write_reports(make_report(), tmp_path, ("all",))
    assert {p.name for p in paths} == {JSON_FILENAME, MARKDOWN_FILENAME, HTML_FILENAME}


def test_write_reports_ignores_terminal_only_formats(tmp_path: Path):
    paths = write_reports(make_report(), tmp_path, ("table", "jsonl"))
    assert [p.name for p in paths] == [JSON_FILENAME]


def test_write_reports_emits_report_generated(tmp_path: Path):
    from vibeguard.core.events import EventBus

    seen: list[dict] = []
    bus = EventBus()
    bus.subscribe("report.generated", lambda _n, payload: seen.append(payload))
    write_reports(make_report(), tmp_path, ("md", "html"), events=bus)

    assert len(seen) == 1
    assert len(seen[0]["paths"]) == 3


def test_the_written_json_round_trips(tmp_path: Path):
    from vibeguard.core.models import ScanReport

    original = make_report(make_finding())
    path = write_reports(original, tmp_path, ())[0]
    restored = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert restored.findings[0].fingerprint == original.findings[0].fingerprint
