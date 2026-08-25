"""Engine wiring for suppressions, the baseline, history, and the CI gate.

These are the integration-level promises of INTERFACES.md §7/§8: a suppressed finding
is reported but not scored, a baselined finding is reported but not gated, and the
regression diff describes the run as the report will present it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from conftest import write_repo
from vibeguard.baseline import save_baseline, suppressions_path, write_history
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.models import Category, Severity
from vibeguard.engine.orchestrator import EXIT_FINDINGS, EXIT_OK, Engine

VULNERABLE = {
    "app.py": (
        "import sqlite3\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/u')\n"
        "def u():\n"
        "    name = request.args.get('name')\n"
        "    conn = sqlite3.connect('app.db')\n"
        '    conn.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        "    return 'ok'\n"
        "\n"
        "app.run(debug=True)\n"
    ),
    "requirements.txt": "flask\n",
}


def build(tmp_path: Path, config: VibeguardConfig | None = None) -> Engine:
    write_repo(tmp_path, VULNERABLE)
    return Engine(config or VibeguardConfig())


def suppress(tmp_path: Path, body: str) -> None:
    path = suppressions_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def score_of(report, category: Category) -> int:
    return next(s.score for s in report.scores_before if s.category is category)


# ------------------------------------------------------------- suppressions


def test_audit_applies_file_suppressions_and_reports_them(tmp_path: Path):
    engine = build(tmp_path)
    first = engine.audit(tmp_path)
    target = first.findings[0]

    suppress(
        tmp_path,
        f"""
- fingerprint: "{target.fingerprint}"
  rule_id: {target.rule_id}
  reason: accepted_risk
  author: alice
  note: tracked in JIRA-1
""",
    )
    second = Engine(VibeguardConfig()).audit(tmp_path)
    suppressed = [f for f in second.findings if f.suppressed]

    assert len(suppressed) == 1
    assert suppressed[0].fingerprint == target.fingerprint
    assert suppressed[0].suppression is not None
    assert suppressed[0].suppression.note == "tracked in JIRA-1"
    # Still present — a suppression is a note on the record, not a deletion.
    assert target.fingerprint in {f.fingerprint for f in second.findings}
    assert second.suppressions and second.suppressions[0].author == "alice"


def test_a_suppressed_finding_is_excluded_from_scoring(tmp_path: Path):
    engine = build(tmp_path)
    before = engine.audit(tmp_path)
    security = [f for f in before.findings if f.category is Category.SECURITY]
    assert security, "fixture must produce a security finding to suppress"

    lines = "\n".join(
        f'- fingerprint: "{f.fingerprint}"\n  rule_id: {f.rule_id}\n'
        f"  reason: false_positive\n  author: alice"
        for f in security
    )
    suppress(tmp_path, lines)
    after = Engine(VibeguardConfig()).audit(tmp_path)

    assert score_of(after, Category.SECURITY) == 100
    assert score_of(after, Category.SECURITY) > score_of(before, Category.SECURITY)
    assert after.counts["suppressed"] == len(security)


def test_an_expired_suppression_comes_back_with_a_report_warning(tmp_path: Path):
    engine = build(tmp_path)
    target = engine.audit(tmp_path).findings[0]
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date().isoformat()
    suppress(
        tmp_path,
        f"""
- fingerprint: "{target.fingerprint}"
  rule_id: {target.rule_id}
  reason: temporary
  author: bob
  expires: {yesterday}
""",
    )
    report = Engine(VibeguardConfig()).audit(tmp_path)

    assert not any(f.suppressed for f in report.findings)
    assert any("expired" in warning for warning in report.warnings)


def test_an_inline_comment_suppresses_the_finding_on_its_line(tmp_path: Path):
    engine = build(tmp_path)
    target = next(f for f in engine.audit(tmp_path).findings if f.file and f.line)

    source = (tmp_path / target.file).read_text(encoding="utf-8").splitlines()
    source[target.line - 1] += f"  # vibeguard: ignore={target.rule_id}"
    (tmp_path / target.file).write_text("\n".join(source) + "\n", encoding="utf-8")

    report = Engine(VibeguardConfig()).audit(tmp_path)
    marked = [f for f in report.findings if f.suppressed]
    assert marked, "the inline comment was not honoured"
    assert all(f.suppression is not None and f.suppression.author == "inline" for f in marked)


def test_a_topic_whose_only_findings_are_suppressed_passes_with_a_note(tmp_path: Path):
    engine = build(tmp_path)
    before = engine.audit(tmp_path)
    failing = next(
        item for item in before.checklist if item.status.value == "fail" and item.finding_ids
    )
    ids = set(failing.finding_ids)
    targets = [f for f in before.findings if f.id in ids]

    suppress(
        tmp_path,
        "\n".join(
            f'- fingerprint: "{f.fingerprint}"\n  rule_id: {f.rule_id}\n'
            f"  reason: not_applicable\n  author: alice"
            for f in targets
        ),
    )
    after = Engine(VibeguardConfig()).audit(tmp_path)
    item = next(i for i in after.checklist if i.topic_id == failing.topic_id)

    assert item.status.value == "pass"
    assert "suppressed" in item.note
    assert "not_applicable" in item.note


# ------------------------------------------------------------------ baseline


def test_a_baselined_finding_is_marked_but_still_scored(tmp_path: Path):
    engine = build(tmp_path)
    first = engine.audit(tmp_path)
    save_baseline(tmp_path, first)

    second = Engine(VibeguardConfig()).audit(tmp_path)
    assert all(f.baselined for f in second.findings)
    assert second.counts["baselined"] == len(second.findings)
    # A baseline defers the work; it does not improve the score.
    assert second.overall_before == first.overall_before


def test_baseline_exempts_findings_from_the_ci_gate(tmp_path: Path):
    config = VibeguardConfig()
    config.ci.fail_on = Severity.LOW
    engine = build(tmp_path, config)

    _, before = engine.ci(tmp_path)
    assert before == EXIT_FINDINGS

    save_baseline(tmp_path, engine.audit(tmp_path))
    _, after = Engine(config).ci(tmp_path)
    assert after == EXIT_OK


def test_no_baseline_flag_brings_the_findings_straight_back(tmp_path: Path):
    config = VibeguardConfig()
    config.ci.fail_on = Severity.LOW
    engine = build(tmp_path, config)
    save_baseline(tmp_path, engine.audit(tmp_path))

    off = VibeguardConfig()
    off.ci.fail_on = Severity.LOW
    off.ci.use_baseline = False
    report, code = Engine(off).ci(tmp_path)

    assert code == EXIT_FINDINGS
    assert any("baseline is disabled" in w for w in report.warnings)


def test_suppressed_findings_are_exempt_from_ci_regardless_of_the_baseline(tmp_path: Path):
    config = VibeguardConfig()
    config.ci.fail_on = Severity.LOW
    config.ci.use_baseline = False
    engine = build(tmp_path, config)
    findings = engine.audit(tmp_path).findings

    suppress(
        tmp_path,
        "\n".join(
            f'- fingerprint: "{f.fingerprint}"\n  rule_id: {f.rule_id}\n'
            f"  reason: accepted_risk\n  author: alice"
            for f in findings
        ),
    )
    _, code = Engine(config).ci(tmp_path)
    assert code == EXIT_OK


def test_gating_findings_excludes_suppressed_baselined_and_fixed(tmp_path: Path):
    engine = build(tmp_path)
    report = engine.audit(tmp_path)
    report.findings[0].suppressed = True
    report.findings[1].baselined = True
    assert {f.id for f in engine.gating_findings(report)} == {
        f.id for f in report.findings[2:]
    }


# ------------------------------------------------------------------- history


def test_the_engine_does_not_write_to_the_repository(tmp_path: Path):
    """DECISIONS.md D8/D32: reading ``.vibeguard/`` is fine, writing it is not."""
    engine = build(tmp_path)
    engine.audit(tmp_path)
    assert not (tmp_path / ".vibeguard").exists()
    assert not (tmp_path / "vibeguard-report.json").exists()


def test_regression_is_none_on_a_first_scan(tmp_path: Path):
    assert build(tmp_path).audit(tmp_path).regression is None


def test_regression_is_attached_once_history_exists(tmp_path: Path):
    engine = build(tmp_path)
    first = engine.audit(tmp_path)
    write_history(first, tmp_path)

    second = Engine(VibeguardConfig()).audit(tmp_path)
    assert second.regression is not None
    assert second.regression.unchanged == len(first.findings)
    assert second.regression.new == []
    assert second.regression.resolved == []


def test_fixing_the_defect_shows_up_as_resolved(tmp_path: Path):
    engine = build(tmp_path)
    write_history(engine.audit(tmp_path), tmp_path)

    write_repo(tmp_path, {"app.py": "print('hello')\n"})
    after = Engine(VibeguardConfig()).audit(tmp_path)

    assert after.regression is not None
    assert after.regression.resolved


def test_a_reintroduced_defect_is_reported_as_regressed(tmp_path: Path):
    engine = build(tmp_path)
    original = engine.audit(tmp_path)
    write_history(original, tmp_path)

    clean = write_repo(tmp_path, {"app.py": "print('hello')\n"})
    fixed = Engine(VibeguardConfig()).audit(clean)
    fixed.scan_date = datetime.now(UTC) + timedelta(seconds=1)
    write_history(fixed, tmp_path)

    write_repo(tmp_path, VULNERABLE)
    back = Engine(VibeguardConfig()).audit(tmp_path)

    assert back.regression is not None
    assert back.regression.regressed, "a defect that came back must not read as merely new"


def test_report_files_are_not_scanned_as_source(tmp_path: Path):
    """Our own output must never become the next run's evidence."""
    from vibeguard.reporting import write_reports

    engine = build(tmp_path)
    first = engine.audit(tmp_path)
    write_reports(first, tmp_path, ("md", "html"))

    second = Engine(VibeguardConfig()).audit(tmp_path)
    assert {f.fingerprint for f in second.findings} == {
        f.fingerprint for f in first.findings
    }
