"""CLI surface for M4: ``--output`` lists, ``report``, ``baseline``, and ``ci``."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.baseline import baseline_path, history_files, suppressions_path
from vibeguard.cli import DEFAULT_OUTPUT, OutputError, app, parse_outputs
from vibeguard.reporting import HTML_FILENAME, JSON_FILENAME, MARKDOWN_FILENAME

runner = CliRunner()


@pytest.fixture(autouse=True)
def wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("TERM", "dumb")


@pytest.fixture
def repo(sample_app: Path, tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(sample_app, target)
    return target


# ------------------------------------------------------------ output parsing


def test_parse_outputs_splits_a_comma_list():
    assert parse_outputs("json,md,html") == {"json", "md", "html"}
    assert parse_outputs(" MD , html ") == {"md", "html"}


def test_parse_outputs_expands_all():
    assert parse_outputs("all") == {"table", "json", "md", "html"}


def test_parse_outputs_defaults_to_table_when_empty():
    assert parse_outputs("") == {"table"}
    assert parse_outputs(",,") == {"table"}


def test_parse_outputs_rejects_nonsense():
    with pytest.raises(OutputError) as excinfo:
        parse_outputs("md,pdf")
    assert "pdf" in str(excinfo.value)


def test_the_documented_default_is_table_plus_markdown():
    assert parse_outputs(DEFAULT_OUTPUT) == {"table", "md"}


def test_an_unknown_output_is_an_execution_error(repo: Path):
    result = runner.invoke(app, ["audit", str(repo), "-o", "pdf"])
    assert result.exit_code == 2
    assert "pdf" in result.output


# -------------------------------------------------------------------- audit


def test_audit_writes_json_and_markdown_by_default(repo: Path):
    result = runner.invoke(app, ["audit", str(repo)])
    assert result.exit_code == 0, result.output
    assert (repo / JSON_FILENAME).is_file()
    assert (repo / MARKDOWN_FILENAME).is_file()
    assert not (repo / HTML_FILENAME).exists()
    assert MARKDOWN_FILENAME in result.output


def test_audit_writes_all_three_formats_on_request(repo: Path):
    result = runner.invoke(app, ["audit", str(repo), "-o", "json,md,html"])
    assert result.exit_code == 0, result.output
    for name in (JSON_FILENAME, MARKDOWN_FILENAME, HTML_FILENAME):
        assert (repo / name).is_file(), name
        assert name in result.output


def test_the_canonical_json_is_written_even_when_not_requested(repo: Path):
    runner.invoke(app, ["audit", str(repo), "-o", "html"])
    assert (repo / JSON_FILENAME).is_file()


def test_audit_records_history(repo: Path):
    runner.invoke(app, ["audit", str(repo)])
    assert len(history_files(repo)) == 1
    runner.invoke(app, ["audit", str(repo)])
    assert len(history_files(repo)) == 2


def test_audit_prints_the_regression_summary_on_the_second_run(repo: Path):
    runner.invoke(app, ["audit", str(repo)])
    result = runner.invoke(app, ["audit", str(repo)])
    assert "since last scan" in result.output
    assert "unchanged" in result.output


def test_audit_says_so_when_there_is_no_history(repo: Path):
    result = runner.invoke(app, ["audit", str(repo)])
    assert "no previous scan on record" in result.output


def test_rendered_markdown_contains_the_whole_checklist(repo: Path):
    runner.invoke(app, ["audit", str(repo)])
    text = (repo / MARKDOWN_FILENAME).read_text(encoding="utf-8")
    data = json.loads((repo / JSON_FILENAME).read_text(encoding="utf-8"))
    assert f"All {len(data['checklist'])} topics" in text
    for section in {item["section"] for item in data["checklist"]}:
        assert f"### {section} (" in text


# ------------------------------------------------------------------- report


def test_report_rerenders_the_last_scan_without_rescanning(repo: Path):
    runner.invoke(app, ["audit", str(repo), "-o", "md"])
    (repo / MARKDOWN_FILENAME).unlink()
    (repo / JSON_FILENAME).unlink()

    result = runner.invoke(app, ["report", str(repo), "-o", "md,html"])
    assert result.exit_code == 0, result.output
    assert (repo / MARKDOWN_FILENAME).is_file()
    assert (repo / HTML_FILENAME).is_file()
    assert "re-rendering" in result.output
    # Re-rendering must not add a history entry: nothing was scanned.
    assert len(history_files(repo)) == 1


def test_report_falls_back_to_the_canonical_json(repo: Path):
    runner.invoke(app, ["audit", str(repo)])
    shutil.rmtree(repo / ".vibeguard")

    result = runner.invoke(app, ["report", str(repo), "-o", "html"])
    assert result.exit_code == 0, result.output
    assert JSON_FILENAME in result.output
    assert (repo / HTML_FILENAME).is_file()


def test_report_without_any_scan_is_an_execution_error(tmp_path: Path):
    result = runner.invoke(app, ["report", str(tmp_path)])
    assert result.exit_code == 2
    assert JSON_FILENAME in result.output


# ----------------------------------------------------------------- baseline


def test_baseline_create_then_show(repo: Path):
    created = runner.invoke(app, ["baseline", "create", str(repo)])
    assert created.exit_code == 0, created.output
    assert baseline_path(repo).is_file()
    assert "fingerprint(s) accepted" in created.output

    raw = json.loads(baseline_path(repo).read_text(encoding="utf-8"))
    assert set(raw) == {"created", "head_sha", "fingerprints"}
    assert raw["fingerprints"]

    shown = runner.invoke(app, ["baseline", "show", str(repo)])
    assert shown.exit_code == 0, shown.output
    assert str(len(raw["fingerprints"])) in shown.output
    assert raw["fingerprints"][0][:16] in shown.output.replace("\n", "")


def test_baseline_show_without_a_baseline_is_not_an_error(tmp_path: Path):
    result = runner.invoke(app, ["baseline", "show", str(tmp_path)])
    assert result.exit_code == 0
    assert "no baseline" in result.output


def test_baseline_show_reports_an_unreadable_file(tmp_path: Path):
    path = baseline_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["baseline", "show", str(tmp_path)])
    assert result.exit_code == 2
    assert "not readable" in result.output


def test_baseline_create_on_a_missing_directory_is_an_execution_error(tmp_path: Path):
    result = runner.invoke(app, ["baseline", "create", str(tmp_path / "nope")])
    assert result.exit_code == 2


# ----------------------------------------------------------------------- ci


def test_ci_fails_on_findings_and_passes_once_baselined(repo: Path):
    failing = runner.invoke(app, ["ci", str(repo), "--fail-on", "low"])
    assert failing.exit_code == 1
    assert "CI gate failed" in failing.output

    runner.invoke(app, ["baseline", "create", str(repo)])
    passing = runner.invoke(app, ["ci", str(repo), "--fail-on", "low"])
    assert passing.exit_code == 0, passing.output
    assert "CI gate passed" in passing.output
    assert "exempt from the gate" in passing.output


def test_ci_no_baseline_ignores_the_stored_baseline(repo: Path):
    runner.invoke(app, ["baseline", "create", str(repo)])
    result = runner.invoke(app, ["ci", str(repo), "--fail-on", "low", "--no-baseline"])
    assert result.exit_code == 1
    assert "CI gate failed" in result.output


def test_ci_prints_a_regression_summary(repo: Path):
    runner.invoke(app, ["audit", str(repo)])
    result = runner.invoke(app, ["ci", str(repo), "--fail-on", "critical"])
    assert result.exit_code == 0, result.output
    assert "since last scan" in result.output


def test_ci_respects_inline_suppressions(repo: Path):
    text = (repo / "app.py").read_text(encoding="utf-8")
    audit = runner.invoke(app, ["audit", str(repo), "-o", "json"])
    assert audit.exit_code == 0, audit.output

    data = json.loads((repo / JSON_FILENAME).read_text(encoding="utf-8"))
    in_app = [f for f in data["findings"] if f["file"] == "app.py" and f["line"]]
    assert in_app, "fixture must have a line-anchored finding in app.py"

    lines = text.splitlines()
    for finding in in_app:
        lines[finding["line"] - 1] += f"  # vibeguard: ignore={finding['rule_id']}"
    (repo / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")

    after = runner.invoke(app, ["audit", str(repo), "-o", "json,md"])
    assert after.exit_code == 0, after.output
    updated = json.loads((repo / JSON_FILENAME).read_text(encoding="utf-8"))
    assert updated["counts"]["suppressed"] >= 1

    rendered = (repo / MARKDOWN_FILENAME).read_text(encoding="utf-8")
    assert "Suppressed findings" in rendered
    assert "inline" in rendered


def test_a_suppressions_file_reaches_the_rendered_report(repo: Path):
    runner.invoke(app, ["audit", str(repo), "-o", "json"])
    data = json.loads((repo / JSON_FILENAME).read_text(encoding="utf-8"))
    target = data["findings"][0]

    path = suppressions_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'- fingerprint: "{target["fingerprint"]}"\n'
        f'  rule_id: {target["rule_id"]}\n'
        "  reason: accepted_risk\n"
        "  author: alice@example.invalid\n"
        "  note: signed off by security\n",
        encoding="utf-8",
    )
    runner.invoke(app, ["audit", str(repo), "-o", "md,html"])

    for name in (MARKDOWN_FILENAME, HTML_FILENAME):
        text = (repo / name).read_text(encoding="utf-8")
        assert "alice@example.invalid" in text, name
        assert "signed off by security" in text, name
        assert "accepted_risk" in text, name
