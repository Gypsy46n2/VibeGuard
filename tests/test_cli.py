from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.cli import REPORT_FILENAME, app

runner = CliRunner()


@pytest.fixture(autouse=True)
def wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rich truncates table columns at 80 columns; give it room to render ids."""
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("TERM", "dumb")


@pytest.fixture
def repo(sample_app: Path, tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(sample_app, target)
    return target


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("audit", "fix", "report", "ci", "baseline", "doctor", "rules"):
        assert command in result.stdout


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "vibeguard" in result.stdout


def test_audit_writes_report_and_prints_summary(repo: Path):
    result = runner.invoke(app, ["audit", str(repo)])
    assert result.exit_code == 0, result.output
    assert "VG-MAINT-001" in result.stdout
    assert "flask" in result.stdout

    report_path = repo / REPORT_FILENAME
    assert report_path.is_file()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1"
    assert data["mode"] == "audit"
    assert any(f["rule_id"] == "VG-MAINT-001" for f in data["findings"])
    assert data["overall_before"] <= 100


def test_audit_json_output(repo: Path):
    result = runner.invoke(app, ["audit", str(repo), "--output", "json"])
    assert result.exit_code == 0
    assert "schema_version" in result.stdout


def test_audit_jsonl_streams_events(repo: Path):
    result = runner.invoke(app, ["audit", str(repo), "--output", "jsonl"])
    assert result.exit_code == 0
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    names = [event["event"] for event in events]
    assert names[0] == "scan.started"
    assert "scan.issue_found" in names
    assert "scan.completed" in names
    assert "report.generated" in names
    for event in events:
        assert set(event) == {"event", "ts", "data"}


def test_audit_missing_path_exits_with_execution_error(tmp_path: Path):
    result = runner.invoke(app, ["audit", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_ci_passes_below_threshold(tmp_path: Path):
    """A clean project passes the gate and says so."""
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "README.md").write_text("# nothing to audit here\n", encoding="utf-8")
    result = runner.invoke(app, ["ci", str(clean), "--fail-on", "critical"])
    assert result.exit_code == 0
    assert "CI gate passed" in result.stdout


def test_ci_reports_the_gate_failure_on_the_vulnerable_fixture(repo: Path):
    result = runner.invoke(app, ["ci", str(repo), "--fail-on", "high"])
    assert result.exit_code == 1
    assert "CI gate failed" in result.stdout + result.stderr


def test_ci_fails_at_threshold(repo: Path):
    result = runner.invoke(app, ["ci", str(repo), "--fail-on", "medium"])
    assert result.exit_code == 1


def test_rules_lists_the_demo_rule():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "VG-MAINT-001" in result.stdout
    assert "testing" in result.stdout


def test_rules_pack_filter():
    result = runner.invoke(app, ["rules", "--pack", "secrets"])
    assert result.exit_code == 0
    assert "VG-MAINT-001" not in result.stdout


def test_doctor_reports_environment():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "python" in result.stdout
    assert "git" in result.stdout
    assert "bandit" in result.stdout


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def fixable_repo(tmp_path: Path) -> Path:
    target = tmp_path / "fixable"
    shutil.copytree(Path(__file__).parent / "fixtures" / "fixable_app", target)
    _git(target, "init", "-q")
    _git(target, "config", "user.email", "test@example.invalid")
    _git(target, "config", "user.name", "Test")
    _git(target, "add", "-A")
    _git(target, "commit", "-qm", "initial")
    return target


def test_fix_safe_repairs_and_reports(fixable_repo: Path):
    result = runner.invoke(app, ["fix", str(fixable_repo), "--safe"])
    assert result.exit_code == 0, result.output
    assert "Repairs" in result.stdout
    assert "fixed" in result.stdout
    assert "vibeguard/fix-" in result.stdout
    assert "timeout=30" in (fixable_repo / "app.py").read_text(encoding="utf-8")

    data = json.loads((fixable_repo / REPORT_FILENAME).read_text(encoding="utf-8"))
    assert data["mode"] == "fix-safe"
    assert data["overall_after"] is not None
    assert any(f.get("fix", {}) and f["fix"]["status"] == "fixed" for f in data["findings"])


def test_fix_without_a_mode_defaults_to_safe_with_a_notice(fixable_repo: Path):
    result = runner.invoke(app, ["fix", str(fixable_repo)])
    assert result.exit_code == 0, result.output
    assert "--safe" in result.stdout
    assert json.loads(
        (fixable_repo / REPORT_FILENAME).read_text(encoding="utf-8")
    )["mode"] == "fix-safe"


def test_fix_rejects_both_modes_at_once(fixable_repo: Path):
    result = runner.invoke(app, ["fix", str(fixable_repo), "--safe", "--interactive"])
    assert result.exit_code == 2


def test_fix_refuses_a_dirty_worktree_with_exit_code_three(fixable_repo: Path):
    (fixable_repo / "app.py").write_text("# scribbled\n", encoding="utf-8")
    result = runner.invoke(app, ["fix", str(fixable_repo), "--safe"])
    assert result.exit_code == 3
    assert "git stash" in result.output


def test_fix_outside_a_repository_is_an_execution_error(tmp_path: Path):
    plain = tmp_path / "plain"
    shutil.copytree(Path(__file__).parent / "fixtures" / "fixable_app", plain)
    result = runner.invoke(app, ["fix", str(plain), "--safe"])
    assert result.exit_code == 2
    assert "--allow-no-git" in result.output


def test_report_renders_the_stored_scan(repo: Path):
    runner.invoke(app, ["audit", str(repo)])
    result = runner.invoke(app, ["report", str(repo)])
    assert result.exit_code == 0
    assert "Findings by severity" in result.stdout


def test_report_without_prior_scan_is_an_execution_error(tmp_path: Path):
    result = runner.invoke(app, ["report", str(tmp_path)])
    assert result.exit_code == 2
    assert REPORT_FILENAME in result.output


def test_baseline_subcommands(repo: Path):
    created = runner.invoke(app, ["baseline", "create", str(repo)])
    assert created.exit_code == 0
    shown = runner.invoke(app, ["baseline", "show", str(repo)])
    assert shown.exit_code == 0
