"""Engine.fix end to end: discovery → repair → validation → checklist → scores."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import Category, ChecklistStatus, FixStatus, ScanReport
from vibeguard.engine.orchestrator import Engine
from vibeguard.fixers.git_safety import DirtyWorktreeError, NoGitRepoError

FIXTURE = Path(__file__).parent / "fixtures" / "fixable_app"


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def app_repo(tmp_path: Path) -> Path:
    """The vulnerable fixture app, committed to a throwaway git repository."""
    root = tmp_path / "app"
    shutil.copytree(FIXTURE, root)
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Test")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    return root


@pytest.fixture
def fixed(app_repo: Path) -> tuple[ScanReport, Engine, Path]:
    engine = Engine(VibeguardConfig())
    report = engine.fix(app_repo, "safe")
    return report, engine, app_repo


# ------------------------------------------------------------------- happy path


def test_fix_reports_the_mode_and_runs_the_full_pipeline(fixed):
    report, _engine, _root = fixed
    assert report.mode == "fix-safe"
    assert report.checklist, "the master checklist must still be produced"
    assert report.validators_used[0] == "syntax"
    assert report.scores_after is not None and report.overall_after is not None


def test_safe_mode_fixes_the_provable_findings_with_commits(fixed):
    report, _engine, root = fixed
    fixed_findings = [f for f in report.findings if f.fix and f.fix.status is FixStatus.FIXED]
    assert len(fixed_findings) >= 3, [f.rule_id for f in fixed_findings]
    assert {f.rule_id for f in fixed_findings} >= {"VG-API-001", "VG-OBS-001"}
    for finding in fixed_findings:
        assert finding.fix.commit_sha, f"{finding.rule_id} claims FIXED with no commit"
        assert finding.fix.validation, "a FIXED finding must carry validation evidence"
        assert any(step.passed and not step.skipped for step in finding.fix.validation)
        assert finding.fix.original_snippet and finding.fix.repaired_snippet

    log = git(root, "log", "--format=%s")
    for finding in fixed_findings:
        assert any(line.endswith(f"[{finding.rule_id}]") for line in log.splitlines())


def test_the_repaired_source_really_changed(fixed):
    _report, _engine, root = fixed
    text = (root / "app.py").read_text(encoding="utf-8")
    assert "timeout=30" in text
    assert "logger.info(" in text
    assert "print(" not in text


def test_work_lands_on_a_fix_branch_and_the_original_is_untouched(app_repo: Path):
    original_sha = git(app_repo, "rev-parse", "HEAD")
    original_branch = git(app_repo, "rev-parse", "--abbrev-ref", "HEAD")

    engine = Engine(VibeguardConfig())
    engine.fix(app_repo, "safe")

    current = git(app_repo, "rev-parse", "--abbrev-ref", "HEAD")
    assert current.startswith("vibeguard/fix-")
    assert git(app_repo, "rev-parse", original_branch) == original_sha
    assert git(app_repo, "rev-parse", "HEAD") != original_sha


def test_scores_after_improve_on_the_categories_that_were_repaired(fixed):
    report, _engine, _root = fixed
    before = {s.category: s.score for s in report.scores_before}
    after = {s.category: s.score for s in report.scores_after}
    assert after[Category.API] > before[Category.API]
    assert report.overall_after >= report.overall_before


def test_the_checklist_reports_fixed_topics_with_evidence(fixed):
    report, _engine, _root = fixed
    timeouts = next(item for item in report.checklist if item.topic_id == "api.timeouts")
    assert timeouts.status is ChecklistStatus.FIXED
    assert timeouts.fixes
    assert timeouts.validation.startswith("validated:")


def test_review_recommended_findings_are_left_for_interactive_mode(fixed):
    report, _engine, root = fixed
    review = [
        f for f in report.findings
        if f.rule_id == "VG-CTR-001" and f.fix is not None
    ]
    assert review, "the fixture Dockerfile runs as root"
    assert review[0].fix.status is FixStatus.NOT_ATTEMPTED
    assert "--interactive" in review[0].fix.patch_summary
    assert "USER appuser" not in (root / "Dockerfile").read_text(encoding="utf-8")


def test_interactive_mode_applies_approved_review_fixes(app_repo: Path):
    engine = Engine(VibeguardConfig())
    report = engine.fix(
        app_repo,
        "interactive",
        confirm=lambda finding, diff: finding.rule_id == "VG-CTR-001",
    )
    ctr = next(f for f in report.findings if f.rule_id == "VG-CTR-001")
    # Applied and committed, but honestly downgraded: no rung of the ladder can
    # confirm a Dockerfile edit unless --deep-validate builds the image.
    assert ctr.fix.status is FixStatus.UNVERIFIED
    assert ctr.fix.commit_sha
    assert "applied but unverified" in ctr.fix.residual_risk
    assert "USER appuser" in (app_repo / "Dockerfile").read_text(encoding="utf-8")
    # A finding the caller declined is recorded as needing review, not as fixed.
    declined = [
        f for f in report.findings
        if f.fix and f.fix.status is FixStatus.REQUIRES_REVIEW and "declined" in
        f.fix.patch_summary
    ]
    assert declined


def test_events_cover_the_repair_loop(app_repo: Path):
    bus = EventBus()
    names: list[str] = []
    bus.subscribe("*", lambda name, _payload: names.append(name))
    Engine(VibeguardConfig(), events=bus).fix(app_repo, "safe")

    assert names[0] == "scan.started"
    assert names[-1] == "scan.completed"
    for expected in (
        "repair.started",
        "repair.completed",
        "validation.started",
        "validation.completed",
    ):
        assert expected in names, expected


# --------------------------------------------------------------------- refusals


def test_a_dirty_worktree_stops_the_run_before_anything_is_written(app_repo: Path):
    (app_repo / "app.py").write_text("# scribbled\n", encoding="utf-8")
    with pytest.raises(DirtyWorktreeError):
        Engine(VibeguardConfig()).fix(app_repo, "safe")
    assert (app_repo / "app.py").read_text(encoding="utf-8") == "# scribbled\n"
    assert git(app_repo, "rev-parse", "--abbrev-ref", "HEAD") != "vibeguard/fix"


def test_a_non_repository_is_refused_without_allow_no_git(tmp_path: Path):
    plain = tmp_path / "plain"
    shutil.copytree(FIXTURE, plain)
    with pytest.raises(NoGitRepoError):
        Engine(VibeguardConfig()).fix(plain, "safe")
    assert "timeout=30" not in (plain / "app.py").read_text(encoding="utf-8")


def test_allow_no_git_repairs_with_orig_backups(tmp_path: Path):
    plain = tmp_path / "plain"
    shutil.copytree(FIXTURE, plain)
    config = VibeguardConfig()
    config.fix.allow_no_git = True

    report = Engine(config).fix(plain, "safe")
    fixed_findings = [f for f in report.findings if f.fix and f.fix.status is FixStatus.FIXED]

    assert fixed_findings
    assert all(f.fix.commit_sha is None for f in fixed_findings)
    assert (plain / "app.py.orig").is_file()
    assert "timeout=30" in (plain / "app.py").read_text(encoding="utf-8")
    assert "timeout=30" not in (plain / "app.py.orig").read_text(encoding="utf-8")
