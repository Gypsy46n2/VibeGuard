"""GitSafety — the guarantees that make automated repair safe to run.

Every test works on a throwaway repository created in ``tmp_path``; nothing here
touches the repository VibeGuard itself lives in.
"""

from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path

import pytest

from vibeguard.core.models import FileEdit, Patch
from vibeguard.fixers.git_safety import (
    BACKUP_SUFFIX,
    CO_AUTHOR_TRAILER,
    DirtyWorktreeError,
    GitSafety,
    NoGitRepoError,
)
from vibeguard.rules._fixes import sha256_text


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Test")
    git(root, "config", "commit.gpgsign", "false")
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    (root / "other.py").write_text("other = 1\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    return root


def patch_for(root: Path, relpath: str, new_content: str) -> Patch:
    current = (root / relpath).read_text(encoding="utf-8")
    return Patch(
        finding_id="VG-TEST-001:abc",
        file_edits=[
            FileEdit(
                path=relpath,
                old_content_sha256=sha256_text(current),
                new_content=new_content,
            )
        ],
        description="test patch",
        commit_message="fix(test): change the value [VG-TEST-001]",
    )


# ------------------------------------------------------------------- preflight


def test_preflight_records_head_and_branch(repo: Path):
    safety = GitSafety(repo)
    state = safety.preflight()
    assert state.is_repo is True
    assert state.dirty is False
    assert state.head_sha == git(repo, "rev-parse", "HEAD")
    assert state.branch == git(repo, "rev-parse", "--abbrev-ref", "HEAD")


def test_preflight_refuses_a_dirty_worktree_and_offers_stash(repo: Path):
    (repo / "app.py").write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(DirtyWorktreeError) as excinfo:
        GitSafety(repo).preflight()
    message = str(excinfo.value)
    assert "app.py" in message
    assert "git stash" in message
    assert "never stashes" in message
    # The refusal must not have touched anything.
    assert (repo / "app.py").read_text(encoding="utf-8") == "value = 2\n"


def test_untracked_files_do_not_count_as_dirty(repo: Path):
    (repo / "notes.txt").write_text("scratch\n", encoding="utf-8")
    state = GitSafety(repo).preflight()
    assert state.dirty is False


def test_preflight_refuses_a_non_repository(tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(NoGitRepoError) as excinfo:
        GitSafety(plain).preflight()
    assert "--allow-no-git" in str(excinfo.value)


def test_allow_no_git_engages_backup_mode(tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    safety = GitSafety(plain, allow_no_git=True)
    state = safety.preflight()
    assert state.is_repo is False
    assert safety.backup_mode is True


# ---------------------------------------------------------------------- branch


def test_fix_branch_uses_the_dated_name(repo: Path):
    safety = GitSafety(repo)
    safety.preflight()
    name = safety.create_fix_branch(today=date(2026, 8, 25))
    assert name == "vibeguard/fix-2026-08-25"
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == name


def test_fix_branch_suffixes_on_collision(repo: Path):
    today = date(2026, 8, 25)
    first = GitSafety(repo)
    first.preflight()
    first.create_fix_branch(today=today)
    git(repo, "checkout", "-q", "-")

    second = GitSafety(repo)
    second.preflight()
    assert second.create_fix_branch(today=today) == "vibeguard/fix-2026-08-25-2"
    git(repo, "checkout", "-q", "-")

    third = GitSafety(repo)
    third.preflight()
    assert third.create_fix_branch(today=today) == "vibeguard/fix-2026-08-25-3"


def test_the_original_branch_is_left_untouched(repo: Path):
    original = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    original_sha = git(repo, "rev-parse", "HEAD")
    safety = GitSafety(repo)
    safety.preflight()
    safety.create_fix_branch()

    (repo / "app.py").write_text("value = 2\n", encoding="utf-8")
    safety.commit(patch_for(repo, "app.py", "value = 2\n"))

    assert git(repo, "rev-parse", original) == original_sha
    assert safety.original_branch == original


# ---------------------------------------------------------------------- commit


def test_commit_stages_only_the_patch_files(repo: Path):
    safety = GitSafety(repo)
    safety.preflight()
    safety.create_fix_branch()

    patch = patch_for(repo, "app.py", "value = 2\n")
    (repo / "app.py").write_text("value = 2\n", encoding="utf-8")
    # An unrelated edit made after preflight must not be swept into the commit.
    (repo / "other.py").write_text("other = 99\n", encoding="utf-8")

    sha = safety.commit(patch)
    assert sha == git(repo, "rev-parse", "HEAD")
    changed = git(repo, "show", "--name-only", "--format=", "HEAD").split()
    assert changed == ["app.py"]
    assert "other.py" in git(repo, "status", "--porcelain")


def test_commit_message_carries_the_conventional_subject_and_trailer(repo: Path):
    safety = GitSafety(repo)
    safety.preflight()
    safety.create_fix_branch()
    (repo / "app.py").write_text("value = 2\n", encoding="utf-8")
    safety.commit(patch_for(repo, "app.py", "value = 2\n"))

    message = git(repo, "log", "-1", "--format=%B")
    assert message.splitlines()[0] == "fix(test): change the value [VG-TEST-001]"
    assert CO_AUTHOR_TRAILER in message


# -------------------------------------------------------------------- rollback


def test_rollback_restores_the_committed_content(repo: Path):
    safety = GitSafety(repo)
    safety.preflight()
    safety.create_fix_branch()
    (repo / "app.py").write_text("value = 999\n", encoding="utf-8")

    safety.rollback_working_tree(["app.py"])
    assert (repo / "app.py").read_text(encoding="utf-8") == "value = 1\n"


def test_no_git_mode_backs_up_and_restores_orig_files(tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("value = 1\n", encoding="utf-8")

    safety = GitSafety(plain, allow_no_git=True)
    safety.preflight()
    safety.prepare(["app.py"])
    backup = plain / f"app.py{BACKUP_SUFFIX}"
    assert backup.is_file()
    assert backup.read_text(encoding="utf-8") == "value = 1\n"

    (plain / "app.py").write_text("value = 2\n", encoding="utf-8")
    safety.rollback_working_tree(["app.py"])
    assert (plain / "app.py").read_text(encoding="utf-8") == "value = 1\n"
    assert not backup.exists()


def test_no_git_mode_commits_nothing(tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("value = 1\n", encoding="utf-8")
    safety = GitSafety(plain, allow_no_git=True)
    safety.preflight()
    assert safety.create_fix_branch() == ""
    assert safety.commit(patch_for(plain, "app.py", "value = 2\n")) is None
    assert "orig" in safety.describe()
