"""Git safety net for the repair loop — INTERFACES.md §5, ARCHITECTURE.md §7.

Nothing in VibeGuard writes to a repository before :meth:`GitSafety.preflight` has
answered three questions: is this a git repository, is the worktree clean, and where
was HEAD when we started. A dirty worktree is refused (never stashed automatically),
fixes land on a dedicated ``vibeguard/fix-YYYY-MM-DD`` branch, each fix is one commit
that stages **only** the files its patch touched, and a failed validation rolls the
working tree back to the pre-fix content.

Non-git directories are audit-only unless ``[fix] allow_no_git`` is set, in which case
the same guarantees are approximated with ``<file>.orig`` backups.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from datetime import date
from pathlib import Path

from vibeguard.core.models import GitState, Patch

__all__ = [
    "BACKUP_SUFFIX",
    "BRANCH_PREFIX",
    "CO_AUTHOR_TRAILER",
    "DirtyWorktreeError",
    "GitCommandError",
    "GitSafety",
    "GitSafetyError",
    "NoGitRepoError",
]

log = logging.getLogger(__name__)

#: Every commit VibeGuard writes carries this trailer.
CO_AUTHOR_TRAILER = "Co-Authored-By: VibeGuard <noreply@vibeguard.dev>"
BRANCH_PREFIX = "vibeguard/fix-"
BACKUP_SUFFIX = ".orig"

_FALLBACK_IDENTITY = (
    "-c",
    "user.name=VibeGuard",
    "-c",
    "user.email=noreply@vibeguard.dev",
)
_IDENTITY_ERROR = "unable to auto-detect email address"
_MAX_BRANCH_SUFFIX = 100


class GitSafetyError(RuntimeError):
    """Base class for every refusal or failure in the git safety layer."""


class NoGitRepoError(GitSafetyError):
    """The target directory is not inside a git repository."""


class DirtyWorktreeError(GitSafetyError):
    """The worktree has uncommitted changes to tracked files (CLI exit code 3)."""

    def __init__(self, paths: Sequence[str]) -> None:
        self.paths = list(paths)
        shown = ", ".join(self.paths[:5]) + (" …" if len(self.paths) > 5 else "")
        super().__init__(
            "refusing to repair a dirty worktree — uncommitted changes to tracked "
            f"files: {shown}. Commit them, or stash them yourself with `git stash "
            "--include-untracked`, then run vibeguard fix again. VibeGuard never "
            "stashes on your behalf."
        )


class GitCommandError(GitSafetyError):
    """A git subprocess exited non-zero."""

    def __init__(self, args: Sequence[str], returncode: int, stderr: str) -> None:
        self.args_run = list(args)
        self.returncode = returncode
        self.stderr = stderr.strip()
        super().__init__(
            f"git {' '.join(args)} failed with exit code {returncode}"
            + (f": {self.stderr}" if self.stderr else "")
        )


class GitSafety:
    """Preflight, branch, commit, and rollback for the repair loop."""

    def __init__(
        self,
        root: str | Path,
        *,
        allow_no_git: bool = False,
        timeout: int = 120,
    ) -> None:
        self.root = Path(root).resolve()
        self.allow_no_git = allow_no_git
        self.timeout = timeout
        #: Populated by :meth:`preflight`.
        self.state = GitState()
        #: True when running without git, using ``.orig`` backups instead.
        self.backup_mode = False
        #: Branch we were on before :meth:`create_fix_branch`.
        self.original_branch: str | None = None
        #: Branch fixes are committed to; None until a branch is created.
        self.fix_branch: str | None = None
        self._backed_up: set[str] = set()

    # ----------------------------------------------------------------- plumbing
    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run a git command with an explicit cwd. Never uses a shell."""
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:  # git not installed
            raise GitSafetyError(
                "git is not installed or not on PATH; run with --allow-no-git to repair "
                "with .orig backups instead"
            ) from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise GitSafetyError(f"git {' '.join(args)} could not be run: {exc}") from exc
        if check and proc.returncode != 0:
            raise GitCommandError(args, proc.returncode, proc.stderr or "")
        return proc

    def _out(self, *args: str) -> str:
        return self._run(*args).stdout.strip()

    # ---------------------------------------------------------------- preflight
    def is_repo(self) -> bool:
        """True when ``root`` sits inside a git worktree."""
        try:
            proc = self._run("rev-parse", "--is-inside-work-tree", check=False)
        except GitSafetyError:
            return False
        return proc.returncode == 0 and proc.stdout.strip() == "true"

    def dirty_paths(self) -> list[str]:
        """Tracked files with staged or unstaged modifications.

        Untracked files are not counted: they cannot be clobbered by a rollback and are
        never staged by :meth:`commit`, which is pathspec-limited to the patch's files.
        """
        proc = self._run("status", "--porcelain", "--untracked-files=no", check=False)
        if proc.returncode != 0:
            return []
        paths: list[str] = []
        for line in proc.stdout.splitlines():
            if len(line) < 4:
                continue
            path = line[3:].strip()
            if " -> " in path:  # rename
                path = path.split(" -> ", 1)[1]
            paths.append(path.strip('"'))
        return paths

    def preflight(self) -> GitState:
        """Verify the repository is safe to write to, and record where HEAD was.

        Raises :class:`NoGitRepoError` outside a repository (unless ``allow_no_git``)
        and :class:`DirtyWorktreeError` when tracked files carry uncommitted changes.
        """
        if not self.is_repo():
            if not self.allow_no_git:
                raise NoGitRepoError(
                    f"{self.root} is not a git repository. VibeGuard will not modify "
                    "files it cannot roll back. Run `git init` and commit your work, or "
                    "pass --allow-no-git to repair with .orig backups instead."
                )
            self.backup_mode = True
            self.state = GitState(is_repo=False)
            return self.state

        dirty = self.dirty_paths()
        if dirty:
            self.state = GitState(is_repo=True, dirty=True, dirty_paths=dirty)
            raise DirtyWorktreeError(dirty)

        head = self._run("rev-parse", "HEAD", check=False)
        branch = self._run("rev-parse", "--abbrev-ref", "HEAD", check=False)
        self.original_branch = branch.stdout.strip() or None
        self.state = GitState(
            is_repo=True,
            head_sha=head.stdout.strip() or None,
            branch=self.original_branch,
            dirty=False,
        )
        return self.state

    # ------------------------------------------------------------------- branch
    def branch_exists(self, name: str) -> bool:
        proc = self._run("rev-parse", "--verify", "--quiet", f"refs/heads/{name}", check=False)
        return proc.returncode == 0

    def create_fix_branch(self, *, today: date | None = None) -> str:
        """Create and switch to ``vibeguard/fix-YYYY-MM-DD[-N]``.

        Never renames, deletes, or force-updates a branch the user owns: if today's
        name is taken the suffix is incremented until a free name is found.
        """
        if self.backup_mode:
            return ""
        base = BRANCH_PREFIX + (today or date.today()).isoformat()
        name = base
        suffix = 2
        while self.branch_exists(name):
            if suffix > _MAX_BRANCH_SUFFIX:  # pragma: no cover - absurd repo state
                raise GitSafetyError(
                    f"{_MAX_BRANCH_SUFFIX} branches named {base}-N already exist; "
                    "clean some up before running fix again"
                )
            name = f"{base}-{suffix}"
            suffix += 1
        self._run("checkout", "-b", name)
        self.fix_branch = name
        return name

    # -------------------------------------------------------------------- write
    def prepare(self, paths: Iterable[str]) -> None:
        """Back up ``paths`` before they are edited (no-git mode only)."""
        if not self.backup_mode:
            return
        for rel in paths:
            source = self.root / rel
            backup = source.with_name(source.name + BACKUP_SUFFIX)
            if rel in self._backed_up or not source.is_file():
                continue
            try:
                shutil.copy2(source, backup)
            except OSError as exc:  # pragma: no cover - filesystem specific
                raise GitSafetyError(f"could not back up {rel}: {exc}") from exc
            self._backed_up.add(rel)

    def commit(self, patch: Patch) -> str | None:
        """Commit exactly the files ``patch`` touched; returns the new sha.

        The message is the patch's conventional-commit subject with the VibeGuard
        co-author trailer appended. Returns ``None`` in no-git (backup) mode.
        """
        paths = [edit.path for edit in patch.file_edits]
        if self.backup_mode or not paths:
            return None
        message = patch.commit_message.rstrip()
        if CO_AUTHOR_TRAILER not in message:
            message = f"{message}\n\n{CO_AUTHOR_TRAILER}"
        self._run("add", "--", *paths)
        args = ["commit", "-m", message, "--", *paths]
        proc = self._run(*args, check=False)
        if proc.returncode != 0 and _IDENTITY_ERROR in (proc.stderr or ""):
            # No committer identity configured: fall back to VibeGuard's own, rather
            # than failing a repair that is otherwise complete.
            proc = self._run(*_FALLBACK_IDENTITY, *args, check=False)
        if proc.returncode != 0:
            raise GitCommandError(args, proc.returncode, proc.stderr or "")
        return self._out("rev-parse", "HEAD")

    def rollback_working_tree(self, paths: Sequence[str]) -> None:
        """Restore ``paths`` to their committed (or backed-up) content."""
        if not paths:
            return
        if self.backup_mode:
            for rel in paths:
                target = self.root / rel
                backup = target.with_name(target.name + BACKUP_SUFFIX)
                if not backup.is_file():
                    continue
                try:
                    shutil.copy2(backup, target)
                    backup.unlink()
                except OSError:  # pragma: no cover - filesystem specific
                    log.warning("could not restore %s from its .orig backup", rel)
                self._backed_up.discard(rel)
            return
        for rel in paths:
            proc = self._run("checkout", "--", rel, check=False)
            if proc.returncode != 0:
                log.warning("could not roll back %s: %s", rel, (proc.stderr or "").strip())

    # ------------------------------------------------------------------ reporting
    def describe(self) -> str:
        """One line describing the safety mode in force, for reports and the CLI."""
        if self.backup_mode:
            return "no git repository — edits are backed up as <file>.orig (--allow-no-git)"
        return (
            f"git: branch {self.fix_branch or self.state.branch}, "
            f"started from {(self.state.head_sha or '?')[:12]} on "
            f"{self.original_branch or '?'}"
        )
