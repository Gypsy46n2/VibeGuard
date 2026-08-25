"""Validator ABC and subprocess plumbing — INTERFACES.md §5.

A validator answers one question about a repository after a patch was applied, and
answers it honestly: ``passed`` when the tool ran and was happy, ``skipped`` when the
tool does not apply to this project (not configured, not installed, nothing relevant
changed). A validator never raises: a crashed or missing tool is a skip with a reason,
because "we could not check" must never read as "we checked and it is fine".
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import ValidationStep

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "CommandResult",
    "JS_EXTS",
    "PY_EXTS",
    "TS_EXTS",
    "Validator",
    "changed_with_suffix",
    "run_command",
    "skipped_step",
    "tool_available",
]

log = logging.getLogger(__name__)

PY_EXTS = (".py",)
JS_EXTS = (".js", ".mjs", ".cjs", ".jsx")
TS_EXTS = (".ts", ".tsx")

#: Output kept per step, so a report never carries megabytes of tool chatter.
MAX_DETAIL = 600


class CommandResult:
    """Outcome of one validation subprocess."""

    __slots__ = ("returncode", "output", "timed_out", "error")

    def __init__(
        self,
        returncode: int,
        output: str = "",
        *,
        timed_out: bool = False,
        error: str = "",
    ) -> None:
        self.returncode = returncode
        self.output = output
        self.timed_out = timed_out
        self.error = error

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    def tail(self, limit: int = MAX_DETAIL) -> str:
        """Last ``limit`` characters of the combined output, whitespace-normalised."""
        text = (self.error or self.output or "").strip()
        if len(text) > limit:
            text = "…" + text[-limit:]
        return " ".join(text.split())


def run_command(
    command: Sequence[str],
    *,
    cwd: str,
    timeout: int,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run ``command`` with an explicit cwd and timeout. Never raises, never shells out."""
    merged = dict(os.environ)
    merged.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            list(command),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=merged,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(1, timed_out=True, error=f"timed out after {timeout}s")
    except FileNotFoundError:
        return CommandResult(1, error=f"{command[0]} not found")
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - defensive
        return CommandResult(1, error=f"{command[0]} could not be run: {exc}")
    return CommandResult(proc.returncode, (proc.stdout or "") + (proc.stderr or ""))


def tool_available(name: str) -> bool:
    """``shutil.which`` wrapper that never raises."""
    try:
        return shutil.which(name) is not None
    except Exception:  # pragma: no cover - defensive
        return False


def changed_with_suffix(changed_files: Sequence[str], suffixes: Sequence[str]) -> list[str]:
    """Subset of ``changed_files`` whose suffix matches (case-insensitive)."""
    wanted = {s.lower() for s in suffixes}
    return [f for f in changed_files if PurePosixPath(f).suffix.lower() in wanted]


def skipped_step(name: str, detail: str) -> ValidationStep:
    """A skipped step carrying the honest reason it did not run."""
    return ValidationStep(name=name, passed=False, skipped=True, detail=detail)


class Validator(ABC):
    """One rung of the validation ladder (INTERFACES.md §5)."""

    #: Matches the ``ValidationStep.name`` values in INTERFACES.md §2.
    name: ClassVar[str]

    def available(self, ctx: ScanContext) -> bool:
        """True when this validator could run at all for this project."""
        return True

    @abstractmethod
    def run(self, ctx: ScanContext, changed_files: list[str]) -> ValidationStep:
        """Validate the repository. ``changed_files`` empty means "the whole project"."""

    # ---------------------------------------------------------------- utilities
    def _timeout(self, ctx: ScanContext, *, full: bool = True) -> int:
        fix = ctx.config.fix
        return fix.validation_timeout_full if full else fix.validation_timeout_targeted

    def _passed(self, detail: str) -> ValidationStep:
        return ValidationStep(name=self.name, passed=True, detail=detail)

    def _failed(self, detail: str) -> ValidationStep:
        return ValidationStep(name=self.name, passed=False, detail=detail)

    def _skipped(self, detail: str) -> ValidationStep:
        return skipped_step(self.name, detail)
