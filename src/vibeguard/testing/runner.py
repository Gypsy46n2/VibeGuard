"""Running generated repro tests — the "Test" rung of Detect → Explain → Repair →
**Test** → Validate → Report.

The contract the fixer engine relies on:

``prepare(ctx, finding)``
    Generate the test, write it, and run it. Return the :class:`ReproTest` **only if
    it failed** — a test that passes on unrepaired code reproduces nothing, so it is
    removed again and the fix proceeds without repro evidence.
``confirm(ctx, repro)``
    Run it again after the patch. ``True`` means the defect is provably gone.

Everything degrades to ``None``/no-op: no pytest on PATH, an unparseable target, a
timeout — all mean "no repro evidence", never a failed fix. Only a repro test that ran
and *failed* before and *passed* after is allowed to influence a verdict.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from vibeguard.core.events import EventBus
from vibeguard.core.models import Finding
from vibeguard.testing.repro import ReproTest, generate_repro_test

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ReproRunner", "ReproOutcome"]

log = logging.getLogger(__name__)

#: pytest exit codes we can interpret. 0 = passed, 1 = tests failed. Anything else
#: (2 interrupted, 3 internal error, 4 usage, 5 no tests collected) means the run told
#: us nothing about the code under test.
_PASSED, _FAILED = 0, 1


class ReproOutcome:
    """Result of one repro run: passed, failed, or inconclusive."""

    __slots__ = ("passed", "detail")

    def __init__(self, passed: bool | None, detail: str = "") -> None:
        #: ``True`` passed, ``False`` failed, ``None`` inconclusive.
        self.passed = passed
        self.detail = detail

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ReproOutcome(passed={self.passed!r}, detail={self.detail!r})"


class ReproRunner:
    """Generates repro tests and runs them with the interpreter running VibeGuard."""

    def __init__(
        self,
        *,
        events: EventBus | None = None,
        timeout: int = 120,
        enabled: bool = True,
    ) -> None:
        self.events = events or EventBus()
        self.timeout = timeout
        self.enabled = enabled
        #: Paths written during this run, so a caller can list or clean them.
        self.generated: list[str] = []

    # ------------------------------------------------------------------ generate
    def prepare(self, ctx: ScanContext, finding: Finding) -> ReproTest | None:
        """Generate + write + run. Returns the test only when it reproduces the defect."""
        if not self.enabled:
            return None
        repro = generate_repro_test(finding)
        if repro is None:
            return None
        try:
            self._write(ctx.root, repro)
        except OSError as exc:
            log.warning("could not write repro test %s: %s", repro.path, exc)
            return None

        self.events.emit(
            "repro.generated",
            finding=finding.id,
            rule_id=finding.rule_id,
            path=repro.path,
            describes=repro.describes,
        )
        outcome = self.run(ctx.root, repro)
        self.events.emit(
            "repro.result",
            finding=finding.id,
            rule_id=finding.rule_id,
            path=repro.path,
            phase="before",
            passed=outcome.passed,
            detail=outcome.detail,
        )
        if outcome.passed is False:
            self.generated.append(repro.path)
            return repro

        # Passing (or inconclusive) before the fix means this is not a reproduction.
        # Keeping it would let a meaningless green tick masquerade as evidence.
        self._remove(ctx.root, repro)
        return None

    def confirm(self, ctx: ScanContext, repro: ReproTest) -> bool | None:
        """Re-run after the patch: ``True`` when the defect is provably gone."""
        outcome = self.run(ctx.root, repro)
        self.events.emit(
            "repro.result",
            finding=repro.finding_id,
            rule_id=repro.rule_id,
            path=repro.path,
            phase="after",
            passed=outcome.passed,
            detail=outcome.detail,
        )
        return outcome.passed

    # ---------------------------------------------------------------------- run
    def run(self, root: Path, repro: ReproTest) -> ReproOutcome:
        """Run one generated test file with pytest. Never raises."""
        command = [
            sys.executable,
            "-m",
            "pytest",
            repro.path,
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ]
        try:
            proc = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ReproOutcome(None, f"repro test timed out after {self.timeout}s")
        except OSError as exc:
            return ReproOutcome(None, f"could not run pytest: {exc}")

        tail = (proc.stdout or proc.stderr or "").strip().splitlines()
        detail = tail[-1][:200] if tail else f"pytest exited {proc.returncode}"
        if proc.returncode == _PASSED:
            return ReproOutcome(True, detail)
        if proc.returncode == _FAILED:
            return ReproOutcome(False, detail)
        return ReproOutcome(None, f"pytest exited {proc.returncode}: {detail}")

    # -------------------------------------------------------------------- files
    @staticmethod
    def _write(root: Path, repro: ReproTest) -> None:
        destination = root / repro.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(repro.content, encoding="utf-8")

    @staticmethod
    def _remove(root: Path, repro: ReproTest) -> None:
        try:
            (root / repro.path).unlink()
        except OSError:  # pragma: no cover - best effort
            log.debug("could not remove %s", repro.path, exc_info=True)
