"""ValidationEngine — the ladder, the baseline, and the honest verdict.

INTERFACES.md §5:

* ``validate`` runs the ladder in ARCHITECTURE.md §7 order and stops early on a hard
  failure (there is nothing to learn from running the test suite once the file does
  not parse).
* ``verdict`` returns ``FIXED`` only when there were no failures, at least one
  validator actually ran and passed, and the repro test (if one existed) passed.

**Baseline rule.** Before any fix is applied the engine runs the whole ladder once
over the untouched repository. A validator that already fails there is failing for
reasons that predate us — a broken test suite, a lint backlog — so its post-fix
result is recorded as *excluded* rather than counted against the patch. The exclusion
is visible in the step detail and in ``FixRecord.residual_risk``: we never silently
launder a pre-broken project into a green verdict.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

from vibeguard.core.events import EventBus
from vibeguard.core.models import FixStatus, ValidationStep
from vibeguard.validation.base import Validator
from vibeguard.validation.validators import default_validators

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["LADDER_ORDER", "ValidationEngine"]

log = logging.getLogger(__name__)

#: Exact ladder order (ARCHITECTURE.md §7); also the ValidationStep.name vocabulary.
LADDER_ORDER: tuple[str, ...] = (
    "syntax",
    "typecheck",
    "lint",
    "tests:targeted",
    "tests:full",
    "build",
    "container_build",
    "startup",
)

_EXCLUDED_PREFIX = "excluded — this validator already failed at baseline"


class ValidationEngine:
    """Runs the validation ladder and turns its steps into a :class:`FixStatus`."""

    def __init__(
        self,
        validators: Sequence[Validator] | None = None,
        *,
        events: EventBus | None = None,
    ) -> None:
        ladder = list(validators if validators is not None else default_validators())
        self.validators = sorted(
            ladder,
            key=lambda v: LADDER_ORDER.index(v.name) if v.name in LADDER_ORDER else len(
                LADDER_ORDER
            ),
        )
        self.events = events or EventBus()
        #: Validators that failed before any fix was applied.
        self.baseline_failures: set[str] = set()
        #: The baseline ladder, kept for the report.
        self.baseline_steps: list[ValidationStep] = []

    # ------------------------------------------------------------------ baseline
    def baseline(self, ctx: ScanContext) -> list[ValidationStep]:
        """Run the whole ladder over the untouched repository and record what fails."""
        steps = self._run_ladder(ctx, [], stop_on_failure=False, apply_baseline=False)
        self.baseline_failures = {s.name for s in steps if not s.passed and not s.skipped}
        self.baseline_steps = steps
        return steps

    # ---------------------------------------------------------------- validation
    def validate(self, ctx: ScanContext, changed_files: list[str]) -> list[ValidationStep]:
        """Run the ladder for one patch; stops at the first hard failure."""
        return self._run_ladder(ctx, changed_files, stop_on_failure=True, apply_baseline=True)

    def _run_ladder(
        self,
        ctx: ScanContext,
        changed_files: list[str],
        *,
        stop_on_failure: bool,
        apply_baseline: bool,
    ) -> list[ValidationStep]:
        steps: list[ValidationStep] = []
        for validator in self.validators:
            step = self._run_one(validator, ctx, changed_files)
            if apply_baseline and step.name in self.baseline_failures and not step.skipped:
                step = ValidationStep(
                    name=step.name,
                    passed=False,
                    skipped=True,
                    detail=f"{_EXCLUDED_PREFIX} ({step.detail})",
                )
            steps.append(step)
            if stop_on_failure and not step.passed and not step.skipped:
                break
        return steps

    def _run_one(
        self, validator: Validator, ctx: ScanContext, changed_files: list[str]
    ) -> ValidationStep:
        try:
            if not validator.available(ctx):
                return ValidationStep(
                    name=validator.name,
                    passed=False,
                    skipped=True,
                    detail="validator unavailable in this environment",
                )
            step = validator.run(ctx, list(changed_files))
        except Exception as exc:  # pragma: no cover - a validator must never crash a fix
            log.warning("validator %s raised", validator.name, exc_info=True)
            return ValidationStep(
                name=validator.name,
                passed=False,
                skipped=True,
                detail=f"validator error, result not counted: {type(exc).__name__}: {exc}",
            )
        if not isinstance(step, ValidationStep):  # pragma: no cover - defensive
            return ValidationStep(
                name=validator.name,
                passed=False,
                skipped=True,
                detail="validator returned a non-ValidationStep",
            )
        return step

    # ------------------------------------------------------------------- verdict
    def verdict(
        self, steps: Sequence[ValidationStep], repro_passed: bool | None = None
    ) -> FixStatus:
        """``FIXED`` only on real evidence; anything less is downgraded honestly."""
        failures = [s for s in steps if not s.passed and not s.skipped]
        if failures or repro_passed is False:
            return FixStatus.FAILED
        if not any(s.passed and not s.skipped for s in steps):
            return FixStatus.UNVERIFIED
        return FixStatus.FIXED

    # ------------------------------------------------------------------ reporting
    @staticmethod
    def summarise(steps: Sequence[ValidationStep]) -> str:
        """One-line evidence summary: ``syntax=pass, lint=skipped, …``."""
        if not steps:
            return "no validators ran"
        return ", ".join(
            f"{s.name}={'skipped' if s.skipped else ('pass' if s.passed else 'fail')}"
            for s in steps
        )

    def validators_used(self) -> list[str]:
        """Validator names in ladder order, for ``ScanReport.validators_used``."""
        return [validator.name for validator in self.validators]

    def baseline_note(self) -> str:
        """Human-readable note about validators excluded by the baseline rule."""
        if not self.baseline_failures:
            return ""
        return (
            "pre-existing failures excluded from fix verdicts: "
            + ", ".join(sorted(self.baseline_failures))
        )
