"""ValidationEngine — ladder order, early stop, the baseline rule, and the verdict.

The ladder's own subprocess rungs are covered through the real ``syntax`` validator
(``py_compile`` is always available); the ordering and verdict logic is exercised with
stub validators so the tests stay fast and deterministic.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from conftest import context_from
from vibeguard.core.models import FixStatus, ValidationStep
from vibeguard.validation.base import Validator
from vibeguard.validation.engine import LADDER_ORDER, ValidationEngine
from vibeguard.validation.validators import (
    ContainerBuildValidator,
    FullTestValidator,
    StartupValidator,
    SyntaxValidator,
    TargetedTestValidator,
    default_validators,
)


class _Stub(Validator):
    """A validator with a scripted outcome, recording that it ran."""

    def __init__(self, name: str, *, passed: bool = True, skipped: bool = False,
                 log: list[str] | None = None) -> None:
        self.name = name  # type: ignore[misc]
        self._passed = passed
        self._skipped = skipped
        self._log = log if log is not None else []

    def run(self, ctx, changed_files):  # noqa: D102 - test double
        self._log.append(self.name)
        return ValidationStep(
            name=self.name, passed=self._passed, skipped=self._skipped, detail="stub"
        )


class _Exploding(Validator):
    name: ClassVar[str] = "lint"

    def run(self, ctx, changed_files):  # noqa: D102 - test double
        raise RuntimeError("validator exploded")


@pytest.fixture
def ctx(tmp_path: Path):
    return context_from(tmp_path, {"app.py": "value = 1\n", "README.md": "# demo\n"})


# ----------------------------------------------------------------------- ladder


def test_the_default_ladder_is_in_the_documented_order():
    assert [v.name for v in default_validators()] == list(LADDER_ORDER)


def test_validators_run_in_ladder_order_even_when_supplied_shuffled(ctx):
    log: list[str] = []
    engine = ValidationEngine(
        [
            _Stub("tests:full", log=log),
            _Stub("syntax", log=log),
            _Stub("lint", log=log),
        ]
    )
    engine.validate(ctx, ["app.py"])
    assert log == ["syntax", "lint", "tests:full"]


def test_the_ladder_stops_at_the_first_hard_failure(ctx):
    log: list[str] = []
    engine = ValidationEngine(
        [
            _Stub("syntax", passed=False, log=log),
            _Stub("lint", log=log),
            _Stub("tests:full", log=log),
        ]
    )
    steps = engine.validate(ctx, ["app.py"])
    assert log == ["syntax"]
    assert [s.name for s in steps] == ["syntax"]


def test_a_skipped_rung_does_not_stop_the_ladder(ctx):
    log: list[str] = []
    engine = ValidationEngine(
        [_Stub("syntax", passed=False, skipped=True, log=log), _Stub("lint", log=log)]
    )
    engine.validate(ctx, ["app.py"])
    assert log == ["syntax", "lint"]


def test_a_crashing_validator_is_recorded_as_skipped_not_failed(ctx):
    engine = ValidationEngine([_Exploding()])
    steps = engine.validate(ctx, ["app.py"])
    assert steps[0].skipped is True
    assert steps[0].passed is False
    assert "validator error" in steps[0].detail
    assert engine.verdict(steps) is FixStatus.UNVERIFIED


# --------------------------------------------------------------------- baseline


def test_baseline_records_pre_existing_failures(ctx):
    engine = ValidationEngine([_Stub("tests:full", passed=False), _Stub("syntax")])
    engine.baseline(ctx)
    assert engine.baseline_failures == {"tests:full"}
    assert "tests:full" in engine.baseline_note()


def test_baseline_runs_the_whole_ladder_without_stopping(ctx):
    log: list[str] = []
    engine = ValidationEngine(
        [_Stub("syntax", passed=False, log=log), _Stub("lint", log=log)]
    )
    engine.baseline(ctx)
    assert log == ["syntax", "lint"]


def test_a_validator_that_failed_at_baseline_cannot_fail_a_fix(ctx):
    """A pre-broken test suite must not mark our repair FAILED."""
    engine = ValidationEngine([_Stub("syntax"), _Stub("tests:full", passed=False)])
    engine.baseline(ctx)

    steps = engine.validate(ctx, ["app.py"])
    tests = next(step for step in steps if step.name == "tests:full")
    assert tests.skipped is True
    assert "already failed at baseline" in tests.detail
    assert engine.verdict(steps) is FixStatus.FIXED


def test_a_validator_that_was_green_at_baseline_still_fails_a_fix(ctx):
    engine = ValidationEngine([_Stub("syntax"), _Stub("tests:full", passed=False)])
    engine.baseline_failures = set()  # nothing was broken beforehand
    steps = engine.validate(ctx, ["app.py"])
    assert engine.verdict(steps) is FixStatus.FAILED


# ---------------------------------------------------------------------- verdict


@pytest.mark.parametrize(
    ("steps", "repro", "expected"),
    [
        ([("syntax", True, False)], None, FixStatus.FIXED),
        ([("syntax", True, False), ("lint", False, True)], None, FixStatus.FIXED),
        ([("syntax", False, False)], None, FixStatus.FAILED),
        ([("syntax", True, False), ("tests:full", False, False)], None, FixStatus.FAILED),
        ([("syntax", False, True), ("lint", False, True)], None, FixStatus.UNVERIFIED),
        ([], None, FixStatus.UNVERIFIED),
        ([("syntax", True, False)], True, FixStatus.FIXED),
        ([("syntax", True, False)], False, FixStatus.FAILED),
    ],
)
def test_verdict_truth_table(steps, repro, expected):
    engine = ValidationEngine([])
    ladder = [
        ValidationStep(name=name, passed=passed, skipped=skipped)
        for name, passed, skipped in steps
    ]
    assert engine.verdict(ladder, repro) is expected


def test_all_skipped_is_unverified_never_fixed():
    engine = ValidationEngine([])
    ladder = [
        ValidationStep(name=name, passed=False, skipped=True) for name in LADDER_ORDER
    ]
    assert engine.verdict(ladder) is FixStatus.UNVERIFIED


# ------------------------------------------------------------ real validators


def test_syntax_validator_passes_on_valid_python(ctx):
    step = SyntaxValidator().run(ctx, ["app.py"])
    assert step.passed is True and step.skipped is False


def test_syntax_validator_fails_on_broken_python(tmp_path: Path):
    broken = context_from(tmp_path, {"app.py": "def f(:\n"})
    step = SyntaxValidator().run(broken, ["app.py"])
    assert step.passed is False and step.skipped is False
    assert "py_compile" in step.detail


def test_syntax_validator_skips_when_nothing_parseable_changed(ctx):
    step = SyntaxValidator().run(ctx, ["README.md"])
    assert step.skipped is True


def test_targeted_tests_skip_without_a_framework(ctx):
    step = TargetedTestValidator().run(ctx, ["app.py"])
    assert step.skipped is True
    assert "no test framework" in step.detail


def test_full_tests_are_honestly_skipped_when_the_project_has_none(ctx):
    step = FullTestValidator().run(ctx, [])
    assert step.skipped is True
    assert "no test suite" in step.detail


def test_container_build_is_skipped_without_deep_validate(ctx):
    step = ContainerBuildValidator().run(ctx, ["Dockerfile"])
    assert step.skipped is True
    assert "--deep-validate" in step.detail


def test_startup_is_documented_as_skipped(ctx):
    step = StartupValidator().run(ctx, ["app.py"])
    assert step.skipped is True
    assert "not implemented in the MVP" in step.detail


def test_targeted_tests_run_a_real_pytest_suite(tmp_path: Path):
    project = context_from(
        tmp_path,
        {
            "calc.py": "def add(a, b):\n    return a + b\n",
            "test_calc.py": (
                "from calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
            ),
        },
    )
    step = TargetedTestValidator().run(project, ["calc.py"])
    assert step.skipped is False
    if "Fatal Python error" in step.detail or "Current thread" in step.detail:
        # This box's CPython 3.14 segfaults at random C-level sites (documented in the
        # M2 notes); a crashed nested interpreter says nothing about the validator.
        pytest.skip("nested interpreter crashed — known local CPython 3.14 instability")
    assert step.passed is True


def test_targeted_tests_report_a_real_failure(tmp_path: Path):
    project = context_from(
        tmp_path,
        {
            "calc.py": "def add(a, b):\n    return a * b\n",
            "test_calc.py": (
                "from calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
            ),
        },
    )
    step = TargetedTestValidator().run(project, ["calc.py"])
    assert step.skipped is False
    assert step.passed is False


def test_summarise_reads_as_evidence():
    steps = [
        ValidationStep(name="syntax", passed=True),
        ValidationStep(name="lint", passed=False, skipped=True),
        ValidationStep(name="tests:full", passed=False),
    ]
    assert ValidationEngine.summarise(steps) == (
        "syntax=pass, lint=skipped, tests:full=fail"
    )
