"""FixerEngine — mode gating, the sha guard, rollback, and honest FixRecords."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import ClassVar

import pytest

from conftest import context_from
from vibeguard.core.events import EventBus
from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    FixStatus,
    Patch,
    ScaleClass,
    Severity,
    ValidationStep,
)
from vibeguard.core.rule import Rule
from vibeguard.fixers.engine import FixerEngine, destructive_reason
from vibeguard.fixers.git_safety import GitSafety
from vibeguard.rules._fixes import whole_file_patch
from vibeguard.validation.base import Validator
from vibeguard.validation.engine import ValidationEngine

ORIGINAL = "value = 1\nsecond = 2\n"


class _Replacing(Rule):
    """Rewrites one line of ``app.py``; the shape every real fix() has."""

    id: ClassVar[str] = "VG-TEST-100"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "test rule"
    description: ClassVar[str] = "a rule that can repair itself"
    why_it_matters: ClassVar[str] = "it is a test"
    references: ClassVar[list[str]] = ["https://example.invalid"]
    topics: ClassVar[set[str]] = {"concurrency.resource-leaks"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.SAFE_AUTOFIX
    target: ClassVar[str] = "value = 1"
    replacement: ClassVar[str] = "value = 42"

    def detect(self, ctx) -> list[Finding]:
        return [self.make_finding(file="app.py", line=1, snippet=self.target)]

    def fix(self, ctx, finding) -> Patch | None:
        text = ctx.read("app.py")
        if self.target not in text:
            return None
        return whole_file_patch(
            finding,
            "app.py",
            text,
            text.replace(self.target, self.replacement, 1),
            description=f"replace {self.target}",
            scope="test",
            summary="replace a value",
        )


class _Second(_Replacing):
    id: ClassVar[str] = "VG-TEST-101"
    target: ClassVar[str] = "second = 2"
    replacement: ClassVar[str] = "second = 99"


class _NoPatch(_Replacing):
    id: ClassVar[str] = "VG-TEST-102"

    def fix(self, ctx, finding) -> Patch | None:
        return None


class _Review(_Replacing):
    id: ClassVar[str] = "VG-TEST-103"
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED


class _Manual(_Replacing):
    id: ClassVar[str] = "VG-TEST-104"
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def fix(self, ctx, finding) -> Patch | None:  # pragma: no cover - must never run
        raise AssertionError("a manual-change finding must never be patched")


class _Database(_Replacing):
    id: ClassVar[str] = "VG-DB-999"
    category: ClassVar[Category] = Category.DATABASE
    topics: ClassVar[set[str]] = {"database.migrations"}

    def fix(self, ctx, finding) -> Patch | None:  # pragma: no cover - must never run
        raise AssertionError("a database finding must never be patched")


class _Secretish(_Replacing):
    id: ClassVar[str] = "VG-SCR-999"
    category: ClassVar[Category] = Category.SECRETS
    topics: ClassVar[set[str]] = {"secrets.hardcoded-secrets"}
    target: ClassVar[str] = "value = 1"
    replacement: ClassVar[str] = 'token = "sk-live-0123456789abcdefghij"'


class _Passing(Validator):
    name: ClassVar[str] = "syntax"

    def run(self, ctx, changed_files) -> ValidationStep:
        return ValidationStep(name=self.name, passed=True, detail="stub pass")


class _Failing(Validator):
    name: ClassVar[str] = "syntax"

    def run(self, ctx, changed_files) -> ValidationStep:
        return ValidationStep(name=self.name, passed=False, detail="stub fail")


class _Skipping(Validator):
    name: ClassVar[str] = "syntax"

    def run(self, ctx, changed_files) -> ValidationStep:
        return ValidationStep(name=self.name, passed=False, skipped=True, detail="nothing to do")


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path):
    """A committed one-file git repository plus its ScanContext."""
    root = tmp_path / "repo"
    root.mkdir()
    ctx = context_from(root, {"app.py": ORIGINAL, "README.md": "# demo\n"})
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Test")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    return ctx


def build(repo, rules, *, validators=None, confirm=None, events=None) -> FixerEngine:
    safety = GitSafety(repo.root)
    safety.preflight()
    safety.create_fix_branch()
    return FixerEngine(
        git=safety,
        validation=ValidationEngine(validators if validators is not None else [_Passing()]),
        rules={rule.id: rule for rule in rules},
        events=events or EventBus(),
        confirm=confirm,
    )


def detect(rule, repo) -> list[Finding]:
    return rule.detect(repo)


# -------------------------------------------------------------------- happy path


def test_a_safe_fix_is_applied_validated_and_committed(repo):
    rule = _Replacing()
    fixer = build(repo, [rule])
    findings = fixer.repair(repo, detect(rule, repo), "safe")

    record = findings[0].fix
    assert record is not None
    assert record.status is FixStatus.FIXED
    assert (repo.root / "app.py").read_text(encoding="utf-8").startswith("value = 42")
    assert record.commit_sha and record.commit_sha == git(repo.root, "rev-parse", "HEAD")
    assert [step.name for step in record.validation] == ["syntax"]
    assert record.original_snippet == "value = 1"
    assert record.repaired_snippet == "value = 42"


def test_two_fixes_to_one_file_compose(repo):
    first, second = _Replacing(), _Second()
    fixer = build(repo, [first, second])
    findings = fixer.repair(repo, detect(first, repo) + detect(second, repo), "safe")

    assert [f.fix.status for f in findings] == [FixStatus.FIXED, FixStatus.FIXED]
    assert (repo.root / "app.py").read_text(encoding="utf-8") == "value = 42\nsecond = 99\n"
    assert len(fixer.commits) == 2


def test_an_unverifiable_fix_is_downgraded_to_unverified(repo):
    rule = _Replacing()
    fixer = build(repo, [rule], validators=[_Skipping()])
    findings = fixer.repair(repo, detect(rule, repo), "safe")

    record = findings[0].fix
    assert record.status is FixStatus.UNVERIFIED
    assert "applied but unverified" in record.residual_risk
    # It is still applied and committed — just not claimed as validated.
    assert "value = 42" in (repo.root / "app.py").read_text(encoding="utf-8")


# ------------------------------------------------------------------ mode gating


def test_safe_mode_does_not_touch_review_recommended_findings(repo):
    rule = _Review()
    fixer = build(repo, [rule])
    findings = fixer.repair(repo, detect(rule, repo), "safe")

    record = findings[0].fix
    assert record.status is FixStatus.NOT_ATTEMPTED
    assert "--interactive" in record.patch_summary
    assert (repo.root / "app.py").read_text(encoding="utf-8") == ORIGINAL


def test_interactive_mode_applies_an_approved_review_fix(repo):
    rule = _Review()
    seen: list[str] = []

    def approve(finding, diff):
        seen.append(diff)
        return True

    fixer = build(repo, [rule], confirm=approve)
    findings = fixer.repair(repo, detect(rule, repo), "interactive")

    assert findings[0].fix.status is FixStatus.FIXED
    assert seen and "-value = 1" in seen[0] and "+value = 42" in seen[0]


def test_interactive_mode_respects_a_declined_fix(repo):
    rule = _Review()
    fixer = build(repo, [rule], confirm=lambda finding, diff: False)
    findings = fixer.repair(repo, detect(rule, repo), "interactive")

    record = findings[0].fix
    assert record.status is FixStatus.REQUIRES_REVIEW
    assert "declined" in record.patch_summary
    assert (repo.root / "app.py").read_text(encoding="utf-8") == ORIGINAL


def test_manual_change_findings_are_never_patched_in_any_mode(repo):
    rule = _Manual()
    for mode in ("safe", "interactive"):
        fixer = build(repo, [rule], confirm=lambda finding, diff: True)
        findings = fixer.repair(repo, detect(rule, repo), mode)
        record = findings[0].fix
        assert record.status is FixStatus.REQUIRES_REVIEW
        assert (repo.root / "app.py").read_text(encoding="utf-8") == ORIGINAL


def test_destructive_domains_are_refused_even_when_marked_safe(repo):
    rule = _Database()
    fixer = build(repo, [rule], confirm=lambda finding, diff: True)
    findings = fixer.repair(repo, detect(rule, repo), "interactive")

    record = findings[0].fix
    assert record.status is FixStatus.REQUIRES_REVIEW
    assert "refused in every mode" in record.patch_summary
    assert (repo.root / "app.py").read_text(encoding="utf-8") == ORIGINAL


def test_destructive_reason_covers_schema_and_infrastructure_topics():
    finding = _Replacing().make_finding(file="app.py", line=1, snippet="x")
    assert destructive_reason(finding, _Replacing()) is None
    assert destructive_reason(finding, _Database()) is not None


# --------------------------------------------------------------------- refusals


def test_a_rule_without_a_patch_records_not_attempted(repo):
    rule = _NoPatch()
    fixer = build(repo, [rule])
    findings = fixer.repair(repo, detect(rule, repo), "safe")

    record = findings[0].fix
    assert record.status is FixStatus.NOT_ATTEMPTED
    assert "provably safe edit" in record.patch_summary
    assert (repo.root / "app.py").read_text(encoding="utf-8") == ORIGINAL


def test_a_file_changed_since_detection_aborts_its_own_fix(repo):
    rule = _Replacing()
    findings = detect(rule, repo)
    fixer = build(repo, [rule])

    # Someone edits the file between detection and repair.
    (repo.root / "app.py").write_text("value = 1\nedited elsewhere\n", encoding="utf-8")

    class _StalePatch(_Replacing):
        def fix(self, ctx, finding):
            patch = super().fix(ctx, finding)
            patch.file_edits[0].old_content_sha256 = "0" * 64
            return patch

    fixer.rules = {rule.id: _StalePatch()}
    repaired = fixer.repair(repo, findings, "safe")

    record = repaired[0].fix
    assert record.status is FixStatus.NOT_ATTEMPTED
    assert "changed on disk" in record.patch_summary
    assert (repo.root / "app.py").read_text(encoding="utf-8") == "value = 1\nedited elsewhere\n"


def test_a_failed_validation_rolls_the_file_back(repo):
    rule = _Replacing()
    fixer = build(repo, [rule], validators=[_Failing()])
    findings = fixer.repair(repo, detect(rule, repo), "safe")

    record = findings[0].fix
    assert record.status is FixStatus.FAILED
    assert "rolled back" in record.residual_risk
    assert (repo.root / "app.py").read_text(encoding="utf-8") == ORIGINAL
    assert git(repo.root, "log", "--oneline").count("\n") == 0  # only the initial commit


# ----------------------------------------------------------------------- events


def test_repair_and_validation_events_carry_the_finding_and_status(repo):
    rule = _Replacing()
    bus = EventBus()
    seen: list[tuple[str, dict]] = []
    bus.subscribe("*", lambda name, payload: seen.append((name, payload)))

    fixer = build(repo, [rule], events=bus)
    findings = fixer.repair(repo, detect(rule, repo), "safe")

    names = [name for name, _ in seen]
    assert names == [
        "repair.started",
        "validation.started",
        "validation.completed",
        "repair.completed",
    ]
    for _, payload in seen:
        assert payload["finding"] == findings[0].id
        assert payload["rule_id"] == "VG-TEST-100"
    assert dict(seen)["repair.completed"]["status"] == "fixed"


def test_a_rolled_back_fix_emits_repair_failed(repo):
    rule = _Replacing()
    bus = EventBus()
    names: list[str] = []
    bus.subscribe("repair.*", lambda name, _payload: names.append(name))
    fixer = build(repo, [rule], validators=[_Failing()], events=bus)
    fixer.repair(repo, detect(rule, repo), "safe")
    assert names == ["repair.started", "repair.failed"]


# --------------------------------------------------------------------- redaction


def test_snippets_are_redacted(repo):
    rule = _Secretish()
    fixer = build(repo, [rule])
    findings = fixer.repair(repo, detect(rule, repo), "safe")
    record = findings[0].fix
    assert "0123456789abcdefghij" not in record.repaired_snippet
    assert "[REDACTED]" in record.repaired_snippet
