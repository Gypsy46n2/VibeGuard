"""FixerEngine — the per-finding repair loop (INTERFACES.md §5, ARCHITECTURE.md §7).

One finding at a time:

``rule.fix()`` → sha-check against disk → apply → validate → commit **or** rollback →
attach a :class:`~vibeguard.core.models.FixRecord`.

Three invariants hold in every mode:

* ``safe`` applies only ``SAFE_AUTOFIX`` findings; ``interactive`` additionally offers
  ``REVIEW_RECOMMENDED`` ones with a unified diff and a confirmation prompt.
* ``MANUAL_CHANGE_REQUIRED`` findings, and anything touching schemas, migrations,
  infrastructure, or authentication, are **never** applied — they get
  ``REQUIRES_REVIEW`` with the remediation instructions instead.
* Files are re-read between fixes and every patch is recomputed against current disk
  content, so two fixes to the same file compose instead of overwriting each other.
"""

from __future__ import annotations

import difflib
import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Literal

from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Finding,
    FixRecord,
    FixStatus,
    Patch,
)
from vibeguard.core.redact import redact
from vibeguard.core.rule import Rule
from vibeguard.fixers.git_safety import GitSafety, GitSafetyError
from vibeguard.rules._fixes import sha256_text
from vibeguard.validation.engine import ValidationEngine

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["FixerEngine", "FixMode", "destructive_reason"]

log = logging.getLogger(__name__)

FixMode = Literal["safe", "interactive"]

#: Confirmation callback: ``(finding, unified_diff) -> approve?``
ConfirmFn = Callable[[Finding, str], bool]

_SNIPPET_LIMIT = 400

#: Domains whose automated repair is refused in every mode: a wrong edit here is not a
#: bad diff, it is data loss or an outage.
_DESTRUCTIVE_CATEGORIES = frozenset({Category.DATABASE})
_DESTRUCTIVE_TOPIC_PREFIXES = ("database.", "iac.", "kubernetes.")
_DESTRUCTIVE_TOPIC_MARKERS = ("migration", "schema", "auth", "backup", "encryption-at-rest")


def destructive_reason(finding: Finding, rule: Rule | None) -> str | None:
    """Why this finding must never be auto-repaired, or ``None`` when it may be."""
    if finding.category in _DESTRUCTIVE_CATEGORIES:
        return f"{finding.category.value} changes are never applied automatically"
    topics = set(getattr(rule, "topics", set()) or ())
    for topic in sorted(topics):
        if topic.startswith(_DESTRUCTIVE_TOPIC_PREFIXES):
            return f"topic {topic} covers schema or infrastructure state"
        if any(marker in topic for marker in _DESTRUCTIVE_TOPIC_MARKERS):
            return f"topic {topic} covers migration, schema, or authentication behaviour"
    return None


class FixerEngine:
    """Applies patches, validates them, and records what really happened."""

    def __init__(
        self,
        *,
        git: GitSafety,
        validation: ValidationEngine,
        rules: dict[str, Rule],
        events: EventBus | None = None,
        config: VibeguardConfig | None = None,
        confirm: ConfirmFn | None = None,
    ) -> None:
        self.git = git
        self.validation = validation
        self.rules = rules
        self.events = events or EventBus()
        self.config = config or VibeguardConfig()
        self.confirm = confirm
        #: Commit shas produced during this run, oldest first.
        self.commits: list[str] = []

    # -------------------------------------------------------------------- entry
    def repair(
        self,
        ctx: ScanContext,
        findings: Sequence[Finding],
        mode: FixMode = "safe",
    ) -> list[Finding]:
        """Attempt every eligible finding in order; returns the same findings, annotated."""
        ordered = list(findings)
        for finding in ordered:
            if finding.suppressed or finding.fix is not None:
                continue
            record = self._repair_one(ctx, finding, mode)
            if record is not None:
                finding.fix = record
        return ordered

    # ------------------------------------------------------------------ one fix
    def _repair_one(
        self, ctx: ScanContext, finding: Finding, mode: FixMode
    ) -> FixRecord | None:
        rule = self.rules.get(finding.rule_id)
        safety = finding.autofix_safety

        if safety in {AutofixSafety.INFORMATIONAL, AutofixSafety.NOT_APPLICABLE}:
            # Advisory findings are judgement calls, not defects; the checklist already
            # reports them as REVIEW_REQUIRED. Leave them untouched.
            return None

        if safety is AutofixSafety.MANUAL_CHANGE_REQUIRED:
            return self._requires_review(
                finding, "the rule declares this change as manual: an automated edit "
                "cannot preserve the intent here"
            )

        reason = destructive_reason(finding, rule)
        if reason is not None:
            return self._requires_review(
                finding, f"refused in every mode — {reason}"
            )

        if safety is AutofixSafety.REVIEW_RECOMMENDED and mode != "interactive":
            return self._not_attempted(
                finding,
                "review-recommended fix: run `vibeguard fix --interactive` to review the "
                "diff and approve it",
            )

        if rule is None:
            return self._not_attempted(finding, "no rule registered for this finding")

        try:
            patch = rule.fix(ctx, finding)
        except Exception:  # pragma: no cover - a broken fix must not stop the run
            log.warning("rule %s raised during fix()", finding.rule_id, exc_info=True)
            return self._not_attempted(finding, "the rule's fix() raised; nothing was written")

        if patch is None or not patch.file_edits:
            return self._not_attempted(
                finding,
                "no deterministic patch: the preconditions for a provably safe edit are "
                "not met in this code, so detection reports it for manual repair",
            )

        if safety is AutofixSafety.REVIEW_RECOMMENDED and not self._approved(ctx, finding, patch):
            return self._requires_review(finding, "declined at the interactive prompt")

        return self._apply(ctx, finding, patch)

    # ------------------------------------------------------------------- apply
    def _apply(self, ctx: ScanContext, finding: Finding, patch: Patch) -> FixRecord:
        paths = [edit.path for edit in patch.file_edits]
        self.events.emit(
            "repair.started",
            finding=finding.id,
            rule_id=finding.rule_id,
            files=paths,
            summary=patch.description,
        )

        originals: dict[str, str] = {}
        for edit in patch.file_edits:
            target = ctx.root / edit.path
            try:
                current = target.read_text(encoding="utf-8")
            except OSError as exc:
                self.events.emit(
                    "repair.failed", finding=finding.id, rule_id=finding.rule_id,
                    status=FixStatus.NOT_ATTEMPTED.value, detail=str(exc),
                )
                return self._not_attempted(finding, f"{edit.path} could not be read: {exc}")
            if sha256_text(current) != edit.old_content_sha256:
                self.events.emit(
                    "repair.failed", finding=finding.id, rule_id=finding.rule_id,
                    status=FixStatus.NOT_ATTEMPTED.value,
                    detail=f"{edit.path} changed on disk",
                )
                return self._not_attempted(
                    finding,
                    f"{edit.path} changed on disk after the patch was computed; the fix "
                    "was abandoned rather than applied to unexpected content",
                )
            originals[edit.path] = current

        try:
            self.git.prepare(paths)
            for edit in patch.file_edits:
                (ctx.root / edit.path).write_text(edit.new_content, encoding="utf-8")
        except (OSError, GitSafetyError) as exc:
            self._restore(ctx, originals)
            self.events.emit(
                "repair.failed", finding=finding.id, rule_id=finding.rule_id,
                status=FixStatus.FAILED.value, detail=str(exc),
            )
            return FixRecord(
                status=FixStatus.FAILED,
                patch_summary=patch.description,
                residual_risk=f"the patch could not be written: {exc}",
            )
        self._invalidate(ctx, paths)

        snippets = self._snippets(patch, originals)

        self.events.emit("validation.started", finding=finding.id, rule_id=finding.rule_id,
                         files=paths)
        steps = self.validation.validate(ctx, paths)
        status = self.validation.verdict(steps)
        self.events.emit(
            "validation.completed",
            finding=finding.id,
            rule_id=finding.rule_id,
            status=status.value,
            steps=[step.model_dump(mode="json") for step in steps],
        )

        residual = self._residual_risk(steps, status)

        if status is FixStatus.FAILED:
            self.git.rollback_working_tree(paths)
            self._restore_if_needed(ctx, originals)
            self._invalidate(ctx, paths)
            self.events.emit(
                "repair.failed",
                finding=finding.id,
                rule_id=finding.rule_id,
                status=FixStatus.FAILED.value,
                detail=self.validation.summarise(steps),
            )
            return FixRecord(
                status=FixStatus.FAILED,
                patch_summary=patch.description,
                original_snippet=snippets[0],
                repaired_snippet=snippets[1],
                validation=steps,
                residual_risk=(
                    "the patch was rolled back after validation failed; the original "
                    "finding is unchanged. " + residual
                ).strip(),
            )

        commit_sha: str | None = None
        try:
            commit_sha = self.git.commit(patch)
        except GitSafetyError as exc:
            log.warning("commit failed for %s: %s", finding.id, exc)
            residual = (
                f"{residual} the edit is in the working tree but not committed: {exc}"
            ).strip()
        if commit_sha:
            self.commits.append(commit_sha)

        self.events.emit(
            "repair.completed",
            finding=finding.id,
            rule_id=finding.rule_id,
            status=status.value,
            commit=commit_sha,
        )
        return FixRecord(
            status=status,
            patch_summary=patch.description,
            original_snippet=snippets[0],
            repaired_snippet=snippets[1],
            commit_sha=commit_sha,
            validation=steps,
            residual_risk=residual,
        )

    # ------------------------------------------------------------------ helpers
    def _approved(self, ctx: ScanContext, finding: Finding, patch: Patch) -> bool:
        if self.confirm is None:
            return False
        diff = self.diff_preview(ctx, patch)
        try:
            return bool(self.confirm(finding, diff))
        except Exception:  # pragma: no cover - a broken prompt means "do not apply"
            log.warning("confirmation callback failed for %s", finding.id, exc_info=True)
            return False

    @staticmethod
    def diff_preview(ctx: ScanContext, patch: Patch) -> str:
        """Unified diff of the patch against the current file content."""
        chunks: list[str] = []
        for edit in patch.file_edits:
            try:
                before = (ctx.root / edit.path).read_text(encoding="utf-8")
            except OSError:  # pragma: no cover - defensive
                before = ""
            chunks.extend(
                difflib.unified_diff(
                    before.splitlines(),
                    edit.new_content.splitlines(),
                    fromfile=f"a/{edit.path}",
                    tofile=f"b/{edit.path}",
                    lineterm="",
                    n=3,
                )
            )
        return "\n".join(chunks)

    @staticmethod
    def _snippets(patch: Patch, originals: dict[str, str]) -> tuple[str, str]:
        """(original, repaired) hunks for the FixRecord, redacted."""
        removed: list[str] = []
        added: list[str] = []
        for edit in patch.file_edits:
            before = originals.get(edit.path, "")
            for line in difflib.unified_diff(
                before.splitlines(), edit.new_content.splitlines(), lineterm="", n=0
            ):
                if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
                    continue
                if line.startswith("-"):
                    removed.append(line[1:])
                elif line.startswith("+"):
                    added.append(line[1:])
        return (
            redact("\n".join(removed))[:_SNIPPET_LIMIT],
            redact("\n".join(added))[:_SNIPPET_LIMIT],
        )

    def _residual_risk(self, steps: Sequence[object], status: FixStatus) -> str:
        bits: list[str] = []
        note = self.validation.baseline_note()
        if note:
            bits.append(note)
        skipped = [
            s.name  # type: ignore[attr-defined]
            for s in steps
            if getattr(s, "skipped", False)
        ]
        if status is FixStatus.UNVERIFIED:
            bits.append(
                "no validator could confirm this edit (all rungs skipped): the change is "
                "applied but unverified"
            )
        elif skipped:
            bits.append("not exercised by: " + ", ".join(skipped))
        return " ".join(bits)

    @staticmethod
    def _invalidate(ctx: ScanContext, paths: Sequence[str]) -> None:
        """Drop cached reads/parses so the next fix sees current disk content."""
        for path in paths:
            ctx._read_cache.pop(path, None)
            ctx._ast_cache.pop(path, None)

    @staticmethod
    def _restore(ctx: ScanContext, originals: dict[str, str]) -> None:
        for path, content in originals.items():
            try:
                (ctx.root / path).write_text(content, encoding="utf-8")
            except OSError:  # pragma: no cover - filesystem specific
                log.warning("could not restore %s", path)

    def _restore_if_needed(self, ctx: ScanContext, originals: dict[str, str]) -> None:
        """Belt and braces: verify the rollback really restored the original content."""
        for path, content in originals.items():
            try:
                current = (ctx.root / path).read_text(encoding="utf-8")
            except OSError:  # pragma: no cover - defensive
                continue
            if current != content:
                self._restore(ctx, {path: content})

    # ------------------------------------------------------------------ records
    @staticmethod
    def _not_attempted(finding: Finding, detail: str) -> FixRecord:
        return FixRecord(
            status=FixStatus.NOT_ATTEMPTED,
            patch_summary=detail,
            residual_risk=finding.recommended_followup,
        )

    @staticmethod
    def _requires_review(finding: Finding, detail: str) -> FixRecord:
        return FixRecord(
            status=FixStatus.REQUIRES_REVIEW,
            patch_summary=detail,
            residual_risk=finding.recommended_followup
            or "apply the remediation described in the finding by hand",
        )
