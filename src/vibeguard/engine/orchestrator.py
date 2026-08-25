"""Engine — discovery → rule selection → detection → dedup → scoring → report.

INTERFACES.md §9: ``Engine(config).audit(path) / .fix(path, mode) / .ci(path)``.

Between detection and scoring the engine consults VibeGuard's own memory under
``.vibeguard/`` (INTERFACES.md §7): suppressions mark findings a human has accepted,
the baseline marks findings the team has scheduled rather than fixed, and the stored
history yields the regression diff. All three are **read**; nothing under
``.vibeguard/`` is written here — persistence stays with the caller (DECISIONS.md
D8, D32), so ``audit`` remains a pure function of the repository.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from vibeguard import __version__
from vibeguard.adapters import ToolAdapter, build_adapters
from vibeguard.ai.gateway import AIGateway
from vibeguard.baseline import (
    apply_baseline,
    apply_suppressions,
    load_baseline,
    regression_against_history,
)
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.fingerprint import normalize
from vibeguard.core.models import (
    Category,
    ChecklistItem,
    Finding,
    FixStatus,
    RegressionDiff,
    ScanReport,
    Severity,
    SuppressionEntry,
    ValidationStep,
)
from vibeguard.core.registry import RuleRegistry, build_registry
from vibeguard.core.rule import Rule
from vibeguard.discovery.context import ScanContext
from vibeguard.discovery.files import collect_files
from vibeguard.discovery.graph import build_graph
from vibeguard.discovery.scale import detect_scale
from vibeguard.discovery.tech import detect_tech
from vibeguard.engine.checklist import DetectorInfo, derive_checklist
from vibeguard.fixers.engine import ConfirmFn, FixerEngine
from vibeguard.fixers.git_safety import GitSafety
from vibeguard.reporting.scoring import score_findings
from vibeguard.validation.engine import ValidationEngine

__all__ = ["Engine", "EXIT_OK", "EXIT_FINDINGS", "EXIT_ERROR", "EXIT_DIRTY_WORKTREE"]

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_DIRTY_WORKTREE = 3

FixMode = Literal["safe", "interactive"]


@dataclass
class _Detection:
    """What one detection pass produced; shared by the audit and fix pipelines."""

    all_rules: list[Rule]
    rules: list[Rule]
    findings: list[Finding]
    adapters_used: list[str] = field(default_factory=list)
    adapters_ran: list[ToolAdapter] = field(default_factory=list)
    categories: set[Category] = field(default_factory=set)
    #: Suppression entries that were honoured or configured — reported verbatim.
    suppressions: list[SuppressionEntry] = field(default_factory=list)
    #: Non-fatal problems (expired suppressions, unreadable memory files).
    warnings: list[str] = field(default_factory=list)
    regression: RegressionDiff | None = None
    #: Rules skipped because they need an AI provider and none was available.
    ai_skipped: list[str] = field(default_factory=list)


class Engine:
    """Runs the VibeGuard pipeline over a repository."""

    def __init__(
        self,
        config: VibeguardConfig | None = None,
        *,
        events: EventBus | None = None,
        registry: RuleRegistry | None = None,
        adapters: list[ToolAdapter] | None = None,
        ai: AIGateway | None = None,
    ) -> None:
        self.config = config or VibeguardConfig()
        self.events = events or EventBus()
        self._registry = registry
        self._adapters = adapters
        self._ai = ai
        #: Populated by :meth:`fix`, so the CLI can report branch and validation context.
        self.last_git_safety: GitSafety | None = None
        self.last_validation: ValidationEngine | None = None
        #: Rule ids skipped by the last :meth:`select_rules` for want of an AI provider.
        self.last_ai_skipped: list[str] = []

    # ------------------------------------------------------------- registry
    @property
    def registry(self) -> RuleRegistry:
        if self._registry is None:
            self._registry = build_registry(self.config.packs)
        return self._registry

    @property
    def adapters(self) -> list[ToolAdapter]:
        if self._adapters is None:
            self._adapters = build_adapters()
        return self._adapters

    @property
    def ai(self) -> AIGateway:
        """The run's AI gateway. Built once, with the ``local_only`` gate applied."""
        if self._ai is None:
            self._ai = AIGateway.from_config(self.config, events=self.events)
        return self._ai

    # ------------------------------------------------------------- discovery
    def build_context(self, path: str | Path) -> ScanContext:
        """Run discovery and return the ScanContext handed to rules."""
        root = Path(path).resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"not a directory: {root}")

        self.events.emit("scan.stage", stage="discovery.files")
        files = collect_files(root, self.config.exclude)

        cache: dict[str, str] = {}

        def read(rel: str) -> str:
            cached = cache.get(rel)
            if cached is None:
                try:
                    cached = (root / rel).read_text(encoding="utf-8", errors="replace")
                except (OSError, ValueError):
                    cached = ""
                cache[rel] = cached
            return cached

        self.events.emit("scan.stage", stage="discovery.tech")
        tech = detect_tech(root, files, read)
        self.events.emit("scan.stage", stage="discovery.scale")
        scale = detect_scale(root, files, read, tech)
        self.events.emit("scan.stage", stage="discovery.graph")
        graph = build_graph(root, files, read, tech)

        ctx = ScanContext(
            root=root,
            files=files,
            tech=tech,
            graph=graph,
            scale=scale,
            config=self.config,
            ai=self.ai,
        )
        ctx._read_cache.update(cache)
        return ctx

    # ------------------------------------------------------------- selection
    def select_rules(self, ctx: ScanContext) -> list[Rule]:
        """Instantiated rules whose applicability gate passes for this repo.

        A rule declaring ``requires_ai`` is additionally gated on a usable provider.
        Without one it is *not* run — a rule that needs a model does not have a
        deterministic half we could quietly substitute — and its id is recorded so the
        report can say the scan was degraded rather than imply full coverage.
        """
        selected: list[Rule] = []
        degraded: list[str] = []
        ai_available = ctx.ai_available()
        for rule in self.registry.instantiate():
            try:
                if not rule.applicable(ctx):
                    continue
                if rule.requires_ai and not ai_available:
                    degraded.append(rule.id)
                    continue
                selected.append(rule)
            except Exception:
                log.warning("rule %s applicable() failed (skipped)", rule.id, exc_info=True)
        self.last_ai_skipped = degraded
        return selected

    # ------------------------------------------------------------- detection
    def _detect(self, ctx: ScanContext, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            self.events.emit("scan.stage", stage=f"detect:{rule.id}")
            try:
                produced = rule.detect(ctx) or []
            except Exception:
                log.warning("rule %s raised during detect (skipped)", rule.id, exc_info=True)
                continue
            for finding in produced:
                if not isinstance(finding, Finding):
                    log.warning("rule %s produced a non-Finding (ignored)", rule.id)
                    continue
                findings.append(finding)
                self.events.emit("scan.issue_found", finding=finding.model_dump(mode="json"))
        return findings

    # -------------------------------------------------------------- adapters
    def _gate_reason(self, rule: Rule, ctx: ScanContext) -> str:
        """Why ``rule`` did not apply — surfaced in NOT_APPLICABLE checklist notes."""
        if rule.requires_ai and not ctx.ai_available():
            return "requires an AI provider (none available — deterministic run)"
        if ctx.scale.scale.order < rule.min_scale.order:
            return f"requires scale >= {rule.min_scale.value} (project is {ctx.scale.scale.value})"
        if rule.technologies and not ({t.lower() for t in rule.technologies}
                                      & ctx.tech.all_technologies()):
            return "requires " + "/".join(sorted(rule.technologies)) + " (not detected)"
        return rule.not_applicable_note or "rule preconditions not met in this repository"

    def _run_adapters(self, ctx: ScanContext) -> tuple[list[Finding], list[str], list[ToolAdapter]]:
        """Run every applicable, available adapter. Returns (findings, log, ran)."""
        findings: list[Finding] = []
        used: list[str] = []
        ran: list[ToolAdapter] = []
        for adapter in self.adapters:
            try:
                if not adapter.applicable(ctx):
                    continue
                skip = adapter.skip_reason(ctx)
                if skip:
                    used.append(f"{adapter.name} (skipped: {skip})")
                    continue
                if not adapter.available():
                    used.append(f"{adapter.name} (skipped: not installed)")
                    continue
            except Exception:
                log.warning("adapter %s failed its preflight (skipped)", adapter.name,
                            exc_info=True)
                used.append(f"{adapter.name} (skipped: preflight error)")
                continue

            self.events.emit("scan.stage", stage=f"adapter:{adapter.name}")
            try:
                produced = adapter.run(ctx) or []
            except Exception:  # pragma: no cover - adapters must never crash a scan
                log.warning("adapter %s raised during run (skipped)", adapter.name, exc_info=True)
                used.append(f"{adapter.name} (skipped: run error)")
                continue
            ran.append(adapter)
            valid = [f for f in produced if isinstance(f, Finding)]
            used.append(f"{adapter.name} ({len(valid)} finding(s))")
            for finding in valid:
                self.events.emit("scan.issue_found", finding=finding.model_dump(mode="json"))
            findings.extend(valid)
        return findings, used, ran

    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        """Drop duplicate fingerprints, keeping the first occurrence."""
        seen: set[str] = set()
        unique: list[Finding] = []
        for finding in findings:
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            unique.append(finding)
        return unique

    @staticmethod
    def _merge_adapter_findings(
        builtin: list[Finding], external: list[Finding]
    ) -> list[Finding]:
        """Merge adapter findings into built-ins, preferring ours.

        Fingerprints embed the rule id, so a built-in and an adapter never share one.
        Cross-tool duplicates are matched on ``(file, normalised snippet)`` instead:
        the built-in finding is kept and annotated with the corroborating tool.
        """
        index: dict[tuple[str, str], Finding] = {}
        for finding in builtin:
            for evidence in finding.evidence:
                if evidence.snippet:
                    index.setdefault((evidence.file, normalize(evidence.snippet)), finding)

        merged = list(builtin)
        for finding in external:
            key: tuple[str, str] | None = None
            for evidence in finding.evidence:
                if evidence.snippet:
                    key = (evidence.file, normalize(evidence.snippet))
                    break
            existing = index.get(key) if key else None
            if existing is None:
                merged.append(finding)
                continue
            tool = finding.rule_id.split("-")[2] if finding.rule_id.count("-") >= 2 else "adapter"
            note = f"corroborated by {tool} ({finding.rule_id})"
            if note not in (existing.recommended_followup, ""):
                for evidence in existing.evidence:
                    if note not in evidence.note:
                        evidence.note = f"{evidence.note}; {note}".lstrip("; ")
                        break
        return merged

    # ------------------------------------------------------------- checklist
    def _detectors(
        self,
        ctx: ScanContext,
        rules: list[Rule],
        applicable: list[Rule],
        adapters_ran: list[ToolAdapter],
    ) -> list[DetectorInfo]:
        applicable_ids = {rule.id for rule in applicable}
        infos: list[DetectorInfo] = []
        for rule in rules:
            is_applicable = rule.id in applicable_ids
            infos.append(
                DetectorInfo(
                    key=rule.id,
                    topics=frozenset(rule.topics),
                    technologies=tuple(sorted(rule.technologies)),
                    applicable=is_applicable,
                    reason="" if is_applicable else self._gate_reason(rule, ctx),
                )
            )
        ran = {adapter.name for adapter in adapters_ran}
        for adapter in self.adapters:
            infos.append(
                DetectorInfo(
                    key=adapter.name,
                    topics=frozenset(adapter.topics),
                    technologies=tuple(sorted(adapter.technologies)),
                    applicable=adapter.name in ran,
                    reason="" if adapter.name in ran else f"{adapter.name} did not run",
                    rule_id_prefix=f"VG-EXT-{adapter.name}-",
                )
            )
        return infos

    def build_checklist(
        self,
        ctx: ScanContext,
        rules: list[Rule],
        applicable: list[Rule],
        adapters_ran: list[ToolAdapter],
        findings: list[Finding],
    ) -> list[ChecklistItem]:
        """Derive the full master checklist (INTERFACES.md §11) with its self-check."""
        detectors = self._detectors(ctx, rules, applicable, adapters_ran)
        return derive_checklist(detectors, findings)

    # -------------------------------------------------------------- detection
    def _detection_pass(self, ctx: ScanContext) -> _Detection:
        """Rule selection + detection + adapters + dedup, shared by audit and fix."""
        self.events.emit("scan.stage", stage="rule_selection")
        all_rules = self.registry.instantiate()
        rules = self.select_rules(ctx)
        categories = {rule.category for rule in rules}

        self.events.emit("scan.stage", stage="detection")
        findings = self._dedup(self._detect(ctx, rules))

        self.events.emit("scan.stage", stage="adapters")
        external, adapters_used, adapters_ran = self._run_adapters(ctx)
        findings = self._dedup(self._merge_adapter_findings(findings, self._dedup(external)))
        categories |= {f.category for f in external}
        detection = _Detection(
            all_rules=all_rules,
            rules=rules,
            findings=findings,
            adapters_used=adapters_used,
            adapters_ran=adapters_ran,
            categories=categories,
            ai_skipped=list(self.last_ai_skipped),
        )
        if detection.ai_skipped:
            detection.warnings.append(
                f"{len(detection.ai_skipped)} AI-assisted rule(s) did not run "
                f"({', '.join(detection.ai_skipped)}): {self.ai.describe()}. The scan is "
                "deterministic-only — coverage of those topics is not claimed."
            )
        return detection

    # ---------------------------------------------------------------- memory
    def _apply_memory(self, ctx: ScanContext, detection: _Detection) -> None:
        """Fold ``.vibeguard/`` into the detection: suppressions, baseline, history.

        Order matters. Suppressions run first, because a suppressed finding is one a
        human already judged and should not also be reported as "baselined"; the
        baseline then marks what is left. Both run *before* any repair, so the fixer
        never spends a patch on a finding somebody already waived.
        """
        self.events.emit("scan.stage", stage="suppressions")
        outcome = apply_suppressions(detection.findings, ctx.root, ctx.read)
        detection.suppressions = list(outcome.entries)
        detection.warnings.extend(outcome.warnings)

        self.events.emit("scan.stage", stage="baseline")
        baseline = load_baseline(ctx.root)
        marked = apply_baseline(
            (f for f in detection.findings if not f.suppressed), baseline
        )
        if marked and not self.config.ci.use_baseline:
            detection.warnings.append(
                f"{marked} finding(s) are in .vibeguard/baseline.json but the baseline is "
                "disabled for this run — they still count towards the CI gate"
            )

    def _apply_regression(self, ctx: ScanContext, detection: _Detection) -> None:
        """Diff against the stored history — run last, so fixes count as resolved."""
        self.events.emit("scan.stage", stage="regression")
        detection.regression = regression_against_history(detection.findings, ctx.root)

    def _build_report(
        self,
        ctx: ScanContext,
        detection: _Detection,
        *,
        mode: str,
        checklist: list[ChecklistItem],
        scores_before: list,
        overall_before: int,
        scores_after: list | None = None,
        overall_after: int | None = None,
        validators_used: list[str] | None = None,
        baseline_validation: list[ValidationStep] | None = None,
    ) -> ScanReport:
        return ScanReport(
            repo=str(ctx.root),
            scan_date=datetime.now(UTC),
            vibeguard_version=__version__,
            mode=mode,
            tech=ctx.tech,
            scale=ctx.scale,
            graph=ctx.graph,
            findings=detection.findings,
            checklist=checklist,
            scores_before=scores_before,
            scores_after=scores_after,
            overall_before=overall_before,
            overall_after=overall_after,
            counts=self._counts(detection.findings),
            regression=detection.regression,
            adapters_used=detection.adapters_used,
            validators_used=validators_used or [],
            baseline_validation=baseline_validation or [],
            # Truthful, not aspirational: ``used`` only becomes true once a completion
            # has actually come back from the provider.
            ai_used=self.ai.used,
            local_only=self.config.local_only or self.ai.is_local,
            suppressions=detection.suppressions,
            warnings=detection.warnings,
        )

    # ----------------------------------------------------------------- audit
    def audit(self, path: str | Path, *, mode: str = "audit") -> ScanReport:
        """Full read-only pipeline; never writes to the target repository."""
        root = Path(path).resolve()
        self.events.emit("scan.started", repo=str(root), mode=mode)

        ctx = self.build_context(root)
        detection = self._detection_pass(ctx)
        self._apply_memory(ctx, detection)
        self._apply_regression(ctx, detection)

        self.events.emit("scan.stage", stage="checklist")
        checklist = self.build_checklist(
            ctx, detection.all_rules, detection.rules, detection.adapters_ran, detection.findings
        )

        self.events.emit("scan.stage", stage="scoring")
        scores, overall = score_findings(detection.findings, detection.categories)

        report = self._build_report(
            ctx,
            detection,
            mode=mode,
            checklist=checklist,
            scores_before=scores,
            overall_before=overall,
        )
        self.events.emit(
            "scan.completed",
            repo=str(root),
            mode=mode,
            findings=len(detection.findings),
            counts=report.counts,
            overall=overall,
        )
        return report

    @staticmethod
    def _counts(findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        counts["total"] = len(findings)
        counts["suppressed"] = 0
        counts["baselined"] = 0
        for category in Category:
            counts.setdefault(f"category:{category.value}", 0)
        # Every fix status is seeded, so a consumer can distinguish "zero failures"
        # from "this report does not track failures".
        for status in FixStatus:
            counts[f"status:{status.value}"] = 0
        for finding in findings:
            if finding.suppressed:
                counts["suppressed"] += 1
                continue
            counts[finding.severity.value] += 1
            counts[f"category:{finding.category.value}"] += 1
            if finding.baselined:
                counts["baselined"] += 1
            if finding.fix is not None:
                counts[f"status:{finding.fix.status.value}"] += 1
        return counts

    # ------------------------------------------------------------------- fix
    def fix(
        self,
        path: str | Path,
        mode: FixMode = "safe",
        *,
        confirm: ConfirmFn | None = None,
    ) -> ScanReport:
        """Detect, repair what is provably safe, validate it, and report honestly.

        The order is deliberate: git preflight happens *before* anything is written, the
        validation baseline is captured before the first patch (so a pre-broken test
        suite cannot be blamed on our edit), and scoring is computed twice — once over
        the findings as detected, once treating validated fixes as closed.
        """
        root = Path(path).resolve()
        scan_mode = f"fix-{mode}"
        self.events.emit("scan.started", repo=str(root), mode=scan_mode)

        ctx = self.build_context(root)
        detection = self._detection_pass(ctx)
        self._apply_memory(ctx, detection)

        self.events.emit("scan.stage", stage="git.preflight")
        git = GitSafety(root, allow_no_git=self.config.fix.allow_no_git)
        state = git.preflight()
        if state.is_repo:
            self.events.emit("scan.stage", stage="git.branch")
            git.create_fix_branch()

        self.events.emit("scan.stage", stage="validation.baseline")
        validation = ValidationEngine(events=self.events)
        validation.baseline(ctx)

        self.events.emit("scan.stage", stage="repair")
        fixer = FixerEngine(
            git=git,
            validation=validation,
            rules={rule.id: rule for rule in detection.rules},
            events=self.events,
            config=self.config,
            confirm=confirm,
        )
        # A suppressed finding has already been judged by a human; spending a patch on
        # it would override that judgement (INTERFACES.md §7).
        repairable = [f for f in detection.findings if not f.suppressed]
        repaired = {f.id: f for f in fixer.repair(ctx, repairable, mode)}
        findings = [repaired.get(f.id, f) for f in detection.findings]
        detection.findings = findings
        self.last_git_safety = git
        self.last_validation = validation
        self._apply_regression(ctx, detection)

        self.events.emit("scan.stage", stage="checklist")
        checklist = self.build_checklist(
            ctx, detection.all_rules, detection.rules, detection.adapters_ran, findings
        )

        self.events.emit("scan.stage", stage="scoring")
        scores_before, overall_before = score_findings(findings, detection.categories)
        remaining = [f for f in findings if f.fix is None or f.fix.status is not FixStatus.FIXED]
        scores_after, overall_after = score_findings(remaining, detection.categories)

        report = self._build_report(
            ctx,
            detection,
            mode=scan_mode,
            checklist=checklist,
            scores_before=scores_before,
            overall_before=overall_before,
            scores_after=scores_after,
            overall_after=overall_after,
            validators_used=validation.validators_used(),
            baseline_validation=validation.baseline_steps,
        )
        self.events.emit(
            "scan.completed",
            repo=str(root),
            mode=scan_mode,
            findings=len(findings),
            counts=report.counts,
            overall=overall_after,
        )
        return report

    # -------------------------------------------------------------------- ci
    def ci(self, path: str | Path) -> tuple[ScanReport, int]:
        """Audit plus the ``fail_on`` threshold check; returns (report, exit code)."""
        report = self.audit(path, mode="ci")
        exit_code = EXIT_FINDINGS if self.threshold_breached(report) else EXIT_OK
        return report, exit_code

    def gating_findings(self, report: ScanReport) -> list[Finding]:
        """The findings the CI gate is allowed to consider.

        Suppressed findings are out unconditionally (a human accepted them). Baselined
        findings are out only when ``[ci] use_baseline`` is on — the baseline is a
        scheduling decision, and turning it off must bring those findings straight
        back into the gate rather than quietly leaving them exempt.
        """
        use_baseline = self.config.ci.use_baseline
        return [
            finding
            for finding in report.findings
            if not finding.suppressed
            and not (use_baseline and finding.baselined)
            and (finding.fix is None or finding.fix.status is not FixStatus.FIXED)
        ]

    def threshold_breached(self, report: ScanReport) -> bool:
        """True when any gating finding is at or above the configured ``fail_on``."""
        threshold = self.config.ci.fail_on.order
        return any(f.severity.order >= threshold for f in self.gating_findings(report))
