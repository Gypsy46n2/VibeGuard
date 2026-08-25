"""Engine — discovery → rule selection → detection → dedup → scoring → report.

INTERFACES.md §9: ``Engine(config).audit(path) / .fix(path, mode) / .ci(path)``.
M1 implements audit and ci; fix arrives in M3.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from vibeguard import __version__
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import (
    Category,
    Finding,
    ScanReport,
    Severity,
)
from vibeguard.core.registry import RuleRegistry, build_registry
from vibeguard.core.rule import Rule
from vibeguard.discovery.context import ScanContext
from vibeguard.discovery.files import collect_files
from vibeguard.discovery.graph import build_graph
from vibeguard.discovery.scale import detect_scale
from vibeguard.discovery.tech import detect_tech
from vibeguard.reporting.scoring import score_findings

__all__ = ["Engine", "EXIT_OK", "EXIT_FINDINGS", "EXIT_ERROR", "EXIT_DIRTY_WORKTREE"]

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_DIRTY_WORKTREE = 3

FixMode = Literal["safe", "interactive"]


class Engine:
    """Runs the VibeGuard pipeline over a repository."""

    def __init__(
        self,
        config: VibeguardConfig | None = None,
        *,
        events: EventBus | None = None,
        registry: RuleRegistry | None = None,
    ) -> None:
        self.config = config or VibeguardConfig()
        self.events = events or EventBus()
        self._registry = registry

    # ------------------------------------------------------------- registry
    @property
    def registry(self) -> RuleRegistry:
        if self._registry is None:
            self._registry = build_registry(self.config.packs)
        return self._registry

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
        )
        ctx._read_cache.update(cache)
        return ctx

    # ------------------------------------------------------------- selection
    def select_rules(self, ctx: ScanContext) -> list[Rule]:
        """Instantiated rules whose applicability gate passes for this repo."""
        selected: list[Rule] = []
        for rule in self.registry.instantiate():
            try:
                if rule.applicable(ctx):
                    selected.append(rule)
            except Exception:
                log.warning("rule %s applicable() failed (skipped)", rule.id, exc_info=True)
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

    # ----------------------------------------------------------------- audit
    def audit(self, path: str | Path, *, mode: str = "audit") -> ScanReport:
        """Full read-only pipeline; never writes to the target repository."""
        root = Path(path).resolve()
        self.events.emit("scan.started", repo=str(root), mode=mode)

        ctx = self.build_context(root)
        self.events.emit("scan.stage", stage="rule_selection")
        rules = self.select_rules(ctx)
        applicable_categories = {rule.category for rule in rules}

        self.events.emit("scan.stage", stage="detection")
        findings = self._dedup(self._detect(ctx, rules))

        self.events.emit("scan.stage", stage="scoring")
        scores, overall = score_findings(findings, applicable_categories)
        counts = self._counts(findings)

        report = ScanReport(
            repo=str(root),
            scan_date=datetime.now(UTC),
            vibeguard_version=__version__,
            mode=mode,
            tech=ctx.tech,
            scale=ctx.scale,
            graph=ctx.graph,
            findings=findings,
            scores_before=scores,
            scores_after=None,
            overall_before=overall,
            overall_after=None,
            counts=counts,
            regression=None,
            adapters_used=[],
            validators_used=[],
            ai_used=False,
            local_only=self.config.local_only or self.config.ai.provider == "null",
            suppressions=[],
        )
        self.events.emit(
            "scan.completed",
            repo=str(root),
            mode=mode,
            findings=len(findings),
            counts=counts,
            overall=overall,
        )
        return report

    @staticmethod
    def _counts(findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        counts["total"] = len(findings)
        counts["suppressed"] = 0
        for category in Category:
            counts.setdefault(f"category:{category.value}", 0)
        for finding in findings:
            if finding.suppressed:
                counts["suppressed"] += 1
                continue
            counts[finding.severity.value] += 1
            counts[f"category:{finding.category.value}"] += 1
            if finding.fix is not None:
                key = f"status:{finding.fix.status.value}"
                counts[key] = counts.get(key, 0) + 1
        return counts

    # ------------------------------------------------------------------- fix
    def fix(self, path: str | Path, mode: FixMode = "safe") -> ScanReport:
        """Repair pipeline — implemented in M3 (fixers + validation ladder)."""
        raise NotImplementedError("M3")

    # -------------------------------------------------------------------- ci
    def ci(self, path: str | Path) -> tuple[ScanReport, int]:
        """Audit plus the ``fail_on`` threshold check; returns (report, exit code)."""
        report = self.audit(path, mode="ci")
        exit_code = EXIT_FINDINGS if self.threshold_breached(report) else EXIT_OK
        return report, exit_code

    def threshold_breached(self, report: ScanReport) -> bool:
        """True when any open finding is at or above the configured ``fail_on``."""
        threshold = self.config.ci.fail_on.order
        return any(
            not finding.suppressed and finding.severity.order >= threshold
            for finding in report.findings
        )
