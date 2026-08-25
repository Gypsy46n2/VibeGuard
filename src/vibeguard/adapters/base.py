"""External tool adapter ABC — INTERFACES.md §4.

Every adapter is **optional**. An adapter must never crash a scan: ``available()``
never raises, and ``run()`` swallows subprocess, timeout, and parse failures and
returns ``[]``. Adapter findings carry rule ids ``VG-EXT-{tool}-{native_id}`` and map
the tool's native severity onto :class:`Severity`.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.fingerprint import PROJECT_PATH, fingerprint
from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from vibeguard.core.redact import redact

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ToolAdapter", "DEFAULT_TIMEOUT", "SKIP_LOCAL_ONLY"]

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300

SKIP_LOCAL_ONLY = "local_only: tool contacts a remote service"


class ToolAdapter(ABC):
    """Base class for subprocess-backed external scanners."""

    name: ClassVar[str]
    #: Human description used by ``vibeguard doctor``.
    description: ClassVar[str] = ""
    #: Executable probed on PATH by the default :meth:`available`.
    command: ClassVar[str] = ""
    #: Default category for findings this tool produces.
    category: ClassVar[Category] = Category.SECURITY
    #: Master-checklist topic ids this adapter evaluates (INTERFACES.md §11).
    topics: ClassVar[set[str]] = set()
    technologies: ClassVar[set[str]] = set()
    #: True when the tool contacts the network — skipped under ``local_only``.
    requires_network: ClassVar[bool] = False
    timeout: ClassVar[int] = DEFAULT_TIMEOUT

    # -------------------------------------------------------------- lifecycle
    def available(self) -> bool:
        """True when the tool can be invoked. Never raises."""
        try:
            return bool(self.command) and shutil.which(self.command) is not None
        except Exception:  # pragma: no cover - defensive
            log.debug("availability probe failed for %s", self.name, exc_info=True)
            return False

    def applicable(self, ctx: ScanContext) -> bool:
        """True when this repository is worth handing to the tool."""
        if not self.technologies:
            return True
        return bool({t.lower() for t in self.technologies} & ctx.tech.all_technologies())

    def skip_reason(self, ctx: ScanContext) -> str | None:
        """Why this adapter will not run, or None when it will."""
        if self.requires_network and ctx.config.local_only:
            return SKIP_LOCAL_ONLY
        return None

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute the tool and return normalised findings. Never raises."""

    # ----------------------------------------------------------- subprocess
    def exec(
        self,
        args: list[str],
        ctx: ScanContext,
        *,
        cwd: str | None = None,
        ok_returncodes: tuple[int, ...] | None = None,
    ) -> subprocess.CompletedProcess[str] | None:
        """Run ``args`` with a timeout; return None on any failure."""
        try:
            proc = subprocess.run(  # noqa: S603 - argument list is adapter-controlled
                args,
                cwd=cwd or str(ctx.root),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("adapter %s failed to run %r: %s", self.name, args[0], exc)
            return None
        if ok_returncodes is not None and proc.returncode not in ok_returncodes:
            log.warning(
                "adapter %s exited %s: %s",
                self.name,
                proc.returncode,
                (proc.stderr or "").strip()[:300],
            )
            return None
        return proc

    def exec_json(
        self,
        args: list[str],
        ctx: ScanContext,
        *,
        cwd: str | None = None,
        ok_returncodes: tuple[int, ...] | None = None,
    ) -> Any | None:
        """Run ``args`` and parse stdout as JSON; None when anything goes wrong."""
        proc = self.exec(args, ctx, cwd=cwd, ok_returncodes=ok_returncodes)
        if proc is None:
            return None
        return self.parse_json(proc.stdout)

    @staticmethod
    def parse_json(payload: str) -> Any | None:
        """Best-effort JSON parse: tolerates leading banner lines from noisy tools."""
        if not payload:
            return None
        try:
            return json.loads(payload)
        except (ValueError, TypeError):
            pass
        for opener, closer in (("{", "}"), ("[", "]")):
            start = payload.find(opener)
            end = payload.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(payload[start : end + 1])
                except (ValueError, TypeError):
                    continue
        log.warning("could not parse tool output as JSON (%d bytes)", len(payload))
        return None

    # ------------------------------------------------------------ findings
    def rule_id(self, native_id: str) -> str:
        """``VG-EXT-{tool}-{native_id}`` per INTERFACES.md §4."""
        cleaned = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in str(native_id))
        return f"VG-EXT-{self.name}-{cleaned.strip('-') or 'unknown'}"

    def make_finding(
        self,
        *,
        native_id: str,
        title: str,
        description: str,
        why_it_matters: str,
        severity: Severity,
        confidence: Confidence = Confidence.MEDIUM,
        category: Category | None = None,
        file: str | None = None,
        line: int | None = None,
        snippet: str = "",
        references: list[str] | None = None,
        recommended_followup: str = "",
        autofix_safety: AutofixSafety = AutofixSafety.REVIEW_RECOMMENDED,
        redact_evidence: bool = False,
    ) -> Finding:
        """Build a normalised :class:`Finding` from a native tool result."""
        rid = self.rule_id(native_id)
        cat = category or self.category
        path = file or PROJECT_PATH
        fp = fingerprint(rid, path, snippet)
        force = redact_evidence or cat is Category.SECRETS
        evidence = [
            Evidence(
                file=path,
                line=line,
                snippet=redact(snippet) if force and snippet else snippet,
                note=f"reported by {self.name}",
                redact=force,
            )
        ]
        return Finding(
            id=f"{rid}:{fp[:12]}",
            rule_id=rid,
            category=cat,
            severity=severity,
            confidence=confidence,
            title=title,
            description=redact(description),
            why_it_matters=why_it_matters,
            evidence=evidence,
            file=file,
            line=line,
            autofix_safety=autofix_safety,
            fingerprint=fp,
            references=list(references or []),
            recommended_followup=recommended_followup,
        )
