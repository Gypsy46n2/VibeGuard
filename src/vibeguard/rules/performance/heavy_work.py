"""VG-PERF-004 — CPU- or memory-heavy work done inline in the request path."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import ancestors, walk
from vibeguard.rules.api._http import Handler, handlers

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["HeavyWorkInRequestPathRule"]

_MAX_FINDINGS = 5
_LOOP_TYPES = {"for_statement", "while_statement", "for_in_statement", "for_of_statement"}

_HEAVY: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("image processing", re.compile(r"\bImage\.open\s*\(|\bPIL\b|\bcv2\.|sharp\(|jimp", re.I)),
    (
        "PDF or video processing",
        re.compile(r"pdfkit|PyPDF|weasyprint|reportlab|ffmpeg|moviepy", re.I),
    ),
    ("dataframe / numeric work", re.compile(r"\bpd\.(?:read_|DataFrame)|pandas\.|\bnp\.|numpy\.")),
    ("whole-file JSON parsing", re.compile(r"json\.loads?\s*\(\s*(?:open|\w+\.read\s*\(\))")),
    ("a large in-memory sort", re.compile(r"\bsorted\s*\(\s*\w+\s*,|\.sort\s*\(\s*key\s*=")),
    ("password hashing", re.compile(r"bcrypt\.(?:hashpw|gensalt)|pbkdf2|scrypt\s*\(", re.I)),
)
_OFFLOAD = re.compile(
    r"celery|\.delay\s*\(|apply_async|\.enqueue\s*\(|BackgroundTasks|background_tasks|"
    r"add_task\s*\(|bullmq|\bqueue\b|\brq\b|dramatiq|ThreadPoolExecutor|ProcessPoolExecutor|"
    r"to_thread|run_in_executor|worker|sidekiq",
    re.IGNORECASE,
)


def _nested_loop_depth(node: Any) -> int:
    """Deepest loop nesting inside ``node`` (0 when there is no loop)."""
    if node is None:
        return 0
    deepest = 0
    for child in walk(node):
        if child.type not in _LOOP_TYPES:
            continue
        depth = 1 + sum(
            1
            for parent in ancestors(child)
            if parent.type in _LOOP_TYPES and parent.start_byte >= node.start_byte
        )
        deepest = max(deepest, depth)
    return deepest


class HeavyWorkInRequestPathRule(Rule):
    """Expensive work that should be a background job, done while the user waits."""

    id: ClassVar[str] = "VG-PERF-004"
    category: ClassVar[Category] = Category.PERFORMANCE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "CPU- or memory-intensive work in the request path"
    description: ClassVar[str] = (
        "An HTTP handler performs image/PDF/video processing, dataframe work, whole-file "
        "parsing, a large sort, or a nested loop over query results inline, with no queue "
        "or worker offload anywhere in the module."
    )
    why_it_matters: ClassVar[str] = (
        "The work occupies a request worker and a full CPU core for seconds at a time, so a "
        "handful of concurrent uploads is enough to make every other request queue behind "
        "them and time out. Memory is worse: decoding a large image or loading a file into "
        "a dataframe can spike hundreds of megabytes per request, and the container is "
        "killed outright when several arrive together."
    )
    references: ClassVar[list[str]] = [
        "https://docs.celeryq.dev/en/stable/getting-started/introduction.html",
        "https://fastapi.tiangolo.com/tutorial/background-tasks/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "performance.cpu-usage",
        "performance.memory-usage",
        "performance.worker-bottlenecks",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        offload_cache: dict[str, bool] = {}
        for handler in handlers(ctx):
            if len(findings) >= _MAX_FINDINGS:
                break
            reason = self._reason(handler)
            if reason is None:
                continue
            if handler.file not in offload_cache:
                offload_cache[handler.file] = bool(_OFFLOAD.search(ctx.read(handler.file)))
            if offload_cache[handler.file]:
                continue
            findings.append(
                self.make_finding(
                    file=handler.file,
                    line=handler.line,
                    snippet=(handler.decorator or handler.path or handler.name)[:400],
                    description=(
                        f"Handler {handler.name}() at {handler.file}:{handler.line} does "
                        f"{reason} inline, and no queue or worker offload was found in the "
                        "module."
                    ),
                    recommended_followup=(
                        "Hand the expensive step to a background worker (Celery/RQ/BullMQ or "
                        "FastAPI `BackgroundTasks`), return 202 with a job id, and let the "
                        "client poll or receive a webhook when the result is ready."
                    ),
                )
            )
        return findings

    @staticmethod
    def _reason(handler: Handler) -> str | None:
        body = handler.text
        if not body:
            return None
        for label, pattern in _HEAVY:
            if pattern.search(body):
                return label
        if _nested_loop_depth(handler.node) >= 2:
            return "a nested loop over query results"
        return None
