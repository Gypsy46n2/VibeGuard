"""VG-API-004 — retry loops and retry-configured clients with no backoff."""

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
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    calls,
    node_text,
    source_files,
    walk,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["RetryWithoutBackoffRule"]

_MAX_FINDINGS = 8
_LOOP_TYPES = {"for_statement", "while_statement", "for_in_statement", "for_of_statement"}

#: The loop is *about* retrying rather than iterating over data.
_RETRY_LOOP = re.compile(
    r"\b(?:attempt|attempts|retry|retries|tries|max_retries|maxRetries|backoff_attempt)\b",
    re.IGNORECASE,
)
#: There is an outbound call inside the loop worth retrying.
_OUTBOUND = re.compile(
    r"requests\.(?:get|post|put|patch|delete|head|request)\s*\(|"
    r"httpx\.(?:get|post|put|patch|delete|request)\s*\(|"
    r"urlopen\s*\(|axios\s*[\.\(]|\bfetch\s*\(|"
    r"session\.(?:get|post|put|patch|delete)\s*\(|client\.(?:get|post|send)\s*\("
)
#: Any pacing at all — sleep, jitter, or a library that owns the retry policy.
_BACKOFF = re.compile(
    r"sleep\s*\(|backoff|jitter|tenacity|\bretrying\b|circuit|pybreaker|"
    r"setTimeout\s*\(|delay\s*\(|p-retry|axios-retry|exponential",
    re.IGNORECASE,
)
_RETRY_CONFIG_CALL = re.compile(r"(?:^|\.)Retry$")
_RETRY_KW = re.compile(r"\b(?:total|connect|read|retries|max_retries|maxRetries)\s*[=:]\s*[1-9]")
_BACKOFF_KW = re.compile(r"backoff_factor|backoff_max|backoff\b|retryDelay|retry_delay")


class RetryWithoutBackoffRule(Rule):
    """Retries that hammer a struggling dependency as fast as the CPU allows."""

    id: ClassVar[str] = "VG-API-004"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Retries without backoff or a circuit breaker"
    description: ClassVar[str] = (
        "A retry loop wraps an outbound call with no sleep, backoff, or jitter between "
        "attempts, or a client sets a retry count without a backoff factor."
    )
    why_it_matters: ClassVar[str] = (
        "Retrying immediately turns a small hiccup into an outage: the moment a dependency "
        "slows down, every caller triples its request rate and finishes off the service "
        "that was only briefly unhealthy. Synchronised retries across many instances "
        "produce a thundering herd that keeps the dependency down long after the original "
        "fault has cleared, and no circuit breaker exists to stop the cycle."
    )
    references: ClassVar[list[str]] = [
        "https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/",
        "https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "api.retries",
        "api.exponential-backoff",
        "api.circuit-breakers",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): insert `time.sleep(min(cap, base * 2 ** attempt) * random.random())`
    # at the end of the retry loop body.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or not _RETRY_LOOP.search(text):
                continue
            findings.extend(self._loops(ctx, rel, text))
            findings.extend(self._configs(ctx, rel))
        return findings[:_MAX_FINDINGS]

    # ------------------------------------------------------------------ loops
    def _loops(self, ctx: ScanContext, rel: str, text: str) -> list[Finding]:
        tree = ctx.ast(rel)
        if tree is None:
            return []
        source = text.encode("utf-8")
        try:
            root: Any = tree.root_node
        except Exception:  # pragma: no cover - defensive
            return []
        out: list[Finding] = []
        seen: set[int] = set()
        for node in walk(root):
            if node.type not in _LOOP_TYPES or node.start_byte in seen:
                continue
            body = node_text(source, node)
            if not body or len(body) > 8000:
                continue
            header = body.split("\n", 1)[0]
            if not _RETRY_LOOP.search(header):
                continue
            if not _OUTBOUND.search(body) or _BACKOFF.search(body):
                continue
            seen.add(node.start_byte)
            line = node.start_point[0] + 1
            out.append(
                self.make_finding(
                    file=rel,
                    line=line,
                    snippet=header.strip()[:400],
                    description=(
                        f"The retry loop at {rel}:{line} repeats an outbound call with no "
                        "sleep, backoff, or jitter between attempts."
                    ),
                    recommended_followup=(
                        "Sleep between attempts with exponential backoff and jitter — "
                        "`time.sleep(random.uniform(0, min(30, 0.5 * 2 ** attempt)))` — or "
                        "hand the policy to `tenacity` / `urllib3.util.Retry` and add a "
                        "circuit breaker so a dead dependency stops being retried at all."
                    ),
                )
            )
        return out

    # ---------------------------------------------------------------- configs
    def _configs(self, ctx: ScanContext, rel: str) -> list[Finding]:
        out: list[Finding] = []
        for call in calls(ctx, rel):
            if not _RETRY_CONFIG_CALL.search(call.name):
                continue
            if not _RETRY_KW.search(call.args) or _BACKOFF_KW.search(call.args):
                continue
            out.append(
                self.make_finding(
                    file=rel,
                    line=call.line,
                    snippet=f"{call.name}{call.args}"[:400],
                    description=(
                        f"{call.name}() at {rel}:{call.line} configures a retry count but no "
                        "backoff_factor, so urllib3 retries with no delay."
                    ),
                    recommended_followup=(
                        "Add a backoff factor, e.g. "
                        "`Retry(total=3, backoff_factor=0.5, "
                        "status_forcelist=[502, 503, 504])`."
                    ),
                )
            )
        return out
