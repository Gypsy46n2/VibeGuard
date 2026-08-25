"""VG-PERF-003 — serverless handlers written as if the platform had no limits."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    line_at,
    source_files,
)
from vibeguard.rules.api._http import repo_matches

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ServerlessLimitsIgnoredRule"]

_HANDLER = re.compile(
    r"def\s+(?:lambda_handler|handler|main)\s*\(\s*event\s*,\s*context|"
    r"(?:exports\.handler|module\.exports\.handler|export\s+const\s+handler)\s*=",
)
_LIMITS = re.compile(
    r"^\s*(?:timeout|memorySize|memory_size|MemorySize|Timeout|memory|maxDuration)\s*[:=]",
    re.IGNORECASE | re.MULTILINE,
)
_LIMITS_TF = re.compile(
    r"timeout\s*=\s*\d+|memory_size\s*=\s*\d+|ephemeral_storage|maxDuration",
    re.IGNORECASE,
)
_HEAVY_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(pandas|numpy|scipy|torch|tensorflow|sklearn|matplotlib|"
    r"transformers|cv2|PIL|selenium|playwright)\b",
    re.MULTILINE,
)


class ServerlessLimitsIgnoredRule(Rule):
    """A Lambda-style handler with no declared timeout/memory or a heavy cold start."""

    id: ClassVar[str] = "VG-PERF-003"
    category: ClassVar[Category] = Category.PERFORMANCE
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Serverless handler ignores platform limits"
    description: ClassVar[str] = (
        "A serverless handler declares no timeout or memory configuration, or imports heavy "
        "libraries at module scope where they are paid on every cold start."
    )
    why_it_matters: ClassVar[str] = (
        "Serverless platforms cap execution time, memory, and payload size, and enforce "
        "them by killing the invocation — so an unconfigured handler fails abruptly and "
        "mid-write the first time real data arrives, with no useful error for the caller. "
        "Heavy module-level imports make every cold start slow, which users feel as random "
        "multi-second delays and you pay for in billed duration on every scale-up."
    )
    references: ClassVar[list[str]] = [
        "https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html",
        "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html",
    ]
    technologies: ClassVar[set[str]] = {
        "serverless-framework",
        "aws-lambda",
        "vercel",
        "netlify",
        "cloud-functions",
    }
    topics: ClassVar[set[str]] = {
        "performance.cold-starts",
        "performance.serverless-limits",
        "cost.unnecessary-serverless-invocations",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    def detect(self, ctx: ScanContext) -> list[Finding]:
        located = self._locate_handler(ctx)
        if located is None:
            return []
        rel, line, snippet, text = located

        limits = bool(repo_matches(ctx, _LIMITS)) or bool(repo_matches(ctx, _LIMITS_TF))
        heavy = _HEAVY_IMPORT.search(text)
        problems: list[str] = []
        if not limits:
            problems.append(
                "no timeout or memory configuration is declared for the function anywhere "
                "in the repository"
            )
        if heavy:
            problems.append(
                f"the module imports {heavy.group(1)} at import time, which is paid on "
                "every cold start"
            )
        if not problems:
            return []

        return [
            self.make_finding(
                file=rel,
                line=line,
                snippet=snippet[:400],
                description=(
                    f"Serverless handler at {rel}:{line}: " + "; ".join(problems) + "."
                ),
                evidence=[
                    Evidence(
                        file=rel,
                        line=line,
                        snippet=snippet[:400],
                        note="checked serverless.yml / SAM / Terraform for timeout and "
                        "memory settings and the handler module for heavy imports",
                    )
                ],
                recommended_followup=(
                    "Declare an explicit `timeout` and `memorySize` for the function, keep "
                    "the response under the platform's payload cap (stream large results to "
                    "object storage and return a link instead), and move heavy imports "
                    "inside the handler or behind a lazy accessor."
                ),
            )
        ]

    @staticmethod
    def _locate_handler(ctx: ScanContext) -> tuple[str, int, str, str] | None:
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            text = ctx.read(rel)
            if not text:
                continue
            match = _HANDLER.search(text)
            if match:
                return rel, line_at(text, match.start()), match.group(0).strip(), text
        return None
