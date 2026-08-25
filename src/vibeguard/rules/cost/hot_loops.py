"""VG-COST-001 / VG-COST-002 — logging and billed calls inside loops.

Both rules use the tree-sitter call index rather than regex, because the question
is structural ("is this call inside a loop body?") rather than textual.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, block_of, calls, source_files
from vibeguard.rules.cost._loops import (
    UNBOUNDED_ITERABLE,
    enclosing_loop,
    in_request_handler,
    loop_iterable,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["BilledCallInLoopRule", "LoggingInHotLoopRule"]

_MAX_FINDINGS = 5
_MAX_FILE_BYTES = 400_000

_LOG_CALL = re.compile(
    r"^(?:print|pprint|console\.(?:log|info|debug|warn|error)|"
    r"(?:[\w.]*\b(?:log|logger|logging|LOG|LOGGER))\."
    r"(?:debug|info|warning|warn|error|exception|log))$"
)

_BILLED_CALL = re.compile(
    r"^(?:requests\.(?:get|post|put|patch|delete|head)|httpx\.(?:get|post|put|patch|delete)|"
    r"urllib\.request\.urlopen|urlopen|axios(?:\.(?:get|post|put|patch|delete))?|fetch|"
    r"[\w.]*\b(?:s3|dynamodb|sqs|sns|ses|lambda_client|table|bucket)\."
    r"(?:get_object|put_object|upload_file|upload_fileobj|download_file|delete_object|"
    r"list_objects_v2|get_item|put_item|update_item|delete_item|query|scan|"
    r"send_message|publish|send_email|invoke)|"
    r"(?:openai|client\.chat\.completions|stripe|sendgrid|twilio|sg|resend)\.[\w.]*"
    r"(?:create|send|charge|retrieve|list|messages)"
    r")$",
    re.IGNORECASE,
)

_BATCHING = re.compile(
    r"batch_get_item|batch_write_item|batch_writer\(|bulk_|_bulk\b|send_batch|"
    r"send_messages\(|itertools\.islice|chunk|chunked|Promise\.all|asyncio\.gather|"
    r"executemany\(|paginat",
    re.IGNORECASE,
)


class LoggingInHotLoopRule(Rule):
    """A log or print statement executed once per row."""

    id: ClassVar[str] = "VG-COST-001"
    category: ClassVar[Category] = Category.COST
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Logging inside a hot loop"
    description: ClassVar[str] = (
        "A log or print call runs once per iteration of a loop over query results or an "
        "otherwise unbounded collection."
    )
    why_it_matters: ClassVar[str] = (
        "Log volume is billed by the gigabyte on every hosted logging product, and a "
        "per-row log line turns one request into thousands of lines. A single busy "
        "endpoint can quietly generate more log spend than the servers it runs on, and "
        "the useful messages become impossible to find in the noise. Synchronous logging "
        "also slows the loop itself."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/howto/logging.html",
        "https://12factor.net/logs",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"cost.excessive-logging"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): none — whether the line is needed is a judgement call; suggest
    # hoisting it out of the loop and logging one summary line instead.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or len(text) > _MAX_FILE_BYTES:
                continue
            source = text.encode("utf-8")
            for site in calls(ctx, rel):
                if len(findings) >= _MAX_FINDINGS:
                    break
                if not _LOG_CALL.match(site.name):
                    continue
                loop = enclosing_loop(site.node)
                if loop is None:
                    continue
                iterable = loop_iterable(source, loop)[:200]
                unbounded = loop.type in {"while_statement"} or bool(
                    UNBOUNDED_ITERABLE.search(iterable)
                )
                handler = in_request_handler(source, site.node)
                if not unbounded and not handler:
                    continue
                where = (
                    f"a loop over `{iterable.strip()[:80]}`"
                    if iterable.strip()
                    else "an unbounded loop"
                )
                context = " inside a request handler" if handler else ""
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=f"{site.name}({site.args[:200]})",
                        description=(
                            f"`{site.name}(...)` runs on every iteration of {where}"
                            f"{context}, so log volume grows with the size of the data."
                        ),
                        recommended_followup=(
                            "Move the call out of the loop and log one summary line "
                            "afterwards (count, duration, error count), or guard it with "
                            "`logger.isEnabledFor(logging.DEBUG)` and keep DEBUG off in "
                            "production."
                        ),
                    )
                )
        return findings


class BilledCallInLoopRule(Rule):
    """A network or paid-SDK call issued once per iteration with no batching."""

    id: ClassVar[str] = "VG-COST-002"
    category: ClassVar[Category] = Category.COST
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Billed API or cloud call inside a loop"
    description: ClassVar[str] = (
        "An HTTP request or a paid-service SDK call (S3, DynamoDB, SQS, OpenAI, Stripe, "
        "SendGrid, Twilio) is issued once per loop iteration with no batching."
    )
    why_it_matters: ClassVar[str] = (
        "These calls are billed per request and paid for in latency twice — once for the "
        "round trip, once for the rate limit you eventually hit. A loop over a thousand "
        "rows becomes a thousand invoices and a thousand network round trips, so a page "
        "that was fast with ten records times out at a thousand and the bill arrives a "
        "month later. Most of these APIs offer a batch form that costs a fraction as much."
    )
    references: ClassVar[list[str]] = [
        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html",
        "https://platform.openai.com/docs/guides/rate-limits",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "cost.excessive-cloud-calls",
        "cost.unnecessary-api-requests",
        "performance.network-bottlenecks",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): none — the batch API differs per service, so the rewrite is manual.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or len(text) > _MAX_FILE_BYTES:
                continue
            source = text.encode("utf-8")
            for site in calls(ctx, rel):
                if len(findings) >= _MAX_FINDINGS:
                    break
                if not _BILLED_CALL.match(site.name):
                    continue
                if enclosing_loop(site.node) is None:
                    continue
                if _BATCHING.search(block_of(source, site.node)):
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=f"{site.name}({site.args[:200]})",
                        description=(
                            f"`{site.name}(...)` is called inside a loop at {rel}:"
                            f"{site.line} and no batching, chunking, or pagination helper "
                            "appears in the enclosing function. Each iteration is a "
                            "separate billed request."
                        ),
                        recommended_followup=(
                            "Batch the calls — `batch_get_item`/`batch_writer` for "
                            "DynamoDB, a bulk endpoint or `send_batch` for the API, or "
                            "chunk the input and issue one request per chunk — and cache "
                            "responses that repeat across iterations."
                        ),
                    )
                )
        return findings


RULES: list[type[Rule]] = [LoggingInHotLoopRule, BilledCallInLoopRule]
