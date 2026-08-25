"""VG-SCALE-004 — long-running work executed inline in a request handler."""

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
from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, source_files
from vibeguard.rules.scaling._signals import autoscaling_evidence, is_web_app

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["InlineLongRunningWorkRule"]

_MAX_FINDINGS = 4
#: Lines of a handler body considered after its decorator/route line.
_HANDLER_WINDOW = 45

_HANDLER_START = re.compile(
    r"@(?:app|api|router|bp|blueprint|routes)\.(?:route|get|post|put|patch|delete)\s*\(|"
    r"\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(\s*[\"'`]/",
    re.IGNORECASE,
)

_HEAVY: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bsmtplib\b|send_mail\(|send_email\(|sendMail\(|nodemailer|"
                   r"sendgrid|mail\.send\(|ses\.send_email", re.IGNORECASE),
        "sends email synchronously",
    ),
    (
        re.compile(r"weasyprint|reportlab|pdfkit|puppeteer|wkhtmltopdf|"
                   r"generate_(?:report|pdf|invoice)|render_pdf", re.IGNORECASE),
        "generates a report or PDF inline",
    ),
    (
        re.compile(r"\bPIL\b|Image\.open\(|sharp\(|ffmpeg|moviepy|thumbnail\(|"
                   r"\.resize\(\s*\(", re.IGNORECASE),
        "processes images or video inline",
    ),
    (
        re.compile(r"bulk_create\(|bulk_insert|executemany\(|insertMany\(|"
                   r"COPY\s+\w+\s+FROM", re.IGNORECASE),
        "performs bulk database writes inline",
    ),
)

_EXTERNAL_CALL = re.compile(
    r"requests\.(?:get|post|put|patch|delete)\(|httpx\.(?:get|post|put)\(|"
    r"urlopen\(|axios\.(?:get|post|put|patch|delete)\(|\bfetch\(\s*[\"'`]http",
    re.IGNORECASE,
)

_WORKER_TECH = {
    "celery",
    "rq",
    "dramatiq",
    "huey",
    "arq",
    "bullmq",
    "bull",
    "sidekiq",
    "sqs",
    "kafka",
    "rabbitmq",
    "temporal",
    "faust",
}
_WORKER_RE = re.compile(
    r"\bcelery\b|\bfrom rq import\b|\bdramatiq\b|\bhuey\b|\bbullmq\b|\bbull\b|"
    r"\bsidekiq\b|\bboto3\.client\(\s*[\"']sqs|@shared_task|\.delay\(|\.apply_async\(|"
    r"BackgroundTasks|background_tasks\.add_task|\bQueue\(\s*connection",
    re.IGNORECASE,
)


def _has_worker(ctx: ScanContext) -> bool:
    if _WORKER_TECH & ctx.tech.all_technologies():
        return True
    if ctx.tech.workers or ctx.tech.brokers:
        return True
    for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES, limit=400):
        text = ctx.read(rel)
        if text and len(text) < 400_000 and _WORKER_RE.search(text):
            return True
    return False


class InlineLongRunningWorkRule(Rule):
    """Work that belongs in a background worker done during the request."""

    id: ClassVar[str] = "VG-SCALE-004"
    category: ClassVar[Category] = Category.SCALABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Long-running work executed inline instead of queued"
    description: ClassVar[str] = (
        "A request handler performs work that belongs in a background worker (email, "
        "report generation, media processing, chained external calls, bulk writes) and no "
        "queue or worker was detected in the project."
    )
    why_it_matters: ClassVar[str] = (
        "Every slow request occupies a worker thread for its whole duration, so a handful "
        "of report downloads can exhaust the pool and make the entire site unresponsive "
        "for everybody else. Users stare at a spinner until a proxy times out, and the "
        "work is lost with no retry — an email that failed halfway is simply never sent."
    )
    references: ClassVar[list[str]] = [
        "https://docs.celeryq.dev/en/stable/getting-started/introduction.html",
        "https://12factor.net/concurrency",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "scaling.queue-workers",
        "scaling.vertical-scaling",
        "scaling.autoscaling",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED
    recommended_followup: ClassVar[str] = (
        "Move the work behind a queue: enqueue a task (Celery/RQ/BullMQ/SQS) from the "
        "handler, return 202 with a job id, and let a separate worker process do the work "
        "with retries — then document how many workers the deployment runs."
    )

    # M3 fix(): none — extracting a task and adding a worker is an architecture change.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        if not is_web_app(ctx) or _has_worker(ctx):
            return []
        headroom = autoscaling_evidence(ctx)
        scaling_note = (
            f"Scaling headroom signals found: {headroom}."
            if headroom
            else "No autoscaling configuration and no documented vertical-scaling headroom "
            "were found either, so there is nothing to absorb the extra latency."
        )
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or len(text) > 400_000:
                continue
            findings.extend(self._scan(rel, text, scaling_note))
        return findings[:_MAX_FINDINGS]

    def _scan(self, rel: str, text: str, scaling_note: str) -> list[Finding]:
        lines = text.splitlines()
        out: list[Finding] = []
        for index, line in enumerate(lines):
            if len(out) >= _MAX_FINDINGS:
                break
            if len(line) > 1000 or not _HANDLER_START.search(line):
                continue
            body = lines[index : index + _HANDLER_WINDOW]
            reason = self._heavy_reason(body)
            if reason is None:
                continue
            out.append(
                self.make_finding(
                    file=rel,
                    line=index + 1,
                    snippet=line.strip()[:400],
                    description=(
                        f"The request handler starting at {rel}:{index + 1} "
                        f"{reason} while the client waits, and no queue or worker "
                        f"(Celery, RQ, BullMQ, SQS, Sidekiq) was detected. {scaling_note}"
                    ),
                    recommended_followup=self.recommended_followup,
                )
            )
        return out

    @staticmethod
    def _heavy_reason(body: list[str]) -> str | None:
        joined = "\n".join(line for line in body if len(line) <= 1000)
        for pattern, reason in _HEAVY:
            if pattern.search(joined):
                return reason
        if len(_EXTERNAL_CALL.findall(joined)) >= 3:
            return "makes three or more external API calls in sequence"
        return None


RULES: list[type[Rule]] = [InlineLongRunningWorkRule]
