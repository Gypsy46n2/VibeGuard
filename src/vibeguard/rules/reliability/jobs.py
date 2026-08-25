"""VG-REL-007 … VG-REL-009 — background work and process lifecycle.

* **VG-REL-007** tasks and cron jobs with no retry, timeout, or idempotency story.
* **VG-REL-008** no graceful shutdown, so every deploy kills in-flight work.
* **VG-REL-009** a queue nobody can see into.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
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
from vibeguard.rules._support import ProjectRule, line_at, source_files
from vibeguard.rules.reliability._common import (
    CODE_SUFFIXES,
    MAX_FINDINGS,
    find_in_repo,
    has_long_running_process,
    probe_files,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["JobResilienceRule", "NoGracefulShutdownRule", "QueueObservabilityRule"]

_WORKER_TECHNOLOGIES = {"celery", "rq", "dramatiq", "bullmq", "sidekiq", "arq"}
_BROKER_TECHNOLOGIES = {"kafka", "rabbitmq", "redis", "sqs", "pubsub"}

_TASK_DEFINITION = re.compile(
    r"@\s*(shared_task|celery\.task|app\.task|[\w\.]*\.task|dramatiq\.actor|"
    r"[\w\.]*\.actor|huey\.task)\s*[\(\n]|"
    r"\bnew\s+Worker\s*\(|\bqueue\.process\s*\(|\bWorker\s*\(\s*['\"]",
)
_RETRY = re.compile(
    r"max_retries|retry_backoff|autoretry_for|acks_late|retry_kwargs|\bretries\b|"
    r"\bbackoff\b|\battempts\b|retry_policy|\.retry\s*\(",
    re.IGNORECASE,
)
_TIMEOUT = re.compile(
    r"time_limit|soft_time_limit|\btimeout\b|visibility_timeout|job_timeout|lockDuration",
    re.IGNORECASE,
)
_DEAD_LETTER = re.compile(
    r"dead[_\-]?letter|\bDLQ\b|\bfailed_job|on_failure|\bfailure_handler|task_failure|"
    r"\bremoveOnFail\b|\bstalled\b",
    re.IGNORECASE,
)
_IDEMPOTENCY = re.compile(
    r"idempoten\w*|dedup\w*|\bjobId\b|\btask_id\b\s*=|unique_key|\bupsert\b|"
    r"get_or_create|ON\s+CONFLICT",
    re.IGNORECASE,
)

_CRON_MARKER = re.compile(
    r"\bcrontab\s*\(|beat_schedule|CELERYBEAT_SCHEDULE|BackgroundScheduler|BlockingScheduler|"
    r"\bnode-cron\b|cron\.schedule\s*\(|\bschedule\.every\b|kind:\s*CronJob|schedule:\s*['\"]",
    re.IGNORECASE,
)
_CRON_GUARD = re.compile(
    r"concurrencyPolicy|\block\b|\bLock\s*\(|\bredlock\b|\bsingleton\b|\bmax_instances\b|"
    r"\bcoalesce\b|advisory_lock|SETNX|\bmutex\b",
    re.IGNORECASE,
)


class JobResilienceRule(Rule):
    """Background tasks defined without retry, timeout, DLQ, or idempotency."""

    id: ClassVar[str] = "VG-REL-007"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Background job without retry, timeout, or idempotency configuration"
    description: ClassVar[str] = (
        "Background tasks are defined with no retry policy, no time limit, no dead-letter "
        "or failure handler, and no idempotency key — and scheduled jobs run without a "
        "distributed lock."
    )
    why_it_matters: ClassVar[str] = (
        "A task that fails once is simply lost: the email is never sent, the invoice is "
        "never generated, and nothing tells anyone. A task with no time limit can hang on "
        "a dead socket and hold a worker slot forever, until the whole pool is stuck. And "
        "once you do add retries without an idempotency key, a partially completed task "
        "gets re-run and charges the customer twice. Scheduled jobs have the mirror "
        "problem: with two instances running, the nightly job fires twice."
    )
    references: ClassVar[list[str]] = [
        "https://docs.celeryq.dev/en/stable/userguide/tasks.html#retrying",
        "https://docs.bullmq.io/guide/retrying-failing-jobs",
    ]
    technologies: ClassVar[set[str]] = set(_WORKER_TECHNOLOGIES)
    topics: ClassVar[set[str]] = {
        "jobs.retry-behavior",
        "jobs.timeout-behavior",
        "jobs.job-idempotency",
        "jobs.dead-letter-handling",
        "jobs.poison-jobs",
        "jobs.job-deduplication",
        "jobs.job-locking",
        "jobs.cron-jobs",
        "jobs.scheduled-workers",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings = self._task_findings(ctx)
        findings.extend(self._cron_findings(ctx))
        return findings[:MAX_FINDINGS]

    def _task_findings(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(out) >= 3:
                break
            text = ctx.read(rel)
            if not text:
                continue
            match = _TASK_DEFINITION.search(text)
            if match is None:
                continue
            missing = [
                label
                for label, pattern in (
                    ("a retry policy", _RETRY),
                    ("a time limit", _TIMEOUT),
                    ("a dead-letter or failure handler", _DEAD_LETTER),
                    ("an idempotency or dedupe key", _IDEMPOTENCY),
                )
                if not pattern.search(text)
            ]
            if len(missing) < 3:
                continue
            line_no = line_at(text, match.start())
            out.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=match.group(0).strip()[:200],
                    description=(
                        f"Background tasks are defined in {rel} (line {line_no}) with no "
                        + ", no ".join(missing)
                        + "."
                    ),
                    recommended_followup=(
                        "Declare the failure behaviour on the task itself — e.g. "
                        "`@shared_task(autoretry_for=(Exception,), retry_backoff=True, "
                        "max_retries=5, acks_late=True, soft_time_limit=30)` or BullMQ "
                        "`{attempts: 5, backoff: {...}, removeOnFail: false}` — and make "
                        "the body idempotent by keying the work on a stable job id."
                    ),
                )
            )
        return out

    def _cron_findings(self, ctx: ScanContext) -> list[Finding]:
        suffixes = CODE_SUFFIXES + (".yml", ".yaml", ".txt", ".cron")
        for rel in probe_files(ctx, suffixes):
            name = PurePosixPath(rel).name.lower()
            text = ctx.read(rel)
            if not text:
                continue
            if not (_CRON_MARKER.search(text) or name in {"crontab", "cronjob.yaml"}):
                continue
            if _CRON_GUARD.search(text):
                continue
            match = _CRON_MARKER.search(text)
            line_no = line_at(text, match.start()) if match else 1
            return [
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=(match.group(0).strip() if match else name)[:200],
                    description=(
                        f"A scheduled job is defined in {rel} (line {line_no}) with no "
                        "distributed lock and no concurrency policy, so it runs once per "
                        "instance and can overlap with its own previous run."
                    ),
                    recommended_followup=(
                        "Guard the schedule: set `concurrencyPolicy: Forbid` on a "
                        "Kubernetes CronJob, `max_instances=1, coalesce=True` on "
                        "APScheduler, or take a Redis/advisory lock at the top of the job "
                        "and exit immediately when it is already held."
                    ),
                )
            ]
        return []


_SHUTDOWN = re.compile(
    r"SIGTERM|SIGINT|signal\.signal|process\.on\s*\(\s*['\"]SIG|"
    r"server\.close\s*\(|\.shutdown\s*\(|graceful|\blifespan\b|on_event\s*\(\s*['\"]shutdown|"
    r"@app\.on_event|terminationGracePeriodSeconds|preStop|atexit\.register|"
    r"\bworker_shutdown\b|--graceful-timeout|stop_signal|\bdrain\w*\s*\(",
    re.IGNORECASE,
)


class NoGracefulShutdownRule(ProjectRule):
    """Long-running processes with no shutdown path."""

    id: ClassVar[str] = "VG-REL-008"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No graceful shutdown handling"
    description: ClassVar[str] = (
        "This project runs long-lived servers or workers but handles no termination "
        "signal, closes no server, and declares no shutdown hook or grace period."
    )
    why_it_matters: ClassVar[str] = (
        "Deploys, autoscaling, and node replacements all work by sending SIGTERM and then "
        "killing the process. With nothing listening, every in-flight request is severed "
        "mid-response and every job that was being processed vanishes without being "
        "acknowledged or requeued. Users see random 502s during each deploy, and the work "
        "that was lost is invisible — nobody knows what to replay."
    )
    references: ClassVar[list[str]] = [
        "https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/",
        "https://fastapi.tiangolo.com/advanced/events/",
    ]
    topics: ClassVar[set[str]] = {
        "jobs.worker-crashes",
        "containers.rolling-deployments",
        "deployment.zero-downtime",
    }
    #: Graceful shutdown is about rolling deploys; a single-process hobby app that is
    #: restarted by hand has no rollout to be graceful during.
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    recommended_followup: ClassVar[str] = (
        "Handle SIGTERM: stop accepting new work, finish or requeue what is in flight, then "
        "exit — `@app.on_event(\"shutdown\")`/lifespan (FastAPI), `server.close()` plus a "
        "drain timeout (Node), `warm_shutdown` (Celery). Pair it with "
        "`terminationGracePeriodSeconds` and a `preStop` sleep so the load balancer stops "
        "routing first."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_long_running_process(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        suffixes = CODE_SUFFIXES + (".yml", ".yaml", ".toml", ".cfg", ".ini", ".sh", ".json")
        if find_in_repo(ctx, _SHUTDOWN, suffixes) is not None:
            return None
        processes = ", ".join(
            sorted(set(ctx.tech.backend) | set(ctx.tech.workers) | set(ctx.tech.brokers))
        )
        return (
            f"Long-running processes are present ({processes or 'a server'}) but no SIGTERM "
            "or SIGINT handler, `server.close()`, lifespan/shutdown hook, `preStop` hook, or "
            "`terminationGracePeriodSeconds` was found anywhere in the repository.",
            "searched source, container, and deployment manifests for signal handlers, "
            "shutdown hooks, preStop, and terminationGracePeriodSeconds",
        )


_QUEUE_OBSERVABILITY = re.compile(
    r"\bflower\b|\bbull-board\b|\brq-dashboard\b|\bqueue_depth\b|queue_length|"
    r"\bqueue.*(gauge|metric|histogram)|(gauge|metric|histogram).*queue|"
    r"task_failure\.connect|on_failure|\bsentry\b|\bstatsd\b|\bprometheus\b|"
    r"\bdatadog\b|task_postrun|worker_process_init|\bgetJobCounts\b|\bqueue\.getMetrics\b",
    re.IGNORECASE,
)


class QueueObservabilityRule(ProjectRule):
    """A job queue with no depth metric, no failure logging, and no dashboard."""

    id: ClassVar[str] = "VG-REL-009"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Job queue without observability"
    description: ClassVar[str] = (
        "A worker or broker is in use, but nothing exposes queue depth or latency, logs "
        "task failures, or provides a dashboard — so a stalled queue is invisible."
    )
    why_it_matters: ClassVar[str] = (
        "Queues fail quietly. If the workers die or a poison job blocks the queue, the web "
        "app keeps accepting requests and enqueuing work that will never run; nothing errors "
        "and no page fires. The problem is usually discovered days later by a customer "
        "asking where their export went, by which point the backlog is enormous and nobody "
        "can tell which jobs were dropped."
    )
    references: ClassVar[list[str]] = [
        "https://flower.readthedocs.io/en/latest/",
        "https://docs.bullmq.io/guide/metrics",
    ]
    technologies: ClassVar[set[str]] = set(_WORKER_TECHNOLOGIES) | set(_BROKER_TECHNOLOGIES)
    topics: ClassVar[set[str]] = {"jobs.job-queues", "jobs.job-observability"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Export queue depth and oldest-job age as metrics and alert when either grows, log "
        "every task failure with its arguments to your error tracker, and run a dashboard "
        "(flower, bull-board, rq-dashboard) so a stalled queue is visible in seconds."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        if not super().applicable(ctx):
            return False
        return bool(ctx.tech.workers or ctx.tech.brokers)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        suffixes = CODE_SUFFIXES + (".yml", ".yaml", ".toml", ".json")
        if find_in_repo(ctx, _QUEUE_OBSERVABILITY, suffixes) is not None:
            return None
        systems = ", ".join(sorted(set(ctx.tech.workers) | set(ctx.tech.brokers)))
        return (
            f"Background processing is in use ({systems}) but no queue depth or latency "
            "metric, task-failure logging, or queue dashboard was found. Failures and "
            "backlogs would be invisible.",
            "searched for flower / bull-board / rq-dashboard, queue depth metrics, and "
            "task failure handlers",
        )
