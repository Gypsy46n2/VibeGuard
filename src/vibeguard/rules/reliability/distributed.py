"""VG-REL-010 and VG-REL-011 — messaging and multi-service failure modes.

* **VG-REL-010** a message consumer with no delivery-semantics story.
* **VG-REL-011** a scale-gated review prompt for genuine distributed systems.
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
from vibeguard.rules._support import ProjectRule, line_at, source_files
from vibeguard.rules.reliability._common import (
    CODE_SUFFIXES,
    MAX_FINDINGS,
    find_in_repo,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["MessageDeliverySemanticsRule", "DistributedFailureModesRule"]

_BROKERS = {"kafka", "rabbitmq", "redis", "sqs", "pubsub"}

_CONSUMER = re.compile(
    r"\bKafkaConsumer\b|\bAIOKafkaConsumer\b|\bconsumer\.subscribe\s*\(|\bconsume\s*\(|"
    r"\bbasic_consume\s*\(|\bstart_consuming\s*\(|\breceive_message\w*\s*\(|"
    r"\bxreadgroup\s*\(|\bxread\s*\(|\bsubscribe\s*\(|\bpubsub\s*\(|"
    r"\beachMessage\b|\bonMessage\b|\bnew\s+Worker\s*\(",
    re.IGNORECASE,
)
_DEAD_LETTER = re.compile(
    r"dead[_\-]?letter|\bDLQ\b|redrive|\bdeadLetterQueue\b|x-dead-letter|"
    r"\bparking[_\-]?lot\b|\bfailed[_\-]?queue\b",
    re.IGNORECASE,
)
_DEDUPE = re.compile(
    r"idempoten\w*|dedup\w*|\bmessage_id\b|\bmessageId\b|MessageDeduplicationId|"
    r"\bseen_ids\b|ON\s+CONFLICT|\bupsert\b|get_or_create|processed_events",
    re.IGNORECASE,
)
_ACK = re.compile(
    r"\back\s*\(|\bbasic_ack\b|\backnowledge\w*|enable_auto_commit|\bcommit\s*\(\s*\)|"
    r"auto_offset_reset|\bnack\s*\(|\bxack\s*\(|delete_message|autoCommit",
    re.IGNORECASE,
)
_ORDERING = re.compile(
    r"\bordering\b|\bpartition_key\b|\bpartitionKey\b|MessageGroupId|\bFIFO\b|"
    r"\bsequence[_\-]?number\b|out[_\-]?of[_\-]?order",
    re.IGNORECASE,
)


class MessageDeliverySemanticsRule(Rule):
    """A broker consumer that assumes exactly-once, in-order, never-failing delivery."""

    id: ClassVar[str] = "VG-REL-010"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Message-queue delivery semantics unhandled"
    description: ClassVar[str] = (
        "A message consumer is implemented with no dead-letter queue, no duplicate "
        "handling, no explicit acknowledgement strategy, and no stated ordering "
        "assumption — so it implicitly assumes exactly-once, in-order delivery that no "
        "broker provides."
    )
    why_it_matters: ClassVar[str] = (
        "Every mainstream broker is at-least-once: a consumer that crashes after doing the "
        "work but before acknowledging will see the same message again, and a handler that "
        "is not idempotent will charge the card or send the email twice. Messages that "
        "always fail are redelivered forever, blocking the partition behind them, and with "
        "several partitions or consumers, events arrive out of order — so a 'deleted' event "
        "can be processed before the 'created' one it refers to."
    )
    references: ClassVar[list[str]] = [
        "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html",
        "https://kafka.apache.org/documentation/#semantics",
    ]
    technologies: ClassVar[set[str]] = set(_BROKERS)
    topics: ClassVar[set[str]] = {
        "distributed.message-queues",
        "distributed.pub-sub",
        "distributed.dead-letter-queues",
        "distributed.duplicate-processing",
        "distributed.out-of-order-events",
        "distributed.poison-messages",
        "distributed.event-driven-architecture",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and bool(ctx.tech.brokers or ctx.tech.workers)

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= 3:
                break
            text = ctx.read(rel)
            if not text:
                continue
            match = _CONSUMER.search(text)
            if match is None:
                continue
            missing = [
                label
                for label, pattern in (
                    ("a dead-letter queue", _DEAD_LETTER),
                    ("duplicate/at-least-once handling", _DEDUPE),
                    ("an explicit acknowledgement strategy", _ACK),
                    ("a documented ordering assumption", _ORDERING),
                )
                if not pattern.search(text)
            ]
            if len(missing) < 3:
                continue
            line_no = line_at(text, match.start())
            findings.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=match.group(0).strip()[:200],
                    description=(
                        f"The consumer in {rel} (line {line_no}) has no "
                        + ", no ".join(missing)
                        + "."
                    ),
                    recommended_followup=(
                        "Make the handler idempotent on the broker's message id (record "
                        "processed ids, or use `INSERT ... ON CONFLICT DO NOTHING`), "
                        "acknowledge only after the work is durably committed, and route "
                        "repeatedly failing messages to a dead-letter queue with an alert "
                        "on its depth."
                    ),
                )
            )
        return findings[:MAX_FINDINGS]


_DISTRIBUTED_PRACTICE = re.compile(
    r"service[_\-]?discovery|\bconsul\b|\betcd\b|\beureka\b|\bservice mesh\b|\bistio\b|"
    r"\blinkerd\b|distributed[_\-]?lock|\bredlock\b|leader[_\-]?election|\bLease\b|"
    r"\bsaga\b|\bcompensat\w+|two[_\-]?phase[_\-]?commit|outbox|"
    r"clock[_\-]?skew|\bNTP\b|logical[_\-]?clock|\bvector[_\-]?clock\b|"
    r"network[_\-]?partition|split[_\-]?brain|\bquorum\b|eventual[_\-]?consisten\w+",
    re.IGNORECASE,
)


class DistributedFailureModesRule(ProjectRule):
    """A genuinely distributed system with none of the distributed-systems machinery."""

    id: ClassVar[str] = "VG-REL-011"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "Distributed-systems failure modes unaddressed"
    description: ClassVar[str] = (
        "This system spans several independently deployed services, but nothing addresses "
        "service discovery, distributed locking or leader election, cross-service write "
        "compensation, clock skew, or network partitions. These concerns apply only to "
        "systems of this size: a single-service or small application should ignore them "
        "entirely, and this rule stays inapplicable there by design."
    )
    why_it_matters: ClassVar[str] = (
        "Once writes span two services there is no shared transaction to roll back, so a "
        "failure halfway through leaves the system permanently inconsistent unless a saga "
        "or an outbox compensates for it. Likewise, a scheduled job running in three "
        "replicas without leader election runs three times, and two instances that disagree "
        "about the time will expire tokens early or honour them too long. Each of these is "
        "an outage that cannot happen in a single process — and only starts to matter at "
        "this scale."
    )
    references: ClassVar[list[str]] = [
        "https://microservices.io/patterns/data/saga.html",
        "https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html",
    ]
    topics: ClassVar[set[str]] = {
        "distributed.service-discovery",
        "distributed.distributed-locks",
        "distributed.distributed-transactions",
        "distributed.saga-patterns",
        "distributed.leader-election",
        "distributed.race-conditions",
        "distributed.network-partitions",
        "distributed.clock-skew",
        "distributed.eventual-consistency",
        "distributed.cap-tradeoffs",
        "distributed.split-brain",
    }
    #: The gate is the point — a toy or small app must report NOT_APPLICABLE here.
    min_scale: ClassVar[ScaleClass] = ScaleClass.LARGE
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Write down, per cross-service workflow, how it fails: which step compensates on "
        "error (saga or transactional outbox), which component holds the lease for "
        "singleton work (leader election via etcd/Consul/a database lease), how services "
        "find each other, and what happens when the network between them is briefly gone."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        if not super().applicable(ctx):
            return False
        if ctx.scale.service_count >= 3:
            return True
        # A broker plus more than one deployable is also a real distributed system.
        return bool(ctx.tech.brokers) and ctx.scale.service_count >= 2

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        suffixes = CODE_SUFFIXES + (".yml", ".yaml", ".tf", ".toml", ".md", ".json")
        if find_in_repo(ctx, _DISTRIBUTED_PRACTICE, suffixes) is not None:
            return None
        return (
            f"This system is classified {ctx.scale.scale.value} with "
            f"{ctx.scale.service_count} deployable service(s)"
            + (f" and broker(s) {', '.join(sorted(ctx.tech.brokers))}" if ctx.tech.brokers else "")
            + ", but no service discovery, distributed lock or leader election, saga or "
            "compensating-transaction mechanism, and no clock-skew or partition handling "
            "was found.",
            "searched source, IaC, and docs for service discovery, distributed locks, "
            "leader election, saga/outbox patterns, clock skew, and partition handling",
        )
