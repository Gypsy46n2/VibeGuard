"""VG-DB-009 and VG-DB-010 — scale-gated database review prompts.

Both rules exist mainly so that their checklist topics resolve to NOT_APPLICABLE on a
small project instead of producing noise. The ``min_scale`` gate *is* the rule: a toy
CRUD app has no business being told to shard, and a single-writer app has no isolation
problem to review.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.database._common import find_in_repo, has_database

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["IsolationAndLockingRule", "ScaleOutReadinessRule"]

_PROBE_SUFFIXES = (".py", ".js", ".ts", ".sql", ".yml", ".yaml", ".toml", ".ini", ".prisma")

_LOCKING = re.compile(
    r"FOR\s+UPDATE|FOR\s+SHARE|SELECT\s+\.\.\.\s+FOR|"
    r"isolation_level|ISOLATION\s+LEVEL|REPEATABLE\s+READ|SERIALIZABLE|READ\s+COMMITTED|"
    r"with_for_update|select_for_update|"
    r"version_id_col|__mapper_args__|optimistic|\brow_version\b|\bversion\b\s*=\s*Column|"
    r"@Version\b|lock_mode|LockMode|\bSKIP\s+LOCKED\b",
    re.IGNORECASE,
)
_CONCURRENT_WRITERS = re.compile(
    r"\bgunicorn\b|\buvicorn\b|--workers|\bworkers\s*=|\bthreading\b|ThreadPoolExecutor|"
    r"\bcelery\b|\brq\b|\bdramatiq\b|\bbullmq\b|\bcluster\.fork\b|\bpm2\b",
    re.IGNORECASE,
)

_SCALE_OUT = re.compile(
    r"read_replica|readreplica|replica_set|replicaSet|\breplication\b|"
    r"\bstandby\b|\bhot_standby\b|\bstreaming_replication\b|"
    r"\bshard\w*|\bpartition\s+by\b|PARTITION\s+BY|\bcitus\b|\bvitess\b|"
    r"\bwriter_endpoint\b|\breader_endpoint\b|READ_DATABASE_URL|REPLICA_URL|"
    r"\bDATABASE_REPLICA\b|routing.*replica",
    re.IGNORECASE,
)


class IsolationAndLockingRule(ProjectRule):
    """Concurrent writers exist, but nothing about isolation or locking is stated."""

    id: ClassVar[str] = "VG-DB-009"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "Transaction isolation and locking behaviour unreviewed"
    description: ClassVar[str] = (
        "This project writes to the database from several workers or threads, but nowhere "
        "sets a transaction isolation level or takes an explicit lock. This is a review "
        "prompt, not a defect: VibeGuard cannot tell whether the default isolation is "
        "correct for your workload — a human has to decide."
    )
    why_it_matters: ClassVar[str] = (
        "With more than one writer, read-modify-write sequences can interleave: two "
        "requests both read a balance of 10, both subtract 3, and the account ends at 7 "
        "instead of 4. The default isolation level of most databases permits this, and it "
        "only shows up under real concurrency, so it survives every test you run locally. "
        "Deciding between `SELECT ... FOR UPDATE`, a version column, and a stricter "
        "isolation level is a design choice worth making on purpose."
    )
    references: ClassVar[list[str]] = [
        "https://www.postgresql.org/docs/current/transaction-iso.html",
        "https://docs.sqlalchemy.org/en/20/orm/queryguide/dml.html",
    ]
    topics: ClassVar[set[str]] = {
        "database.isolation-levels",
        "database.locking-behavior",
        "database.optimistic-locking",
        "database.pessimistic-locking",
    }
    #: Single-writer projects have no isolation problem to review.
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Pick one strategy per contended write path and write it down: `SELECT ... FOR "
        "UPDATE` (pessimistic), a `version` column with a compare-and-set UPDATE "
        "(optimistic), or an explicit `SERIALIZABLE` transaction with retry-on-conflict. "
        "Then add a test that runs two writers against the same row."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        if not super().applicable(ctx) or not has_database(ctx):
            return False
        if ctx.tech.workers or ctx.tech.brokers or ctx.scale.service_count > 1:
            return True
        return find_in_repo(ctx, _CONCURRENT_WRITERS, _PROBE_SUFFIXES) is not None

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if find_in_repo(ctx, _LOCKING, _PROBE_SUFFIXES) is not None:
            return None
        writers = ", ".join(sorted(set(ctx.tech.workers) | set(ctx.tech.brokers)))
        detail = writers or f"{ctx.scale.service_count} deployable service(s)"
        return (
            "No transaction isolation level, `SELECT ... FOR UPDATE`, or version column "
            f"was found anywhere, although this project has concurrent writers ({detail}). "
            "This is flagged for review rather than as a defect — the correct answer "
            "depends on which write paths can actually contend.",
            "searched source, SQL, and config for isolation_level / FOR UPDATE / "
            "select_for_update / with_for_update / version columns",
        )


class ScaleOutReadinessRule(ProjectRule):
    """A single primary with no replica, partitioning, or sharding story."""

    id: ClassVar[str] = "VG-DB-010"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "Database scale-out readiness not established"
    description: ClassVar[str] = (
        "All traffic goes to a single database primary: no read-replica routing, no "
        "partitioning or sharding key, and no replication configuration. This only "
        "applies to large projects — smaller ones should keep a single primary, and this "
        "rule stays inapplicable for them by design."
    )
    why_it_matters: ClassVar[str] = (
        "At this size, one primary eventually becomes the ceiling for the whole system: "
        "reporting queries compete with user traffic, the largest table stops fitting in "
        "memory, and there is no second copy to fail over to when the instance is lost. "
        "Deciding on replica routing and a partitioning key is far cheaper before the "
        "tables are enormous than during an outage."
    )
    references: ClassVar[list[str]] = [
        "https://www.postgresql.org/docs/current/high-availability.html",
        "https://www.postgresql.org/docs/current/ddl-partitioning.html",
    ]
    topics: ClassVar[set[str]] = {
        "database.read-replicas",
        "database.sharding-readiness",
        "database.partitioning",
        "database.replication",
        "scaling.db-bottlenecks",
    }
    #: The gate is the point: small projects must report NOT_APPLICABLE, not noise.
    min_scale: ClassVar[ScaleClass] = ScaleClass.LARGE
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Write down the scale-out plan before it is urgent: configure a streaming replica "
        "and route read-only queries to it (a second engine/session bound to "
        "`READ_DATABASE_URL`), choose a partition key for the largest table, and record "
        "the replication lag budget the application tolerates."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_database(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if find_in_repo(ctx, _SCALE_OUT, _PROBE_SUFFIXES) is not None:
            return None
        stores = ", ".join(sorted(ctx.tech.databases)) or "the database"
        return (
            f"This project is classified {ctx.scale.scale.value} "
            f"({ctx.scale.loc} LOC, {ctx.scale.service_count} service(s)) and uses "
            f"{stores}, but no read-replica routing, partitioning key, sharding strategy, "
            "or replication configuration was found.",
            "searched source and config for read replica routing, replication/standby "
            "settings, PARTITION BY, and sharding keywords",
        )
