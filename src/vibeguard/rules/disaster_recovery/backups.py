"""VG-DR-001 / VG-DR-002 — backup existence and backup verification.

The two rules share one precondition (a datastore that is deployed somewhere) and
split on the inverse of the same signal: DR-001 fires when no backup evidence
exists at all, DR-002 fires when backup evidence exists but nothing exercises a
restore. At most one of them can fire on a given repository.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.disaster_recovery._signals import (
    backup_hits,
    deployment_evidence,
    restore_hits,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoBackupConfigurationRule", "UnverifiedBackupRestoreRule"]


def _datastore(ctx: ScanContext) -> str:
    return ", ".join(sorted(ctx.tech.databases))


class NoBackupConfigurationRule(ProjectRule):
    """Deployed datastore with no backup signal anywhere in the repository."""

    id: ClassVar[str] = "VG-DR-001"
    category: ClassVar[Category] = Category.DISASTER_RECOVERY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No backup configuration for a production datastore"
    description: ClassVar[str] = (
        "A database is in use and the project is deployed, but no backup mechanism is "
        "visible anywhere in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "A database without backups is one bad migration, one accidental DELETE, or one "
        "deleted volume away from permanent data loss — customer records, orders, and "
        "accounts gone with no way to get them back. Recovery is not a thing you can "
        "arrange after the incident; the copy either already exists or it does not."
    )
    references: ClassVar[list[str]] = [
        "https://www.postgresql.org/docs/current/backup.html",
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/BackupRestore.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "disaster-recovery.backups",
        "disaster-recovery.backup-frequency",
        "disaster-recovery.database-recovery",
        "iac.missing-backups",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    recommended_followup: ClassVar[str] = (
        "Enable managed backups on the datastore (for RDS/Cloud SQL set "
        "`backup_retention_period` and point-in-time recovery in the IaC that creates it), "
        "or add a scheduled `pg_dump`/`mysqldump`/`mongodump` job that writes to "
        "off-host storage, and record the schedule and retention in the README."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        databases = _datastore(ctx)
        if not databases:
            return None
        deployment = deployment_evidence(ctx)
        if not deployment:
            return None
        if backup_hits(ctx):
            return None
        return (
            f"Datastore(s) detected ({databases}) and the project is deployed "
            f"({deployment}), but VibeGuard found no backup signal in the repository: no "
            "pg_dump/mysqldump/mongodump script, no backup or snapshot cron/CI job, no "
            "managed-backup setting in infrastructure code (backup_retention_period, "
            "PointInTimeRecovery, VolumeSnapshot, velero), and no documented backup "
            "procedure. Backups configured only by hand in a cloud console would not be "
            "visible here — if that is the case, commit the configuration so it is "
            "reviewable and reproducible.",
            "searched scripts, CI workflows, IaC, and docs for backup, snapshot, dump, "
            "retention, and PITR markers; none matched",
        )


class UnverifiedBackupRestoreRule(ProjectRule):
    """Backups exist, but nothing in the repository exercises a restore."""

    id: ClassVar[str] = "VG-DR-002"
    category: ClassVar[Category] = Category.DISASTER_RECOVERY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Backup restores are unverified"
    description: ClassVar[str] = (
        "Backups are configured, but no restore script, restore test, or documented "
        "RPO/RTO exists — so the backups have never been shown to work."
    )
    why_it_matters: ClassVar[str] = (
        "An untested backup is not a backup, it is a hope. Silently truncated dumps, "
        "unreadable archives, missing extensions, and forgotten encryption keys are all "
        "discovered at restore time — which, if nobody has rehearsed it, is during the "
        "outage. Teams routinely learn their backups were empty only when they need them."
    )
    references: ClassVar[list[str]] = [
        "https://www.postgresql.org/docs/current/app-pgrestore.html",
        "https://sre.google/sre-book/managing-critical-state/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "disaster-recovery.backup-validation",
        "disaster-recovery.restore-procedures",
        "disaster-recovery.rpo",
        "disaster-recovery.rto",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Add a `scripts/restore.sh` that restores the newest backup into a scratch "
        "database, run it on a schedule in CI, assert a known row count afterwards, and "
        "write the resulting RPO (how much data you can lose) and RTO (how long recovery "
        "takes) into the README."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        databases = _datastore(ctx)
        if not databases:
            return None
        if not deployment_evidence(ctx):
            return None
        found = backup_hits(ctx)
        if not found:
            return None  # VG-DR-001 owns this case.
        if restore_hits(ctx):
            return None
        where = ", ".join(f"{rel}:{line}" for rel, line, _ in found[:3])
        return (
            f"Backup signals were found ({where}) but nothing in the repository restores "
            "from them: no restore script, no restore test in CI, and no documented RPO "
            "or RTO. VibeGuard cannot verify a restore from source alone — it can only "
            "report that no restore path is expressed anywhere in this codebase. An "
            "untested backup is not a backup; treat this as a prompt to rehearse a "
            "restore, not as proof that the backups are broken.",
            "backup markers present; searched for pg_restore/mongorestore/velero "
            "restore, restore scripts and tests, and RPO/RTO documentation — none found",
        )


RULES: list[type[Rule]] = [NoBackupConfigurationRule, UnverifiedBackupRestoreRule]
