"""VG-COST-004 — wasteful scheduled work and storage."""

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
from vibeguard.rules._support import is_generated_path, is_test_path

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["WastefulWorkAndStorageRule"]

_MAX_FINDINGS = 4
_MAX_FILE_BYTES = 300_000
_SCAN_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".yml",
    ".yaml",
    ".tf",
    ".json",
    ".sql",
    ".sh",
}

#: A cron expression that fires every minute (or a sub-minute scheduler interval).
_HOT_SCHEDULE = re.compile(
    r"[\"'*]\s*\*\s+\*\s+\*\s+\*\s+\*|\*/1\s+\*\s+\*\s+\*\s+\*|"
    r"rate\(1\s+minute\)|schedule\.every\(\)\.(?:second|minute)\b|"
    r"(?:seconds|minutes)\s*=\s*1\b|IntervalTrigger\(\s*seconds\s*=",
    re.IGNORECASE,
)
#: Unconditional recomputation typically found in such a job.
_FULL_SCAN = re.compile(
    r"SELECT\s+\*\s+FROM|\.objects\.all\(\)|\.query\.all\(\)|find\(\{\s*\}\)|"
    r"\.scan\(|recompute|rebuild_|refresh_all|recalculate",
    re.IGNORECASE,
)
_POLL_SLEEP = re.compile(
    r"time\.sleep\(\s*(?:0(?:\.\d+)?|1)\s*\)|await\s+asyncio\.sleep\(\s*(?:0(?:\.\d+)?|1)\s*\)|"
    r"setInterval\([^,]+,\s*(?:[0-9]{1,3}|[1-4][0-9]{3})\s*\)",
)
#: Binary blobs parked in relational columns.
_BLOB_COLUMN = re.compile(
    r"Column\(\s*(?:sa\.)?LargeBinary|Column\(\s*(?:sa\.)?BLOB|BinaryField\(|"
    r"\b(?:BYTEA|LONGBLOB|MEDIUMBLOB|BLOB)\b|"
    r"(?:image|photo|avatar|file|attachment|document|pdf)_?(?:data|base64|blob|bytes)\s*"
    r"[=:]|base64\.b64encode\([^)]*\)\s*(?:\)|,)?\s*(?:#.*)?$",
    re.IGNORECASE,
)
_RETENTION = re.compile(
    r"lifecycle_rule|lifecycle_configuration|aws_s3_bucket_lifecycle|expiration\s*\{|"
    r"logrotate|retention_in_days|retentionPolicy|RotatingFileHandler|"
    r"TimedRotatingFileHandler|max_age|ttl\s*[=:]|expire_after|cleanup_old",
    re.IGNORECASE,
)
_STORAGE_DIRS = ("logs/", "log/", "uploads/", "upload/", "media/", "var/log/")


def _scannable(ctx: ScanContext) -> list[str]:
    out: list[str] = []
    for rel in ctx.files:
        if PurePosixPath(rel).suffix.lower() not in _SCAN_SUFFIXES:
            continue
        if is_test_path(rel) or is_generated_path(rel):
            continue
        out.append(rel)
        if len(out) >= 600:
            break
    return out


class WastefulWorkAndStorageRule(Rule):
    """High-frequency recomputation, tight polling loops, and storage kept forever."""

    id: ClassVar[str] = "VG-COST-004"
    category: ClassVar[Category] = Category.COST
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Wasteful scheduled work and storage"
    description: ClassVar[str] = (
        "Work is scheduled far more often than the data changes, or is polled in a tight "
        "loop, or data is stored in a way that accumulates cost forever."
    )
    why_it_matters: ClassVar[str] = (
        "A job that rescans the whole table every minute runs 43,200 times a month whether "
        "or not anything changed, burning CPU, database IO, and — on serverless or managed "
        "databases — a directly billed quantity. Storage waste compounds the same way: "
        "images kept as base64 in table columns bloat every backup and every query, and a "
        "log or upload directory with no expiry grows until someone gets a surprise bill "
        "or the disk fills."
    )
    references: ClassVar[list[str]] = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
        "https://cloud.google.com/architecture/framework/cost-optimization",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "cost.wasteful-background-jobs",
        "cost.inefficient-storage",
        "iac.missing-lifecycle-rules",
        "cost.excessive-db-queries",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): none — the right schedule and retention period are product decisions.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_kinds: set[str] = set()
        files = _scannable(ctx)
        for rel in files:
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or len(text) > _MAX_FILE_BYTES:
                continue
            for kind, finding in self._file_findings(rel, text):
                if kind in seen_kinds or len(findings) >= _MAX_FINDINGS:
                    continue
                seen_kinds.add(kind)
                findings.append(finding)
        retention = self._retention_finding(ctx, files)
        if retention is not None and len(findings) < _MAX_FINDINGS:
            findings.append(retention)
        return findings

    # ------------------------------------------------------------------ helpers
    def _file_findings(self, rel: str, text: str) -> list[tuple[str, Finding]]:
        out: list[tuple[str, Finding]] = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if len(line) > 1000:
                continue
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            window = "\n".join(lines[index : index + 12])
            if _HOT_SCHEDULE.search(line) and _FULL_SCAN.search(window):
                out.append(
                    (
                        "schedule",
                        self._make(
                            rel,
                            index + 1,
                            stripped,
                            (
                                f"{rel}:{index + 1} schedules work at minute or "
                                "sub-minute frequency and the job body performs an "
                                "unconditional full scan or recomputation, so the same "
                                "result is recomputed tens of thousands of times a month."
                            ),
                            (
                                "Lower the frequency to match how often the data actually "
                                "changes, and make the job incremental — filter on "
                                "`updated_at > last_run` and skip the work when nothing "
                                "changed."
                            ),
                        ),
                    )
                )
            elif _POLL_SLEEP.search(line):
                out.append(
                    (
                        "poll",
                        self._make(
                            rel,
                            index + 1,
                            stripped,
                            (
                                f"{rel}:{index + 1} polls on a very short sleep interval. "
                                "A busy-poll keeps a process (and, on serverless, billed "
                                "execution time) awake continuously to discover work that "
                                "arrives rarely."
                            ),
                            (
                                "Replace the poll with a push mechanism — a queue "
                                "consumer, a webhook, or LISTEN/NOTIFY — or back the "
                                "interval off exponentially when no work is found."
                            ),
                        ),
                    )
                )
            elif _BLOB_COLUMN.search(line):
                out.append(
                    (
                        "blob",
                        self._make(
                            rel,
                            index + 1,
                            stripped,
                            (
                                f"{rel}:{index + 1} stores binary or base64-encoded "
                                "content in a database column. Blobs in the database are "
                                "copied into every backup and every replica, and base64 "
                                "inflates them by a third on top."
                            ),
                            (
                                "Store the bytes in object storage and keep only the "
                                "object key (plus size and content type) in the database "
                                "column."
                            ),
                        ),
                    )
                )
        return out

    def _retention_finding(self, ctx: ScanContext, files: list[str]) -> Finding | None:
        directories = sorted(
            {
                prefix
                for prefix in _STORAGE_DIRS
                for rel in ctx.files
                if rel.lower().startswith(prefix)
            }
        )
        if not directories:
            return None
        for rel in files:
            text = ctx.read(rel)
            if text and len(text) <= _MAX_FILE_BYTES and _RETENTION.search(text):
                return None
        return self._make(
            None,
            None,
            "",
            (
                "The repository contains accumulating storage directories "
                f"({', '.join(directories)}) but no retention or lifecycle policy was "
                "found anywhere — no S3 lifecycle rule, no log rotation, no TTL, and no "
                "cleanup job. VibeGuard can only see what is configured in the "
                "repository; a policy set by hand in a cloud console would not appear "
                "here."
            ),
            (
                "Add an explicit expiry: an S3/GCS lifecycle rule (or "
                "`retention_in_days` on the log group) for remote storage, and log "
                "rotation plus a cleanup job for anything written to local disk."
            ),
        )

    def _make(
        self,
        rel: str | None,
        line: int | None,
        snippet: str,
        description: str,
        followup: str,
    ) -> Finding:
        return self.make_finding(
            file=rel,
            line=line,
            snippet=snippet[:400],
            description=description,
            recommended_followup=followup,
        )


RULES: list[type[Rule]] = [WastefulWorkAndStorageRule]
