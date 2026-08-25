"""Private signal helpers for the disaster-recovery pack.

These are deliberately *evidence* helpers, not verdicts: every one answers "can
VibeGuard see a trace of X in the source tree?", which is a strictly weaker claim
than "X exists". Rules built on them must say so in their descriptions.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from vibeguard.rules._support import is_generated_path, is_test_path

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "Hit",
    "backup_hits",
    "deployment_evidence",
    "find_markers",
    "name_hits",
    "restore_hits",
    "text_files",
]

#: Files worth grepping for infrastructure/documentation signals.
_TEXT_SUFFIXES = {
    ".yml",
    ".yaml",
    ".tf",
    ".tfvars",
    ".hcl",
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".md",
    ".rst",
    ".txt",
    ".sql",
}
_TEXT_NAMES = {
    "dockerfile",
    "makefile",
    "procfile",
    "justfile",
    "crontab",
    "jenkinsfile",
}

_MAX_TEXT_FILES = 900
_MAX_BYTES = 200_000

Hit = tuple[str, int, str]


def text_files(ctx: ScanContext, *, limit: int = _MAX_TEXT_FILES) -> Iterator[str]:
    """Config, script, and documentation files worth a marker grep."""
    seen = 0
    for rel in ctx.files:
        if seen >= limit:
            return
        path = PurePosixPath(rel)
        name = path.name.lower()
        if path.suffix.lower() not in _TEXT_SUFFIXES and not (
            name in _TEXT_NAMES or name.startswith("dockerfile")
        ):
            continue
        if is_test_path(rel) or is_generated_path(rel):
            continue
        seen += 1
        yield rel


def find_markers(
    ctx: ScanContext,
    pattern: re.Pattern[str],
    *,
    max_hits: int = 3,
    limit: int = _MAX_TEXT_FILES,
) -> list[Hit]:
    """Up to ``max_hits`` ``(relpath, line_no, line)`` matches of ``pattern``.

    Matching is case-insensitive by convention (compile the pattern that way).
    Never raises: unreadable files simply contribute nothing.
    """
    hits: list[Hit] = []
    for rel in text_files(ctx, limit=limit):
        text = ctx.read(rel)
        if not text or len(text) > _MAX_BYTES:
            continue
        if not pattern.search(text):
            continue
        for index, line in enumerate(text.splitlines()):
            if len(line) > 1000:
                continue
            if pattern.search(line):
                hits.append((rel, index + 1, line.strip()[:200]))
                break
        if len(hits) >= max_hits:
            break
    return hits


def name_hits(ctx: ScanContext, hints: tuple[str, ...], *, max_hits: int = 3) -> list[Hit]:
    """Files whose *name* contains one of ``hints`` (lowercased substring match)."""
    hits: list[Hit] = []
    for rel in ctx.files:
        if is_generated_path(rel) or is_test_path(rel):
            continue
        name = PurePosixPath(rel).name.lower()
        if any(hint in name for hint in hints):
            hits.append((rel, 1, name))
        if len(hits) >= max_hits:
            break
    return hits


# ------------------------------------------------------------------ deployment

_DEPLOY_CI_RE = re.compile(
    r"\b(deploy|release|publish|helm\s+upgrade|kubectl\s+apply|terraform\s+apply|"
    r"docker\s+push|fly\s+deploy|serverless\s+deploy)\b",
    re.IGNORECASE,
)


def deployment_evidence(ctx: ScanContext) -> str:
    """A human-readable summary of why the project looks deployed, or ``""``.

    "Deployed somewhere" means: a container image definition, a compose or
    Kubernetes manifest, infrastructure-as-code, or a CI job that mentions
    deploying. Nothing here proves the project actually runs in production.
    """
    bits: list[str] = []
    if ctx.tech.containers:
        bits.append("containers: " + ", ".join(sorted(ctx.tech.containers)))
    if ctx.tech.iac:
        bits.append("iac: " + ", ".join(sorted(ctx.tech.iac)))
    if ctx.tech.serverless:
        bits.append("serverless: " + ", ".join(sorted(ctx.tech.serverless)))
    if ctx.tech.ci_cd:
        for rel in ctx.files:
            lower = rel.lower()
            is_ci = (
                lower.startswith(".github/workflows/")
                or lower.endswith(".gitlab-ci.yml")
                or PurePosixPath(lower).name in {"jenkinsfile", "bitbucket-pipelines.yml"}
            )
            if not is_ci:
                continue
            text = ctx.read(rel)
            if text and len(text) <= _MAX_BYTES and _DEPLOY_CI_RE.search(text):
                bits.append(f"CI deploy job in {rel}")
                break
    return "; ".join(bits)


# --------------------------------------------------------------------- backups

_BACKUP_RE = re.compile(
    r"pg_dump|pg_dumpall|pg_basebackup|mysqldump|mongodump|sqlite3\s+\S+\s+\.dump|"
    r"\.backup\(|backup_retention_period|point_in_time_recovery|pointintimerecovery|"
    r"deletion_protection\s*=\s*true|volumesnapshot|velero|litestream|wal-g|wal-e|"
    r"barman|pgbackrest|restic|borgbackup|duplicity|aws\s+backup|snapshot_identifier|"
    r"backup_window|automated_backups|(?:^|[^a-z])backup(?:s)?[ _-]?(?:job|cron|schedule|"
    r"policy|plan|procedure|strategy|retention)",
    re.IGNORECASE,
)
_BACKUP_NAME_HINTS = ("backup", "snapshot", "pg_dump", "mysqldump", "mongodump")

_RESTORE_RE = re.compile(
    r"pg_restore|mysql\s+<|mongorestore|velero\s+restore|litestream\s+restore|"
    r"restore[_-]?(?:test|drill|check|verify|rehearsal|runbook|procedure|from)|"
    r"(?:^|[^a-z])(?:rpo|rto)\b|recovery[_-]?point[_-]?objective|"
    r"recovery[_-]?time[_-]?objective|test[_-]?restore|verify[_-]?backup",
    re.IGNORECASE,
)
_RESTORE_NAME_HINTS = ("restore", "recovery", "failback")


def backup_hits(ctx: ScanContext) -> list[Hit]:
    """Evidence that *some* backup mechanism exists in the tree."""
    hits = find_markers(ctx, _BACKUP_RE)
    if len(hits) < 3:
        hits.extend(name_hits(ctx, _BACKUP_NAME_HINTS, max_hits=3 - len(hits)))
    return hits


def restore_hits(ctx: ScanContext) -> list[Hit]:
    """Evidence that a restore path is scripted, tested, or documented."""
    hits = find_markers(ctx, _RESTORE_RE)
    if len(hits) < 3:
        hits.extend(name_hits(ctx, _RESTORE_NAME_HINTS, max_hits=3 - len(hits)))
    return hits
