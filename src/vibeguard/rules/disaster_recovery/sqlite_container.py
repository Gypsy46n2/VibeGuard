"""VG-DR-003 — SQLite used as the production datastore inside a container."""

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
from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, source_files

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["SqliteInContainerRule"]

#: `sqlite:///relative.db`, `sqlite+aiosqlite:////abs.db`
_SQLITE_URL_RE = re.compile(r"sqlite(?:\+[a-z0-9_]+)?:/{2,4}([^'\"\s?]+)", re.IGNORECASE)
#: A quoted path ending in a SQLite-ish extension.
_SQLITE_PATH_RE = re.compile(r"""['"]([^'"\s]{1,200}\.(?:db|sqlite|sqlite3))['"]""")

_IN_MEMORY = {":memory:", "", "file::memory:"}

#: Any sign that *some* durable volume is mounted into the container.
_PERSISTENCE_RE = re.compile(
    r"^\s*volumes\s*:|^\s*volumeMounts\s*:|persistentVolumeClaim|"
    r"persistentvolumeclaim|^\s*VOLUME\s|volumeClaimTemplates|"
    r"\bmount_path\b|--mount\s|-v\s+[\w./-]+:",
    re.IGNORECASE | re.MULTILINE,
)

_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
_MAX_FINDINGS = 3


def _container_files(ctx: ScanContext) -> list[str]:
    out: list[str] = []
    for rel in ctx.files:
        name = PurePosixPath(rel).name.lower()
        suffix = PurePosixPath(rel).suffix.lower()
        if name == "dockerfile" or name.startswith("dockerfile.") or name in _COMPOSE_NAMES:
            out.append(rel)
        elif suffix in {".yml", ".yaml"} and "kind:" in ctx.read(rel).lower():
            out.append(rel)
        if len(out) >= 40:
            break
    return out


def _has_persistent_volume(ctx: ScanContext, container_files: list[str]) -> str:
    for rel in container_files:
        text = ctx.read(rel)
        if text and len(text) < 200_000 and _PERSISTENCE_RE.search(text):
            return rel
    return ""


class SqliteInContainerRule(Rule):
    """SQLite database file living on the ephemeral container filesystem."""

    id: ClassVar[str] = "VG-DR-003"
    category: ClassVar[Category] = Category.DISASTER_RECOVERY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "SQLite used as the production datastore in a container"
    description: ClassVar[str] = (
        "The application's SQLite database file lives inside the container filesystem "
        "and no volume or persistent volume claim covers it."
    )
    why_it_matters: ClassVar[str] = (
        "A container filesystem is thrown away every time the container is replaced — a "
        "redeploy, a crash restart, a node reschedule. With the database file inside it, "
        "every one of those events silently deletes all user data, with no error and no "
        "backup to fall back on. Teams typically discover this the first time they ship a "
        "second version and every account is gone."
    )
    references: ClassVar[list[str]] = [
        "https://www.sqlite.org/whentouse.html",
        "https://docs.docker.com/storage/volumes/",
    ]
    technologies: ClassVar[set[str]] = {"sqlite"}
    topics: ClassVar[set[str]] = {
        "disaster-recovery.database-recovery",
        "disaster-recovery.backups",
        "scaling.shared-storage",
        "scaling.statelessness",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    # M3 fix(): add a named volume for the database directory to docker-compose.yml
    # and point the connection string at the mounted path.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        if "sqlite" not in {db.lower() for db in ctx.tech.databases}:
            return []
        container_files = _container_files(ctx)
        if not container_files:
            return []
        mounted = _has_persistent_volume(ctx, container_files)
        if mounted:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or len(text) > 400_000:
                continue
            for index, line in enumerate(text.splitlines()):
                if len(findings) >= _MAX_FINDINGS:
                    break
                if len(line) > 1000:
                    continue
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                match = _SQLITE_URL_RE.search(line) or _SQLITE_PATH_RE.search(line)
                if match is None:
                    continue
                path = match.group(1).strip()
                if path.lower() in _IN_MEMORY or ":memory:" in path.lower():
                    continue
                key = path.lower()
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=index + 1,
                        snippet=stripped[:400],
                        description=(
                            f"The SQLite database file {path!r} is opened from application "
                            "code, the project ships as a container "
                            f"({', '.join(container_files[:3])}), and no named volume, "
                            "bind mount, or persistent volume claim was found in any "
                            "container manifest. The database therefore lives on the "
                            "container's writable layer and is destroyed on every "
                            "redeploy or restart."
                        ),
                        recommended_followup=(
                            "Move the database file onto a mounted volume (in compose: a "
                            "named volume mounted at the file's directory; in Kubernetes: "
                            "a PersistentVolumeClaim with a matching volumeMount), or "
                            "migrate to a managed Postgres/MySQL instance — and back it up."
                        ),
                    )
                )
        return findings


RULES: list[type[Rule]] = [SqliteInContainerRule]
