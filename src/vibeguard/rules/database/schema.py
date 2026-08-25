"""VG-DB-004 and VG-DB-008 — what the schema itself declares.

* **VG-DB-004** a foreign key or a frequently filtered column with no index.
* **VG-DB-008** integrity constraints that are declared but never enforced.
"""

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
from vibeguard.rules._support import PY_SUFFIXES, source_files
from vibeguard.rules.database._common import MAX_FINDINGS, has_database, scannable

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["MissingIndexRule", "IntegrityConstraintRule"]

_SCHEMA_SUFFIXES = PY_SUFFIXES + (".js", ".ts", ".prisma", ".sql")

#: ``name = Column(...)`` / ``name = models.ForeignKey(...)`` / ``name = CharField(...)``
_COLUMN_DECL = re.compile(
    r"^[ \t]*(\w+)[ \t]*=[ \t]*(?:[\w\.]*\.)?"
    r"(Column|mapped_column|ForeignKey|ForeignKeyField|[A-Z]\w*Field|relationship)\s*\((.*)$",
)
_FOREIGN_KEY = re.compile(r"ForeignKey\s*\(|ForeignKeyField\s*\(|references\s*\(|\bREFERENCES\b")
_INDEXED = re.compile(
    r"index\s*=\s*True|db_index\s*=\s*True|unique\s*=\s*True|primary_key\s*=\s*True"
)
_INDEX_ELSEWHERE = re.compile(r"\bIndex\s*\(|CREATE\s+(UNIQUE\s+)?INDEX|@@index|\.index\s*\(", re.I)

#: Columns the application filters on.
_FILTERED = (
    re.compile(r"filter_by\s*\(\s*(\w+)\s*="),
    re.compile(r"\.filter\s*\(\s*\w+\.(\w+)\s*=="),
    re.compile(r"\.where\s*\(\s*\w+\.(\w+)\s*[=,]"),
    re.compile(r"\bWHERE\s+(?:\w+\.)?(\w+)\s*=", re.IGNORECASE),
    re.compile(r"\bwhere\s*:\s*\{\s*(\w+)\s*:"),
)


def _declared_columns(ctx: ScanContext) -> dict[tuple[str, int], tuple[str, str]]:
    """``(file, line) -> (column name, declaration text)`` for every model column."""
    out: dict[tuple[str, int], tuple[str, str]] = {}
    for rel in source_files(ctx, _SCHEMA_SUFFIXES):
        text = ctx.read(rel)
        if not text:
            continue
        for index, line in enumerate(text.splitlines()):
            if len(line) > 600:
                continue
            match = _COLUMN_DECL.match(line)
            if match:
                out[(rel, index + 1)] = (match.group(1), line.strip())
    return out


def _index_names(ctx: ScanContext) -> set[str]:
    """Identifiers mentioned near an explicit index declaration anywhere in the repo."""
    names: set[str] = set()
    for rel in scannable(ctx, _SCHEMA_SUFFIXES, skip_tests=True):
        text = ctx.read(rel)
        if not text or not _INDEX_ELSEWHERE.search(text):
            continue
        for line in text.splitlines():
            if _INDEX_ELSEWHERE.search(line):
                names.update(re.findall(r"[\"'`]?\b([a-z_][a-z0-9_]{2,})\b", line.lower()))
    return names


class MissingIndexRule(Rule):
    """A foreign key or filtered column that declares no index."""

    id: ClassVar[str] = "VG-DB-004"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Foreign-key or frequently filtered column without an index"
    description: ClassVar[str] = (
        "A column that the application joins or filters on declares no index, and no "
        "matching index was found in a migration."
    )
    why_it_matters: ClassVar[str] = (
        "Without an index the database reads every row in the table to answer the query. "
        "That is invisible on the hundred rows you have in development and catastrophic on "
        "the million rows you have in production: the query goes from a millisecond to "
        "several seconds, holds its connection the whole time, and drags every other "
        "request down with it. Foreign keys are the usual victims — most databases do not "
        "index them for you."
    )
    references: ClassVar[list[str]] = [
        "https://use-the-index-luke.com/sql/where-clause",
        "https://www.postgresql.org/docs/current/indexes-intro.html",
    ]
    topics: ClassVar[set[str]] = {
        "database.indexing",
        "database.missing-indexes",
        "database.unused-indexes",
        "performance.slow-queries",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    #: Never SAFE_AUTOFIX — adding an index means writing and sequencing a migration.
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_database(ctx)

    def detect(self, ctx: ScanContext) -> list[Finding]:
        columns = _declared_columns(ctx)
        if not columns:
            return []
        indexed_elsewhere = _index_names(ctx)
        filtered = self._filtered_columns(ctx)

        findings: list[Finding] = []
        for (rel, line_no), (name, decl) in sorted(columns.items()):
            if len(findings) >= MAX_FINDINGS:
                break
            if _INDEXED.search(decl) or name.lower() in indexed_elsewhere:
                continue
            is_fk = bool(_FOREIGN_KEY.search(decl))
            if not is_fk and name.lower() not in filtered:
                continue
            reason = (
                "it is a foreign key" if is_fk else "the application filters on it"
            )
            findings.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=decl[:200],
                    description=(
                        f"Column {name!r} in {rel} (line {line_no}) has no index, although "
                        f"{reason}."
                    ),
                    recommended_followup=(
                        f"Declare the index on the column (`index=True` / `db_index=True`) "
                        f"and generate the migration, or add an explicit "
                        f"`CREATE INDEX CONCURRENTLY ... ON <table> ({name})` migration so "
                        "the change is versioned and can be rolled back."
                    ),
                )
            )
        return findings

    def _filtered_columns(self, ctx: ScanContext) -> set[str]:
        found: set[str] = set()
        for rel in source_files(ctx, PY_SUFFIXES + (".js", ".ts", ".sql")):
            text = ctx.read(rel)
            if not text:
                continue
            for pattern in _FILTERED:
                found.update(match.lower() for match in pattern.findall(text[:200_000]))
        found.discard("id")
        return found


_PRAGMA_FK = re.compile(r"PRAGMA\s+foreign_keys\s*=\s*(ON|1|True)", re.IGNORECASE)
_NATURAL_KEYS = ("email", "username", "slug", "handle")
_UNIQUE = re.compile(r"unique\s*=\s*True|\bUNIQUE\b|@unique|primary_key\s*=\s*True", re.IGNORECASE)
_NULLABILITY = re.compile(
    r"nullable\s*=|null\s*=|\bNOT\s+NULL\b|optional\s*=|\?\s*$", re.IGNORECASE
)


class IntegrityConstraintRule(Rule):
    """Constraints the schema relies on but never actually enforces."""

    id: ClassVar[str] = "VG-DB-008"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Data integrity constraints not enforced"
    description: ClassVar[str] = (
        "Foreign keys, uniqueness, or nullability are assumed by the code but not enforced "
        "by the database, so nothing stops bad rows from being written."
    )
    why_it_matters: ClassVar[str] = (
        "SQLite ignores every foreign key you declare unless `PRAGMA foreign_keys = ON` is "
        "issued on each connection — so deletes silently orphan child rows and the "
        "corruption is only discovered months later. Likewise, a natural key such as an "
        "email address without a UNIQUE constraint will eventually hold duplicates: two "
        "accounts for one person, password resets going to the wrong row, and a cleanup "
        "job that has to guess which record is real."
    )
    references: ClassVar[list[str]] = [
        "https://www.sqlite.org/foreignkeys.html",
        "https://www.postgresql.org/docs/current/ddl-constraints.html",
    ]
    topics: ClassVar[set[str]] = {
        "database.foreign-keys",
        "database.referential-integrity",
        "database.unique-constraints",
        "database.nullability",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_database(ctx)

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings = self._sqlite_pragma(ctx)
        findings.extend(self._natural_keys(ctx))
        return findings[:MAX_FINDINGS]

    def _sqlite_pragma(self, ctx: ScanContext) -> list[Finding]:
        if "sqlite" not in {db.lower() for db in ctx.tech.databases}:
            return []
        declared_in: str | None = None
        for rel in scannable(ctx, _SCHEMA_SUFFIXES, skip_tests=True):
            text = ctx.read(rel)
            if not text:
                continue
            if _PRAGMA_FK.search(text):
                return []
            if declared_in is None and _FOREIGN_KEY.search(text):
                declared_in = rel
        if declared_in is None:
            return []
        return [
            self.make_finding(
                file=declared_in,
                description=(
                    f"Foreign keys are declared in {declared_in} but this SQLite project "
                    "never issues `PRAGMA foreign_keys = ON`, so SQLite does not enforce "
                    "them."
                ),
                evidence=[
                    Evidence(
                        file=declared_in,
                        note=(
                            "searched every scanned source file for "
                            "`PRAGMA foreign_keys = ON`"
                        ),
                    )
                ],
                recommended_followup=(
                    "Execute `PRAGMA foreign_keys = ON` on every new connection — e.g. a "
                    "SQLAlchemy `connect` event listener, or `conn.execute('PRAGMA "
                    "foreign_keys = ON')` in your connection factory."
                ),
            )
        ]

    def _natural_keys(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for (rel, line_no), (name, decl) in sorted(_declared_columns(ctx).items()):
            if len(out) >= 3:
                break
            lowered = name.lower()
            if not any(key in lowered for key in _NATURAL_KEYS):
                continue
            if _UNIQUE.search(decl):
                continue
            missing = ["a unique constraint"]
            if not _NULLABILITY.search(decl):
                missing.append("an explicit nullability declaration")
            out.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=decl[:200],
                    description=(
                        f"Natural-key column {name!r} in {rel} (line {line_no}) declares "
                        f"neither {' nor '.join(missing)}."
                    ),
                    recommended_followup=(
                        f"Add `unique=True` (and `nullable=False` if the value is always "
                        f"required) to {name}, then generate the migration — and "
                        "deduplicate existing rows before applying it."
                    ),
                )
            )
        return out
