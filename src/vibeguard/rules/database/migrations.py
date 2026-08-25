"""VG-DB-005 and VG-DB-006 — schema change safety.

* **VG-DB-005** a destructive statement inside a migration.
* **VG-DB-006** a schema exists but nothing versions it.
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
from vibeguard.rules._support import ProjectRule, line_at
from vibeguard.rules.database._common import (
    SCHEMA_DEFINITION,
    find_in_repo,
    has_database,
    migration_files,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DestructiveMigrationRule", "NoMigrationToolingRule"]

_DESTRUCTIVE = re.compile(
    r"\bDROP\s+TABLE\b|\bDROP\s+COLUMN\b|\bRENAME\s+COLUMN\b|\bTRUNCATE\b|"
    r"\bop\.drop_column\b|\bop\.drop_table\b|\bop\.alter_column\b\s*\(\s*[^)]*new_column_name|"
    r"\bmigrations\.RemoveField\b|\bmigrations\.DeleteModel\b|\bRemoveField\s*\(|"
    r"\bDeleteModel\s*\(|\bRenameField\s*\(|"
    r"\.dropColumn\s*\(|\.dropTable\s*\(|\bdropTable\s*\(|\bdropColumn\s*\(|"
    r"\brenameColumn\s*\(",
    re.IGNORECASE,
)
_MAX_MIGRATION_FINDINGS = 6


class DestructiveMigrationRule(Rule):
    """A migration drops, truncates, or renames existing data."""

    id: ClassVar[str] = "VG-DB-005"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Destructive operation in a migration"
    description: ClassVar[str] = (
        "A migration drops, truncates, or renames a table or column. Applying it deletes "
        "production data that no rollback can bring back."
    )
    why_it_matters: ClassVar[str] = (
        "Migrations run automatically on deploy, usually before anyone is watching. A "
        "`DROP COLUMN` executes in milliseconds and destroys every value in that column "
        "forever — the down-migration can recreate the column but not its contents, so the "
        "only recovery is a database restore and the data written since the last backup is "
        "simply gone. A rename is just as bad in a rolling deploy: the old application "
        "version is still running and starts erroring the instant the column disappears."
    )
    references: ClassVar[list[str]] = [
        "https://alembic.sqlalchemy.org/en/latest/ops.html",
        "https://docs.djangoproject.com/en/stable/topics/migrations/",
    ]
    topics: ClassVar[set[str]] = {
        "database.migration-safety",
        "database.rollback-strategy",
        "deployment.migration-sequencing",
        "database.data-integrity",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    #: Never auto-fixable: deleting or restoring data is a human decision.
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in migration_files(ctx):
            if len(findings) >= _MAX_MIGRATION_FINDINGS:
                break
            text = ctx.read(rel)
            if not text:
                continue
            match = _DESTRUCTIVE.search(text)
            if match is None:
                continue
            line_no = line_at(text, match.start())
            snippet = text.splitlines()[line_no - 1].strip() if text.splitlines() else ""
            findings.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=snippet[:200],
                    description=(
                        f"{rel} contains a destructive schema operation "
                        f"({match.group(0).strip()}) at line {line_no}."
                    ),
                    recommended_followup=(
                        "Split this into an expand/contract pair: ship a migration that "
                        "adds the new shape and backfills it, deploy code that stops using "
                        "the old column, and only then — after a verified backup and a "
                        "retention window — drop it in a separate, reviewed migration."
                    ),
                )
            )
        return findings


_MIGRATION_TOOL_FILES = (
    "alembic.ini",
    "knexfile.js",
    "knexfile.ts",
    "atlas.hcl",
    "sqitch.plan",
    "sqitch.conf",
    "liquibase.properties",
    "flyway.conf",
    "flyway.toml",
    "prisma/schema.prisma",
    "db/migrate",
    "migrations",
    "alembic",
)
_MIGRATION_TOOL_TEXT = re.compile(
    r"\balembic\b|\bdjango\b|\bprisma\b|\bknex\b|\bflyway\b|\bliquibase\b|\bsqitch\b|"
    r"\batlas\b|\bnode-pg-migrate\b|\bumzug\b|\btypeorm\b|\bdbmate\b|\bgoose\b",
    re.IGNORECASE,
)
_MANIFESTS = ("requirements.txt", "pyproject.toml", "package.json", "Gemfile", "go.mod")


def _has_migration_tooling(ctx: ScanContext) -> str | None:
    """Name of the migration mechanism this repo uses, or None."""
    for candidate in _MIGRATION_TOOL_FILES:
        if ctx.exists(candidate):
            return candidate
    for rel in ctx.files:
        parts = [part.lower() for part in PurePosixPath(rel).parts[:-1]]
        if "migrations" in parts or "migrate" in parts or "versions" in parts:
            return rel
    for rel in ctx.files:
        if PurePosixPath(rel).name in _MANIFESTS:
            match = _MIGRATION_TOOL_TEXT.search(ctx.read(rel))
            if match:
                return f"{rel} declares {match.group(0)}"
    return None


class NoMigrationToolingRule(ProjectRule):
    """A schema is defined in code but nothing versions changes to it."""

    id: ClassVar[str] = "VG-DB-006"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Database schema with no migration tooling"
    description: ClassVar[str] = (
        "The project defines a database schema but has no migration tool, so schema "
        "changes are applied by hand and are not versioned with the code."
    )
    why_it_matters: ClassVar[str] = (
        "Without migrations there is no record of what shape the database is supposed to "
        "be in, and no way to reproduce it. Staging drifts from production, a new "
        "developer's local database is missing columns the code expects, and every deploy "
        "needs someone to remember to run the right ALTER by hand at the right moment. "
        "The first forgotten step takes the application down with a column-does-not-exist "
        "error, and there is no rollback path."
    )
    references: ClassVar[list[str]] = [
        "https://alembic.sqlalchemy.org/en/latest/tutorial.html",
        "https://www.prisma.io/docs/orm/prisma-migrate",
    ]
    topics: ClassVar[set[str]] = {
        "database.schema-versioning",
        "database.migration-ordering",
        "deployment.migration-sequencing",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    recommended_followup: ClassVar[str] = (
        "Adopt a migration tool and commit the initial migration alongside the models: "
        "`alembic init migrations` (SQLAlchemy), `manage.py makemigrations` (Django), "
        "`prisma migrate dev` (Prisma), or `knex migrate:make` (Knex). Run it in the "
        "deploy pipeline, never by hand."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_database(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        schema_file = find_in_repo(ctx, SCHEMA_DEFINITION, (".py", ".js", ".ts", ".sql", ".prisma"))
        if schema_file is None:
            return None
        if _has_migration_tooling(ctx) is not None:
            return None
        stores = ", ".join(sorted(set(ctx.tech.databases) | set(ctx.tech.orms))) or "a database"
        return (
            f"Schema definitions were found in {schema_file} and the project uses "
            f"{stores}, but no migration tool (alembic, django migrations, prisma "
            "migrate, knex, flyway, liquibase, sqitch, atlas) is configured.",
            "searched for alembic.ini, knexfile, prisma/schema.prisma, flyway/liquibase/"
            "sqitch config, any migrations/ or versions/ directory, and migration "
            "dependencies in the manifests",
        )
