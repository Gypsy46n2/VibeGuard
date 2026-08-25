"""Tests for the database rule pack (VG-DB-001 … VG-DB-010).

Every rule gets a positive case (it fires on the defective code) and a negative case
(it stays silent on the idiomatic equivalent). For the scale-gated rules VG-DB-009 and
VG-DB-010 the negative case proves the gate itself: ``applicable()`` is False on a
small project, so ``run_rule`` returns no findings at all.
"""

from __future__ import annotations

from pathlib import Path

from conftest import context_from, run_rule
from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules.database import (
    RULES,
    ConnectionPerRequestRule,
    DestructiveMigrationRule,
    IntegrityConstraintRule,
    IsolationAndLockingRule,
    MissingIndexRule,
    NoMigrationToolingRule,
    NPlusOneQueryRule,
    ScaleOutReadinessRule,
    SelectStarRule,
    UntransactedMultiWriteRule,
)
from vibeguard.rules.topics import topic_ids

SQLALCHEMY = "sqlalchemy==2.0.0\n"


def _ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


def _compose(count: int) -> str:
    services = ["  db:\n    image: postgres:16\n"]
    for index in range(count - 1):
        services.append(f"  svc{index}:\n    build: ./svc{index}\n")
    return "services:\n" + "".join(services)


# --------------------------------------------------------------------- pack shape


def test_pack_exposes_every_rule_in_id_order():
    assert [rule.id for rule in RULES] == [f"VG-DB-{n:03d}" for n in range(1, 11)]


def test_rule_metadata_is_well_formed():
    known = topic_ids()
    for rule in RULES:
        assert rule.category is Category.DATABASE
        assert rule.title and not rule.title.endswith(".")
        assert rule.description and rule.why_it_matters
        assert rule.references
        assert rule.topics and rule.topics <= known
        assert isinstance(rule.severity, Severity)
        assert isinstance(rule.confidence, Confidence)
        # M3 owns repairs: no pack rule may override fix().
        assert "fix" not in vars(rule)


def test_no_rule_fires_on_the_shared_clean_fixture(sample_ctx):
    for rule_cls in RULES:
        rule = rule_cls()
        if rule.applicable(sample_ctx):
            assert rule.detect(sample_ctx) == [], rule_cls.id


# ------------------------------------------------------------------- VG-DB-001


def test_n_plus_one_fires_on_query_in_loop(tmp_path: Path):
    findings = run_rule(
        NPlusOneQueryRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "app.py": (
                "def show(order_ids):\n"
                "    rows = []\n"
                "    for oid in order_ids:\n"
                "        rows.append(session.query(Order).get(oid))\n"
                "    return rows\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-DB-001"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].autofix_safety is AutofixSafety.REVIEW_RECOMMENDED
    assert findings[0].recommended_followup


def test_n_plus_one_silent_on_single_batched_query(tmp_path: Path):
    findings = run_rule(
        NPlusOneQueryRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "app.py": (
                "def show(order_ids):\n"
                "    rows = session.query(Order).filter(Order.id.in_(order_ids)).all()\n"
                "    return [row for row in rows]\n"
            ),
        },
    )
    assert findings == []


# ------------------------------------------------------------------- VG-DB-002

_HANDLER_CONNECT = (
    "import psycopg2\n"
    "from flask import Flask\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/users")\n'
    "def show_users():\n"
    "    conn = psycopg2.connect(DSN)\n"
    "    return conn.execute(SQL).fetchall()\n"
)


def test_connection_per_request_fires(tmp_path: Path):
    findings = run_rule(
        ConnectionPerRequestRule,
        tmp_path,
        {"requirements.txt": "flask\npsycopg2-binary\n", "app.py": _HANDLER_CONNECT},
    )
    assert _ids(findings) == ["VG-DB-002"]
    assert "psycopg2.connect" in findings[0].description


def test_connection_per_request_silent_for_module_singleton(tmp_path: Path):
    findings = run_rule(
        ConnectionPerRequestRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\n",
            "app.py": (
                "import psycopg2\n"
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n"
                "CONN = psycopg2.connect(DSN)\n\n\n"
                '@app.route("/users")\n'
                "def show_users():\n"
                "    return CONN.execute(SQL).fetchall()\n"
            ),
        },
    )
    assert findings == []


def test_null_pool_engine_fires(tmp_path: Path):
    findings = run_rule(
        ConnectionPerRequestRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "db.py": (
                "from sqlalchemy import create_engine\n"
                "from sqlalchemy.pool import NullPool\n\n"
                "engine = create_engine(URL, poolclass=NullPool)\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-DB-002"]
    assert "NullPool" in findings[0].description


# ------------------------------------------------------------------- VG-DB-003


def test_select_star_fires(tmp_path: Path):
    findings = run_rule(
        SelectStarRule,
        tmp_path,
        {"app.py": 'def all_users(cur):\n    return cur.execute("SELECT * FROM users")\n'},
    )
    assert _ids(findings) == ["VG-DB-003"]
    assert findings[0].severity is Severity.LOW
    assert findings[0].confidence is Confidence.HIGH


def test_select_star_silent_on_explicit_columns(tmp_path: Path):
    findings = run_rule(
        SelectStarRule,
        tmp_path,
        {"app.py": 'def all_users(cur):\n    return cur.execute("SELECT id, email FROM users")\n'},
    )
    assert findings == []


# ------------------------------------------------------------------- VG-DB-004

_MODELS_HEADER = (
    "from sqlalchemy import Column, ForeignKey, Integer\n"
    "from sqlalchemy.orm import declarative_base\n\n"
    "Base = declarative_base()\n\n\n"
    "class Order(Base):\n"
    '    __tablename__ = "orders"\n'
    "    id = Column(Integer, primary_key=True)\n"
)


def test_missing_index_fires_on_unindexed_foreign_key(tmp_path: Path):
    findings = run_rule(
        MissingIndexRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "models.py": _MODELS_HEADER + '    user_id = Column(Integer, ForeignKey("users.id"))\n',
        },
    )
    assert _ids(findings) == ["VG-DB-004"]
    assert "user_id" in findings[0].description
    # Adding an index means writing a migration — never a safe autofix.
    assert findings[0].autofix_safety is not AutofixSafety.SAFE_AUTOFIX


def test_missing_index_silent_when_index_declared(tmp_path: Path):
    findings = run_rule(
        MissingIndexRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "models.py": _MODELS_HEADER
            + '    user_id = Column(Integer, ForeignKey("users.id"), index=True)\n',
        },
    )
    assert findings == []


# ------------------------------------------------------------------- VG-DB-005


def test_destructive_migration_fires(tmp_path: Path):
    findings = run_rule(
        DestructiveMigrationRule,
        tmp_path,
        {
            "requirements.txt": "alembic\n" + SQLALCHEMY,
            "alembic.ini": "[alembic]\n",
            "migrations/versions/0002_drop_legacy.py": (
                "def upgrade():\n"
                '    op.drop_column("users", "legacy_token")\n'
                "\n"
                "def downgrade():\n"
                "    pass\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-DB-005"]
    assert findings[0].severity is Severity.HIGH
    # Destroying data must never be auto-fixed.
    assert findings[0].autofix_safety is AutofixSafety.MANUAL_CHANGE_REQUIRED


def test_destructive_migration_silent_on_additive_migration(tmp_path: Path):
    findings = run_rule(
        DestructiveMigrationRule,
        tmp_path,
        {
            "requirements.txt": "alembic\n" + SQLALCHEMY,
            "alembic.ini": "[alembic]\n",
            "migrations/versions/0002_add_flag.py": (
                "def upgrade():\n"
                '    op.add_column("users", sa.Column("is_active", sa.Boolean()))\n'
            ),
        },
    )
    assert findings == []


# ------------------------------------------------------------------- VG-DB-006

_SCHEMA_ONLY = {
    "requirements.txt": SQLALCHEMY,
    "models.py": _MODELS_HEADER + "    total = Column(Integer)\n",
}


def test_no_migration_tooling_fires(tmp_path: Path):
    findings = run_rule(NoMigrationToolingRule, tmp_path, dict(_SCHEMA_ONLY))
    assert _ids(findings) == ["VG-DB-006"]
    assert findings[0].file is None  # project-level finding


def test_no_migration_tooling_silent_with_alembic(tmp_path: Path):
    files = dict(_SCHEMA_ONLY)
    files["alembic.ini"] = "[alembic]\nscript_location = migrations\n"
    assert run_rule(NoMigrationToolingRule, tmp_path, files) == []


# ------------------------------------------------------------------- VG-DB-007


def test_untransacted_multi_write_fires(tmp_path: Path):
    findings = run_rule(
        UntransactedMultiWriteRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "service.py": (
                "def transfer(src, dst):\n"
                "    db.session.add(src)\n"
                "    db.session.add(dst)\n"
                "    db.session.commit()\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-DB-007"]
    assert "transfer" in findings[0].description


def test_untransacted_multi_write_silent_inside_transaction(tmp_path: Path):
    findings = run_rule(
        UntransactedMultiWriteRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "service.py": (
                "def transfer(src, dst):\n"
                "    with db.session.begin():\n"
                "        db.session.add(src)\n"
                "        db.session.add(dst)\n"
            ),
        },
    )
    assert findings == []


# ------------------------------------------------------------------- VG-DB-008

_SQLITE_FK = (
    "import sqlite3\n\n"
    'SCHEMA = """\n'
    "CREATE TABLE orders (\n"
    "    id INTEGER PRIMARY KEY,\n"
    "    owner_id INTEGER REFERENCES users(id)\n"
    ")\n"
    '"""\n'
)


def test_integrity_fires_when_sqlite_never_enables_foreign_keys(tmp_path: Path):
    findings = run_rule(IntegrityConstraintRule, tmp_path, {"store.py": _SQLITE_FK})
    assert _ids(findings) == ["VG-DB-008"]
    assert "PRAGMA foreign_keys" in findings[0].description


def test_integrity_silent_when_pragma_is_set(tmp_path: Path):
    findings = run_rule(
        IntegrityConstraintRule,
        tmp_path,
        {
            "store.py": _SQLITE_FK
            + "\n\ndef connect(path):\n"
            "    conn = sqlite3.connect(path)\n"
            '    conn.execute("PRAGMA foreign_keys = ON")\n'
            "    return conn\n"
        },
    )
    assert findings == []


def test_integrity_fires_on_natural_key_without_unique(tmp_path: Path):
    findings = run_rule(
        IntegrityConstraintRule,
        tmp_path,
        {
            "requirements.txt": SQLALCHEMY,
            "models.py": _MODELS_HEADER + "    email = Column(String)\n",
        },
    )
    assert _ids(findings) == ["VG-DB-008"]
    assert "email" in findings[0].description


# ------------------------------------------------------------------- VG-DB-009

_CONCURRENT_REPO = {
    "requirements.txt": "flask\npsycopg2-binary\n",
    "docker-compose.yml": _compose(3),
    "app.py": "def write(row):\n    session.add(row)\n    session.commit()\n",
}


def test_isolation_review_fires_on_medium_project_with_concurrent_writers(tmp_path: Path):
    ctx = context_from(tmp_path, dict(_CONCURRENT_REPO))
    assert ctx.scale.scale >= ScaleClass.MEDIUM
    findings = IsolationAndLockingRule().detect(ctx)
    assert _ids(findings) == ["VG-DB-009"]
    # Advisory, not a defect: the checklist maps this to REVIEW_REQUIRED, not FAIL.
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL
    assert findings[0].severity is Severity.LOW


def test_isolation_review_silent_when_locking_is_explicit(tmp_path: Path):
    files = dict(_CONCURRENT_REPO)
    files["app.py"] = (
        "def write(row):\n"
        "    session.query(Row).with_for_update().first()\n"
        "    session.add(row)\n"
        "    session.commit()\n"
    )
    assert run_rule(IsolationAndLockingRule, tmp_path, files) == []


def test_isolation_review_gate_excludes_a_small_project(tmp_path: Path):
    files = {
        "requirements.txt": "flask\npsycopg2-binary\n",
        "app.py": "def write(row):\n    pass\n",
    }
    ctx = context_from(tmp_path, files)
    assert ctx.scale.scale < ScaleClass.MEDIUM
    assert IsolationAndLockingRule().applicable(ctx) is False
    assert run_rule(IsolationAndLockingRule, tmp_path, files) == []


# ------------------------------------------------------------------- VG-DB-010

_LARGE_REPO = {
    "requirements.txt": "flask\npsycopg2-binary\n",
    "docker-compose.yml": _compose(5),
    "app.py": "def write(row):\n    session.add(row)\n",
}


def test_scale_out_readiness_fires_only_at_large_scale(tmp_path: Path):
    ctx = context_from(tmp_path, dict(_LARGE_REPO))
    assert ctx.scale.scale is ScaleClass.LARGE
    findings = ScaleOutReadinessRule().detect(ctx)
    assert _ids(findings) == ["VG-DB-010"]
    assert findings[0].severity is Severity.INFO
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL


def test_scale_out_readiness_silent_when_replicas_are_configured(tmp_path: Path):
    files = dict(_LARGE_REPO)
    files["settings.py"] = 'READ_DATABASE_URL = os.environ["READ_DATABASE_URL"]\n'
    assert run_rule(ScaleOutReadinessRule, tmp_path, files) == []


def test_scale_out_readiness_gate_excludes_a_toy_project(tmp_path: Path):
    files = {"requirements.txt": "flask\npsycopg2-binary\n", "app.py": "print('hello')\n"}
    ctx = context_from(tmp_path, files)
    assert ctx.scale.scale < ScaleClass.LARGE
    assert ScaleOutReadinessRule().applicable(ctx) is False
    assert run_rule(ScaleOutReadinessRule, tmp_path, files) == []


# ---------------------------------------------------------------- robustness


def test_rules_never_raise_on_malformed_sources(tmp_path: Path):
    files = {
        "requirements.txt": SQLALCHEMY,
        "broken.py": "def (:\n  this is not python at all ][\n",
        "weird.js": "function ( { const = ;;;\n",
        "migrations/versions/x.py": "\x00\x01 not really a migration\n",
        "empty.py": "",
    }
    ctx = context_from(tmp_path, files)
    for rule_cls in RULES:
        rule = rule_cls()
        if rule.applicable(ctx):
            assert isinstance(rule.detect(ctx), list), rule_cls.id
