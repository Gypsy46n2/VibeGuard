"""Tests for the disaster_recovery rule pack (VG-DR-001 … VG-DR-006)."""

from __future__ import annotations

from pathlib import Path

from conftest import run_rule
from vibeguard.core.models import AutofixSafety, Category, ChecklistStatus
from vibeguard.engine.checklist import DetectorInfo, derive_checklist
from vibeguard.rules.disaster_recovery import RULES
from vibeguard.rules.disaster_recovery.backups import (
    NoBackupConfigurationRule,
    UnverifiedBackupRestoreRule,
)
from vibeguard.rules.disaster_recovery.readiness import IncidentReadinessRule
from vibeguard.rules.disaster_recovery.resilience import (
    FailoverStrategyRule,
    FailureInjectionRule,
)
from vibeguard.rules.disaster_recovery.sqlite_container import SqliteInContainerRule

# --------------------------------------------------------------------- fixtures

DEPLOYED_PG_APP = {
    "requirements.txt": "flask\npsycopg2-binary\n",
    "app.py": (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "DATABASE_URL = 'postgres://user:pw@db:5432/app'\n"
    ),
    "Dockerfile": "FROM python:3.12-slim\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
}

BACKUP_SCRIPT = (
    "#!/bin/sh\n"
    "pg_dump \"$DATABASE_URL\" | gzip > /backups/app-$(date +%F).sql.gz\n"
)

#: A synthetic tree big enough for detect_scale() to classify the project LARGE.
def _large_repo(extra: dict[str, str] | None = None) -> dict[str, str]:
    services = {f"svc{i}": {} for i in range(6)}
    compose = "services:\n" + "".join(
        f"  {name}:\n    image: example/{name}:latest\n" for name in services
    )
    files = {
        "docker-compose.yml": compose,
        "requirements.txt": "flask\n",
        "app.py": "\n".join(f"X{i} = {i}" for i in range(50)) + "\n",
    }
    files.update(extra or {})
    return files


# ------------------------------------------------------------------- VG-DR-001


def test_dr001_fires_for_deployed_database_without_backups(tmp_path: Path) -> None:
    findings = run_rule(NoBackupConfigurationRule, tmp_path, DEPLOYED_PG_APP)
    assert [f.rule_id for f in findings] == ["VG-DR-001"]
    assert "no backup signal" in findings[0].description
    assert findings[0].recommended_followup


def test_dr001_silent_when_a_backup_job_exists(tmp_path: Path) -> None:
    files = dict(DEPLOYED_PG_APP)
    files["scripts/backup.sh"] = BACKUP_SCRIPT
    assert run_rule(NoBackupConfigurationRule, tmp_path, files) == []


def test_dr001_silent_without_a_database(tmp_path: Path) -> None:
    files = {
        "requirements.txt": "flask\n",
        "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        "Dockerfile": "FROM python:3.12-slim\n",
    }
    assert run_rule(NoBackupConfigurationRule, tmp_path, files) == []


def test_dr001_silent_when_not_deployed_anywhere(tmp_path: Path) -> None:
    files = {k: v for k, v in DEPLOYED_PG_APP.items() if k != "Dockerfile"}
    assert run_rule(NoBackupConfigurationRule, tmp_path, files) == []


# ------------------------------------------------------------------- VG-DR-002


def test_dr002_fires_when_backups_exist_but_no_restore(tmp_path: Path) -> None:
    files = dict(DEPLOYED_PG_APP)
    files["scripts/backup.sh"] = BACKUP_SCRIPT
    findings = run_rule(UnverifiedBackupRestoreRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DR-002"]
    assert "cannot verify a restore" in findings[0].description
    assert "untested backup is not a backup" in findings[0].description
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL


def test_dr002_silent_when_a_restore_drill_exists(tmp_path: Path) -> None:
    files = dict(DEPLOYED_PG_APP)
    files["scripts/backup.sh"] = BACKUP_SCRIPT
    files["scripts/restore.sh"] = "#!/bin/sh\npg_restore -d scratch /backups/latest.dump\n"
    assert run_rule(UnverifiedBackupRestoreRule, tmp_path, files) == []


def test_dr001_and_dr002_are_mutually_exclusive(tmp_path: Path) -> None:
    without = run_rule(NoBackupConfigurationRule, tmp_path / "a", DEPLOYED_PG_APP)
    inverse = run_rule(UnverifiedBackupRestoreRule, tmp_path / "a", DEPLOYED_PG_APP)
    assert without and not inverse


# ------------------------------------------------------------------- VG-DR-003


SQLITE_APP = {
    "requirements.txt": "flask\naiosqlite\n",
    "app.py": (
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "conn = sqlite3.connect('data/app.db')\n"
    ),
    "Dockerfile": "FROM python:3.12-slim\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
}


def test_dr003_fires_for_sqlite_in_an_unmounted_container(tmp_path: Path) -> None:
    findings = run_rule(SqliteInContainerRule, tmp_path, SQLITE_APP)
    assert [f.rule_id for f in findings] == ["VG-DR-003"]
    assert findings[0].file == "app.py"
    assert "data/app.db" in findings[0].description


def test_dr003_silent_when_the_database_sits_on_a_volume(tmp_path: Path) -> None:
    files = dict(SQLITE_APP)
    files["docker-compose.yml"] = (
        "services:\n"
        "  web:\n"
        "    build: .\n"
        "    volumes:\n"
        "      - appdata:/app/data\n"
        "volumes:\n"
        "  appdata:\n"
    )
    assert run_rule(SqliteInContainerRule, tmp_path, files) == []


def test_dr003_silent_for_in_memory_sqlite(tmp_path: Path) -> None:
    files = dict(SQLITE_APP)
    files["app.py"] = (
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "conn = sqlite3.connect(':memory:')\n"
    )
    assert run_rule(SqliteInContainerRule, tmp_path, files) == []


# ------------------------------------------------------------------- VG-DR-004


def test_dr004_fires_when_nothing_operational_is_documented(tmp_path: Path) -> None:
    findings = run_rule(IncidentReadinessRule, tmp_path, DEPLOYED_PG_APP)
    assert [f.rule_id for f in findings] == ["VG-DR-004"]
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL


def test_dr004_silent_with_a_runbook(tmp_path: Path) -> None:
    files = dict(DEPLOYED_PG_APP)
    files["RUNBOOK.md"] = "# Runbook\n\n## Restart\n\n`docker compose restart web`\n"
    assert run_rule(IncidentReadinessRule, tmp_path, files) == []


def test_dr004_silent_with_alert_routing(tmp_path: Path) -> None:
    files = dict(DEPLOYED_PG_APP)
    files["alerts.yml"] = "receivers:\n  - name: team\n    pagerduty_configs: []\n"
    assert run_rule(IncidentReadinessRule, tmp_path, files) == []


def test_dr004_gated_out_on_a_toy_project(tmp_path: Path) -> None:
    files = {"app.py": "print('hello')\n"}
    assert run_rule(IncidentReadinessRule, tmp_path, files) == []


# ------------------------------------------------------- VG-DR-005 / VG-DR-006


def test_dr005_fires_on_a_large_project_without_chaos_tooling(tmp_path: Path) -> None:
    findings = run_rule(FailureInjectionRule, tmp_path, _large_repo())
    assert [f.rule_id for f in findings] == ["VG-DR-005"]
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL


def test_dr005_silent_when_chaos_tooling_exists(tmp_path: Path) -> None:
    files = _large_repo({"chaos/latency.yaml": "kind: NetworkChaos\ntool: chaos-mesh\n"})
    assert run_rule(FailureInjectionRule, tmp_path, files) == []


def test_dr005_min_scale_keeps_it_silent_on_a_small_project(tmp_path: Path) -> None:
    """The scale gate is the point of VG-DR-005: no chaos advice for small apps."""
    assert run_rule(FailureInjectionRule, tmp_path, DEPLOYED_PG_APP) == []


def test_dr006_fires_on_a_large_single_region_project(tmp_path: Path) -> None:
    findings = run_rule(FailoverStrategyRule, tmp_path, _large_repo())
    assert [f.rule_id for f in findings] == ["VG-DR-006"]


def test_dr006_silent_with_a_failover_configuration(tmp_path: Path) -> None:
    files = _large_repo({"infra/rds.tf": 'resource "x" {\n  multi_az = true\n}\n'})
    assert run_rule(FailoverStrategyRule, tmp_path, files) == []


def test_dr006_min_scale_keeps_it_silent_on_a_small_project(tmp_path: Path) -> None:
    assert run_rule(FailoverStrategyRule, tmp_path, DEPLOYED_PG_APP) == []


# ------------------------------------------------------------------- pack-wide


def test_every_rule_declares_valid_metadata() -> None:
    from vibeguard.rules.topics import topic_ids

    known = set(topic_ids())
    assert len(RULES) == 6
    for rule_cls in RULES:
        assert rule_cls.category is Category.DISASTER_RECOVERY
        assert rule_cls.topics <= known
        assert rule_cls.title and not rule_cls.title.endswith(".")
        assert rule_cls.why_it_matters
        assert rule_cls.references


def test_no_rule_overrides_fix() -> None:
    from vibeguard.core.rule import Rule

    for rule_cls in RULES:
        assert rule_cls.fix is Rule.fix


def test_advisory_findings_map_to_review_required(tmp_path: Path) -> None:
    """INFORMATIONAL findings must not turn a checklist topic red."""
    findings = run_rule(FailureInjectionRule, tmp_path, _large_repo())
    detector = DetectorInfo(
        key=FailureInjectionRule.id,
        topics=frozenset(FailureInjectionRule.topics),
        applicable=True,
    )
    checklist = derive_checklist([detector], findings)
    item = next(i for i in checklist if i.topic_id == "disaster-recovery.chaos-engineering")
    assert item.status is ChecklistStatus.REVIEW_REQUIRED


def test_dr003_fires_on_the_shared_fixture_app() -> None:
    from conftest import FIXTURES, make_context

    ctx = make_context(FIXTURES / "dr_sqlite_container")
    rule = SqliteInContainerRule()
    assert rule.applicable(ctx)
    findings = rule.detect(ctx)
    assert [f.rule_id for f in findings] == ["VG-DR-003"]
