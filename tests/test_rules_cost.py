"""Tests for the cost rule pack (VG-COST-001 … VG-COST-004)."""

from __future__ import annotations

from pathlib import Path

from conftest import run_rule
from vibeguard.core.models import Category
from vibeguard.rules.cost import RULES
from vibeguard.rules.cost.hot_loops import BilledCallInLoopRule, LoggingInHotLoopRule
from vibeguard.rules.cost.images import OversizedBaseImageRule
from vibeguard.rules.cost.waste import WastefulWorkAndStorageRule

# ----------------------------------------------------------------- VG-COST-001


def test_cost001_fires_on_per_row_logging(tmp_path: Path) -> None:
    findings = run_rule(
        LoggingInHotLoopRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "report.py": (
                "import logging\n"
                "log = logging.getLogger(__name__)\n"
                "\n"
                "def run(cursor):\n"
                "    for row in cursor.fetchall():\n"
                "        log.info('processing %s', row)\n"
                "        handle(row)\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-001"]
    assert "every iteration" in findings[0].description


def test_cost001_silent_for_logging_outside_the_loop(tmp_path: Path) -> None:
    findings = run_rule(
        LoggingInHotLoopRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "report.py": (
                "import logging\n"
                "log = logging.getLogger(__name__)\n"
                "\n"
                "def run(cursor):\n"
                "    rows = cursor.fetchall()\n"
                "    for row in rows:\n"
                "        handle(row)\n"
                "    log.info('processed %d rows', len(rows))\n"
            ),
        },
    )
    assert findings == []


def test_cost001_silent_for_a_bounded_literal_loop(tmp_path: Path) -> None:
    findings = run_rule(
        LoggingInHotLoopRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "boot.py": (
                "import logging\n"
                "log = logging.getLogger(__name__)\n"
                "\n"
                "def announce():\n"
                "    for stage in ('load', 'warm', 'serve'):\n"
                "        log.info('stage %s', stage)\n"
            ),
        },
    )
    assert findings == []


# ----------------------------------------------------------------- VG-COST-002


def test_cost002_fires_on_http_call_in_a_loop(tmp_path: Path) -> None:
    findings = run_rule(
        BilledCallInLoopRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "sync.py": (
                "import requests\n"
                "\n"
                "def sync(user_ids):\n"
                "    out = []\n"
                "    for uid in user_ids:\n"
                "        out.append(requests.get(f'https://api.example.com/u/{uid}'))\n"
                "    return out\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-002"]
    assert "separate billed request" in findings[0].description


def test_cost002_fires_on_dynamodb_get_item_in_a_loop(tmp_path: Path) -> None:
    findings = run_rule(
        BilledCallInLoopRule,
        tmp_path,
        {
            "requirements.txt": "boto3\n",
            "store.py": (
                "import boto3\n"
                "table = boto3.resource('dynamodb').Table('items')\n"
                "\n"
                "def load(keys):\n"
                "    for key in keys:\n"
                "        yield table.get_item(Key={'id': key})\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-002"]


def test_cost002_silent_when_the_function_batches(tmp_path: Path) -> None:
    findings = run_rule(
        BilledCallInLoopRule,
        tmp_path,
        {
            "requirements.txt": "boto3\n",
            "store.py": (
                "import boto3\n"
                "client = boto3.client('dynamodb')\n"
                "\n"
                "def load(keys):\n"
                "    for chunk in chunked(keys, 100):\n"
                "        yield client.batch_get_item(RequestItems=request_for(chunk))\n"
            ),
        },
    )
    assert findings == []


def test_cost002_silent_for_a_single_call_outside_a_loop(tmp_path: Path) -> None:
    findings = run_rule(
        BilledCallInLoopRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "sync.py": (
                "import requests\n"
                "\n"
                "def sync(uid):\n"
                "    return requests.get(f'https://api.example.com/u/{uid}')\n"
            ),
        },
    )
    assert findings == []


# ----------------------------------------------------------------- VG-COST-003


def test_cost003_fires_on_a_full_distribution_base(tmp_path: Path) -> None:
    findings = run_rule(
        OversizedBaseImageRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "Dockerfile": (
                "FROM python:3.12\n"
                "RUN apt-get update && apt-get install -y build-essential\n"
                "COPY requirements.txt .\n"
                "RUN pip install -r requirements.txt\n"
                "COPY . /app\n"
                "CMD [\"python\", \"app.py\"]\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-003"]
    assert "full distribution image" in findings[0].description
    assert "single-stage" in findings[0].description


def test_cost003_silent_for_an_idiomatic_slim_single_stage_build(tmp_path: Path) -> None:
    """A slim base with only `pip install` is the recommended Python layout."""
    findings = run_rule(
        OversizedBaseImageRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "Dockerfile": (
                "FROM python:3.11-slim\n"
                "WORKDIR /app\n"
                "COPY requirements.txt .\n"
                "RUN pip install --no-cache-dir -r requirements.txt\n"
                "COPY . .\n"
                "CMD [\"python\", \"app.py\"]\n"
            ),
        },
    )
    assert findings == []


def test_cost003_silent_for_a_slim_multi_stage_build(tmp_path: Path) -> None:
    findings = run_rule(
        OversizedBaseImageRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "Dockerfile": (
                "FROM python:3.12-slim AS build\n"
                "RUN pip install --prefix=/out -r requirements.txt\n"
                "\n"
                "FROM python:3.12-slim\n"
                "COPY --from=build /out /usr/local\n"
                "CMD [\"python\", \"app.py\"]\n"
            ),
        },
    )
    assert findings == []


def test_cost003_silent_when_the_workload_needs_a_fat_image(tmp_path: Path) -> None:
    findings = run_rule(
        OversizedBaseImageRule,
        tmp_path,
        {
            "requirements.txt": "torch\n",
            "Dockerfile": "FROM python:3.12\nRUN pip install torch\n",
        },
    )
    assert findings == []


# ----------------------------------------------------------------- VG-COST-004


def test_cost004_fires_on_a_minutely_full_scan_job(tmp_path: Path) -> None:
    findings = run_rule(
        WastefulWorkAndStorageRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "jobs.py": (
                "SCHEDULE = '* * * * *'\n"
                "\n"
                "def recompute_totals(db):\n"
                "    rows = db.execute('SELECT * FROM orders')\n"
                "    return summarise(rows)\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-004"]
    assert "sub-minute frequency" in findings[0].description


def test_cost004_fires_on_blob_columns(tmp_path: Path) -> None:
    findings = run_rule(
        WastefulWorkAndStorageRule,
        tmp_path,
        {
            "requirements.txt": "sqlalchemy\n",
            "models.py": (
                "import sqlalchemy as sa\n"
                "\n"
                "class Doc(Base):\n"
                "    body = sa.Column(sa.LargeBinary)\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-004"]
    assert "database column" in findings[0].description


def test_cost004_fires_on_storage_without_retention(tmp_path: Path) -> None:
    findings = run_rule(
        WastefulWorkAndStorageRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": "print('hi')\n",
            "logs/app.log": "started\n",
        },
    )
    assert [f.rule_id for f in findings] == ["VG-COST-004"]
    assert "no retention or lifecycle policy" in findings[0].description


def test_cost004_silent_on_a_sane_schedule_and_lifecycle(tmp_path: Path) -> None:
    findings = run_rule(
        WastefulWorkAndStorageRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "jobs.py": (
                "SCHEDULE = '0 3 * * *'\n"
                "\n"
                "def recompute_totals(db):\n"
                "    return db.execute('SELECT id FROM orders WHERE updated_at > ?')\n"
            ),
            "logs/app.log": "started\n",
            "infra/logs.tf": 'resource "aws_s3_bucket_lifecycle_configuration" "logs" {}\n',
        },
    )
    assert findings == []


# ------------------------------------------------------------------- pack-wide


def test_every_rule_declares_valid_metadata() -> None:
    from vibeguard.rules.topics import topic_ids

    known = set(topic_ids())
    assert len(RULES) == 4
    for rule_cls in RULES:
        assert rule_cls.category is Category.COST
        assert rule_cls.topics <= known
        assert rule_cls.title and not rule_cls.title.endswith(".")
        assert rule_cls.why_it_matters
        assert rule_cls.references


def test_only_the_slim_image_rule_repairs_itself() -> None:
    """M3 gave VG-COST-003 a repair; the rest of the cost pack stays detect-only."""
    from vibeguard.core.rule import Rule

    for rule_cls in RULES:
        if rule_cls.id == "VG-COST-003":
            assert rule_cls.fix is not Rule.fix
        else:
            assert rule_cls.fix is Rule.fix


def test_rules_never_raise_on_malformed_sources(tmp_path: Path) -> None:
    junk = {
        "requirements.txt": "flask\n",
        "app.py": "for x in (:\n    log.info(???)\n",
        "Dockerfile": "NOTAFROM whatever\n",
        "jobs.py": "\x00\x01 binary-ish\n",
    }
    for rule_cls in RULES:
        assert isinstance(run_rule(rule_cls, tmp_path, junk), list)


def test_shared_fixture_app_trips_both_hot_loop_rules() -> None:
    from conftest import FIXTURES, make_context

    ctx = make_context(FIXTURES / "cost_hot_loops")
    fired = {
        rule_cls.id
        for rule_cls in RULES
        if (rule := rule_cls()).applicable(ctx) and rule.detect(ctx)
    }
    assert fired == {"VG-COST-001", "VG-COST-002"}
