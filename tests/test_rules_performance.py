"""Tests for the built-in ``performance`` rule pack (VG-PERF-001 … VG-PERF-004)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_context, run_rule
from vibeguard.rules.performance import RULES
from vibeguard.rules.performance.blocking import BlockingCallInHandlerRule
from vibeguard.rules.performance.heavy_work import HeavyWorkInRequestPathRule
from vibeguard.rules.performance.pagination import ListEndpointWithoutPaginationRule
from vibeguard.rules.performance.serverless import ServerlessLimitsIgnoredRule

FIXTURE = Path(__file__).parent / "fixtures" / "performance_vulnerable"

COMPOSE_THREE = """\
services:
  web:
    build: .
  db:
    image: postgres:16
  api:
    build: .
"""


def ids_of(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


# -------------------------------------------------------------- VG-PERF-001


def test_blocking_sleep_in_handler_fires(tmp_path):
    findings = run_rule(
        BlockingCallInHandlerRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": (
                "import time\n\nfrom flask import Flask\n\n"
                "app = Flask(__name__)\n\n\n"
                '@app.route("/wait")\n'
                "def wait():\n"
                "    time.sleep(5)\n"
                '    return "ok"\n'
            ),
        },
    )
    assert ids_of(findings) == ["VG-PERF-001"]


def test_blocking_call_in_async_def_fires(tmp_path):
    findings = run_rule(
        BlockingCallInHandlerRule,
        tmp_path,
        {
            "requirements.txt": "fastapi\n",
            "main.py": (
                "import time\n\nfrom fastapi import FastAPI\n\n"
                "app = FastAPI()\n\n\n"
                '@app.get("/wait")\n'
                "async def wait():\n"
                "    time.sleep(5)\n"
                '    return {"ok": True}\n'
            ),
        },
    )
    assert ids_of(findings) == ["VG-PERF-001"]


def test_non_blocking_handler_is_clean(tmp_path):
    findings = run_rule(
        BlockingCallInHandlerRule,
        tmp_path,
        {
            "requirements.txt": "fastapi\nhttpx\n",
            "main.py": (
                "import asyncio\n\nimport httpx\nfrom fastapi import FastAPI\n\n"
                "app = FastAPI()\n"
                "client = httpx.AsyncClient(timeout=10.0)\n\n\n"
                '@app.get("/wait")\n'
                "async def wait():\n"
                "    await asyncio.sleep(0)\n"
                '    resp = await client.get("https://example.test/x")\n'
                "    return resp.json()\n"
            ),
        },
    )
    assert findings == []


def test_sync_fs_call_in_express_handler_fires(tmp_path):
    findings = run_rule(
        BlockingCallInHandlerRule,
        tmp_path,
        {
            "package.json": '{"name": "app", "dependencies": {"express": "^4"}}\n',
            "server.js": (
                "const fs = require('fs');\n"
                "const express = require('express');\n"
                "const app = express();\n\n"
                "app.get('/report', (req, res) => {\n"
                "  const data = fs.readFileSync('./report.csv', 'utf8');\n"
                "  res.send(data);\n"
                "});\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-PERF-001"]


def test_async_fs_call_in_express_handler_is_clean(tmp_path):
    findings = run_rule(
        BlockingCallInHandlerRule,
        tmp_path,
        {
            "package.json": '{"name": "app", "dependencies": {"express": "^4"}}\n',
            "server.js": (
                "const fs = require('fs/promises');\n"
                "const express = require('express');\n"
                "const app = express();\n\n"
                "app.get('/report', async (req, res) => {\n"
                "  const data = await fs.readFile('./report.csv', 'utf8');\n"
                "  res.send(data);\n"
                "});\n"
            ),
        },
    )
    assert findings == []


# -------------------------------------------------------------- VG-PERF-002


def test_list_endpoint_without_pagination_fires(tmp_path):
    findings = run_rule(
        ListEndpointWithoutPaginationRule,
        tmp_path,
        {
            "requirements.txt": "flask\nflask-sqlalchemy\n",
            "app.py": (
                "from flask import Flask, jsonify\n\n"
                "app = Flask(__name__)\n\n\n"
                '@app.route("/users")\n'
                "def list_users():\n"
                "    rows = User.query.all()\n"
                "    return jsonify([r.to_dict() for r in rows])\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-PERF-002"]


def test_paginated_list_endpoint_is_clean(tmp_path):
    findings = run_rule(
        ListEndpointWithoutPaginationRule,
        tmp_path,
        {
            "requirements.txt": "flask\nflask-sqlalchemy\n",
            "app.py": (
                "from flask import Flask, jsonify, request\n\n"
                "app = Flask(__name__)\n\n\n"
                '@app.route("/users")\n'
                "def list_users():\n"
                '    limit = min(int(request.args.get("limit", 50)), 200)\n'
                '    offset = int(request.args.get("offset", 0))\n'
                "    rows = User.query.limit(limit).offset(offset).all()\n"
                "    return jsonify([r.to_dict() for r in rows])\n"
            ),
        },
    )
    assert findings == []


# -------------------------------------------------------------- VG-PERF-003

_SERVERLESS_BASE = """\
service: reports
provider:
  name: aws
  runtime: python3.11
functions:
  build:
    handler: handler.lambda_handler
"""

_LAMBDA = (
    "import json\n\n\n"
    "def lambda_handler(event, context):\n"
    '    return {"statusCode": 200, "body": json.dumps({"ok": True})}\n'
)


def test_serverless_handler_without_limits_fires(tmp_path):
    findings = run_rule(
        ServerlessLimitsIgnoredRule,
        tmp_path,
        {"serverless.yml": _SERVERLESS_BASE, "handler.py": _LAMBDA},
    )
    assert ids_of(findings) == ["VG-PERF-003"]
    assert findings[0].autofix_safety.value == "informational"


def test_serverless_handler_with_limits_is_clean(tmp_path):
    findings = run_rule(
        ServerlessLimitsIgnoredRule,
        tmp_path,
        {
            "serverless.yml": _SERVERLESS_BASE + "    timeout: 30\n    memorySize: 512\n",
            "handler.py": _LAMBDA,
        },
    )
    assert findings == []


def test_serverless_heavy_module_import_fires(tmp_path):
    findings = run_rule(
        ServerlessLimitsIgnoredRule,
        tmp_path,
        {
            "serverless.yml": _SERVERLESS_BASE + "    timeout: 30\n    memorySize: 512\n",
            "handler.py": "import pandas as pd\n\n\n" + _LAMBDA.split("\n\n\n", 1)[1],
        },
    )
    assert ids_of(findings) == ["VG-PERF-003"]
    assert "pandas" in findings[0].description


# -------------------------------------------------------------- VG-PERF-004

_UPLOAD_APP = (
    "from PIL import Image\n"
    "from flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/upload", methods=["POST"])\n'
    "def upload():\n"
    '    img = Image.open(request.files["file"])\n'
    "    img.thumbnail((2048, 2048))\n"
    '    img.save("/tmp/out.png")\n'
    '    return "ok"\n'
)


def test_image_processing_in_handler_fires(tmp_path):
    findings = run_rule(
        HeavyWorkInRequestPathRule,
        tmp_path,
        {
            "requirements.txt": "flask\npillow\n",
            "app.py": _UPLOAD_APP,
            "docker-compose.yml": COMPOSE_THREE,
        },
    )
    assert ids_of(findings) == ["VG-PERF-004"]
    assert "image processing" in findings[0].description


def test_offloaded_image_processing_is_clean(tmp_path):
    offloaded = (
        "from flask import Flask, request\n\n"
        "from tasks import resize_image\n\n"
        "app = Flask(__name__)\n\n\n"
        '@app.route("/upload", methods=["POST"])\n'
        "def upload():\n"
        '    path = store(request.files["file"])\n'
        "    resize_image.delay(path)\n"
        '    return {"status": "queued"}, 202\n'
    )
    findings = run_rule(
        HeavyWorkInRequestPathRule,
        tmp_path,
        {
            "requirements.txt": "flask\npillow\ncelery\n",
            "app.py": offloaded,
            "docker-compose.yml": COMPOSE_THREE,
        },
    )
    assert findings == []


def test_heavy_work_rule_is_scale_gated(tmp_path):
    findings = run_rule(
        HeavyWorkInRequestPathRule,
        tmp_path,
        {"requirements.txt": "flask\npillow\n", "app.py": _UPLOAD_APP},
    )
    assert findings == []


# ---------------------------------------------------------------- pack-wide


def test_pack_registers_expected_rule_ids():
    assert [rule.id for rule in RULES] == [f"VG-PERF-{n:03d}" for n in range(1, 5)]


@pytest.mark.parametrize("rule_cls", RULES, ids=[r.id for r in RULES])
def test_every_rule_declares_known_topics(rule_cls):
    from vibeguard.rules.topics import topic_ids

    assert rule_cls.topics
    assert rule_cls.topics <= set(topic_ids())


@pytest.mark.parametrize("rule_cls", RULES, ids=[r.id for r in RULES])
def test_rules_never_raise_on_the_fixture_app(rule_cls):
    ctx = make_context(FIXTURE)
    rule = rule_cls()
    if rule.applicable(ctx):
        rule.detect(ctx)


@pytest.mark.parametrize("rule_cls", RULES, ids=[r.id for r in RULES])
def test_rules_survive_malformed_sources(tmp_path, rule_cls):
    run_rule(
        rule_cls,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "serverless.yml": "functions: [broken\n",
            "broken.py": "def (:::\n  @@@ not python at all\n",
            "broken.js": "function ( { ] ) => \n",
        },
    )
