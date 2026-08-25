"""Tests for the built-in ``network`` rule pack (VG-NET-001 … VG-NET-003)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_context, run_rule
from vibeguard.rules.network import RULES
from vibeguard.rules.network.cdn import NoCdnForStaticAssetsRule
from vibeguard.rules.network.connection_reuse import NoConnectionReuseRule
from vibeguard.rules.network.protocol import NoProtocolPostureRule

FIXTURE = Path(__file__).parent / "fixtures" / "network_vulnerable"

COMPOSE_THREE = """\
services:
  web:
    build: .
  db:
    image: postgres:16
  jobs:
    build: .
"""

COMPOSE_FIVE = """\
services:
  web:
    build: .
  api:
    build: .
  billing:
    build: .
  search:
    build: .
  db:
    image: postgres:16
"""

_STATIC_APP = (
    "from flask import Flask, send_from_directory\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/assets/<path:name>")\n'
    "def assets(name):\n"
    '    return send_from_directory("static", name)\n'
)

_STATIC_FILES = {
    "static/app.css": "body { margin: 0 }\n",
    "static/logo.svg": "<svg xmlns='http://www.w3.org/2000/svg'></svg>\n",
    "static/main.js": "console.log('hello');\n",
    "static/vendor.js": "window.__vendor = 1;\n",
}


def ids_of(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------- VG-NET-001


def test_static_assets_without_cdn_fire(tmp_path):
    findings = run_rule(
        NoCdnForStaticAssetsRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": _STATIC_APP,
            "docker-compose.yml": COMPOSE_THREE,
            **_STATIC_FILES,
        },
    )
    assert ids_of(findings) == ["VG-NET-001"]
    assert findings[0].category.value == "reliability"


def test_static_assets_with_edge_caching_are_clean(tmp_path):
    findings = run_rule(
        NoCdnForStaticAssetsRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": _STATIC_APP,
            "docker-compose.yml": COMPOSE_THREE,
            "deploy/edge.conf": (
                "location /assets/ {\n  expires 365d;\n  add_header X-Edge cloudfront;\n}\n"
            ),
            **_STATIC_FILES,
        },
    )
    assert findings == []


def test_no_static_tree_is_clean(tmp_path):
    findings = run_rule(
        NoCdnForStaticAssetsRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": "from flask import Flask\n\napp = Flask(__name__)\n",
            "docker-compose.yml": COMPOSE_THREE,
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-NET-002


def test_oneshot_request_in_loop_fires(tmp_path):
    findings = run_rule(
        NoConnectionReuseRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "sync.py": (
                "import requests\n\n\n"
                "def fetch_all(urls):\n"
                "    out = []\n"
                "    for url in urls:\n"
                "        out.append(requests.get(url, timeout=5).json())\n"
                "    return out\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-NET-002"]


def test_pooled_session_is_clean(tmp_path):
    findings = run_rule(
        NoConnectionReuseRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "sync.py": (
                "import requests\n\n"
                "SESSION = requests.Session()\n\n\n"
                "def fetch_all(urls):\n"
                "    return [SESSION.get(url, timeout=5).json() for url in urls]\n"
            ),
        },
    )
    assert findings == []


def test_node_request_without_keepalive_agent_fires(tmp_path):
    findings = run_rule(
        NoConnectionReuseRule,
        tmp_path,
        {
            "package.json": '{"name": "app"}\n',
            "client.js": (
                "const https = require('https');\n\n"
                "function call(options) {\n"
                "  return https.request(options, (res) => res.resume());\n"
                "}\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-NET-002"]


def test_node_keepalive_agent_is_clean(tmp_path):
    findings = run_rule(
        NoConnectionReuseRule,
        tmp_path,
        {
            "package.json": '{"name": "app"}\n',
            "client.js": (
                "const https = require('https');\n\n"
                "const agent = new https.Agent({ keepAlive: true, maxSockets: 50 });\n\n"
                "function call(options) {\n"
                "  return https.request({ ...options, agent }, (res) => res.resume());\n"
                "}\n"
            ),
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-NET-003


def test_multi_service_without_protocol_posture_fires(tmp_path):
    findings = run_rule(
        NoProtocolPostureRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": "from flask import Flask\n\napp = Flask(__name__)\n",
            "docker-compose.yml": COMPOSE_FIVE,
        },
    )
    assert ids_of(findings) == ["VG-NET-003"]
    assert findings[0].autofix_safety.value == "informational"
    assert "review prompt" in NoProtocolPostureRule.description.lower()


def test_declared_protocol_posture_is_clean(tmp_path):
    findings = run_rule(
        NoProtocolPostureRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": "from flask import Flask\n\napp = Flask(__name__)\n",
            "docker-compose.yml": COMPOSE_FIVE,
            "deploy/mesh.yaml": (
                "protocol: grpc\n"
                "dnsPolicy: ClusterFirst\n"
                "connect_timeout: 2s\n"
                "idle_timeout: 60s\n"
            ),
        },
    )
    assert findings == []


def test_single_service_repo_is_not_prompted(tmp_path):
    findings = run_rule(
        NoProtocolPostureRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": "from flask import Flask\n\napp = Flask(__name__)\n",
        },
    )
    assert findings == []


# ---------------------------------------------------------------- pack-wide


def test_pack_registers_expected_rule_ids():
    assert [rule.id for rule in RULES] == ["VG-NET-001", "VG-NET-002", "VG-NET-003"]


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
            "requirements.txt": "flask\nrequests\n",
            "docker-compose.yml": "services: [not, a, mapping\n",
            "broken.py": "def (:::\n  @@@ not python at all\n",
            "broken.js": "function ( { ] ) => \n",
        },
    )
