"""Tests for the built-in ``api`` rule pack (VG-API-001 … VG-API-010)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_context, run_rule
from vibeguard.rules.api import RULES
from vibeguard.rules.api.caching import NoCachingStrategyRule, NoReverseProxyRule
from vibeguard.rules.api.rate_limiting import NoRateLimitingRule
from vibeguard.rules.api.realtime import RealtimeWithoutHeartbeatRule
from vibeguard.rules.api.retries import RetryWithoutBackoffRule
from vibeguard.rules.api.timeouts import HttpTimeoutJsRule, HttpTimeoutPythonRule
from vibeguard.rules.api.versioning import NoApiVersioningRule
from vibeguard.rules.api.webhooks import NoIdempotencyKeyRule, UnverifiedWebhookRule

FIXTURE = Path(__file__).parent / "fixtures" / "api_vulnerable"

FLASK_REQS = "flask\n"

COMPOSE_THREE = """\
services:
  web:
    build: .
  db:
    image: postgres:16
  cache:
    image: memcached:1
"""


def ids_of(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------- VG-API-001


def test_python_http_call_without_timeout_fires(tmp_path):
    findings = run_rule(
        HttpTimeoutPythonRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "client.py": (
                "import requests\n\n\ndef fetch(url):\n    return requests.get(url).json()\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-API-001"]
    assert findings[0].line == 5


def test_python_http_call_with_timeout_is_clean(tmp_path):
    findings = run_rule(
        HttpTimeoutPythonRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "client.py": (
                "import requests\n\n\ndef fetch(url):\n"
                "    return requests.get(url, timeout=(3.05, 10)).json()\n"
            ),
        },
    )
    assert findings == []


def test_python_session_default_timeout_is_clean(tmp_path):
    findings = run_rule(
        HttpTimeoutPythonRule,
        tmp_path,
        {
            "requirements.txt": "httpx\n",
            "client.py": (
                "import httpx\n\n"
                "client = httpx.Client(timeout=httpx.Timeout(10.0, connect=3.0))\n\n\n"
                "def fetch(url):\n    return client.get(url).json()\n"
            ),
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-002


def test_axios_without_timeout_fires(tmp_path):
    findings = run_rule(
        HttpTimeoutJsRule,
        tmp_path,
        {
            "package.json": '{"name": "app", "dependencies": {"axios": "^1.0.0"}}\n',
            "client.js": (
                "const axios = require('axios');\n\n"
                "async function load(url) {\n"
                "  return axios.get(url);\n"
                "}\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-API-002"]


def test_fetch_without_signal_is_low_confidence(tmp_path):
    findings = run_rule(
        HttpTimeoutJsRule,
        tmp_path,
        {
            "package.json": '{"name": "app"}\n',
            "client.js": "async function load(url) {\n  return fetch(url);\n}\n",
        },
    )
    assert ids_of(findings) == ["VG-API-002"]
    assert findings[0].confidence.value == "low"


def test_axios_and_fetch_with_timeouts_are_clean(tmp_path):
    findings = run_rule(
        HttpTimeoutJsRule,
        tmp_path,
        {
            "package.json": '{"name": "app", "dependencies": {"axios": "^1.0.0"}}\n',
            "client.js": (
                "const axios = require('axios');\n\n"
                "async function load(url) {\n"
                "  await axios.get(url, { timeout: 10000 });\n"
                "  return fetch(url, { signal: AbortSignal.timeout(10000) });\n"
                "}\n"
            ),
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-003

_FLASK_APP = (
    "from flask import Flask\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/users")\n'
    "def list_users():\n"
    '    return {"users": []}\n'
)


def test_no_rate_limiting_fires(tmp_path):
    findings = run_rule(
        NoRateLimitingRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": _FLASK_APP}
    )
    assert ids_of(findings) == ["VG-API-003"]


def test_rate_limiter_dependency_is_clean(tmp_path):
    findings = run_rule(
        NoRateLimitingRule,
        tmp_path,
        {
            "requirements.txt": "flask\nflask-limiter\n",
            "app.py": _FLASK_APP,
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-004


def test_retry_loop_without_backoff_fires(tmp_path):
    findings = run_rule(
        RetryWithoutBackoffRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "sync.py": (
                "import requests\n\n\n"
                "def pull(url):\n"
                "    for attempt in range(5):\n"
                "        resp = requests.get(url, timeout=5)\n"
                "        if resp.ok:\n"
                "            return resp.json()\n"
                "    return None\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-API-004"]


def test_retry_loop_with_backoff_is_clean(tmp_path):
    findings = run_rule(
        RetryWithoutBackoffRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "sync.py": (
                "import random\nimport time\n\nimport requests\n\n\n"
                "def pull(url):\n"
                "    for attempt in range(5):\n"
                "        resp = requests.get(url, timeout=5)\n"
                "        if resp.ok:\n"
                "            return resp.json()\n"
                "        time.sleep(random.uniform(0, min(30, 0.5 * 2 ** attempt)))\n"
                "    return None\n"
            ),
        },
    )
    assert findings == []


def test_retry_config_without_backoff_factor_fires(tmp_path):
    findings = run_rule(
        RetryWithoutBackoffRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "http.py": (
                "from urllib3.util import Retry\n\n"
                "retry_policy = Retry(total=3, status_forcelist=[502])\n"
            ),
        },
    )
    assert ids_of(findings) == ["VG-API-004"]


def test_retry_config_with_backoff_factor_is_clean(tmp_path):
    findings = run_rule(
        RetryWithoutBackoffRule,
        tmp_path,
        {
            "requirements.txt": "requests\n",
            "http.py": (
                "from urllib3.util import Retry\n\n"
                "retry_policy = Retry(total=3, backoff_factor=0.5, status_forcelist=[502])\n"
            ),
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-005


def test_unversioned_routes_fire(tmp_path):
    findings = run_rule(
        NoApiVersioningRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": _FLASK_APP}
    )
    assert ids_of(findings) == ["VG-API-005"]
    assert findings[0].severity.value == "info"


def test_versioned_routes_are_clean(tmp_path):
    findings = run_rule(
        NoApiVersioningRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": _FLASK_APP.replace('"/users"', '"/api/v1/users"'),
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-006

_WEBHOOK = (
    "from flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/webhooks/stripe", methods=["POST"])\n'
    "def stripe_webhook():\n"
    "    event = request.get_json()\n"
    '    handle(event)\n'
    '    return "", 204\n'
)


def test_unverified_webhook_fires(tmp_path):
    findings = run_rule(
        UnverifiedWebhookRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": _WEBHOOK}
    )
    assert ids_of(findings) == ["VG-API-006"]


def test_verified_webhook_is_clean(tmp_path):
    verified = _WEBHOOK.replace(
        "    event = request.get_json()\n",
        "    expected = sign(request.data)\n"
        '    if not hmac.compare_digest(expected, request.headers["Stripe-Signature"]):\n'
        '        return "", 400\n'
        "    event = request.get_json()\n",
    )
    findings = run_rule(
        UnverifiedWebhookRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": verified}
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-007

_PAYMENT = (
    "from flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/payments", methods=["POST"])\n'
    "def create_payment():\n"
    "    body = request.get_json()\n"
    '    return charge(body["amount"])\n'
)


def test_payment_route_without_idempotency_fires(tmp_path):
    findings = run_rule(
        NoIdempotencyKeyRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": _PAYMENT}
    )
    assert ids_of(findings) == ["VG-API-007"]
    assert findings[0].autofix_safety.value == "review_recommended"


def test_payment_route_with_idempotency_key_is_clean(tmp_path):
    guarded = _PAYMENT.replace(
        "    body = request.get_json()\n",
        '    key = request.headers["Idempotency-Key"]\n'
        "    if seen(key):\n"
        "        return stored(key)\n"
        "    body = request.get_json()\n",
    )
    findings = run_rule(
        NoIdempotencyKeyRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": guarded}
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-008

_TWO_READS = (
    "from flask import Flask\n\n"
    "app = Flask(__name__)\n\n\n"
    '@app.route("/users")\n'
    "def list_users():\n"
    '    return {"users": []}\n\n\n'
    '@app.route("/posts")\n'
    "def list_posts():\n"
    '    return {"posts": []}\n'
)


def test_no_caching_strategy_fires(tmp_path):
    findings = run_rule(
        NoCachingStrategyRule,
        tmp_path,
        {"requirements.txt": "flask\npsycopg2-binary\n", "app.py": _TWO_READS},
    )
    assert ids_of(findings) == ["VG-API-008"]
    assert findings[0].autofix_safety.value == "informational"


def test_cache_layer_present_is_clean(tmp_path):
    findings = run_rule(
        NoCachingStrategyRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\nflask-caching\n",
            "app.py": _TWO_READS,
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-009

_SERVED_DIRECTLY = _FLASK_APP + '\n\nif __name__ == "__main__":\n    app.run(port=8000)\n'


def test_no_reverse_proxy_fires(tmp_path):
    findings = run_rule(
        NoReverseProxyRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": _SERVED_DIRECTLY,
            "docker-compose.yml": COMPOSE_THREE,
        },
    )
    assert ids_of(findings) == ["VG-API-009"]


def test_reverse_proxy_config_is_clean(tmp_path):
    findings = run_rule(
        NoReverseProxyRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": _SERVED_DIRECTLY,
            "docker-compose.yml": COMPOSE_THREE,
            "deploy/nginx.conf": "server {\n  listen 80;\n  proxy_pass http://web:8000;\n}\n",
        },
    )
    assert findings == []


# --------------------------------------------------------------- VG-API-010

_WS_SERVER = (
    "import asyncio\n\nimport websockets\n\n\n"
    "async def echo(conn):\n"
    "    async for message in conn:\n"
    "        await conn.send(message)\n\n\n"
    "async def main():\n"
    '    async with websockets.serve(echo, "0.0.0.0", 8765):\n'
    "        await asyncio.Future()\n"
)


def test_realtime_without_heartbeat_fires(tmp_path):
    findings = run_rule(
        RealtimeWithoutHeartbeatRule,
        tmp_path,
        {"requirements.txt": "websockets\n", "server.py": _WS_SERVER},
    )
    assert ids_of(findings) == ["VG-API-010"]


def test_realtime_with_heartbeat_and_backpressure_is_clean(tmp_path):
    tuned = _WS_SERVER.replace(
        'websockets.serve(echo, "0.0.0.0", 8765)',
        'websockets.serve(\n            echo,\n            "0.0.0.0",\n            8765,\n'
        "            ping_interval=20,\n            ping_timeout=20,\n"
        "            max_size=1048576,\n            max_queue=32,\n        )",
    )
    client = (
        "let delay = 500;\n"
        "function connect() {\n"
        "  const ws = new WebSocket(url);\n"
        "  ws.onclose = () => setTimeout(connect, delay * 2);\n"
        "}\n"
    )
    findings = run_rule(
        RealtimeWithoutHeartbeatRule,
        tmp_path,
        {"requirements.txt": "websockets\n", "server.py": tuned, "client.js": client},
    )
    assert findings == []


# ---------------------------------------------------------------- pack-wide


def test_pack_registers_expected_rule_ids():
    assert [rule.id for rule in RULES] == [f"VG-API-{n:03d}" for n in range(1, 11)]


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
            "requirements.txt": "flask\nwebsockets\n",
            "package.json": '{"dependencies": {"axios": "^1"}}',
            "broken.py": "def (:::\n  @@@ not python at all\n",
            "broken.js": "function ( { ] ) => \n",
        },
    )
