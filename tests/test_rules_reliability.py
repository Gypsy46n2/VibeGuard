"""Tests for the reliability rule pack (VG-REL-001 … VG-REL-011).

Every rule gets a positive and a negative case. For the scale-gated VG-REL-011 the
negative case proves the gate: a small project makes ``applicable()`` False, so no
finding is produced at all.
"""

from __future__ import annotations

from pathlib import Path

from conftest import context_from, run_rule
from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules.reliability import (
    RULES,
    BlockingCallInAsyncRule,
    DistributedFailureModesRule,
    JobResilienceRule,
    MessageDeliverySemanticsRule,
    NoGracefulShutdownRule,
    QueueObservabilityRule,
    SharedMutableStateRule,
    SwallowedExceptionRule,
    UnboundedCacheRule,
    UnboundedConcurrencyRule,
    UnreleasedResourceRule,
)
from vibeguard.rules.topics import topic_ids

FLASK = "flask==3.0.0\n"


def _ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


def _compose(count: int) -> str:
    services = ["  web:\n    build: .\n"]
    for index in range(count - 1):
        services.append(f"  svc{index}:\n    build: ./svc{index}\n")
    return "services:\n" + "".join(services)


# --------------------------------------------------------------------- pack shape


def test_pack_exposes_every_rule_in_id_order():
    assert [rule.id for rule in RULES] == [f"VG-REL-{n:03d}" for n in range(1, 12)]


def test_rule_metadata_is_well_formed():
    known = topic_ids()
    for rule in RULES:
        assert rule.category is Category.RELIABILITY
        assert rule.title and not rule.title.endswith(".")
        assert rule.description and rule.why_it_matters
        assert rule.references
        assert rule.topics and rule.topics <= known
        assert isinstance(rule.severity, Severity)
        assert isinstance(rule.confidence, Confidence)
        # Only VG-REL-002 gained a repair in M3; the rest stay detect-only.
        assert ("fix" in vars(rule)) == (rule.id == "VG-REL-002")


def test_no_rule_fires_on_the_shared_clean_fixture(sample_ctx):
    for rule_cls in RULES:
        rule = rule_cls()
        if rule.applicable(sample_ctx):
            assert rule.detect(sample_ctx) == [], rule_cls.id


# ------------------------------------------------------------------ VG-REL-001


def test_swallowed_exception_fires(tmp_path: Path):
    findings = run_rule(
        SwallowedExceptionRule,
        tmp_path,
        {
            "sync.py": (
                "def sync(order):\n"
                "    try:\n"
                "        push(order)\n"
                "    except Exception:\n"
                "        pass\n"
            )
        },
    )
    assert _ids(findings) == ["VG-REL-001"]
    assert findings[0].confidence is Confidence.HIGH


def test_swallowed_exception_silent_when_logged_and_reraised(tmp_path: Path):
    findings = run_rule(
        SwallowedExceptionRule,
        tmp_path,
        {
            "sync.py": (
                "import logging\n\n"
                "log = logging.getLogger(__name__)\n\n\n"
                "def sync(order):\n"
                "    try:\n"
                "        push(order)\n"
                "    except Exception:\n"
                '        log.exception("failed to push order %s", order.id)\n'
                "        raise\n"
            )
        },
    )
    assert findings == []


def test_swallowed_exception_fires_on_empty_js_catch(tmp_path: Path):
    findings = run_rule(
        SwallowedExceptionRule,
        tmp_path,
        {
            "package.json": '{"name": "app", "dependencies": {"express": "^4"}}\n',
            "index.js": "async function main() {\n  try { await push(); } catch (e) {}\n}\n",
        },
    )
    assert _ids(findings) == ["VG-REL-001"]


# ------------------------------------------------------------------ VG-REL-002


def test_unreleased_resource_fires(tmp_path: Path):
    findings = run_rule(
        UnreleasedResourceRule,
        tmp_path,
        {"report.py": 'def load():\n    fh = open("data.txt")\n    return fh.read()\n'},
    )
    assert _ids(findings) == ["VG-REL-002"]
    assert "file handle" in findings[0].description


def test_unreleased_resource_silent_with_context_manager(tmp_path: Path):
    findings = run_rule(
        UnreleasedResourceRule,
        tmp_path,
        {
            "report.py": (
                "def load():\n"
                '    with open("data.txt") as fh:\n'
                "        return fh.read()\n"
            )
        },
    )
    assert findings == []


def test_unreleased_cursor_silent_when_closed(tmp_path: Path):
    findings = run_rule(
        UnreleasedResourceRule,
        tmp_path,
        {
            "store.py": (
                "def rows(conn):\n"
                "    cur = conn.cursor()\n"
                "    try:\n"
                '        cur.execute("SELECT id FROM t")\n'
                "        return cur.fetchall()\n"
                "    finally:\n"
                "        cur.close()\n"
            )
        },
    )
    assert findings == []


# ------------------------------------------------------------------ VG-REL-003


def test_blocking_call_in_async_fires(tmp_path: Path):
    findings = run_rule(
        BlockingCallInAsyncRule,
        tmp_path,
        {
            "requirements.txt": "fastapi\nrequests\n",
            "worker.py": (
                "import time\n\n\n"
                "async def poll(url):\n"
                "    time.sleep(5)\n"
                "    return url\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-003"]
    assert findings[0].severity is Severity.HIGH


def test_blocking_call_in_async_silent_when_awaited(tmp_path: Path):
    findings = run_rule(
        BlockingCallInAsyncRule,
        tmp_path,
        {
            "requirements.txt": "fastapi\n",
            "worker.py": (
                "import asyncio\n\n\n"
                "async def poll(url):\n"
                "    await asyncio.sleep(5)\n"
                "    return url\n"
            ),
        },
    )
    assert findings == []


def test_sync_flask_handler_is_not_flagged(tmp_path: Path):
    """A blocking read in a synchronous WSGI handler is not an event-loop defect."""
    findings = run_rule(
        BlockingCallInAsyncRule,
        tmp_path,
        {
            "requirements.txt": FLASK,
            "app.py": (
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n\n\n"
                '@app.route("/motd")\n'
                "def show_motd():\n"
                '    with open("motd.txt") as fh:\n'
                "        return fh.read()\n"
            ),
        },
    )
    assert findings == []


# ------------------------------------------------------------------ VG-REL-004


def test_unbounded_concurrency_fires_on_gather_spread(tmp_path: Path):
    findings = run_rule(
        UnboundedConcurrencyRule,
        tmp_path,
        {
            "requirements.txt": "aiohttp\n",
            "fetcher.py": (
                "import asyncio\n\n\n"
                "async def fetch_all(urls):\n"
                "    return await asyncio.gather(*[fetch(u) for u in urls])\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-004"]


def test_unbounded_concurrency_silent_with_semaphore(tmp_path: Path):
    findings = run_rule(
        UnboundedConcurrencyRule,
        tmp_path,
        {
            "requirements.txt": "aiohttp\n",
            "fetcher.py": (
                "import asyncio\n\n"
                "GATE = asyncio.Semaphore(10)\n\n\n"
                "async def one(url):\n"
                "    async with GATE:\n"
                "        return await fetch(url)\n\n\n"
                "async def fetch_all(urls):\n"
                "    return await asyncio.gather(*[one(u) for u in urls])\n"
            ),
        },
    )
    assert findings == []


def test_unbounded_concurrency_fires_on_promise_all_map(tmp_path: Path):
    findings = run_rule(
        UnboundedConcurrencyRule,
        tmp_path,
        {
            "package.json": '{"name": "app", "dependencies": {"express": "^4"}}\n',
            "fan.js": (
                "export async function fanOut(items) {\n"
                "  return Promise.all(items.map((item) => send(item)));\n"
                "}\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-004"]


# ------------------------------------------------------------------ VG-REL-005


def test_unbounded_cache_fires(tmp_path: Path):
    findings = run_rule(
        UnboundedCacheRule,
        tmp_path,
        {
            "requirements.txt": FLASK,
            "app.py": (
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n"
                "CACHE = {}\n\n\n"
                '@app.route("/thing/<key>")\n'
                "def thing(key):\n"
                "    CACHE[key] = compute(key)\n"
                "    return CACHE[key]\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-005"]
    assert "CACHE" in findings[0].description


def test_unbounded_cache_silent_with_ttl_cache(tmp_path: Path):
    findings = run_rule(
        UnboundedCacheRule,
        tmp_path,
        {
            "requirements.txt": FLASK + "cachetools\n",
            "app.py": (
                "from cachetools import TTLCache\n"
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n"
                "CACHE = TTLCache(maxsize=1000, ttl=60)\n\n\n"
                '@app.route("/thing/<key>")\n'
                "def thing(key):\n"
                "    CACHE[key] = compute(key)\n"
                "    return CACHE[key]\n"
            ),
        },
    )
    assert findings == []


# ------------------------------------------------------------------ VG-REL-006


def test_shared_mutable_state_fires_on_unguarded_global(tmp_path: Path):
    findings = run_rule(
        SharedMutableStateRule,
        tmp_path,
        {
            "requirements.txt": FLASK,
            "app.py": (
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n"
                "HITS = 0\n\n\n"
                '@app.route("/hit")\n'
                "def hit():\n"
                "    global HITS\n"
                "    HITS += 1\n"
                "    return str(HITS)\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-006"]
    assert "HITS" in findings[0].description


def test_shared_mutable_state_silent_when_locked(tmp_path: Path):
    findings = run_rule(
        SharedMutableStateRule,
        tmp_path,
        {
            "requirements.txt": FLASK,
            "app.py": (
                "import threading\n"
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n"
                "HITS = 0\n"
                "GUARD = threading.Lock()\n\n\n"
                '@app.route("/hit")\n'
                "def hit():\n"
                "    global HITS\n"
                "    with GUARD:\n"
                "        HITS += 1\n"
                "    return str(HITS)\n"
            ),
        },
    )
    assert findings == []


def test_shared_mutable_state_fires_on_nested_lock_acquisition(tmp_path: Path):
    findings = run_rule(
        SharedMutableStateRule,
        tmp_path,
        {
            "requirements.txt": FLASK,
            "app.py": (
                "import threading\n\n"
                "lock_a = threading.Lock()\n"
                "lock_b = threading.Lock()\n\n\n"
                "def move(src, dst):\n"
                "    with lock_a:\n"
                "        with lock_b:\n"
                "            dst.append(src.pop())\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-006"]
    assert "deadlock" in findings[0].description


# ------------------------------------------------------------------ VG-REL-007


def test_job_resilience_fires_on_bare_task(tmp_path: Path):
    findings = run_rule(
        JobResilienceRule,
        tmp_path,
        {
            "requirements.txt": "celery\n",
            "tasks.py": (
                "from celery import shared_task\n\n\n"
                "@shared_task\n"
                "def send_welcome(user_id):\n"
                "    mailer.send(user_id)\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-007"]


def test_job_resilience_silent_when_configured(tmp_path: Path):
    findings = run_rule(
        JobResilienceRule,
        tmp_path,
        {
            "requirements.txt": "celery\n",
            "tasks.py": (
                "from celery import shared_task\n\n\n"
                "@shared_task(\n"
                "    autoretry_for=(Exception,),\n"
                "    retry_backoff=True,\n"
                "    max_retries=5,\n"
                "    acks_late=True,\n"
                "    soft_time_limit=30,\n"
                ")\n"
                "def send_welcome(user_id):\n"
                "    Delivery.objects.get_or_create(user_id=user_id)\n"
                "    mailer.send(user_id)\n"
            ),
        },
    )
    assert findings == []


def test_job_resilience_flags_unguarded_cron(tmp_path: Path):
    findings = run_rule(
        JobResilienceRule,
        tmp_path,
        {
            "requirements.txt": "celery\n",
            "tasks.py": (
                "from celery import shared_task\n\n\n"
                "@shared_task(autoretry_for=(Exception,), max_retries=3, soft_time_limit=5)\n"
                "def nightly():\n"
                "    Report.objects.get_or_create(day=today())\n"
            ),
            "schedule.py": (
                "from apscheduler.schedulers.background import BackgroundScheduler\n\n"
                "scheduler = BackgroundScheduler()\n"
                'scheduler.add_job(nightly, "cron", hour=2)\n'
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-007"]
    assert "scheduled job" in findings[0].description


# ------------------------------------------------------------------ VG-REL-008

_DEPLOYED_SERVER = {
    "requirements.txt": FLASK,
    "docker-compose.yml": _compose(3),
    "main.py": (
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n\n"
        'if __name__ == "__main__":\n'
        '    app.run(host="0.0.0.0")\n'
    ),
}


def test_no_graceful_shutdown_fires(tmp_path: Path):
    ctx = context_from(tmp_path, dict(_DEPLOYED_SERVER))
    assert ctx.scale.scale >= ScaleClass.MEDIUM
    findings = NoGracefulShutdownRule().detect(ctx)
    assert _ids(findings) == ["VG-REL-008"]
    assert findings[0].file is None


def test_no_graceful_shutdown_silent_with_sigterm_handler(tmp_path: Path):
    files = dict(_DEPLOYED_SERVER)
    files["main.py"] += (
        "\nimport signal\n\n\n"
        "def _stop(signum, frame):\n"
        "    server.close()\n\n\n"
        "signal.signal(signal.SIGTERM, _stop)\n"
    )
    assert run_rule(NoGracefulShutdownRule, tmp_path, files) == []


def test_no_graceful_shutdown_gate_excludes_a_small_project(tmp_path: Path):
    files = {
        "requirements.txt": FLASK,
        "main.py": "from flask import Flask\napp = Flask(__name__)\n",
    }
    ctx = context_from(tmp_path, files)
    assert ctx.scale.scale < ScaleClass.MEDIUM
    assert NoGracefulShutdownRule().applicable(ctx) is False


# ------------------------------------------------------------------ VG-REL-009

_WORKER_REPO = {
    "requirements.txt": "celery\nredis\n",
    "docker-compose.yml": _compose(2),
    "tasks.py": "from celery import shared_task\n",
}


def test_queue_observability_fires(tmp_path: Path):
    ctx = context_from(tmp_path, dict(_WORKER_REPO))
    assert ctx.scale.scale >= ScaleClass.SMALL
    findings = QueueObservabilityRule().detect(ctx)
    assert _ids(findings) == ["VG-REL-009"]
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL
    assert findings[0].severity is Severity.LOW


def test_queue_observability_silent_with_queue_metrics(tmp_path: Path):
    files = dict(_WORKER_REPO)
    files["metrics.py"] = (
        "from prometheus_client import Gauge\n\n"
        'queue_depth = Gauge("queue_depth", "pending jobs")\n'
    )
    assert run_rule(QueueObservabilityRule, tmp_path, files) == []


# ------------------------------------------------------------------ VG-REL-010


def test_message_delivery_semantics_fires(tmp_path: Path):
    findings = run_rule(
        MessageDeliverySemanticsRule,
        tmp_path,
        {
            "requirements.txt": "kafka-python\n",
            "consumer.py": (
                "from kafka import KafkaConsumer\n\n\n"
                "def run():\n"
                '    consumer = KafkaConsumer("orders")\n'
                "    for message in consumer:\n"
                "        handle(message.value)\n"
            ),
        },
    )
    assert _ids(findings) == ["VG-REL-010"]


def test_message_delivery_semantics_silent_when_handled(tmp_path: Path):
    findings = run_rule(
        MessageDeliverySemanticsRule,
        tmp_path,
        {
            "requirements.txt": "kafka-python\n",
            "consumer.py": (
                "from kafka import KafkaConsumer\n\n"
                "DEAD_LETTER_TOPIC = 'orders.dlq'\n\n\n"
                "def run():\n"
                '    consumer = KafkaConsumer("orders", enable_auto_commit=False)\n'
                "    for message in consumer:\n"
                "        if already_processed(message.headers['message_id']):\n"
                "            consumer.commit()\n"
                "            continue\n"
                "        try:\n"
                "            handle(message.value)\n"
                "        except PoisonMessage:\n"
                "            publish(DEAD_LETTER_TOPIC, message)\n"
                "        consumer.commit()\n"
            ),
        },
    )
    assert findings == []


# ------------------------------------------------------------------ VG-REL-011

_DISTRIBUTED_REPO = {
    "requirements.txt": "flask\nkafka-python\n",
    "docker-compose.yml": _compose(5),
    "app.py": "def main():\n    return 0\n",
}


def test_distributed_failure_modes_fires_only_at_large_scale(tmp_path: Path):
    ctx = context_from(tmp_path, dict(_DISTRIBUTED_REPO))
    assert ctx.scale.scale is ScaleClass.LARGE
    rule = DistributedFailureModesRule()
    assert rule.applicable(ctx) is True
    findings = rule.detect(ctx)
    assert _ids(findings) == ["VG-REL-011"]
    assert findings[0].severity is Severity.INFO
    assert findings[0].autofix_safety is AutofixSafety.INFORMATIONAL


def test_distributed_failure_modes_silent_when_addressed(tmp_path: Path):
    files = dict(_DISTRIBUTED_REPO)
    files["docs/architecture.md"] = (
        "# Architecture\n\n"
        "Cross-service writes use the transactional outbox pattern with a saga "
        "coordinator; singleton jobs use leader election via etcd leases.\n"
    )
    assert run_rule(DistributedFailureModesRule, tmp_path, files) == []


def test_distributed_failure_modes_gate_excludes_a_small_app(tmp_path: Path):
    files = {
        "requirements.txt": FLASK,
        "docker-compose.yml": _compose(2),
        "app.py": "def main():\n    return 0\n",
    }
    ctx = context_from(tmp_path, files)
    assert ctx.scale.scale < ScaleClass.LARGE
    assert DistributedFailureModesRule().applicable(ctx) is False
    assert run_rule(DistributedFailureModesRule, tmp_path, files) == []


# ---------------------------------------------------------------- robustness


def test_rules_never_raise_on_malformed_sources(tmp_path: Path):
    files = {
        "requirements.txt": "celery\nflask\nkafka-python\n",
        "broken.py": "async def (:\n  ][ not python\n",
        "weird.ts": "class { => ;;; catch (\n",
        "empty.js": "",
    }
    ctx = context_from(tmp_path, files)
    for rule_cls in RULES:
        rule = rule_cls()
        if rule.applicable(ctx):
            assert isinstance(rule.detect(ctx), list), rule_cls.id
