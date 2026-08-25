"""Tests for the scaling rule pack (VG-SCALE-001 … VG-SCALE-004)."""

from __future__ import annotations

from pathlib import Path

from conftest import run_rule
from vibeguard.core.models import Category
from vibeguard.rules.scaling import RULES
from vibeguard.rules.scaling.caching import InProcessCacheRule
from vibeguard.rules.scaling.state import InProcessStateRule
from vibeguard.rules.scaling.storage import LocalUploadStorageRule
from vibeguard.rules.scaling.workers import InlineLongRunningWorkRule

FLASK_REQS = "flask\n"


def _medium(extra: dict[str, str]) -> dict[str, str]:
    """A repo big enough for detect_scale() to return MEDIUM (three services)."""
    files = {
        "requirements.txt": FLASK_REQS,
        "docker-compose.yml": (
            "services:\n"
            "  web:\n    build: .\n"
            "  worker_placeholder:\n    image: example/side:latest\n"
            "  proxy:\n    image: nginx:latest\n"
        ),
    }
    files.update(extra)
    return files


# ---------------------------------------------------------------- VG-SCALE-001


def test_scale001_fires_on_module_level_session_dict(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessStateRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": (
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n"
                "carts = {}\n"
                "\n"
                "@app.post('/cart')\n"
                "def add():\n"
                "    carts[request.form['user']] = request.form['item']\n"
                "    return 'ok'\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCALE-001"]
    assert "`carts`" in findings[0].description


def test_scale001_fires_on_filesystem_session_type(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessStateRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                "app.config['SESSION_TYPE'] = 'filesystem'\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCALE-001"]
    assert "SESSION_TYPE" in findings[0].description


def test_scale001_fires_on_express_session_without_a_store(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessStateRule,
        tmp_path,
        {
            "package.json": '{"dependencies": {"express": "^4", "express-session": "^1"}}',
            "server.js": (
                "const session = require('express-session');\n"
                "app.use(session({ secret: process.env.SECRET, resave: false }));\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCALE-001"]
    assert "MemoryStore" in findings[0].description


def test_scale001_silent_with_a_redis_backed_session_store(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessStateRule,
        tmp_path,
        {
            "requirements.txt": "flask\nflask-session\nredis\n",
            "app.py": (
                "from flask import Flask\n"
                "from flask_session import Session\n"
                "app = Flask(__name__)\n"
                "app.config['SESSION_TYPE'] = 'redis'\n"
                "Session(app)\n"
            ),
        },
    )
    assert findings == []


def test_scale001_silent_on_a_module_constant(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessStateRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                "CACHE_TTL = 60\n"
                "STATE_NAMES = ['new', 'done']\n"
            ),
        },
    )
    assert findings == []


def test_scale001_silent_outside_a_web_app(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessStateRule,
        tmp_path,
        {"script.py": "cache = {}\ncache['x'] = 1\n"},
    )
    assert findings == []


# ---------------------------------------------------------------- VG-SCALE-002


UPLOAD_APP = {
    "requirements.txt": FLASK_REQS,
    "app.py": (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.post('/upload')\n"
        "def upload():\n"
        "    f = request.files['file']\n"
        "    f.save('uploads/' + f.filename)\n"
        "    return 'ok'\n"
    ),
}


def test_scale002_fires_on_local_upload_write(tmp_path: Path) -> None:
    findings = run_rule(LocalUploadStorageRule, tmp_path, UPLOAD_APP)
    assert [f.rule_id for f in findings] == ["VG-SCALE-002"]
    assert findings[0].file == "app.py"
    assert "object-storage client" in findings[0].description


def test_scale002_silent_when_uploads_go_to_object_storage(tmp_path: Path) -> None:
    files = dict(UPLOAD_APP)
    files["requirements.txt"] = "flask\nboto3\n"
    files["storage.py"] = (
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        "\n"
        "def put(fileobj, key):\n"
        "    s3.upload_fileobj(fileobj, 'my-bucket', key)\n"
    )
    assert run_rule(LocalUploadStorageRule, tmp_path, files) == []


def test_scale002_fires_on_multer_disk_storage(tmp_path: Path) -> None:
    findings = run_rule(
        LocalUploadStorageRule,
        tmp_path,
        {
            "package.json": '{"dependencies": {"express": "^4", "multer": "^1"}}',
            "server.js": "const upload = multer({ dest: 'uploads/' });\n",
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCALE-002"]


# ---------------------------------------------------------------- VG-SCALE-003


def test_scale003_fires_on_lru_cache_without_a_shared_cache(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessCacheRule,
        tmp_path,
        _medium(
            {
                "app.py": (
                    "from functools import lru_cache\n"
                    "\n"
                    "@lru_cache(maxsize=1024)\n"
                    "def pricing(sku):\n"
                    "    return db_lookup(sku)\n"
                )
            }
        ),
    )
    assert [f.rule_id for f in findings] == ["VG-SCALE-003"]
    assert "shared cache" in findings[0].description


def test_scale003_silent_when_redis_is_in_the_stack(tmp_path: Path) -> None:
    files = _medium(
        {
            "requirements.txt": "flask\nredis\n",
            "app.py": (
                "from functools import lru_cache\n"
                "\n"
                "@lru_cache(maxsize=1024)\n"
                "def pricing(sku):\n"
                "    return db_lookup(sku)\n"
            ),
        }
    )
    assert run_rule(InProcessCacheRule, tmp_path, files) == []


def test_scale003_gated_out_below_medium_scale(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessCacheRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app.py": "from functools import lru_cache\n\n@lru_cache\ndef f():\n    return 1\n",
        },
    )
    assert findings == []


# ---------------------------------------------------------------- VG-SCALE-004


INLINE_HANDLER = (
    "import smtplib\n"
    "from flask import Flask\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.post('/signup')\n"
    "def signup():\n"
    "    user = create_user()\n"
    "    server = smtplib.SMTP('smtp.example.com')\n"
    "    server.send_message(welcome_email(user))\n"
    "    return 'ok'\n"
)


def test_scale004_fires_on_inline_email_send(tmp_path: Path) -> None:
    findings = run_rule(InlineLongRunningWorkRule, tmp_path, _medium({"app.py": INLINE_HANDLER}))
    assert [f.rule_id for f in findings] == ["VG-SCALE-004"]
    assert "sends email synchronously" in findings[0].description
    assert "autoscaling" in findings[0].description.lower()


def test_scale004_silent_when_a_queue_exists(tmp_path: Path) -> None:
    files = _medium(
        {
            "requirements.txt": "flask\ncelery\n",
            "app.py": (
                "from flask import Flask\n"
                "from tasks import send_welcome\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.post('/signup')\n"
                "def signup():\n"
                "    user = create_user()\n"
                "    send_welcome.delay(user.id)\n"
                "    return 'ok', 202\n"
            ),
        }
    )
    assert run_rule(InlineLongRunningWorkRule, tmp_path, files) == []


def test_scale004_gated_out_below_medium_scale(tmp_path: Path) -> None:
    findings = run_rule(
        InlineLongRunningWorkRule,
        tmp_path,
        {"requirements.txt": FLASK_REQS, "app.py": INLINE_HANDLER},
    )
    assert findings == []


# ------------------------------------------------------------------- pack-wide


def test_every_rule_declares_valid_metadata() -> None:
    from vibeguard.rules.topics import topic_ids

    known = set(topic_ids())
    assert len(RULES) == 4
    for rule_cls in RULES:
        assert rule_cls.category is Category.SCALABILITY
        assert rule_cls.topics <= known
        assert rule_cls.title and not rule_cls.title.endswith(".")
        assert rule_cls.why_it_matters
        assert rule_cls.references


def test_no_rule_overrides_fix() -> None:
    from vibeguard.core.rule import Rule

    for rule_cls in RULES:
        assert rule_cls.fix is Rule.fix


def test_rules_never_raise_on_malformed_sources(tmp_path: Path) -> None:
    junk = {
        "requirements.txt": FLASK_REQS,
        "app.py": "def broken(:\n    yield ???\n",
        "server.js": "function ( { [ )\n",
        "docker-compose.yml": "services: [oh no\n",
    }
    for rule_cls in RULES:
        assert isinstance(run_rule(rule_cls, tmp_path, junk), list)


def test_shared_fixture_app_trips_state_and_storage_rules() -> None:
    from conftest import FIXTURES, make_context

    ctx = make_context(FIXTURES / "scaling_stateful_app")
    fired = {
        rule_cls.id
        for rule_cls in RULES
        if (rule := rule_cls()).applicable(ctx) and rule.detect(ctx)
    }
    assert fired == {"VG-SCALE-001", "VG-SCALE-002"}
