"""Positive and negative cases for the observability rule pack (VG-OBS-001..007)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import run_rule
from vibeguard.core.models import Category
from vibeguard.rules.observability import RULES
from vibeguard.rules.observability.health import NoCorrelationIdRule, NoHealthCheckRule
from vibeguard.rules.observability.logging_practices import (
    DebugLogLevelRule,
    NoLoggingFrameworkRule,
    PrintDiagnosticsRule,
)
from vibeguard.rules.observability.monitoring import NoErrorTrackingRule, NoMetricsRule

#: Three compose services push discovery to ScaleClass.MEDIUM, which is what the
#: SRE-maturity rules require before they say anything.
MEDIUM_SCALE_COMPOSE = (
    "services:\n"
    "  web:\n    image: app\n"
    "  worker:\n    image: app\n"
    "  db:\n    image: postgres:16\n"
)

FLASK_APP = (
    "import logging\n"
    "from flask import Flask\n\n"
    "app = Flask(__name__)\n"
    "logger = logging.getLogger(__name__)\n\n\n"
    "@app.route('/items')\n"
    "def items():\n"
    "    logger.info('listing items')\n"
    "    return {'items': []}\n"
)


def medium_repo(**extra: str) -> dict[str, str]:
    """A Flask project big enough to be classified MEDIUM."""
    files = {
        "requirements.txt": "flask\ngunicorn\n",
        "docker-compose.yml": MEDIUM_SCALE_COMPOSE,
        "app/__init__.py": "",
        "app/main.py": FLASK_APP,
    }
    files.update(extra)
    return files


# ------------------------------------------------------------- VG-OBS-001 print()


def test_print_in_application_code_fires(tmp_path: Path):
    findings = run_rule(
        PrintDiagnosticsRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app/service.py": "def charge(order):\n    print('charging', order)\n    return True\n",
        },
    )
    assert [f.rule_id for f in findings] == ["VG-OBS-001"]
    assert findings[0].line == 2
    assert findings[0].autofix_safety.value == "safe_autofix"


def test_console_log_in_server_js_fires(tmp_path: Path):
    findings = run_rule(
        PrintDiagnosticsRule,
        tmp_path,
        {
            "package.json": '{"dependencies": {"express": "^4"}}\n',
            "src/server.js": "const app = require('express')();\nconsole.log('booting');\n",
        },
    )
    assert [f.rule_id for f in findings] == ["VG-OBS-001"]


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        ("app/service.py", "import logging\nlogging.getLogger(__name__).info('hi')\n"),
        ("scripts/seed.py", "print('seeding')\n"),
        ("app/cli.py", "import argparse\nprint('hello')\n"),
        ("app/run.py", "if __name__ == '__main__':\n    print('starting')\n"),
        ("frontend/components/Button.js", "console.log('render')\n"),
        ("src/components/Card.jsx", "console.log('render')\n"),
    ],
)
def test_print_rule_stays_quiet(tmp_path: Path, relpath: str, content: str):
    assert run_rule(PrintDiagnosticsRule, tmp_path, {relpath: content}) == []


# -------------------------------------------------------- VG-OBS-002 no logger


def test_no_logging_framework_fires(tmp_path: Path):
    findings = run_rule(
        NoLoggingFrameworkRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\n",
            "app/__init__.py": "",
            "app/main.py": "from flask import Flask\napp = Flask(__name__)\n",
            "app/db.py": "import psycopg2\n",
        },
    )
    assert [f.rule_id for f in findings] == ["VG-OBS-002"]
    assert findings[0].category is Category.OBSERVABILITY


def test_logging_import_silences_the_rule(tmp_path: Path):
    findings = run_rule(
        NoLoggingFrameworkRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\n",
            "app/__init__.py": "",
            "app/main.py": "import logging\nfrom flask import Flask\napp = Flask(__name__)\n",
            "app/db.py": "import psycopg2\n",
        },
    )
    assert findings == []


def test_no_logging_framework_ignores_projects_without_a_server(tmp_path: Path):
    findings = run_rule(
        NoLoggingFrameworkRule,
        tmp_path,
        {
            "requirements.txt": "numpy\npsycopg2-binary\n",
            "lib/a.py": "x = 1\n",
            "lib/b.py": "y = 2\n",
        },
    )
    assert findings == []


# ---------------------------------------------------- VG-OBS-003 error tracking


def test_no_error_tracking_fires(tmp_path: Path):
    findings = run_rule(NoErrorTrackingRule, tmp_path, medium_repo())
    assert [f.rule_id for f in findings] == ["VG-OBS-003"]
    assert findings[0].autofix_safety.value == "informational"


def test_sentry_silences_error_tracking(tmp_path: Path):
    findings = run_rule(
        NoErrorTrackingRule,
        tmp_path,
        medium_repo(**{"requirements.txt": "flask\nsentry-sdk\n"}),
    )
    assert findings == []


def test_error_tracking_skipped_below_medium_scale(tmp_path: Path):
    findings = run_rule(
        NoErrorTrackingRule,
        tmp_path,
        {"requirements.txt": "flask\n", "app.py": FLASK_APP},
    )
    assert findings == []


# ----------------------------------------------------- VG-OBS-004 health checks


def test_no_health_endpoint_fires(tmp_path: Path):
    findings = run_rule(NoHealthCheckRule, tmp_path, medium_repo())
    assert [f.rule_id for f in findings] == ["VG-OBS-004"]


def test_healthz_route_silences_the_rule(tmp_path: Path):
    findings = run_rule(
        NoHealthCheckRule,
        tmp_path,
        medium_repo(
            **{
                "app/health.py": (
                    "from flask import Blueprint\n"
                    "bp = Blueprint('health', __name__)\n\n\n"
                    "@bp.route('/healthz')\n"
                    "def healthz():\n"
                    "    return {'status': 'ok'}\n"
                )
            }
        ),
    )
    assert findings == []


# ------------------------------------------------- VG-OBS-005 correlation ids


def test_no_correlation_ids_fires(tmp_path: Path):
    findings = run_rule(NoCorrelationIdRule, tmp_path, medium_repo())
    assert [f.rule_id for f in findings] == ["VG-OBS-005"]


def test_request_id_middleware_silences_the_rule(tmp_path: Path):
    findings = run_rule(
        NoCorrelationIdRule,
        tmp_path,
        medium_repo(
            **{
                "app/middleware.py": (
                    "import uuid\n\n\n"
                    "def request_id_middleware(request):\n"
                    "    return request.headers.get('X-Request-ID') or str(uuid.uuid4())\n"
                )
            }
        ),
    )
    assert findings == []


# -------------------------------------------------- VG-OBS-006 debug log level


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        ("app/log.py", "import logging\nlogging.basicConfig(level=logging.DEBUG)\n"),
        ("app/log.py", "import logging\nlogging.getLogger().setLevel(logging.DEBUG)\n"),
        ("config/logging.yaml", "root:\n  level: 'debug'\n"),
        (
            "docker-compose.yml",
            "services:\n  web:\n    environment:\n      - LOG_LEVEL=debug\n",
        ),
    ],
)
def test_debug_level_fires(tmp_path: Path, relpath: str, content: str):
    findings = run_rule(DebugLogLevelRule, tmp_path, {relpath: content})
    assert [f.rule_id for f in findings] == ["VG-OBS-006"]


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        (
            "app/log.py",
            "import logging\nimport os\n"
            "logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))\n",
        ),
        ("config/logging.yaml", "root:\n  level: 'info'\n"),
        ("app/log.py", "import logging\nlogging.basicConfig(level=logging.INFO)\n"),
    ],
)
def test_debug_level_stays_quiet(tmp_path: Path, relpath: str, content: str):
    assert run_rule(DebugLogLevelRule, tmp_path, {relpath: content}) == []


# --------------------------------------------------------- VG-OBS-007 metrics


def test_no_metrics_fires(tmp_path: Path):
    findings = run_rule(NoMetricsRule, tmp_path, medium_repo())
    assert [f.rule_id for f in findings] == ["VG-OBS-007"]


def test_prometheus_client_silences_the_rule(tmp_path: Path):
    findings = run_rule(
        NoMetricsRule,
        tmp_path,
        medium_repo(**{"requirements.txt": "flask\nprometheus_client\n"}),
    )
    assert findings == []


def test_slo_document_silences_the_rule(tmp_path: Path):
    findings = run_rule(
        NoMetricsRule,
        tmp_path,
        medium_repo(**{"docs/slo.md": "# Service level objectives\n99% under 500ms.\n"}),
    )
    assert findings == []


# ---------------------------------------------------------------- pack level


def test_pack_exposes_every_rule_in_id_order():
    ids = [cls.id for cls in RULES]
    assert ids == sorted(ids)
    assert ids == [f"VG-OBS-00{n}" for n in range(1, 8)]


def test_every_rule_is_well_formed():
    from vibeguard.rules.topics import topic_ids

    known = topic_ids()
    for cls in RULES:
        assert cls.category is Category.OBSERVABILITY
        assert cls.title and not cls.title.endswith(".")
        assert cls.description and cls.why_it_matters
        assert cls.references
        assert cls.topics <= known, f"{cls.id} claims unknown topics"


def test_no_rule_raises_on_a_hostile_tree(tmp_path: Path):
    files = {
        "weird.py": "def (((:\n",
        "empty.yaml": "",
        "app.js": "console.",
    }
    for cls in RULES:
        assert isinstance(run_rule(cls, tmp_path, files), list)
