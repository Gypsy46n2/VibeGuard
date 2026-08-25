"""Positive and negative cases for the testing rule pack (VG-TEST-001..005)."""

from __future__ import annotations

from pathlib import Path

from conftest import run_rule
from vibeguard.core.models import Category
from vibeguard.rules.testing import RULES
from vibeguard.rules.testing.coverage_gaps import NoDatabaseTestsRule, NoIntegrationTestsRule
from vibeguard.rules.testing.nonfunctional import NoEndToEndTestsRule, NoNonFunctionalTestsRule
from vibeguard.rules.testing.pipeline import CiDoesNotRunTestsRule

MEDIUM_SCALE_COMPOSE = (
    "services:\n"
    "  web:\n    image: app\n"
    "  worker:\n    image: app\n"
    "  db:\n    image: postgres:16\n"
)

FLASK_APP = (
    "from flask import Flask\n\n"
    "app = Flask(__name__)\n\n\n"
    "@app.route('/items')\n"
    "def items():\n"
    "    return {'items': []}\n"
)

UNIT_TEST = "from app.main import app\n\n\ndef test_app_exists():\n    assert app is not None\n"


def repo(**extra: str) -> dict[str, str]:
    files = {
        "requirements.txt": "flask\npsycopg2-binary\npytest\n",
        "app/__init__.py": "",
        "app/main.py": FLASK_APP,
        "tests/test_unit.py": UNIT_TEST,
    }
    files.update(extra)
    return files


def medium_repo(**extra: str) -> dict[str, str]:
    return repo(**{"docker-compose.yml": MEDIUM_SCALE_COMPOSE, **extra})


# ---------------------------------------------------- VG-TEST-001 integration


def test_no_integration_tests_fires(tmp_path: Path):
    findings = run_rule(NoIntegrationTestsRule, tmp_path, repo())
    assert [f.rule_id for f in findings] == ["VG-TEST-001"]
    assert findings[0].category is Category.TESTING
    assert findings[0].autofix_safety.value == "informational"


def test_test_client_silences_integration_rule(tmp_path: Path):
    findings = run_rule(
        NoIntegrationTestsRule,
        tmp_path,
        repo(
            **{
                "tests/test_api.py": (
                    "from app.main import app\n\n\n"
                    "def test_items():\n"
                    "    client = app.test_client()\n"
                    "    assert client.get('/items').status_code == 200\n"
                )
            }
        ),
    )
    assert findings == []


def test_integration_rule_is_silent_without_any_tests(tmp_path: Path):
    """VG-MAINT-001 owns the "no tests at all" message; this rule must not repeat it."""
    findings = run_rule(
        NoIntegrationTestsRule,
        tmp_path,
        {"requirements.txt": "flask\n", "app/main.py": FLASK_APP},
    )
    assert findings == []


# ------------------------------------------------------------ VG-TEST-002 CI


def test_ci_without_a_test_step_fires(tmp_path: Path):
    findings = run_rule(
        CiDoesNotRunTestsRule,
        tmp_path,
        repo(
            **{
                ".github/workflows/ci.yml": (
                    "name: ci\non: [push]\njobs:\n  build:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: pip install -r requirements.txt\n"
                    "      - run: ruff check .\n"
                )
            }
        ),
    )
    assert [f.rule_id for f in findings] == ["VG-TEST-002"]


def test_ci_running_pytest_does_not_fire(tmp_path: Path):
    findings = run_rule(
        CiDoesNotRunTestsRule,
        tmp_path,
        repo(
            **{
                ".github/workflows/ci.yml": (
                    "name: ci\non: [push]\njobs:\n  build:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: pytest -q\n"
                )
            }
        ),
    )
    assert findings == []


def test_ci_rule_is_silent_without_ci(tmp_path: Path):
    assert run_rule(CiDoesNotRunTestsRule, tmp_path, repo()) == []


def test_ci_rule_is_silent_without_tests(tmp_path: Path):
    findings = run_rule(
        CiDoesNotRunTestsRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app/main.py": FLASK_APP,
            ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: ruff check .\n",
        },
    )
    assert findings == []


# ------------------------------------------------------ VG-TEST-003 database


def test_no_database_tests_fires(tmp_path: Path):
    findings = run_rule(NoDatabaseTestsRule, tmp_path, repo())
    assert [f.rule_id for f in findings] == ["VG-TEST-003"]


def test_database_test_silences_the_rule(tmp_path: Path):
    findings = run_rule(
        NoDatabaseTestsRule,
        tmp_path,
        repo(
            **{
                "tests/test_repo.py": (
                    "def test_insert(db_session):\n"
                    "    db_session.execute('insert into t values (1)')\n"
                    "    assert db_session.execute('select count(*) from t')\n"
                )
            }
        ),
    )
    assert findings == []


def test_database_rule_is_silent_without_a_database(tmp_path: Path):
    findings = run_rule(
        NoDatabaseTestsRule,
        tmp_path,
        {
            "requirements.txt": "flask\npytest\n",
            "app/main.py": FLASK_APP,
            "tests/test_unit.py": UNIT_TEST,
        },
    )
    assert findings == []


# ----------------------------------------------------------- VG-TEST-004 e2e


def test_no_e2e_tests_fires(tmp_path: Path):
    findings = run_rule(NoEndToEndTestsRule, tmp_path, medium_repo())
    assert [f.rule_id for f in findings] == ["VG-TEST-004"]


def test_playwright_silences_the_e2e_rule(tmp_path: Path):
    findings = run_rule(
        NoEndToEndTestsRule,
        tmp_path,
        medium_repo(
            **{
                "e2e/test_checkout.py": (
                    "from playwright.sync_api import sync_playwright\n\n\n"
                    "def test_checkout():\n"
                    "    with sync_playwright() as p:\n"
                    "        assert p is not None\n"
                )
            }
        ),
    )
    assert findings == []


def test_e2e_rule_skipped_below_medium_scale(tmp_path: Path):
    assert run_rule(NoEndToEndTestsRule, tmp_path, repo()) == []


# ------------------------------------------------- VG-TEST-005 non-functional


def test_no_non_functional_tests_fires(tmp_path: Path):
    findings = run_rule(NoNonFunctionalTestsRule, tmp_path, medium_repo())
    assert [f.rule_id for f in findings] == ["VG-TEST-005"]


def test_load_concurrency_and_security_tests_silence_the_rule(tmp_path: Path):
    findings = run_rule(
        NoNonFunctionalTestsRule,
        tmp_path,
        medium_repo(
            **{
                "tests/test_load.py": "from locust import HttpUser\n",
                "tests/test_concurrent.py": (
                    "import threading\n\n\ndef test_parallel_writes():\n"
                    "    threading.Thread(target=lambda: None).start()\n"
                ),
                "tests/test_security.py": "def test_xss_is_escaped():\n    assert True\n",
            }
        ),
    )
    assert findings == []


def test_non_functional_rule_is_silent_without_tests(tmp_path: Path):
    findings = run_rule(
        NoNonFunctionalTestsRule,
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "docker-compose.yml": MEDIUM_SCALE_COMPOSE,
            "app/main.py": FLASK_APP,
        },
    )
    assert findings == []


# ---------------------------------------------------------------- pack level


def test_pack_exposes_every_rule_in_id_order():
    ids = [cls.id for cls in RULES]
    assert ids == sorted(ids)
    assert ids == [f"VG-TEST-00{n}" for n in range(1, 6)]


def test_every_rule_is_well_formed():
    from vibeguard.rules.topics import topic_ids

    known = topic_ids()
    for cls in RULES:
        assert cls.category is Category.TESTING
        assert cls.title and not cls.title.endswith(".")
        assert cls.description and cls.why_it_matters
        assert cls.references
        assert cls.topics <= known, f"{cls.id} claims unknown topics"


def test_no_rule_double_reports_an_untested_project(tmp_path: Path):
    """A project with no tests must yield exactly one finding — VG-MAINT-001's."""
    files = {
        "requirements.txt": "flask\npsycopg2-binary\n",
        "docker-compose.yml": MEDIUM_SCALE_COMPOSE,
        "app/main.py": FLASK_APP,
        ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: ruff check .\n",
    }
    for cls in RULES:
        assert run_rule(cls, tmp_path, files) == [], f"{cls.id} fired without a test suite"


def test_no_rule_raises_on_a_hostile_tree(tmp_path: Path):
    files = {
        "weird.py": "def (((:\n",
        "tests/test_broken.py": "\x00 not python\n",
        ".gitlab-ci.yml": "::: not yaml",
    }
    for cls in RULES:
        assert isinstance(run_rule(cls, tmp_path, files), list)
