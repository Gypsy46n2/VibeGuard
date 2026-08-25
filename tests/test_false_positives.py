"""Regression net for the dogfooding pass (DECISIONS.md D63-D69).

Most tests here come in a pair: the rule must stay **silent** on a *mention* of a
dangerous pattern (a docstring, a comment, a prose string, a fake test constant) and
must still **fire** on the real thing. A one-sided test would let a fix quietly turn
into a hole -- which is how the false positives covered here got in.
"""

from __future__ import annotations

from pathlib import Path

from conftest import run_rule
from vibeguard.rules._literals import (
    is_non_code_span,
    non_code_lines_of_text,
    non_code_spans_of_text,
)
from vibeguard.rules.containers.dockerfile_quality import DockerfileNoHealthcheckRule
from vibeguard.rules.cost.waste import WastefulWorkAndStorageRule
from vibeguard.rules.database.queries import NPlusOneQueryRule
from vibeguard.rules.dependencies.conflicts import DuplicateDependencyRule
from vibeguard.rules.observability.logging_practices import PrintDiagnosticsRule
from vibeguard.rules.scaling.caching import InProcessCacheRule
from vibeguard.rules.secrets.connections import SigningSecretRule
from vibeguard.rules.secrets.files import PrivateKeyCommittedRule
from vibeguard.rules.security.headers import PermissiveCorsRule
from vibeguard.rules.security.transport import TlsVerificationDisabledRule

FLASK_REQS = "flask\n"
MEDIUM_COMPOSE = (
    "services:\n"
    "  web:\n    image: app\n"
    "  worker:\n    image: app\n"
    "  db:\n    image: postgres:16\n"
)


def ids(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


# ------------------------------------------------------- the helper itself (D63)


def test_non_code_lines_marks_docstrings_and_wrapped_prose() -> None:
    source = (
        "class Rule:\n"
        '    description = (\n'
        '        "skips validation "\n'
        '        "(`verify=False`, `CERT_NONE`), which is bad."\n'
        "    )\n"
        "\n"
        "    def fix(self):\n"
        '        """Rewrite verify=False into verify=True."""\n'
        "        requests.get(url, verify=False)\n"
    )
    lines = non_code_lines_of_text(source, ".py")
    assert 3 in lines and 4 in lines  # wrapped prose string
    assert 8 in lines  # docstring
    assert 9 not in lines  # the actual call
    assert 1 not in lines


def test_non_code_lines_keeps_string_values_on_executing_lines() -> None:
    """A line that *assigns* a string still carries code, so rules keep seeing it."""
    source = (
        'headers["Access-Control-Allow-Origin"] = "*"\n'
        'SECRET_KEY = "s3cr3t-value-not-a-placeholder"\n'
    )
    assert non_code_lines_of_text(source, ".py") == frozenset()


def test_non_code_lines_handles_comments_and_multiline_sql() -> None:
    source = "# verify=False in a comment\nq = '''\n    SELECT * FROM users\n'''\n"
    lines = non_code_lines_of_text(source, ".py")
    assert 1 in lines
    assert 3 in lines
    assert 2 not in lines


def test_non_code_lines_survives_a_syntax_error() -> None:
    """An unparsable file falls back to the lexer instead of blowing up."""
    assert isinstance(non_code_lines_of_text("def broken(:\n  # note\n", ".py"), frozenset)


def test_non_code_lines_javascript_comments_and_templates() -> None:
    source = (
        "const a = 'verify=False';\n"
        "/* rejectUnauthorized: false lives here */\n"
        "const t = `prefix ${dangerous()} suffix`;\n"
    )
    lines = non_code_lines_of_text(source, ".js")
    assert 2 in lines
    assert 1 not in lines
    assert 3 not in lines


def test_non_code_spans_cover_string_interiors() -> None:
    source = 'call = "print()" if flag else "console.log()"\n'
    spans = non_code_spans_of_text(source, ".py")
    assert spans, "the string literals should be masked"
    start = source.index('"print()"')
    inner = source.index("print()")
    assert any(lo <= inner and inner + 7 <= hi for lo, hi in spans[1])
    assert any(lo <= start for lo, hi in spans[1])


# ------------------------------------------------------------------- VG-SEC-018


def test_sec018_silent_on_a_docstring_that_names_verify_false(tmp_path: Path) -> None:
    module = (
        "import requests\n"
        "\n"
        "\n"
        "def fetch(url):\n"
        '    """Never pass verify=False here.\n'
        "\n"
        "    Other spellings are `CERT_NONE` and `rejectUnauthorized: false`.\n"
        '    """\n'
        "    return requests.get(url)\n"
    )
    assert run_rule(TlsVerificationDisabledRule, tmp_path, {"client.py": module}) == []


def test_sec018_silent_on_a_class_attribute_of_prose(tmp_path: Path) -> None:
    module = (
        "class Doc:\n"
        "    description = (\n"
        '        "An outbound connection that skips validation "\n'
        '        "(`verify=False`, `CERT_NONE`, `InsecureSkipVerify`)."\n'
        "    )\n"
    )
    assert run_rule(TlsVerificationDisabledRule, tmp_path, {"doc.py": module}) == []


def test_sec018_still_fires_on_a_real_call(tmp_path: Path) -> None:
    module = (
        "import requests\n"
        "\n"
        "\n"
        "def call():\n"
        "    return requests.get('https://api.example.com', verify=False)\n"
    )
    findings = run_rule(TlsVerificationDisabledRule, tmp_path, {"client.py": module})
    assert ids(findings) == ["VG-SEC-018"]
    assert findings[0].line == 5


# ------------------------------------------------------------------- VG-SEC-015


def test_sec015_silent_on_prose_describing_cors(tmp_path: Path) -> None:
    module = (
        "class Doc:\n"
        "    description = (\n"
        '        "Cross-origin access granted to any origin - "\n'
        "        \"Access-Control-Allow-Origin: *, or origins='*'.\"\n"
        "    )\n"
    )
    assert run_rule(PermissiveCorsRule, tmp_path, {"doc.py": module}) == []


def test_sec015_still_fires_when_the_header_is_assigned(tmp_path: Path) -> None:
    """The value *is* a string here -- the rule must keep matching it."""
    module = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "\n"
        "@app.after_request\n"
        "def cors(response):\n"
        "    response.headers.update({'Access-Control-Allow-Origin': '*'})\n"
        "    return response\n"
    )
    findings = run_rule(
        PermissiveCorsRule, tmp_path, {"requirements.txt": FLASK_REQS, "app.py": module}
    )
    assert ids(findings) == ["VG-SEC-015"]


# ------------------------------------------------------------------- VG-OBS-001


def test_obs001_silent_on_a_docstring_naming_print(tmp_path: Path) -> None:
    module = (
        "import logging\n"
        "\n"
        "logger = logging.getLogger(__name__)\n"
        "\n"
        "\n"
        "def charge(order):\n"
        '    """Diagnostics go through the logger, never print() or console.log()."""\n'
        "    logger.info('charging %s', order)\n"
        "    return True\n"
    )
    assert (
        run_rule(
            PrintDiagnosticsRule,
            tmp_path,
            {"requirements.txt": FLASK_REQS, "app/service.py": module},
        )
        == []
    )


def test_obs001_silent_on_print_named_inside_a_string_literal(tmp_path: Path) -> None:
    module = (
        "def label(is_python):\n"
        "    call = 'print()' if is_python else 'console.log()'\n"
        "    return call\n"
    )
    assert (
        run_rule(
            PrintDiagnosticsRule,
            tmp_path,
            {"requirements.txt": FLASK_REQS, "app/service.py": module},
        )
        == []
    )


def test_obs001_still_fires_on_a_real_print(tmp_path: Path) -> None:
    findings = run_rule(
        PrintDiagnosticsRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "app/service.py": "def charge(order):\n    print('charging', order)\n    return True\n",
        },
    )
    assert ids(findings) == ["VG-OBS-001"]
    assert findings[0].line == 2


# -------------------------------------------- secrets still read string content


def test_secret_rules_are_not_weakened_by_the_non_code_filter(tmp_path: Path) -> None:
    """A hardcoded secret lives in a string -- the D63 filter must not hide it."""
    module = (
        "import jwt\n"
        "\n"
        'SECRET_KEY = "8f2c19aa4be74d0aa2f1c0d3e5b7a9c1"\n'
        "\n"
        "\n"
        "def issue(payload):\n"
        "    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')\n"
    )
    findings = run_rule(
        SigningSecretRule, tmp_path, {"requirements.txt": "pyjwt\n", "auth.py": module}
    )
    assert ids(findings) == ["VG-SCR-008"]


# ------------------------------------------------------------------- VG-DB-001


def test_db001_silent_on_a_module_constant_lookup_in_a_loop(tmp_path: Path) -> None:
    """``SOURCE_EXTENSIONS.get(ext)`` is a dict lookup, not a database round-trip."""
    module = (
        "SOURCE_EXTENSIONS = {'.py': 'python'}\n"
        "\n"
        "\n"
        "def languages(paths):\n"
        "    out = []\n"
        "    for path in paths:\n"
        "        out.append(SOURCE_EXTENSIONS.get(path.suffix))\n"
        "    return out\n"
    )
    assert run_rule(NPlusOneQueryRule, tmp_path, {"tech.py": module}) == []


def test_db001_still_fires_on_a_model_query_in_a_loop(tmp_path: Path) -> None:
    module = (
        "def enrich(order_ids):\n"
        "    out = []\n"
        "    for order_id in order_ids:\n"
        "        out.append(Order.get(order_id))\n"
        "    return out\n"
    )
    findings = run_rule(
        NPlusOneQueryRule, tmp_path, {"requirements.txt": "sqlalchemy\n", "views.py": module}
    )
    assert ids(findings) == ["VG-DB-001"]


# ---------------------------------------------------------------- VG-SCALE-003


def test_scale003_silent_for_a_cache_outside_the_request_path(tmp_path: Path) -> None:
    """A parser cache in a CLI's own package is not multi-instance state."""
    findings = run_rule(
        InProcessCacheRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "docker-compose.yml": MEDIUM_COMPOSE,
            "web/app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "toolkit/parsers.py": (
                "from functools import lru_cache\n"
                "\n"
                "\n"
                "@lru_cache(maxsize=8)\n"
                "def parser_for(language):\n"
                "    return build(language)\n"
            ),
        },
    )
    assert findings == []


def test_scale003_still_fires_inside_the_request_path(tmp_path: Path) -> None:
    findings = run_rule(
        InProcessCacheRule,
        tmp_path,
        {
            "requirements.txt": FLASK_REQS,
            "docker-compose.yml": MEDIUM_COMPOSE,
            "web/app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "web/pricing.py": (
                "from functools import lru_cache\n"
                "\n"
                "\n"
                "@lru_cache(maxsize=1024)\n"
                "def pricing(sku):\n"
                "    return db_lookup(sku)\n"
            ),
        },
    )
    assert ids(findings) == ["VG-SCALE-003"]


# ------------------------------------------------------------------- VG-SCR-005

_REAL_KEY_BODY = "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qNabcdefghij\n" * 12
_REAL_KEY = f"-----BEGIN RSA PRIVATE KEY-----\n{_REAL_KEY_BODY}-----END RSA PRIVATE KEY-----\n"


def test_scr005_silent_on_a_truncated_stub_in_a_test_file(tmp_path: Path) -> None:
    stub = (
        "def test_private_key_block_is_masked():\n"
        '    pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAK\\n'
        '-----END RSA PRIVATE KEY-----"\n'
        "    assert redact(pem) != pem\n"
    )
    assert run_rule(PrivateKeyCommittedRule, tmp_path, {"tests/test_redact.py": stub}) == []


def test_scr005_silent_on_a_bare_header_mention(tmp_path: Path) -> None:
    doc = 'HEADER = "-----BEGIN PRIVATE KEY-----"\n'
    assert run_rule(PrivateKeyCommittedRule, tmp_path, {"scanner.py": doc}) == []


def test_scr005_fires_on_real_key_material_in_source(tmp_path: Path) -> None:
    findings = run_rule(
        PrivateKeyCommittedRule, tmp_path, {"app/keys.py": f'KEY = """{_REAL_KEY}"""\n'}
    )
    assert ids(findings) == ["VG-SCR-005"]
    assert findings[0].severity.value == "critical"


def test_scr005_fires_on_a_real_key_even_inside_a_test_file(tmp_path: Path) -> None:
    """The test-path allowance is a size threshold, not a blanket exemption."""
    findings = run_rule(
        PrivateKeyCommittedRule, tmp_path, {"tests/test_tls.py": f'KEY = """{_REAL_KEY}"""\n'}
    )
    assert ids(findings) == ["VG-SCR-005"]


def test_scr005_still_fires_on_a_key_file_by_name(tmp_path: Path) -> None:
    findings = run_rule(PrivateKeyCommittedRule, tmp_path, {"deploy/id_rsa": "anything\n"})
    assert ids(findings) == ["VG-SCR-005"]


# ------------------------------------------------------------------ VG-DEPS-003


_PYPROJECT_TWO_EXTRAS = """
[project]
name = "demo"
version = "0.1.0"
dependencies = ["typer>=0.12"]

[project.optional-dependencies]
ui = ["fastapi>=0.110"]
dev = ["pytest>=8", "fastapi>=0.110"]
"""

_PYPROJECT_CONFLICT = """
[project]
name = "demo"
version = "0.1.0"
dependencies = ["typer>=0.12"]

[project.optional-dependencies]
ui = ["fastapi>=0.110"]
dev = ["pytest>=8", "fastapi>=0.95"]
"""


def test_deps003_silent_when_two_extras_restate_one_constraint(tmp_path: Path) -> None:
    files = {"pyproject.toml": _PYPROJECT_TWO_EXTRAS}
    assert run_rule(DuplicateDependencyRule, tmp_path, files) == []


def test_deps003_fires_when_the_constraints_actually_differ(tmp_path: Path) -> None:
    findings = run_rule(DuplicateDependencyRule, tmp_path, {"pyproject.toml": _PYPROJECT_CONFLICT})
    assert ids(findings) == ["VG-DEPS-003"]
    assert "fastapi" in findings[0].description


# ------------------------------------------------------------------- VG-CTR-002


def test_ctr002_silent_for_a_one_shot_cli_image(tmp_path: Path) -> None:
    dockerfile = (
        "FROM python:3.12-slim\n"
        "RUN pip install --no-cache-dir mytool\n"
        'ENTRYPOINT ["mytool"]\n'
        'CMD ["--help"]\n'
    )
    assert run_rule(DockerfileNoHealthcheckRule, tmp_path, {"Dockerfile": dockerfile}) == []


def test_ctr002_fires_when_the_image_exposes_a_port(tmp_path: Path) -> None:
    dockerfile = "FROM python:3.12-slim\nEXPOSE 8000\nCMD [\"python\", \"-m\", \"myapp\"]\n"
    assert ids(run_rule(DockerfileNoHealthcheckRule, tmp_path, {"Dockerfile": dockerfile})) == [
        "VG-CTR-002"
    ]


def test_ctr002_fires_on_a_server_shaped_command(tmp_path: Path) -> None:
    dockerfile = 'FROM python:3.12-slim\nCMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]\n'
    assert ids(run_rule(DockerfileNoHealthcheckRule, tmp_path, {"Dockerfile": dockerfile})) == [
        "VG-CTR-002"
    ]


# ------------------------------------------------------------------ VG-COST-004


def test_cost004_silent_on_a_size_constant_and_a_label(tmp_path: Path) -> None:
    module = "_MAX_FILE_BYTES = 2_000_000\nKINDS = ('schedule', 'blob')\n"
    assert run_rule(WastefulWorkAndStorageRule, tmp_path, {"limits.py": module}) == []


def test_cost004_still_fires_on_a_real_blob_column(tmp_path: Path) -> None:
    findings = run_rule(
        WastefulWorkAndStorageRule,
        tmp_path,
        {
            "requirements.txt": "sqlalchemy\n",
            "models.py": (
                "import sqlalchemy as sa\n\n\n"
                "class Doc(Base):\n"
                "    body = sa.Column(sa.LargeBinary)\n"
            ),
        },
    )
    assert ids(findings) == ["VG-COST-004"]


def test_cost004_still_fires_on_a_sql_blob_declaration(tmp_path: Path) -> None:
    findings = run_rule(
        WastefulWorkAndStorageRule,
        tmp_path,
        {
            "requirements.txt": "psycopg2\n",
            "schema.sql": "CREATE TABLE docs (\n  id serial,\n  body BYTEA\n);\n",
        },
    )
    assert ids(findings) == ["VG-COST-004"]


def test_is_non_code_span_needs_a_context() -> None:
    """Sanity: the span helper is span-based, not line-based."""
    spans = non_code_spans_of_text('x = "print()"\n', ".py")
    assert spans[1]
    assert is_non_code_span is not None
