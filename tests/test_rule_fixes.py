"""Every implemented ``fix()``: one exact-output repair, one refusal.

The positive tests assert the *whole* repaired file, so an accidental reformat or a
stray extra edit fails the test. The negative tests pin the conservatism contract:
when the preconditions for a provably safe edit are not met, ``fix()`` returns None
and the finding is still reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from conftest import context_from
from vibeguard.core.models import Finding, Patch
from vibeguard.core.rule import Rule
from vibeguard.rules._fixes import sha256_text
from vibeguard.rules.api.timeouts import HttpTimeoutPythonRule
from vibeguard.rules.containers.dockerfile_quality import (
    DockerfileNoHealthcheckRule,
    InstallAfterFullContextCopyRule,
)
from vibeguard.rules.containers.dockerfile_security import ContainerRunsAsRootRule
from vibeguard.rules.cost.images import OversizedBaseImageRule
from vibeguard.rules.observability.logging_practices import PrintDiagnosticsRule
from vibeguard.rules.reliability.errors import UnreleasedResourceRule
from vibeguard.rules.security.cookies import InsecureSessionCookieRule
from vibeguard.rules.security.crypto import UnsafeRandomnessRule
from vibeguard.rules.security.headers import MissingSecurityHeadersRule
from vibeguard.rules.security.injection import CommandInjectionRule
from vibeguard.rules.security.sql import SqlInjectionJavaScriptRule, SqlInjectionPythonRule
from vibeguard.rules.security.transport import TlsVerificationDisabledRule


def detect_one(rule: Rule, root: Path, files: Mapping[str, str]) -> tuple[Finding, object]:
    """Run ``rule`` over ``files`` and return its single finding plus the context."""
    ctx = context_from(root, files)
    assert rule.applicable(ctx), f"{rule.id} did not apply to the fixture"
    findings = rule.detect(ctx)
    assert findings, f"{rule.id} produced no finding for the fixture"
    return findings[0], ctx


def repaired(patch: Patch, files: Mapping[str, str], path: str | None = None) -> str:
    """The new content of the patched file, with the Patch contract checked."""
    assert patch is not None
    assert len(patch.file_edits) == 1
    edit = patch.file_edits[0]
    if path is not None:
        assert edit.path == path
    assert edit.old_content_sha256 == sha256_text(files[edit.path])
    assert patch.commit_message.startswith("fix(")
    assert patch.commit_message.endswith(f"[{patch.finding_id.split(':')[0]}]")
    return edit.new_content


def fix_for(rule: Rule, root: Path, files: Mapping[str, str]) -> Patch | None:
    finding, ctx = detect_one(rule, root, files)
    return rule.fix(ctx, finding)


# ---------------------------------------------------------------- VG-API-001


def test_timeout_is_added_to_a_bare_request(tmp_path: Path):
    files = {
        "requirements.txt": "requests\n",
        "app.py": (
            "import requests\n"
            "\n"
            "\n"
            "def fetch(url):\n"
            "    return requests.get(url)\n"
        ),
    }
    patch = fix_for(HttpTimeoutPythonRule(), tmp_path, files)
    assert repaired(patch, files, "app.py") == (
        "import requests\n"
        "\n"
        "\n"
        "def fetch(url):\n"
        "    return requests.get(url, timeout=30)\n"
    )


def test_timeout_keeps_a_multiline_call_shape(tmp_path: Path):
    files = {
        "requirements.txt": "requests\n",
        "app.py": (
            "import requests\n"
            "\n"
            "\n"
            "def fetch(url, payload):\n"
            "    return requests.post(\n"
            "        url,\n"
            "        json=payload,\n"
            "    )\n"
        ),
    }
    patch = fix_for(HttpTimeoutPythonRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import requests\n"
        "\n"
        "\n"
        "def fetch(url, payload):\n"
        "    return requests.post(\n"
        "        url,\n"
        "        json=payload, timeout=30\n"
        "    )\n"
    )


def test_timeout_is_not_added_when_kwargs_could_already_carry_one(tmp_path: Path):
    files = {
        "requirements.txt": "requests\n",
        "app.py": (
            "import requests\n"
            "\n"
            "\n"
            "def fetch(url, **options):\n"
            "    return requests.get(url, **options)\n"
        ),
    }
    assert fix_for(HttpTimeoutPythonRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-SEC-018


def test_tls_verification_is_turned_back_on(tmp_path: Path):
    files = {
        "requirements.txt": "requests\n",
        "app.py": (
            "import requests\n"
            "\n"
            "\n"
            "def fetch(url):\n"
            "    return requests.get(url, verify=False, timeout=5)\n"
        ),
    }
    patch = fix_for(TlsVerificationDisabledRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import requests\n"
        "\n"
        "\n"
        "def fetch(url):\n"
        "    return requests.get(url, verify=True, timeout=5)\n"
    )


def test_reject_unauthorized_is_turned_back_on(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo", "dependencies": {"axios": "1.0.0"}}\n',
        "client.js": (
            "const https = require('https');\n"
            "const agent = new https.Agent({ rejectUnauthorized: false });\n"
        ),
    }
    patch = fix_for(TlsVerificationDisabledRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "const https = require('https');\n"
        "const agent = new https.Agent({ rejectUnauthorized: true });\n"
    )


def test_cert_none_is_reported_but_not_patched(tmp_path: Path):
    """Fixing this needs a CA bundle, which VibeGuard cannot invent."""
    files = {
        "app.py": (
            "import ssl\n"
            "\n"
            "context = ssl.create_default_context()\n"
            "context.verify_mode = ssl.CERT_NONE\n"
        ),
    }
    assert fix_for(TlsVerificationDisabledRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-SEC-016


def test_cookie_flags_are_added_to_a_flask_response(tmp_path: Path):
    files = {
        "requirements.txt": "flask\n",
        "app.py": (
            "def login(response, token):\n"
            "    response.set_cookie('session', token)\n"
            "    return response\n"
        ),
    }
    patch = fix_for(InsecureSessionCookieRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "def login(response, token):\n"
        "    response.set_cookie('session', token, secure=True, httponly=True, "
        'samesite="Lax")\n'
        "    return response\n"
    )


def test_cookie_flags_are_added_to_an_express_options_object(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo", "dependencies": {"express": "4.0.0"}}\n',
        "routes.js": (
            "function login(res, token) {\n"
            "  res.cookie('sid', token, { maxAge: 900000 });\n"
            "}\n"
        ),
    }
    patch = fix_for(InsecureSessionCookieRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "function login(res, token) {\n"
        "  res.cookie('sid', token, { maxAge: 900000, secure: true, httpOnly: true, "
        "sameSite: 'lax' });\n"
        "}\n"
    )


def test_a_deliberately_disabled_flag_is_left_for_a_human(tmp_path: Path):
    files = {
        "requirements.txt": "flask\n",
        "app.py": (
            "def login(response, token):\n"
            "    response.set_cookie('session', token, secure=False)\n"
            "    return response\n"
        ),
    }
    assert fix_for(InsecureSessionCookieRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-SEC-011


def test_a_hand_rolled_token_becomes_secrets_token_urlsafe(tmp_path: Path):
    files = {
        "app.py": (
            "import random\n"
            "import string\n"
            "\n"
            "\n"
            "def make_token():\n"
            "    return ''.join(random.choice(string.ascii_letters) for _ in range(32))\n"
        ),
    }
    patch = fix_for(UnsafeRandomnessRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import secrets\n"
        "import random\n"
        "import string\n"
        "\n"
        "\n"
        "def make_token():\n"
        "    return secrets.token_urlsafe(32)\n"
    )


def test_other_random_calls_keep_their_semantics_via_systemrandom(tmp_path: Path):
    files = {
        "app.py": (
            "import random\n"
            "\n"
            "\n"
            "def otp():\n"
            "    return random.randint(100000, 999999)\n"
        ),
    }
    patch = fix_for(UnsafeRandomnessRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import secrets\n"
        "import random\n"
        "\n"
        "\n"
        "def otp():\n"
        "    return secrets.SystemRandom().randint(100000, 999999)\n"
    )


def test_the_javascript_token_idiom_becomes_random_bytes(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo"}\n',
        "token.js": (
            "function makeToken() {\n"
            "  const token = Math.random().toString(36).substring(2);\n"
            "  return token;\n"
            "}\n"
        ),
    }
    patch = fix_for(UnsafeRandomnessRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "const crypto = require('crypto');\n"
        "function makeToken() {\n"
        "  const token = crypto.randomBytes(16).toString('hex');\n"
        "  return token;\n"
        "}\n"
    )


def test_math_random_outside_the_token_idiom_is_not_rewritten(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo"}\n',
        "token.js": (
            "function jitter() {\n"
            "  const sessionDelay = Math.random() * 1000;\n"
            "  return sessionDelay;\n"
            "}\n"
        ),
    }
    assert fix_for(UnsafeRandomnessRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-SEC-007


def test_a_static_shell_command_becomes_an_argument_list(tmp_path: Path):
    """Reachable only when the command is provably static — see the negative below."""
    files = {
        "app.py": (
            "import subprocess\n"
            "\n"
            "\n"
            "def backup():\n"
            "    subprocess.run('tar -cf backup.tar data', shell=True)\n"
        ),
    }
    ctx = context_from(tmp_path, files)
    rule = CommandInjectionRule()
    finding = rule.make_finding(
        file="app.py", line=5, snippet="subprocess.run('tar -cf backup.tar data', shell=True)"
    )
    patch = rule.fix(ctx, finding)
    assert repaired(patch, files) == (
        "import subprocess\n"
        "\n"
        "\n"
        "def backup():\n"
        "    subprocess.run(['tar', '-cf', 'backup.tar', 'data'], shell=False)\n"
    )


def test_an_interpolated_shell_command_is_never_split(tmp_path: Path):
    files = {
        "app.py": (
            "import subprocess\n"
            "\n"
            "\n"
            "def convert(name):\n"
            "    subprocess.run(f'convert {name} out.png', shell=True)\n"
        ),
    }
    assert fix_for(CommandInjectionRule(), tmp_path, files) is None


# ------------------------------------------------------------ VG-SEC-001/002


def test_a_simple_sqlite_query_is_parameterised(tmp_path: Path):
    files = {
        "app.py": (
            "import sqlite3\n"
            "\n"
            "\n"
            "def get_user(cur, user_id):\n"
            '    return cur.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
        ),
    }
    patch = fix_for(SqlInjectionPythonRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import sqlite3\n"
        "\n"
        "\n"
        "def get_user(cur, user_id):\n"
        '    return cur.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()\n'
    )


def test_quotes_around_the_interpolation_are_dropped(tmp_path: Path):
    files = {
        "app.py": (
            "import psycopg2\n"
            "\n"
            "\n"
            "def get_user(cur, email):\n"
            "    cur.execute(f\"SELECT * FROM users WHERE email = '{email}'\")\n"
        ),
    }
    patch = fix_for(SqlInjectionPythonRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import psycopg2\n"
        "\n"
        "\n"
        "def get_user(cur, email):\n"
        '    cur.execute("SELECT * FROM users WHERE email = %s", (email,))\n'
    )


def test_a_multi_hole_query_is_left_alone(tmp_path: Path):
    files = {
        "app.py": (
            "import sqlite3\n"
            "\n"
            "\n"
            "def search(cur, table, term):\n"
            '    cur.execute(f"SELECT * FROM {table} WHERE name = {term}")\n'
        ),
    }
    assert fix_for(SqlInjectionPythonRule(), tmp_path, files) is None


def test_a_pg_template_literal_is_parameterised(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo", "dependencies": {"pg": "8.0.0"}}\n',
        "users.js": (
            "const { Pool } = require('pg');\n"
            "const pool = new Pool();\n"
            "\n"
            "async function getUser(id) {\n"
            "  return pool.query(`SELECT * FROM users WHERE id = ${id}`);\n"
            "}\n"
        ),
    }
    patch = fix_for(SqlInjectionJavaScriptRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "const { Pool } = require('pg');\n"
        "const pool = new Pool();\n"
        "\n"
        "async function getUser(id) {\n"
        "  return pool.query('SELECT * FROM users WHERE id = $1', [id]);\n"
        "}\n"
    )


def test_an_unknown_driver_gets_no_placeholder_guess(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo"}\n',
        "users.js": (
            "async function getUser(db, id) {\n"
            "  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
            "}\n"
        ),
    }
    assert fix_for(SqlInjectionJavaScriptRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-CTR-001


def test_a_non_root_user_is_appended_to_the_final_stage(tmp_path: Path):
    files = {
        "Dockerfile": (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            'CMD ["python", "app.py"]\n'
        ),
    }
    patch = fix_for(ContainerRunsAsRootRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        'CMD ["python", "app.py"]\n'
        "\n"
        "# vibeguard: run the container process as an unprivileged user\n"
        "RUN adduser --system --no-create-home --group appuser\n"
        "USER appuser\n"
    )


def test_alpine_gets_the_busybox_adduser_form(tmp_path: Path):
    files = {
        "Dockerfile": ("FROM node:20-alpine\nWORKDIR /app\nCMD [\"node\", \"index.js\"]\n"),
    }
    patch = fix_for(ContainerRunsAsRootRule(), tmp_path, files)
    assert "RUN addgroup -S appuser && adduser -S -G appuser appuser" in repaired(patch, files)


def test_an_unknown_base_image_gets_no_invented_adduser(tmp_path: Path):
    files = {
        "Dockerfile": (
            "FROM registry.internal/acme/runtime:2.1\n"
            "COPY . .\n"
            'CMD ["/entrypoint"]\n'
        ),
    }
    assert fix_for(ContainerRunsAsRootRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-CTR-002


def test_a_healthcheck_is_added_when_the_port_is_obvious(tmp_path: Path):
    files = {
        "Dockerfile": (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "EXPOSE 8000\n"
            'CMD ["python", "app.py"]\n'
        ),
    }
    patch = fix_for(DockerfileNoHealthcheckRule(), tmp_path, files)
    output = repaired(patch, files)
    assert "HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3" in output
    assert "127.0.0.1:8000" in output
    assert output.splitlines()[-1] == 'CMD ["python", "app.py"]'
    assert "curl" not in output  # slim images have no curl


def test_no_healthcheck_is_invented_without_an_exposed_port(tmp_path: Path):
    files = {
        "Dockerfile": (
            "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"
        ),
    }
    assert fix_for(DockerfileNoHealthcheckRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-CTR-004


def test_the_manifest_copy_is_moved_before_the_install(tmp_path: Path):
    files = {
        "requirements.txt": "flask\n",
        "Dockerfile": (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            'CMD ["python", "app.py"]\n'
        ),
    }
    patch = fix_for(InstallAfterFullContextCopyRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt ./\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "COPY . .\n"
        'CMD ["python", "app.py"]\n'
    )


def test_no_reorder_when_the_manifest_is_not_in_the_repository(tmp_path: Path):
    files = {
        "Dockerfile": (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            'CMD ["python", "app.py"]\n'
        ),
    }
    assert fix_for(InstallAfterFullContextCopyRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-OBS-001


def test_a_print_becomes_a_module_logger_call(tmp_path: Path):
    files = {
        "requirements.txt": "flask\n",
        "service.py": (
            "import os\n"
            "\n"
            "\n"
            "def handle(event):\n"
            "    print(f'handling {event}')\n"
            "    return os.getpid()\n"
        ),
    }
    patch = fix_for(PrintDiagnosticsRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import logging\n"
        "import os\n"
        "\n"
        "logger = logging.getLogger(__name__)\n"
        "\n"
        "\n"
        "def handle(event):\n"
        "    logger.info(f'handling {event}')\n"
        "    return os.getpid()\n"
    )


def test_an_existing_logger_is_reused(tmp_path: Path):
    files = {
        "service.py": (
            "import logging\n"
            "\n"
            "log = logging.getLogger(__name__)\n"
            "\n"
            "\n"
            "def handle(event):\n"
            "    print(event)\n"
        ),
    }
    patch = fix_for(PrintDiagnosticsRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "import logging\n"
        "\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "\n"
        "def handle(event):\n"
        "    log.info(event)\n"
    )


def test_a_multi_argument_print_is_not_a_like_for_like_rewrite(tmp_path: Path):
    files = {
        "service.py": (
            "def handle(event, extra):\n"
            "    print('handling', event, extra)\n"
            "    return None\n"
        ),
    }
    assert fix_for(PrintDiagnosticsRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-REL-002


def test_a_single_use_open_is_wrapped_in_a_with_statement(tmp_path: Path):
    files = {
        "loader.py": (
            "def load(path):\n"
            "    handle = open(path)\n"
            "    data = handle.read()\n"
            "    return data\n"
        ),
    }
    patch = fix_for(UnreleasedResourceRule(), tmp_path, files)
    assert repaired(patch, files) == (
        "def load(path):\n"
        "    with open(path) as handle:\n"
        "        data = handle.read()\n"
        "    return data\n"
    )


def test_a_handle_used_more_than_once_is_left_to_a_human(tmp_path: Path):
    files = {
        "loader.py": (
            "def load(path):\n"
            "    handle = open(path)\n"
            "    header = handle.readline()\n"
            "    body = handle.read()\n"
            "    return header, body\n"
        ),
    }
    assert fix_for(UnreleasedResourceRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-COST-003


def test_a_plain_python_image_is_slimmed(tmp_path: Path):
    files = {
        "requirements.txt": "flask\nrequests\n",
        "Dockerfile": (
            "FROM python:3.12\n"
            "WORKDIR /app\n"
            "COPY requirements.txt ./\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY . .\n"
            'CMD ["python", "app.py"]\n'
        ),
    }
    patch = fix_for(OversizedBaseImageRule(), tmp_path, files)
    assert repaired(patch, files).splitlines()[0] == "FROM python:3.12-slim"


def test_a_compiled_dependency_blocks_the_slim_swap(tmp_path: Path):
    files = {
        "requirements.txt": "flask\npsycopg2==2.9.9\n",
        "Dockerfile": (
            "FROM python:3.12\n"
            "WORKDIR /app\n"
            "COPY requirements.txt ./\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY . .\n"
            'CMD ["python", "app.py"]\n'
        ),
    }
    assert fix_for(OversizedBaseImageRule(), tmp_path, files) is None


# ---------------------------------------------------------------- VG-SEC-014


def test_an_unused_helmet_dependency_is_wired_up(tmp_path: Path):
    files = {
        "package.json": (
            '{"name": "demo", "dependencies": {"express": "4.18.2", "helmet": "7.0.0"}}\n'
        ),
        "server.js": (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/', (req, res) => res.send('ok'));\n"
            "app.listen(3000);\n"
        ),
    }
    patch = fix_for(MissingSecurityHeadersRule(), tmp_path, files)
    assert repaired(patch, files, "server.js") == (
        "const helmet = require('helmet');\n"
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(helmet());\n"
        "app.get('/', (req, res) => res.send('ok'));\n"
        "app.listen(3000);\n"
    )


def test_no_middleware_is_installed_that_the_project_did_not_choose(tmp_path: Path):
    files = {
        "package.json": '{"name": "demo", "dependencies": {"express": "4.18.2"}}\n',
        "server.js": (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.listen(3000);\n"
        ),
    }
    assert fix_for(MissingSecurityHeadersRule(), tmp_path, files) is None


# ------------------------------------------------------------------ contract


@pytest.mark.parametrize(
    "rule_cls",
    [
        HttpTimeoutPythonRule,
        TlsVerificationDisabledRule,
        InsecureSessionCookieRule,
        UnsafeRandomnessRule,
        CommandInjectionRule,
        SqlInjectionPythonRule,
        SqlInjectionJavaScriptRule,
        ContainerRunsAsRootRule,
        DockerfileNoHealthcheckRule,
        InstallAfterFullContextCopyRule,
        PrintDiagnosticsRule,
        UnreleasedResourceRule,
        OversizedBaseImageRule,
        MissingSecurityHeadersRule,
    ],
)
def test_fix_returns_none_for_a_finding_it_cannot_place(rule_cls, tmp_path: Path):
    """A finding pointing at a file that no longer contains the defect is not guessed at."""
    ctx = context_from(tmp_path, {"app.py": "value = 1\n", "Dockerfile": "FROM scratch\n"})
    rule = rule_cls()
    finding = rule.make_finding(file="app.py", line=1, snippet="value = 1")
    assert rule.fix(ctx, finding) is None
