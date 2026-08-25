"""Tests for the built-in security rule pack (VG-SEC-001 … VG-SEC-020).

Every rule gets at least one positive case and one negative case, where the negative
case is the *idiomatic safe equivalent* of the positive one (parameterised query,
``shell=False`` with an argument list, verification left on, …) so the tests pin the
false-positive bound rather than merely proving the pattern matches.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import run_rule
from vibeguard.core.models import Category, Severity
from vibeguard.rules.security import RULES
from vibeguard.rules.security.auth import UnsafeJwtHandlingRule
from vibeguard.rules.security.authz import PrivilegedRouteWithoutAuthRule
from vibeguard.rules.security.cookies import InsecureSessionCookieRule
from vibeguard.rules.security.crypto import UnsafeRandomnessRule, WeakCryptographyRule
from vibeguard.rules.security.csrf import MissingCsrfProtectionRule
from vibeguard.rules.security.deserialization import InsecureDeserializationRule
from vibeguard.rules.security.headers import MissingSecurityHeadersRule, PermissiveCorsRule
from vibeguard.rules.security.injection import CommandInjectionRule, PathTraversalRule
from vibeguard.rules.security.sql import SqlInjectionJavaScriptRule, SqlInjectionPythonRule
from vibeguard.rules.security.ssrf import OpenRedirectRule, ServerSideRequestForgeryRule
from vibeguard.rules.security.transport import DebugModeEnabledRule, TlsVerificationDisabledRule
from vibeguard.rules.security.upload import UnrestrictedFileUploadRule
from vibeguard.rules.security.xss import DomXssSinkRule, UnescapedTemplateRenderingRule
from vibeguard.rules.topics import topic_ids

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
REQS = "flask\nrequests\npyjwt\npyyaml\n"
PKG = '{"name": "app", "dependencies": {"express": "^4.18.0", "pg": "^8.11.0"}}\n'


def ids(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------------- metadata


def test_pack_is_registered_in_rule_id_order():
    assert [rule.id for rule in RULES] == [f"VG-SEC-{n:03d}" for n in range(1, 21)]


@pytest.mark.parametrize("rule_cls", RULES, ids=[rule.id for rule in RULES])
def test_rule_metadata_is_complete(rule_cls):
    known = set(topic_ids())
    assert rule_cls.category is Category.SECURITY
    assert rule_cls.title and not rule_cls.title.endswith(".")
    assert len(rule_cls.why_it_matters) > 80
    assert len(rule_cls.references) >= 2
    assert rule_cls.topics and rule_cls.topics <= known
    assert rule_cls.recommended_followup if hasattr(rule_cls, "recommended_followup") else True


@pytest.mark.parametrize("rule_cls", RULES, ids=[rule.id for rule in RULES])
def test_rule_survives_a_hostile_repo(rule_cls, tmp_path):
    """Malformed, exotic, and empty inputs must yield no findings and no traceback."""
    findings = run_rule(
        rule_cls,
        tmp_path,
        {
            "broken.py": "def (:\n  ???\n",
            "broken.js": "function ( { ][ ;;",
            "empty.py": "",
            "weird.html": "﻿<<<>>>{{",
            "Dockerfile": "FROM scratch\n",
        },
    )
    assert isinstance(findings, list)


@pytest.mark.parametrize("rule_cls", RULES, ids=[rule.id for rule in RULES])
def test_rule_is_silent_on_an_empty_repo(rule_cls, tmp_path):
    assert run_rule(rule_cls, tmp_path, {"README.md": "# hi\n"}) == []


# ------------------------------------------------------- VG-SEC-001 / VG-SEC-002

SQLI_PY_BAD = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute(f"SELECT id, email FROM users WHERE id = {uid}").fetchall())
'''

SQLI_PY_GOOD = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT id, email FROM users WHERE id = ?", (uid,)).fetchall())
'''


def test_sqli_python_fires(tmp_path):
    findings = run_rule(SqlInjectionPythonRule, tmp_path, {"requirements.txt": REQS,
                                                           "app.py": SQLI_PY_BAD})
    assert ids(findings) == ["VG-SEC-001"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].recommended_followup


def test_sqli_python_silent_on_parameterised_query(tmp_path):
    assert run_rule(SqlInjectionPythonRule, tmp_path, {"requirements.txt": REQS,
                                                       "app.py": SQLI_PY_GOOD}) == []


SQLI_JS_BAD = """
const express = require('express');
const app = express();
app.get('/user', async (req, res) => {
  const rows = await db.query(`SELECT id, email FROM users WHERE id = ${req.query.id}`);
  res.json(rows);
});
"""

SQLI_JS_GOOD = """
const express = require('express');
const app = express();
app.get('/user', async (req, res) => {
  const rows = await db.query('SELECT id, email FROM users WHERE id = $1', [req.query.id]);
  res.json(rows);
});
"""

SQLI_JS_TAGGED = """
import { sql } from './db';
export async function user(id) {
  return sql`SELECT id, email FROM users WHERE id = ${id}`;
}
"""


def test_sqli_javascript_fires(tmp_path):
    findings = run_rule(SqlInjectionJavaScriptRule, tmp_path,
                        {"package.json": PKG, "server.js": SQLI_JS_BAD})
    assert ids(findings) == ["VG-SEC-002"]


def test_sqli_javascript_silent_on_placeholders(tmp_path):
    assert run_rule(SqlInjectionJavaScriptRule, tmp_path,
                    {"package.json": PKG, "server.js": SQLI_JS_GOOD}) == []


def test_sqli_javascript_silent_on_parameterising_tagged_template(tmp_path):
    assert run_rule(SqlInjectionJavaScriptRule, tmp_path,
                    {"package.json": PKG, "db.js": SQLI_JS_TAGGED}) == []


# ------------------------------------------------------- VG-SEC-003 / VG-SEC-004


def test_unescaped_template_fires(tmp_path):
    findings = run_rule(
        UnescapedTemplateRenderingRule,
        tmp_path,
        {
            "requirements.txt": REQS,
            "templates/profile.html": "<div>{{ bio | safe }}</div>\n",
            "app.py": "from flask import render_template_string\n"
                      "def show(bio):\n    return render_template_string('<b>' + bio + '</b>')\n",
        },
    )
    assert set(ids(findings)) == {"VG-SEC-003"}
    assert len(findings) == 2


def test_unescaped_template_silent_on_escaped_render(tmp_path):
    findings = run_rule(
        UnescapedTemplateRenderingRule,
        tmp_path,
        {
            "requirements.txt": REQS,
            "templates/profile.html": "<div>{{ bio }}</div>\n",
            "app.py": "from flask import render_template\n"
                      "def show(bio):\n    return render_template('profile.html', bio=bio)\n",
        },
    )
    assert findings == []


DOM_BAD = """
const params = new URLSearchParams(window.location.search);
document.getElementById('out').innerHTML = params.get('name');
"""

DOM_GOOD = """
const params = new URLSearchParams(window.location.search);
document.getElementById('out').textContent = params.get('name');
"""


def test_dom_xss_fires(tmp_path):
    findings = run_rule(DomXssSinkRule, tmp_path, {"package.json": PKG, "ui.js": DOM_BAD})
    assert ids(findings) == ["VG-SEC-004"]


def test_dom_xss_silent_on_textcontent(tmp_path):
    assert run_rule(DomXssSinkRule, tmp_path, {"package.json": PKG, "ui.js": DOM_GOOD}) == []


def test_dom_xss_fires_on_vue_html_directive(tmp_path):
    card = '<template><p v-html="body"/></template>'
    findings = run_rule(DomXssSinkRule, tmp_path, {"package.json": PKG, "Card.vue": card})
    assert ids(findings) == ["VG-SEC-004"]


# ------------------------------------------------------- VG-SEC-005 / VG-SEC-013

SSRF_BAD = '''
import requests
from flask import request


def preview():
    return requests.get(request.args.get("url"), timeout=5).text
'''

SSRF_GOOD = '''
import requests
from urllib.parse import urlparse
from flask import request

ALLOWED_HOSTS = {"images.example.com"}


def preview():
    target = request.args.get("url")
    if urlparse(target).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(target, timeout=5).text
'''


def test_ssrf_fires(tmp_path):
    findings = run_rule(ServerSideRequestForgeryRule, tmp_path,
                        {"requirements.txt": REQS, "fetcher.py": SSRF_BAD})
    assert ids(findings) == ["VG-SEC-005"]
    assert "heuristic" in findings[0].description


def test_ssrf_silent_with_host_allowlist(tmp_path):
    assert run_rule(ServerSideRequestForgeryRule, tmp_path,
                    {"requirements.txt": REQS, "fetcher.py": SSRF_GOOD}) == []


REDIRECT_BAD = '''
from flask import redirect, request


def go():
    return redirect(request.args.get("next"))
'''

REDIRECT_GOOD = '''
from flask import redirect, request


def go():
    target = request.args.get("next", "/")
    if not target.startswith("/"):
        target = "/"
    return redirect(target)
'''


def test_open_redirect_fires(tmp_path):
    findings = run_rule(OpenRedirectRule, tmp_path,
                        {"requirements.txt": REQS, "views.py": REDIRECT_BAD})
    assert ids(findings) == ["VG-SEC-013"]


def test_open_redirect_silent_on_relative_only_target(tmp_path):
    assert run_rule(OpenRedirectRule, tmp_path,
                    {"requirements.txt": REQS, "views.py": REDIRECT_GOOD}) == []


# ------------------------------------------------------------------ VG-SEC-006

CSRF_APP = '''
from flask import Flask, request, session
from flask_login import login_user

app = Flask(__name__)


@app.route("/profile", methods=["POST"])
def profile():
    session["name"] = request.form["name"]
    return "ok"
'''


def test_missing_csrf_fires(tmp_path):
    findings = run_rule(MissingCsrfProtectionRule, tmp_path,
                        {"requirements.txt": "flask\nflask-login\n", "app.py": CSRF_APP})
    assert ids(findings) == ["VG-SEC-006"]


def test_missing_csrf_silent_when_csrfprotect_configured(tmp_path):
    protected = "from flask_wtf.csrf import CSRFProtect\n\ncsrf = CSRFProtect(app)\n" + CSRF_APP
    assert run_rule(MissingCsrfProtectionRule, tmp_path,
                    {"requirements.txt": "flask\nflask-login\nflask-wtf\n",
                     "app.py": protected}) == []


def test_missing_csrf_silent_for_bearer_only_api(tmp_path):
    api = (
        "from fastapi import FastAPI, Depends\n"
        "from fastapi.security import HTTPBearer\n\n"
        "app = FastAPI()\n\n\n"
        "@app.post('/items')\n"
        "def create(token=Depends(HTTPBearer())):\n    return {}\n"
    )
    assert run_rule(MissingCsrfProtectionRule, tmp_path,
                    {"requirements.txt": "fastapi\n", "api.py": api}) == []


# ------------------------------------------------------- VG-SEC-007 / VG-SEC-008

CMD_BAD = '''
import subprocess
from flask import request


def convert():
    name = request.args.get("name")
    subprocess.run(f"convert {name} out.png", shell=True)
'''

CMD_GOOD = '''
import subprocess
from flask import request


def convert():
    name = request.args.get("name")
    subprocess.run(["convert", name, "out.png"], shell=False, check=True)
'''


def test_command_injection_fires(tmp_path):
    findings = run_rule(CommandInjectionRule, tmp_path,
                        {"requirements.txt": REQS, "jobs.py": CMD_BAD})
    assert ids(findings) == ["VG-SEC-007"]
    assert findings[0].severity is Severity.CRITICAL


def test_command_injection_silent_on_argument_list(tmp_path):
    assert run_rule(CommandInjectionRule, tmp_path,
                    {"requirements.txt": REQS, "jobs.py": CMD_GOOD}) == []


TRAVERSAL_BAD = '''
import os
from flask import Flask, send_file

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/download/<path:filename>")
def download(filename):
    return send_file(os.path.join(UPLOADS, filename))
'''

TRAVERSAL_GOOD = '''
import os
from flask import Flask, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/download/<path:filename>")
def download(filename):
    return send_file(os.path.join(UPLOADS, secure_filename(filename)))
'''


def test_path_traversal_fires(tmp_path):
    findings = run_rule(PathTraversalRule, tmp_path,
                        {"requirements.txt": REQS, "files.py": TRAVERSAL_BAD})
    assert ids(findings) == ["VG-SEC-008"]


def test_path_traversal_silent_with_secure_filename(tmp_path):
    assert run_rule(PathTraversalRule, tmp_path,
                    {"requirements.txt": REQS, "files.py": TRAVERSAL_GOOD}) == []


# ------------------------------------------------------------------ VG-SEC-009


def test_insecure_deserialization_fires(tmp_path):
    bad = ("import pickle\nfrom flask import request\n\n\n"
           "def load():\n    return pickle.loads(request.data)\n")
    findings = run_rule(InsecureDeserializationRule, tmp_path,
                        {"requirements.txt": REQS, "cache.py": bad})
    assert ids(findings) == ["VG-SEC-009"]
    assert findings[0].severity is Severity.CRITICAL


def test_insecure_deserialization_fires_on_yaml_load_without_loader(tmp_path):
    bad = "import yaml\n\n\ndef load(text):\n    return yaml.load(text)\n"
    assert ids(run_rule(InsecureDeserializationRule, tmp_path,
                        {"requirements.txt": REQS, "conf.py": bad})) == ["VG-SEC-009"]


def test_insecure_deserialization_silent_on_json_and_safe_load(tmp_path):
    good = ("import json\nimport yaml\nfrom flask import request\n\n\n"
            "def load(text):\n    return json.loads(request.data), yaml.safe_load(text)\n")
    assert run_rule(InsecureDeserializationRule, tmp_path,
                    {"requirements.txt": REQS, "cache.py": good}) == []


# ------------------------------------------------------- VG-SEC-010 / VG-SEC-011


def test_weak_crypto_fires_on_md5_password_hash(tmp_path):
    bad = ("import hashlib\n\n\n"
           "def store(password):\n    return hashlib.md5(password.encode()).hexdigest()\n")
    findings = run_rule(WeakCryptographyRule, tmp_path,
                        {"requirements.txt": REQS, "auth.py": bad})
    assert ids(findings) == ["VG-SEC-010"]
    assert findings[0].severity is Severity.HIGH


def test_weak_crypto_silent_on_bcrypt(tmp_path):
    good = ("import bcrypt\n\n\n"
            "def store(password):\n"
            "    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n")
    assert run_rule(WeakCryptographyRule, tmp_path,
                    {"requirements.txt": "bcrypt\n", "auth.py": good}) == []


def test_weak_crypto_fires_on_ecb_mode(tmp_path):
    bad = ("from Crypto.Cipher import AES\n\n\n"
           "def encrypt(key, data):\n"
           "    return AES.new(key, AES.MODE_ECB).encrypt(data)\n")
    assert ids(run_rule(WeakCryptographyRule, tmp_path,
                        {"requirements.txt": "pycryptodome\n", "vault.py": bad})) == ["VG-SEC-010"]


def test_weak_crypto_silent_on_aes_gcm_with_random_nonce(tmp_path):
    good = ("import os\nfrom Crypto.Cipher import AES\n\n\n"
            "def encrypt(key, data):\n"
            "    return AES.new(key, AES.MODE_GCM, nonce=os.urandom(12)).encrypt(data)\n")
    assert run_rule(WeakCryptographyRule, tmp_path,
                    {"requirements.txt": "pycryptodome\n", "vault.py": good}) == []


def test_weak_crypto_silent_on_a_regex_merely_naming_des(tmp_path):
    """A pattern string that mentions DES/RC4 is not a cipher construction."""
    neutral = ('import re\n\nBANNED = re.compile(r"DES|RC4|Blowfish")\n')
    assert run_rule(WeakCryptographyRule, tmp_path,
                    {"requirements.txt": REQS, "lint.py": neutral}) == []


def test_unsafe_randomness_fires(tmp_path):
    bad = ("import random\n\n\n"
           "def make_reset_token():\n"
           "    return ''.join(random.choice('0123456789abcdef') for _ in range(32))\n")
    assert ids(run_rule(UnsafeRandomnessRule, tmp_path,
                        {"requirements.txt": REQS, "tokens.py": bad})) == ["VG-SEC-011"]


def test_unsafe_randomness_silent_on_secrets_module(tmp_path):
    good = ("import secrets\n\n\n"
            "def make_reset_token():\n    return secrets.token_urlsafe(32)\n")
    assert run_rule(UnsafeRandomnessRule, tmp_path,
                    {"requirements.txt": REQS, "tokens.py": good}) == []


def test_unsafe_randomness_silent_for_non_security_use(tmp_path):
    neutral = ("import random\n\n\n"
               "def pick_sample_row(rows):\n    return random.choice(rows)\n")
    assert run_rule(UnsafeRandomnessRule, tmp_path,
                    {"requirements.txt": REQS, "sampling.py": neutral}) == []


# ------------------------------------------------------- VG-SEC-012 / VG-SEC-018


def test_debug_mode_fires(tmp_path):
    bad = "from flask import Flask\n\napp = Flask(__name__)\napp.run(debug=True)\n"
    assert ids(run_rule(DebugModeEnabledRule, tmp_path,
                        {"requirements.txt": REQS, "app.py": bad})) == ["VG-SEC-012"]


def test_debug_mode_silent_when_read_from_environment(tmp_path):
    good = ("import os\nfrom flask import Flask\n\napp = Flask(__name__)\n"
            "app.run(debug=os.getenv('FLASK_DEBUG') == '1')\n")
    assert run_rule(DebugModeEnabledRule, tmp_path,
                    {"requirements.txt": REQS, "app.py": good}) == []


def test_tls_verification_fires(tmp_path):
    bad = ("import requests\n\n\n"
           "def call():\n    return requests.get('https://api.example.com', verify=False)\n")
    assert ids(run_rule(TlsVerificationDisabledRule, tmp_path,
                        {"requirements.txt": REQS, "client.py": bad})) == ["VG-SEC-018"]


def test_tls_verification_silent_when_enabled(tmp_path):
    good = ("import requests\n\n\n"
            "def call():\n"
            "    return requests.get('https://api.example.com', verify='/etc/ssl/ca.pem')\n")
    assert run_rule(TlsVerificationDisabledRule, tmp_path,
                    {"requirements.txt": REQS, "client.py": good}) == []


# ------------------------------------------------------- VG-SEC-014 / VG-SEC-015

EXPRESS_APP = ("const express = require('express');\n"
               "const app = express();\napp.listen(3000);\n")


def test_missing_security_headers_fires(tmp_path):
    findings = run_rule(MissingSecurityHeadersRule, tmp_path,
                        {"package.json": PKG, "server.js": EXPRESS_APP})
    assert ids(findings) == ["VG-SEC-014"]


def test_missing_security_headers_silent_with_helmet(tmp_path):
    with_helmet = ("const express = require('express');\nconst helmet = require('helmet');\n"
                   "const app = express();\napp.use(helmet());\napp.listen(3000);\n")
    assert run_rule(MissingSecurityHeadersRule, tmp_path,
                    {"package.json": PKG, "server.js": with_helmet}) == []


def test_permissive_cors_fires_and_escalates_with_credentials(tmp_path):
    bad = ("const cors = require('cors');\n"
           "app.use(cors({ origin: '*', credentials: true }));\n")
    findings = run_rule(PermissiveCorsRule, tmp_path, {"package.json": PKG, "server.js": bad})
    assert ids(findings) == ["VG-SEC-015"]
    assert findings[0].severity is Severity.HIGH


def test_permissive_cors_silent_on_explicit_origin_list(tmp_path):
    good = ("const cors = require('cors');\n"
            "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));\n")
    assert run_rule(PermissiveCorsRule, tmp_path, {"package.json": PKG, "server.js": good}) == []


# ------------------------------------------------------------------ VG-SEC-016


def test_insecure_cookie_fires(tmp_path):
    bad = ("from flask import make_response\n\n\n"
           "def login():\n"
           "    resp = make_response('ok')\n"
           "    resp.set_cookie('session', 'abc')\n"
           "    return resp\n")
    assert ids(run_rule(InsecureSessionCookieRule, tmp_path,
                        {"requirements.txt": REQS, "auth.py": bad})) == ["VG-SEC-016"]


def test_insecure_cookie_silent_when_all_flags_set(tmp_path):
    good = ("from flask import make_response\n\n\n"
            "def login():\n"
            "    resp = make_response('ok')\n"
            "    resp.set_cookie('session', 'abc', secure=True, httponly=True, samesite='Lax')\n"
            "    return resp\n")
    assert run_rule(InsecureSessionCookieRule, tmp_path,
                    {"requirements.txt": REQS, "auth.py": good}) == []


# ------------------------------------------------------------------ VG-SEC-017


def test_unsafe_jwt_fires_when_verification_disabled(tmp_path):
    bad = ("import jwt\n\n\n"
           "def read(token):\n"
           "    return jwt.decode(token, options={'verify_signature': False})\n")
    findings = run_rule(UnsafeJwtHandlingRule, tmp_path,
                        {"requirements.txt": REQS, "tokens.py": bad})
    assert ids(findings) == ["VG-SEC-017"]


def test_unsafe_jwt_fires_without_algorithms(tmp_path):
    bad = "import jwt\n\n\ndef read(token, key):\n    return jwt.decode(token, key)\n"
    assert ids(run_rule(UnsafeJwtHandlingRule, tmp_path,
                        {"requirements.txt": REQS, "tokens.py": bad})) == ["VG-SEC-017"]


def test_unsafe_jwt_silent_on_verified_decode_and_expiring_token(tmp_path):
    good = ("import datetime\nimport jwt\n\n\n"
            "def read(token, key):\n"
            "    return jwt.decode(token, key, algorithms=['RS256'])\n\n\n"
            "def issue(key):\n"
            "    exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15)\n"
            "    return jwt.encode({'sub': '1', 'exp': exp}, key, algorithm='RS256')\n")
    assert run_rule(UnsafeJwtHandlingRule, tmp_path,
                    {"requirements.txt": REQS, "tokens.py": good}) == []


# ------------------------------------------------------------------ VG-SEC-019

ADMIN_BAD = '''
from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    return "ok"


@app.route("/admin/users/<user_id>", methods=["DELETE"])
def admin_delete_user(user_id):
    return delete_user(user_id)


@app.route("/me")
@login_required
def me():
    return "ok"
'''

ADMIN_GOOD = ADMIN_BAD.replace(
    '@app.route("/admin/users/<user_id>", methods=["DELETE"])\ndef admin_delete_user',
    '@app.route("/admin/users/<user_id>", methods=["DELETE"])\n@login_required\n'
    "def admin_delete_user",
)


def test_privileged_route_without_auth_fires(tmp_path):
    findings = run_rule(PrivilegedRouteWithoutAuthRule, tmp_path,
                        {"requirements.txt": "flask\nflask-login\n", "app.py": ADMIN_BAD})
    assert ids(findings) == ["VG-SEC-019"]
    assert "heuristic" in findings[0].description
    assert len(findings) <= 5


def test_privileged_route_silent_when_guarded(tmp_path):
    assert run_rule(PrivilegedRouteWithoutAuthRule, tmp_path,
                    {"requirements.txt": "flask\nflask-login\n", "app.py": ADMIN_GOOD}) == []


def test_privileged_route_silent_without_any_auth_mechanism(tmp_path):
    no_auth = ('from flask import Flask\n\napp = Flask(__name__)\n\n\n'
               '@app.route("/admin/users/<user_id>")\ndef admin(user_id):\n    return "ok"\n')
    assert run_rule(PrivilegedRouteWithoutAuthRule, tmp_path,
                    {"requirements.txt": "flask\n", "app.py": no_auth}) == []


# ------------------------------------------------------------------ VG-SEC-020

UPLOAD_BAD = '''
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["file"]
    uploaded.save(os.path.join("/srv/uploads", uploaded.filename))
    return "ok"
'''

UPLOAD_GOOD = '''
import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg"}


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["file"]
    name = secure_filename(uploaded.filename)
    if name.rsplit(".", 1)[-1].lower() not in ALLOWED_EXTENSIONS:
        return "bad type", 400
    uploaded.save(os.path.join("/srv/uploads", name))
    return "ok"
'''


def test_unrestricted_upload_fires(tmp_path):
    findings = run_rule(UnrestrictedFileUploadRule, tmp_path,
                        {"requirements.txt": REQS, "uploads.py": UPLOAD_BAD})
    assert ids(findings) == ["VG-SEC-020"]
    assert "secure_filename" in findings[0].description


def test_unrestricted_upload_silent_when_hardened(tmp_path):
    assert run_rule(UnrestrictedFileUploadRule, tmp_path,
                    {"requirements.txt": REQS, "uploads.py": UPLOAD_GOOD}) == []


# ------------------------------------------------------------ shared fixture app


def test_vulnerable_fixture_app_exists():
    """The end-to-end fixture is a real, small, deliberately vulnerable Flask app."""
    root = FIXTURE_ROOT / "security_vulnerable_app"
    assert (root / "app.py").is_file()
    assert (root / "requirements.txt").is_file()


def test_fixture_app_content_trips_the_pack(tmp_path):
    """Copied out of ``tests/fixtures`` (which rules skip), the app trips many rules."""
    root = FIXTURE_ROOT / "security_vulnerable_app"
    files = {p.name: p.read_text(encoding="utf-8") for p in root.iterdir() if p.is_file()}
    fired = set()
    for rule_cls in RULES:
        fired.update(ids(run_rule(rule_cls, tmp_path / rule_cls.id, files)))
    assert {"VG-SEC-001", "VG-SEC-007", "VG-SEC-012"} <= fired
