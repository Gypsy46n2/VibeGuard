"""Positive and negative cases for the secrets rule pack (VG-SCR-001..009)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import run_rule
from vibeguard.core.models import Category
from vibeguard.rules.secrets import RULES
from vibeguard.rules.secrets.cloud import AwsCredentialsRule, GcpAzureCredentialsRule
from vibeguard.rules.secrets.connections import DatabaseUrlCredentialsRule, SigningSecretRule
from vibeguard.rules.secrets.files import EnvFileCommittedRule, PrivateKeyCommittedRule
from vibeguard.rules.secrets.management import NoSecretManagementRule
from vibeguard.rules.secrets.tokens import ApiKeyRule, PasswordRule

# A synthetic AWS key that is not the AWS documentation example (which is filtered
# as a placeholder on purpose).
AWS_KEY = "AKIA" + "3NZ7QWERTYUIOPAS"
AWS_SECRET = "wJalr" + "XUtnFEMI" + "K7MDENG" + "bPxRfiCY"
GOOGLE_KEY = "AIza" + "Sy" + "B" * 10 + "3xQ7" + "z" * 19
OPENAI_KEY = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8J9k0L1m2"
BASE_MANIFEST = "flask\n"


def _fires(rule_cls, tmp_path: Path, files: dict[str, str]) -> list:
    return run_rule(rule_cls, tmp_path, files)


# --------------------------------------------------------------- VG-SCR-001 AWS


def test_aws_access_key_fires(tmp_path: Path):
    findings = _fires(
        AwsCredentialsRule,
        tmp_path,
        {
            "requirements.txt": "boto3\n",
            "app/settings.py": f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n',
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-001"]
    assert findings[0].category is Category.SECRETS


def test_aws_secret_access_key_fires(tmp_path: Path):
    findings = _fires(
        AwsCredentialsRule,
        tmp_path,
        {"app/settings.py": f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"\n'},
    )
    assert len(findings) == 1


def test_aws_key_is_redacted_in_evidence(tmp_path: Path):
    findings = _fires(
        AwsCredentialsRule, tmp_path, {"app/settings.py": f'KEY = "{AWS_KEY}"\n'}
    )
    snippet = findings[0].evidence[0].snippet
    assert AWS_KEY not in snippet
    assert "REDACTED" in snippet


def test_aws_env_lookup_does_not_fire(tmp_path: Path):
    findings = _fires(
        AwsCredentialsRule,
        tmp_path,
        {"app/settings.py": 'import os\nAWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET"]\n'},
    )
    assert findings == []


def test_aws_documentation_example_does_not_fire(tmp_path: Path):
    findings = _fires(
        AwsCredentialsRule,
        tmp_path,
        {"README.md": "x\n", "app/settings.py": 'KEY = "AKIAIOSFODNN7EXAMPLE"\n'},
    )
    assert findings == []


def test_aws_env_template_is_skipped(tmp_path: Path):
    findings = _fires(
        AwsCredentialsRule, tmp_path, {".env.example": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"}
    )
    assert findings == []


# ------------------------------------------------------------ VG-SCR-002 GCP/Azure


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        ("app/config.py", f'GOOGLE_API_KEY = "{GOOGLE_KEY}"\n'),
        ("app/config.py", 'TOKEN = "ya29.a0AfH6SMBx7q2Zk1LpQrStUvWxYz01234567"\n'),
        (
            "infra/storage.py",
            'CONN = "DefaultEndpointsProtocol=https;AccountName=prod;'
            'AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==;"\n',
        ),
        (
            "credentials.json",
            '{\n  "type": "service_account",\n  "private_key": "-----BEGIN PRIVATE KEY-----"\n}\n',
        ),
    ],
)
def test_gcp_azure_credentials_fire(tmp_path: Path, relpath: str, content: str):
    findings = _fires(GcpAzureCredentialsRule, tmp_path, {relpath: content})
    assert [f.rule_id for f in findings] == ["VG-SCR-002"]


def test_service_account_type_without_private_key_does_not_fire(tmp_path: Path):
    findings = _fires(
        GcpAzureCredentialsRule,
        tmp_path,
        {"schema.json": '{\n  "type": "service_account",\n  "project_id": "demo"\n}\n'},
    )
    assert findings == []


def test_gcp_env_lookup_does_not_fire(tmp_path: Path):
    findings = _fires(
        GcpAzureCredentialsRule,
        tmp_path,
        {"app/config.py": 'import os\nGOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")\n'},
    )
    assert findings == []


# ----------------------------------------------------------- VG-SCR-003 API keys


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        ("app/client.py", f'api_key = "{OPENAI_KEY}"\n'),
        ("app/client.py", 'ACCESS_TOKEN = "ghp_A1b2C3d4E5f6G7h8J9k0L1m2N3o4P5q6R7"\n'),
        ("app/client.py", 'client_secret = "9f8e7d6c5b4a39281706fedcba9876"\n'),
        ("config/app.yaml", "auth_token: xoxb-1234567890-abcdefghijkl\n"),
        (".env", "REFRESH_TOKEN=1a2b3c4d5e6f7g8h9i0j1k2l\n"),
    ],
)
def test_api_key_rule_fires(tmp_path: Path, relpath: str, content: str):
    findings = _fires(ApiKeyRule, tmp_path, {relpath: content})
    assert [f.rule_id for f in findings] == ["VG-SCR-003"]


@pytest.mark.parametrize(
    "content",
    [
        'import os\napi_key = os.environ["API_KEY"]\n',
        'api_key = "${OPENAI_API_KEY}"\n',
        'api_key = "your-key-here"\n',
        'api_key = "changeme"\n',
        "api_key = settings.api_key\n",
    ],
)
def test_api_key_rule_does_not_fire_on_clean_code(tmp_path: Path, content: str):
    assert _fires(ApiKeyRule, tmp_path, {"app/client.py": content}) == []


# ----------------------------------------------------------- VG-SCR-004 passwords


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        ("app/db.py", 'DB_PASSWORD = "Hunter2Correct!"\n'),
        (
            "docker-compose.yml",
            "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: s3cr3tPw9\n",
        ),
        ("config/app.ini", "[db]\npassword = R4inbowT4ble\n"),
    ],
)
def test_password_rule_fires(tmp_path: Path, relpath: str, content: str):
    findings = _fires(PasswordRule, tmp_path, {relpath: content})
    assert [f.rule_id for f in findings] == ["VG-SCR-004"]


@pytest.mark.parametrize(
    "content",
    [
        'import os\nDB_PASSWORD = os.environ["DB_PASSWORD"]\n',
        'password = request.form["password"]\n',
        'DB_PASSWORD = "changeme"\n',
        'DB_PASSWORD = "<your-password>"\n',
        "def login(password: str):\n    return check_password(password)\n",
    ],
)
def test_password_rule_does_not_fire_on_clean_code(tmp_path: Path, content: str):
    assert _fires(PasswordRule, tmp_path, {"app/db.py": content}) == []


# --------------------------------------------------------- VG-SCR-005 private keys


def test_private_key_file_name_fires(tmp_path: Path):
    findings = _fires(
        PrivateKeyCommittedRule,
        tmp_path,
        {"deploy/id_rsa": "not really a key but the name is the signal\n"},
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-005"]


def test_pem_header_in_any_file_fires(tmp_path: Path):
    body = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qN\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    findings = _fires(PrivateKeyCommittedRule, tmp_path, {"app/keys.py": f'KEY = """{body}"""\n'})
    assert [f.rule_id for f in findings] == ["VG-SCR-005"]


def test_public_key_does_not_fire(tmp_path: Path):
    findings = _fires(
        PrivateKeyCommittedRule,
        tmp_path,
        {"deploy/id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ user@host\n"},
    )
    assert findings == []


# ------------------------------------------------------------- VG-SCR-006 .env file


def test_env_file_committed_fires(tmp_path: Path):
    findings = _fires(
        EnvFileCommittedRule,
        tmp_path,
        {".env": "DATABASE_URL=postgres://app:pw@db/app\n", "app.py": "x = 1\n"},
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-006"]


def test_env_example_alone_does_not_fire(tmp_path: Path):
    findings = _fires(
        EnvFileCommittedRule,
        tmp_path,
        {".env.example": "DATABASE_URL=\n", ".gitignore": ".env\n", "app.py": "x = 1\n"},
    )
    assert findings == []


def test_gitignored_env_file_does_not_fire(tmp_path: Path):
    findings = _fires(
        EnvFileCommittedRule,
        tmp_path,
        {".env": "SECRET=abc\n", ".gitignore": ".env\n", "app.py": "x = 1\n"},
    )
    assert findings == []


# ------------------------------------------------------ VG-SCR-007 connection URLs


@pytest.mark.parametrize(
    "content",
    [
        'DATABASE_URL = "postgres://app:Tr0ub4dor@db.internal:5432/app"\n',
        'MONGO_URI = "mongodb+srv://svc:9sK2mQx1@cluster0.mongodb.net/prod"\n',
        'BROKER = "amqp://worker:R4bbitPass@rabbit:5672//"\n',
    ],
)
def test_database_url_credentials_fire(tmp_path: Path, content: str):
    findings = _fires(DatabaseUrlCredentialsRule, tmp_path, {"app/db.py": content})
    assert [f.rule_id for f in findings] == ["VG-SCR-007"]


@pytest.mark.parametrize(
    "content",
    [
        'import os\nDATABASE_URL = os.environ["DATABASE_URL"]\n',
        'DATABASE_URL = "postgres://postgres:postgres@localhost:5432/dev"\n',
        'DATABASE_URL = "postgres://app@db.internal:5432/app"\n',
        'DATABASE_URL = "sqlite:///./app.db"\n',
    ],
)
def test_database_url_clean_forms_do_not_fire(tmp_path: Path, content: str):
    assert _fires(DatabaseUrlCredentialsRule, tmp_path, {"app/db.py": content}) == []


# --------------------------------------------------------- VG-SCR-008 signing keys


def test_flask_secret_key_fires(tmp_path: Path):
    findings = _fires(
        SigningSecretRule,
        tmp_path,
        {
            "requirements.txt": BASE_MANIFEST,
            "app/settings.py": 'SECRET_KEY = "8f2b91ac0e4d47f1b6c3"\n',
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-008"]


def test_jwt_encode_literal_key_fires(tmp_path: Path):
    findings = _fires(
        SigningSecretRule,
        tmp_path,
        {
            "requirements.txt": "pyjwt\n",
            "app/auth.py": (
                "import jwt\n\n\n"
                "def issue(sub):\n"
                '    return jwt.encode({"sub": sub}, "7c1f9ab24de6", algorithm="HS256")\n'
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-008"]
    assert findings[0].line == 5


def test_jsonwebtoken_sign_literal_key_fires(tmp_path: Path):
    findings = _fires(
        SigningSecretRule,
        tmp_path,
        {
            "package.json": '{"dependencies": {"jsonwebtoken": "^9"}}\n',
            "src/auth.js": (
                "const jwt = require('jsonwebtoken');\n"
                "module.exports = (sub) => jwt.sign({ sub }, 'a91be47c02f5', "
                "{ expiresIn: '1h' });\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-008"]


@pytest.mark.parametrize(
    ("relpath", "content"),
    [
        ("app/settings.py", 'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\n'),
        ("app/auth.py", "import jwt\njwt.encode(payload, SECRET_KEY, algorithm='HS256')\n"),
        ("app/auth.py", 'import jwt\nimport os\njwt.encode(p, os.environ["JWT_SECRET"])\n'),
        ("app/settings.py", 'SECRET_KEY = "dev-secret"\n'),
    ],
)
def test_signing_secret_clean_forms_do_not_fire(tmp_path: Path, relpath: str, content: str):
    assert _fires(SigningSecretRule, tmp_path, {relpath: content}) == []


# ------------------------------------------------------ VG-SCR-009 secret management


_ENV_HEAVY_APP = (
    "import os\n"
    "DB = os.environ['DATABASE_URL']\n"
    "KEY = os.environ['API_KEY']\n"
    "MAIL = os.getenv('MAIL_URL')\n"
)


def test_no_secret_management_fires(tmp_path: Path):
    findings = run_rule(
        NoSecretManagementRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\n",
            "app/settings.py": _ENV_HEAVY_APP,
            "app/main.py": "from app.settings import DB\n",
        },
    )
    assert [f.rule_id for f in findings] == ["VG-SCR-009"]
    assert findings[0].autofix_safety.value == "informational"


def test_documented_dotenv_workflow_does_not_fire(tmp_path: Path):
    findings = run_rule(
        NoSecretManagementRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\n",
            "app/settings.py": _ENV_HEAVY_APP,
            ".env.example": "DATABASE_URL=\nAPI_KEY=\nMAIL_URL=\n",
            ".gitignore": ".env\n",
        },
    )
    assert findings == []


def test_managed_secret_store_does_not_fire(tmp_path: Path):
    findings = run_rule(
        NoSecretManagementRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\nboto3\n",
            "app/settings.py": _ENV_HEAVY_APP,
            "app/secrets.py": (
                "import boto3\n"
                "def load(name):\n"
                "    return boto3.client('secretsmanager').get_secret_value(SecretId=name)\n"
            ),
        },
    )
    assert findings == []


def test_project_without_config_surface_does_not_fire(tmp_path: Path):
    findings = run_rule(
        NoSecretManagementRule,
        tmp_path,
        {
            "requirements.txt": "flask\npsycopg2-binary\n",
            "app/main.py": "import os\nDEBUG = os.getenv('DEBUG')\n",
        },
    )
    assert findings == []


# ---------------------------------------------------------------------- pack level


def test_pack_exposes_every_rule_in_id_order():
    ids = [cls.id for cls in RULES]
    assert ids == sorted(ids)
    assert ids == [f"VG-SCR-00{n}" for n in range(1, 10)]


def test_every_rule_is_well_formed():
    from vibeguard.rules.topics import topic_ids

    known = topic_ids()
    for cls in RULES:
        assert cls.category is Category.SECRETS
        assert cls.title and not cls.title.endswith(".")
        assert cls.description and cls.why_it_matters
        assert cls.references
        assert cls.topics <= known, f"{cls.id} claims unknown topics"


def test_no_rule_raises_on_a_hostile_tree(tmp_path: Path):
    files = {
        "weird.py": "\x00\x01 not really python (((\n",
        "empty.yaml": "",
        ".env": "",
        "deep/nested/thing.json": "{{{ not json",
    }
    for cls in RULES:
        assert isinstance(run_rule(cls, tmp_path, files), list)
