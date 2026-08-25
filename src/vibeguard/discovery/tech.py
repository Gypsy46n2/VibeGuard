"""Technology detection: manifests, lockfiles, config files, and import inspection."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath

from vibeguard.core.models import TechProfile
from vibeguard.discovery.files import SOURCE_EXTENSIONS, ProgressFn

__all__ = ["detect_tech"]

Reader = Callable[[str], str]

_MANIFEST_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
}

# dependency / import token -> (TechProfile field, value), or a list of them
_DEPENDENCY_SIGNALS: dict[str, tuple[str, str] | list[tuple[str, str]]] = {
    # backend frameworks
    "flask": ("backend", "flask"),
    "django": ("backend", "django"),
    "fastapi": ("backend", "fastapi"),
    "starlette": ("backend", "starlette"),
    "express": ("backend", "express"),
    "koa": ("backend", "koa"),
    "nestjs": ("backend", "nestjs"),
    "@nestjs/core": ("backend", "nestjs"),
    "hapi": ("backend", "hapi"),
    "tornado": ("backend", "tornado"),
    "aiohttp": ("backend", "aiohttp"),
    # frontend frameworks
    "react": ("frontend", "react"),
    "react-dom": ("frontend", "react"),
    "vue": ("frontend", "vue"),
    "next": ("frontend", "next"),
    "nuxt": ("frontend", "nuxt"),
    "svelte": ("frontend", "svelte"),
    "@angular/core": ("frontend", "angular"),
    # databases / drivers
    "psycopg": ("databases", "postgres"),
    "psycopg2": ("databases", "postgres"),
    "psycopg2-binary": ("databases", "postgres"),
    "asyncpg": ("databases", "postgres"),
    "pg": ("databases", "postgres"),
    "postgres": ("databases", "postgres"),
    "postgresql": ("databases", "postgres"),
    "mysqlclient": ("databases", "mysql"),
    "pymysql": ("databases", "mysql"),
    "mysql": ("databases", "mysql"),
    "mysql2": ("databases", "mysql"),
    "sqlite3": ("databases", "sqlite"),
    "aiosqlite": ("databases", "sqlite"),
    "better-sqlite3": ("databases", "sqlite"),
    "pymongo": ("databases", "mongo"),
    "motor": ("databases", "mongo"),
    "mongodb": ("databases", "mongo"),
    "mongoose": [("orms", "mongoose"), ("databases", "mongo")],
    "redis": ("caches", "redis"),
    "ioredis": ("caches", "redis"),
    "aioredis": ("caches", "redis"),
    "memcached": ("caches", "memcached"),
    "pymemcache": ("caches", "memcached"),
    # ORMs
    "sqlalchemy": ("orms", "sqlalchemy"),
    "sqlmodel": ("orms", "sqlalchemy"),
    "flask-sqlalchemy": ("orms", "sqlalchemy"),
    "peewee": ("orms", "peewee"),
    "tortoise-orm": ("orms", "tortoise"),
    "prisma": ("orms", "prisma"),
    "@prisma/client": ("orms", "prisma"),
    "typeorm": ("orms", "typeorm"),
    "sequelize": ("orms", "sequelize"),
    "drizzle-orm": ("orms", "drizzle"),
    # brokers / workers
    "celery": ("workers", "celery"),
    "rq": ("workers", "rq"),
    "dramatiq": ("workers", "dramatiq"),
    "bullmq": ("workers", "bullmq"),
    "bull": ("workers", "bullmq"),
    "sidekiq": ("workers", "sidekiq"),
    "kombu": ("brokers", "rabbitmq"),
    "pika": ("brokers", "rabbitmq"),
    "amqplib": ("brokers", "rabbitmq"),
    "kafka-python": ("brokers", "kafka"),
    "confluent-kafka": ("brokers", "kafka"),
    "kafkajs": ("brokers", "kafka"),
    "aiokafka": ("brokers", "kafka"),
    "boto3": ("external_services", "aws"),
    # tests
    "pytest": ("test_frameworks", "pytest"),
    "unittest": ("test_frameworks", "unittest"),
    "nose": ("test_frameworks", "nose"),
    "jest": ("test_frameworks", "jest"),
    "vitest": ("test_frameworks", "vitest"),
    "mocha": ("test_frameworks", "mocha"),
    "jasmine": ("test_frameworks", "jasmine"),
    "playwright": ("test_frameworks", "playwright"),
    "cypress": ("test_frameworks", "cypress"),
    # realtime
    "websockets": ("realtime", "websockets"),
    "websocket": ("realtime", "websockets"),
    "socket.io": ("realtime", "websockets"),
    "socketio": ("realtime", "websockets"),
    "python-socketio": ("realtime", "websockets"),
    "ws": ("realtime", "websockets"),
    "sse-starlette": ("realtime", "sse"),
    "eventsource": ("realtime", "sse"),
    # auth
    "pyjwt": ("auth", "jwt"),
    "jwt": ("auth", "jwt"),
    "jsonwebtoken": ("auth", "jwt"),
    "python-jose": ("auth", "jwt"),
    "authlib": ("auth", "authlib"),
    "passport": ("auth", "passport"),
    "next-auth": ("auth", "next-auth"),
    "@auth/core": ("auth", "next-auth"),
    "flask-login": ("auth", "flask-login"),
    "django.contrib.auth": ("auth", "django-auth"),
    "passlib": ("auth", "passlib"),
    "bcrypt": ("auth", "bcrypt"),
    "oauthlib": ("auth", "oauth"),
    # secret mechanisms
    "python-dotenv": ("secret_mechanisms", "dotenv"),
    "dotenv": ("secret_mechanisms", "dotenv"),
    "pydantic-settings": ("secret_mechanisms", "pydantic-settings"),
    "hvac": ("secret_mechanisms", "vault"),
    # serverless
    "serverless": ("serverless", "serverless-framework"),
    "aws-lambda-powertools": ("serverless", "aws-lambda"),
    "chalice": ("serverless", "aws-lambda"),
    "mangum": ("serverless", "aws-lambda"),
}

# Python import root -> dependency key (when the import name differs)
_IMPORT_ALIASES: dict[str, str] = {
    "flask_sqlalchemy": "flask-sqlalchemy",
    "flask_login": "flask-login",
    "jose": "python-jose",
    "dotenv": "python-dotenv",
    "socketio": "python-socketio",
    "jwt": "pyjwt",
}

_PY_IMPORT_RE = re.compile(
    r"^[ \t]*(?:from[ \t]+([\w\.]+)[ \t]+import|import[ \t]+([^\n#]+))", re.MULTILINE
)
_JS_IMPORT_RE = re.compile(
    r"""(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))"""
)
_URL_RE = re.compile(r"https?://([A-Za-z0-9\.\-]+)")
_MAX_INSPECTED_SOURCE_FILES = 400


def _add(profile_lists: dict[str, list[str]], field: str, value: str) -> None:
    bucket = profile_lists.setdefault(field, [])
    if value not in bucket:
        bucket.append(value)


def _apply_dependency(lists: dict[str, list[str]], token: str) -> None:
    key = _IMPORT_ALIASES.get(token, token).lower()
    signal = _DEPENDENCY_SIGNALS.get(key)
    if signal is None:
        return
    for field, value in signal if isinstance(signal, list) else [signal]:
        _add(lists, field, value)


def _python_imports(text: str) -> Iterable[str]:
    for from_mod, import_mods in _PY_IMPORT_RE.findall(text):
        if from_mod:
            yield from_mod.split(".")[0]
            yield from_mod
        for mod in import_mods.split(","):
            mod = mod.strip().split(" ")[0]
            if mod:
                yield mod
                yield mod.split(".")[0]


def _js_imports(text: str) -> Iterable[str]:
    for a, b in _JS_IMPORT_RE.findall(text):
        module = a or b
        if not module or module.startswith("."):
            continue
        parts = module.split("/")
        yield module
        yield parts[0] if not module.startswith("@") else "/".join(parts[:2])


def detect_tech(
    root: Path, files: list[str], read: Reader, progress: ProgressFn | None = None
) -> TechProfile:
    """Build a :class:`TechProfile` from manifests, config files, and imports."""
    lists: dict[str, list[str]] = {}
    languages: dict[str, int] = {}
    manifests: list[str] = []
    fileset = set(files)

    for rel in files:
        name = PurePosixPath(rel).name
        ext = PurePosixPath(rel).suffix.lower()
        language = SOURCE_EXTENSIONS.get(ext)
        if language:
            languages[language] = languages.get(language, 0) + 1
        if name in _MANIFEST_FILES:
            manifests.append(rel)

    # ------------------------------------------------------------- manifests
    for rel in manifests:
        name = PurePosixPath(rel).name
        text = read(rel)
        lowered = text.lower()
        if name in {"requirements.txt", "requirements-dev.txt"}:
            _add(lists, "package_managers", "pip")
            for line in text.splitlines():
                dep = re.split(r"[<>=!~\[;#\s]", line.strip(), maxsplit=1)[0]
                if dep:
                    _apply_dependency(lists, dep.lower())
        elif name == "pyproject.toml":
            if "[tool.poetry" in lowered:
                _add(lists, "package_managers", "poetry")
            if "[tool.uv" in lowered or "uv.lock" in fileset:
                _add(lists, "package_managers", "uv")
            if not any(pm in lists.get("package_managers", []) for pm in ("poetry", "uv")):
                _add(lists, "package_managers", "pip")
            for dep in re.findall(r"['\"]([A-Za-z0-9._\-\[\]]+)[<>=!~,\s'\"]", text):
                _apply_dependency(lists, dep.split("[")[0].lower())
        elif name in {"setup.py", "setup.cfg", "Pipfile"}:
            _add(lists, "package_managers", "pip")
            for dep in re.findall(r"[A-Za-z0-9._\-]+", text):
                _apply_dependency(lists, dep.lower())
        elif name == "poetry.lock":
            _add(lists, "package_managers", "poetry")
        elif name == "uv.lock":
            _add(lists, "package_managers", "uv")
        elif name == "package.json":
            _add(lists, "package_managers", "npm")
            for dep in re.findall(r'"(@?[A-Za-z0-9._/\-]+)"\s*:', text):
                _apply_dependency(lists, dep.lower())
            if '"jest"' in lowered:
                _add(lists, "test_frameworks", "jest")
        elif name == "yarn.lock":
            _add(lists, "package_managers", "yarn")
        elif name == "pnpm-lock.yaml":
            _add(lists, "package_managers", "pnpm")
        elif name in {"go.mod", "go.sum"}:
            _add(lists, "package_managers", "gomod")
        elif name in {"Cargo.toml", "Cargo.lock"}:
            _add(lists, "package_managers", "cargo")
        elif name in {"pom.xml", "build.gradle"}:
            _add(lists, "package_managers", "maven" if name == "pom.xml" else "gradle")
        elif name == "Gemfile":
            _add(lists, "package_managers", "bundler")
            if "sidekiq" in lowered:
                _add(lists, "workers", "sidekiq")

    # ------------------------------------------------- infra / ci / iac files
    for rel in files:
        name = PurePosixPath(rel).name
        lname = name.lower()
        ext = PurePosixPath(rel).suffix.lower()
        if lname == "dockerfile" or lname.startswith("dockerfile."):
            _add(lists, "containers", "docker")
        elif lname in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            _add(lists, "containers", "docker")
            _add(lists, "containers", "compose")
        elif rel.startswith(".github/workflows/") and ext in {".yml", ".yaml"}:
            _add(lists, "ci_cd", "github-actions")
        elif lname == ".gitlab-ci.yml":
            _add(lists, "ci_cd", "gitlab-ci")
        elif lname in {"jenkinsfile", "jenkinsfile.groovy"}:
            _add(lists, "ci_cd", "jenkins")
        elif lname in {"chart.yaml", "chart.yml"} or lname == "values.yaml":
            _add(lists, "iac", "helm")
        elif ext == ".tf" or lname == "terraform.tfvars":
            _add(lists, "iac", "terraform")
        elif lname in {"playbook.yml", "playbook.yaml", "ansible.cfg"} or rel.startswith("roles/"):
            _add(lists, "iac", "ansible")
        elif lname in {"template.yaml", "template.yml", "cloudformation.yaml"}:
            _add(lists, "iac", "cloudformation")
        elif lname in {"pulumi.yaml", "pulumi.yml"}:
            _add(lists, "iac", "pulumi")
        elif lname in {"serverless.yml", "serverless.yaml"}:
            _add(lists, "serverless", "serverless-framework")
        elif lname in {"pytest.ini", "tox.ini", "conftest.py"}:
            _add(lists, "test_frameworks", "pytest")
        elif lname in {"vitest.config.ts", "vitest.config.js"}:
            _add(lists, "test_frameworks", "vitest")
        elif lname in {"jest.config.js", "jest.config.ts", "jest.config.mjs"}:
            _add(lists, "test_frameworks", "jest")
        elif lname in {".mocharc.json", ".mocharc.yml", ".mocharc.yaml"}:
            _add(lists, "test_frameworks", "mocha")
        elif lname in {".env", ".env.example", ".env.sample", ".env.local"}:
            _add(lists, "secret_mechanisms", "dotenv")
        elif lname == "next.config.js" or lname == "next.config.mjs":
            _add(lists, "frontend", "next")
        elif lname == "manage.py":
            _add(lists, "backend", "django")

        if ext in {".yml", ".yaml"} and not rel.startswith(".github/"):
            text = read(rel)
            lowered = text.lower()
            if re.search(r"^\s*(apiVersion|kind)\s*:", text, re.MULTILINE | re.IGNORECASE) and (
                "kind:" in lowered and "apiversion:" in lowered
            ):
                _add(lists, "containers", "k8s")
            _scan_service_strings(lists, lowered)

    # ----------------------------------------------------- config value scan
    for rel in files:
        name = PurePosixPath(rel).name.lower()
        if name.startswith(".env") or name in {
            "settings.py",
            "config.py",
            "config.json",
            "config.yaml",
            "config.yml",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        }:
            text = read(rel).lower()
            _scan_service_strings(lists, text)

    # ------------------------------------------------------- import scanning
    inspected = 0
    for rel in files:
        ext = PurePosixPath(rel).suffix.lower()
        if ext not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
        if inspected >= _MAX_INSPECTED_SOURCE_FILES:
            break
        inspected += 1
        if progress is not None:
            progress(inspected, min(len(files), _MAX_INSPECTED_SOURCE_FILES), rel)
        text = read(rel)
        tokens = _python_imports(text) if ext in {".py", ".pyi"} else _js_imports(text)
        for token in tokens:
            _apply_dependency(lists, token.lower())
        lowered = text.lower()
        if "eventsource(" in lowered or "text/event-stream" in lowered:
            _add(lists, "realtime", "sse")
        if "websocket" in lowered:
            _add(lists, "realtime", "websockets")
        if "os.environ" in text or "process.env" in text or "getenv(" in lowered:
            _add(lists, "secret_mechanisms", "env-vars")
        for host in _URL_RE.findall(text):
            if _is_external_host(host):
                _add(lists, "external_services", host.lower())

    frameworks = list(dict.fromkeys(lists.get("backend", []) + lists.get("frontend", [])))
    return TechProfile(
        languages=languages,
        frameworks=frameworks,
        frontend=lists.get("frontend", []),
        backend=lists.get("backend", []),
        databases=lists.get("databases", []),
        orms=lists.get("orms", []),
        package_managers=lists.get("package_managers", []),
        containers=lists.get("containers", []),
        ci_cd=lists.get("ci_cd", []),
        iac=lists.get("iac", []),
        test_frameworks=lists.get("test_frameworks", []),
        caches=lists.get("caches", []),
        brokers=lists.get("brokers", []),
        workers=lists.get("workers", []),
        serverless=lists.get("serverless", []),
        realtime=lists.get("realtime", []),
        auth=lists.get("auth", []),
        secret_mechanisms=lists.get("secret_mechanisms", []),
        external_services=lists.get("external_services", []),
        manifest_files=sorted(manifests),
    )


_SERVICE_STRINGS: list[tuple[str, tuple[str, str]]] = [
    ("postgres://", ("databases", "postgres")),
    ("postgresql://", ("databases", "postgres")),
    ("image: postgres", ("databases", "postgres")),
    ("mysql://", ("databases", "mysql")),
    ("image: mysql", ("databases", "mysql")),
    ("mariadb", ("databases", "mysql")),
    ("sqlite://", ("databases", "sqlite")),
    (".sqlite3", ("databases", "sqlite")),
    (".db", ("databases", "sqlite")),
    ("mongodb://", ("databases", "mongo")),
    ("mongodb+srv://", ("databases", "mongo")),
    ("image: mongo", ("databases", "mongo")),
    ("redis://", ("caches", "redis")),
    ("image: redis", ("caches", "redis")),
    ("amqp://", ("brokers", "rabbitmq")),
    ("image: rabbitmq", ("brokers", "rabbitmq")),
    ("image: memcached", ("caches", "memcached")),
    ("kafka:", ("brokers", "kafka")),
]

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "example.com"}


def _scan_service_strings(lists: dict[str, list[str]], lowered_text: str) -> None:
    for needle, (field, value) in _SERVICE_STRINGS:
        if needle in lowered_text:
            _add(lists, field, value)


def _is_external_host(host: str) -> bool:
    host = host.lower()
    if host in _LOCAL_HOSTS or host.endswith(".local"):
        return False
    if host.startswith("www.w3.org") or host.endswith("schema.org"):
        return False
    return "." in host
