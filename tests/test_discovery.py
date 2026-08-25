from __future__ import annotations

from pathlib import Path

from conftest import context_from, make_context
from vibeguard.core.models import ScaleClass
from vibeguard.discovery.files import collect_files
from vibeguard.discovery.scale import count_loc, count_services


def test_collect_files_on_fixture(sample_app: Path):
    files = collect_files(sample_app, [])
    assert set(files) == {"app.py", "requirements.txt", "Dockerfile"}


def test_collect_files_honours_gitignore_and_excludes(tmp_path: Path):
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "ignored.log").write_text("noise\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("module.exports = {}\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("y = 2\n", encoding="utf-8")

    files = collect_files(tmp_path, ["**/vendor/**"])
    assert "keep.py" in files
    assert "ignored.log" not in files
    assert not any(f.startswith("node_modules/") for f in files)
    assert "vendor/lib.py" not in files


def test_collect_files_skips_binaries(tmp_path: Path):
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (tmp_path / "blob.dat").write_bytes(b"abc\x00def")
    (tmp_path / "ok.py").write_text("z = 3\n", encoding="utf-8")
    assert collect_files(tmp_path, []) == ["ok.py"]


def test_tech_detection_on_fixture(sample_ctx):
    tech = sample_ctx.tech
    assert tech.languages == {"python": 1}
    assert "flask" in tech.backend
    assert "flask" in tech.frameworks
    assert "sqlite" in tech.databases
    assert "pip" in tech.package_managers
    assert "docker" in tech.containers
    assert "jwt" in tech.auth
    assert "dotenv" in tech.secret_mechanisms
    assert "env-vars" in tech.secret_mechanisms
    assert tech.test_frameworks == []
    assert "requirements.txt" in tech.manifest_files
    assert "api.stripe.com" in tech.external_services


def test_tech_detection_javascript_stack(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        """
        {
          "name": "demo",
          "dependencies": {"express": "^4", "mongoose": "^8", "ioredis": "^5"},
          "devDependencies": {"jest": "^29"}
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / "server.js").write_text(
        "const express = require('express');\nconst jwt = require('jsonwebtoken');\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  api:\n    build: .\n  cache:\n    image: redis:7\n",
        encoding="utf-8",
    )
    ctx = make_context(tmp_path)
    assert "express" in ctx.tech.backend
    assert "mongo" in ctx.tech.databases
    assert "mongoose" in ctx.tech.orms
    assert "redis" in ctx.tech.caches
    assert "jest" in ctx.tech.test_frameworks
    assert {"npm", "pnpm"} <= set(ctx.tech.package_managers)
    assert "compose" in ctx.tech.containers
    assert "jwt" in ctx.tech.auth
    assert ctx.tech.languages.get("javascript") == 1


def test_scale_profile_on_fixture(sample_ctx):
    scale = sample_ctx.scale
    assert scale.scale is ScaleClass.SMALL  # sqlite database present
    assert scale.loc > 0
    assert scale.service_count == 1
    assert scale.has_sensitive_data is True  # auth stack + "password" keyword
    assert "LOC" in scale.rationale


def test_count_loc_ignores_blank_lines_and_non_source(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n\n\ny = 2\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# hi\n", encoding="utf-8")
    read = (tmp_path / "a.py").read_text
    assert count_loc(["a.py", "notes.md"], lambda rel: (tmp_path / rel).read_text()) == 2
    assert read()  # sanity


def test_count_services_from_compose_and_k8s(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n  db:\n    image: postgres\n  worker:\n    build: .\n",
        encoding="utf-8",
    )
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n", encoding="utf-8"
    )
    files = ["docker-compose.yml", "deploy.yaml"]
    assert count_services(files, lambda rel: (tmp_path / rel).read_text()) == 3


def test_graph_on_fixture(sample_ctx):
    graph = sample_ctx.graph
    ids = {node.id for node in graph.nodes}
    assert "app" in ids
    assert "db:sqlite" in ids
    assert all(edge.src == "app" for edge in graph.edges)
    assert {edge.dst for edge in graph.edges} <= ids - {"app"}


def test_scan_context_read_and_ast(sample_ctx):
    text = sample_ctx.read("app.py")
    assert "flask" in text
    assert sample_ctx.read("app.py") is text  # cached
    assert sample_ctx.read("does-not-exist.py") == ""

    tree = sample_ctx.ast("app.py")
    assert tree is None or tree.root_node.type == "module"
    assert sample_ctx.ast("requirements.txt") is None


def test_scan_context_helpers(sample_ctx):
    assert sample_ctx.exists("app.py")
    assert not sample_ctx.exists("tests")
    assert sample_ctx.files_matching(".py") == ["app.py"]


# ------------------------------------------- fixture/vendor exclusion (D64)


FIXTURE_POLLUTED_REPO = {
    "pyproject.toml": (
        '[project]\nname = "mytool"\nversion = "0.1.0"\n'
        'requires-python = ">=3.11"\ndependencies = ["typer>=0.12"]\n'
    ),
    "src/mytool/cli.py": "import typer\n\napp = typer.Typer()\n",
    # Everything below is material the project *carries*, not what it *is*.
    "tests/fixtures/sample_app/requirements.txt": "flask\npsycopg2\nflask-login\npyjwt\n",
    "tests/fixtures/sample_app/app.py": (
        "from flask import Flask\nimport psycopg2\n\napp = Flask(__name__)\n"
    ),
    "tests/fixtures/sample_app/docker-compose.yml": (
        "services:\n"
        "  web:\n    build: .\n"
        "  db:\n    image: postgres:16\n"
        "  cache:\n    image: redis:7\n"
        "  proxy:\n    image: nginx\n"
        "  worker:\n    image: app\n"
    ),
    "tests/fixtures/sample_app/deploy.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
    ),
    "examples/vulnerable-app/package.json": '{"dependencies": {"express": "^4"}}',
    "examples/vulnerable-app/server.js": "const express = require('express');\n",
}


def test_split_primary_separates_fixture_material():
    from vibeguard.discovery.paths import is_fixture_path, split_primary

    files = sorted(FIXTURE_POLLUTED_REPO)
    primary, fixture = split_primary(files)
    assert "src/mytool/cli.py" in primary
    assert "pyproject.toml" in primary
    assert all(f.startswith(("tests/", "examples/")) for f in fixture)
    assert is_fixture_path("vendor/lib/thing.py")
    assert is_fixture_path("node_modules/x/index.js")
    assert is_fixture_path("app/test_helpers.py")
    assert not is_fixture_path("src/mytool/cli.py")


def test_split_primary_falls_back_when_everything_looks_like_a_fixture():
    """Scanning a test tree directly must still profile it, not give up."""
    from vibeguard.discovery.paths import split_primary

    files = ["tests/app.py", "tests/requirements.txt"]
    primary, fixture = split_primary(files)
    assert primary == files
    assert fixture == []


def test_fixture_material_does_not_define_the_stack(tmp_path):
    ctx = context_from(tmp_path, FIXTURE_POLLUTED_REPO)
    assert ctx.tech.backend == []
    assert ctx.tech.frameworks == []
    assert ctx.tech.databases == []
    assert ctx.tech.auth == []
    assert "k8s" not in ctx.tech.containers
    # ...but the files are still there for rules to scan.
    assert "tests/fixtures/sample_app/app.py" in ctx.files
    assert ctx.is_fixture("tests/fixtures/sample_app/app.py")
    assert not ctx.is_fixture("src/mytool/cli.py")


def test_fixture_material_does_not_inflate_the_scale(tmp_path):
    ctx = context_from(tmp_path, FIXTURE_POLLUTED_REPO)
    assert ctx.scale.service_count == 1
    assert ctx.scale.scale is ScaleClass.TOY
    assert not ctx.scale.has_sensitive_data


def test_a_fixture_tree_scanned_directly_is_primary(tmp_path):
    """Relative-to-the-scan-root is what makes this correct in both directions."""
    inner = {
        rel[len("tests/fixtures/sample_app/") :]: body
        for rel, body in FIXTURE_POLLUTED_REPO.items()
        if rel.startswith("tests/fixtures/sample_app/")
    }
    ctx = context_from(tmp_path, inner)
    assert ctx.tech.backend == ["flask"]
    assert "postgres" in ctx.tech.databases
    assert ctx.scale.service_count >= 5


def test_fixture_paths_config_extends_the_defaults(tmp_path):
    from vibeguard.core.config import VibeguardConfig

    config = VibeguardConfig.from_dict(
        {"vibeguard": {"fixture_paths": ["playground"]}}
    )
    assert "playground" in config.fixture_paths
    assert "tests" in config.fixture_paths  # defaults are extended, not replaced

    ctx = context_from(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "t"\nversion = "0"\n',
            "src/t/__init__.py": "",
            "playground/requirements.txt": "django\n",
            "playground/manage.py": "import django\n",
        },
        config,
    )
    assert ctx.tech.backend == []
    assert ctx.is_fixture("playground/manage.py")
