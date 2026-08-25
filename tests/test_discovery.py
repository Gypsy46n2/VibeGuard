from __future__ import annotations

from pathlib import Path

from conftest import make_context
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
