"""Positive and negative coverage for the dependencies pack (VG-DEPS-001..005)."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import context_from, run_rule
from vibeguard.rules.dependencies import RULES
from vibeguard.rules.dependencies.conflicts import DuplicateDependencyRule
from vibeguard.rules.dependencies.pinning import NoLockfileRule, UnpinnedDependencyRule
from vibeguard.rules.dependencies.runtime import (
    DependencyHealthUnverifiedRule,
    UnpinnedRuntimeVersionRule,
)

APP = "import flask\n\nprint('hello')\n"

LOOSE_REQUIREMENTS = "flask\nrequests>=2.0\nboto3\n"
PINNED_REQUIREMENTS = "flask==3.0.0\nrequests==2.32.3\nboto3==1.34.0\n"

PINNED_PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.12,<3.13"
dependencies = ["flask==3.0.0"]
"""

LOOSE_PACKAGE_JSON = json.dumps(
    {"name": "demo", "dependencies": {"express": "^4.18.0", "lodash": "*"}}, indent=2
)
PINNED_PACKAGE_JSON = json.dumps(
    {
        "name": "demo",
        "engines": {"node": ">=20 <21"},
        "dependencies": {"express": "4.18.2", "lodash": "4.17.21"},
    },
    indent=2,
)


def _ids(findings: list) -> list[str]:
    return sorted({f.rule_id for f in findings})


# ----------------------------------------------------------------- VG-DEPS-001


def test_no_lockfile_fires_for_loose_requirements(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": LOOSE_REQUIREMENTS}
    findings = run_rule(NoLockfileRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-001"]


def test_no_lockfile_fires_for_package_json_without_lock(tmp_path: Path) -> None:
    files = {"index.js": "console.log(1)\n", "package.json": PINNED_PACKAGE_JSON}
    findings = run_rule(NoLockfileRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-001"]


def test_no_lockfile_silent_when_lockfiles_present(tmp_path: Path) -> None:
    files = {
        "app.py": APP,
        "requirements.txt": LOOSE_REQUIREMENTS,
        "poetry.lock": "# lock\n",
        "package.json": PINNED_PACKAGE_JSON,
        "package-lock.json": '{"lockfileVersion": 3}\n',
    }
    assert run_rule(NoLockfileRule, tmp_path, files) == []


def test_no_lockfile_silent_when_requirements_fully_pinned(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": PINNED_REQUIREMENTS}
    assert run_rule(NoLockfileRule, tmp_path, files) == []


# ----------------------------------------------------------------- VG-DEPS-002


def test_unpinned_dependency_fires(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": LOOSE_REQUIREMENTS}
    findings = run_rule(UnpinnedDependencyRule, tmp_path, files)
    assert _ids(findings) == ["VG-DEPS-002"]
    assert {f.evidence[0].snippet.split()[0] for f in findings} == {"flask", "requests", "boto3"}


def test_unpinned_dependency_flags_wildcards_in_package_json(tmp_path: Path) -> None:
    files = {"index.js": "console.log(1)\n", "package.json": LOOSE_PACKAGE_JSON}
    findings = run_rule(UnpinnedDependencyRule, tmp_path, files)
    assert _ids(findings) == ["VG-DEPS-002"]
    assert len(findings) == 2


def test_unpinned_dependency_silent_when_pinned(tmp_path: Path) -> None:
    files = {
        "app.py": APP,
        "requirements.txt": PINNED_REQUIREMENTS,
        "package.json": PINNED_PACKAGE_JSON,
    }
    assert run_rule(UnpinnedDependencyRule, tmp_path, files) == []


def test_unpinned_dependency_caps_output(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": "".join(f"pkg{n}\n" for n in range(50))}
    assert len(run_rule(UnpinnedDependencyRule, tmp_path, files)) <= 6


def test_unpinned_dependency_survives_malformed_manifests(tmp_path: Path) -> None:
    files = {"app.py": APP, "package.json": "{not json", "pyproject.toml": "[[[broken"}
    assert run_rule(UnpinnedDependencyRule, tmp_path, files) == []


# ----------------------------------------------------------------- VG-DEPS-003


def test_duplicate_dependency_in_one_manifest_fires(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": "flask==3.0.0\nrequests==2.32.3\nflask==2.0.0\n"}
    findings = run_rule(DuplicateDependencyRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-003"]
    assert "flask" in findings[0].description


def test_conflicting_constraints_across_manifests_fire(tmp_path: Path) -> None:
    files = {
        "app.py": APP,
        "requirements.txt": "flask==3.0.0\n",
        "pyproject.toml": PINNED_PYPROJECT.replace('"flask==3.0.0"', '"flask==2.0.0"'),
    }
    findings = run_rule(DuplicateDependencyRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-003"]


def test_identical_constraints_across_manifests_are_silent(tmp_path: Path) -> None:
    files = {
        "app.py": APP,
        "requirements.txt": "flask==3.0.0\n",
        "pyproject.toml": PINNED_PYPROJECT,
    }
    assert run_rule(DuplicateDependencyRule, tmp_path, files) == []


def test_peer_dependencies_are_not_duplicates(tmp_path: Path) -> None:
    manifest = json.dumps(
        {
            "name": "demo",
            "dependencies": {"react": "18.2.0"},
            "peerDependencies": {"react": ">=17"},
        }
    )
    files = {"index.js": "console.log(1)\n", "package.json": manifest}
    assert run_rule(DuplicateDependencyRule, tmp_path, files) == []


# ----------------------------------------------------------------- VG-DEPS-004


def test_unpinned_runtime_fires(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": PINNED_REQUIREMENTS}
    findings = run_rule(UnpinnedRuntimeVersionRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-004"]
    assert "Python" in findings[0].description


def test_unpinned_runtime_silent_with_requires_python(tmp_path: Path) -> None:
    files = {"app.py": APP, "pyproject.toml": PINNED_PYPROJECT}
    assert run_rule(UnpinnedRuntimeVersionRule, tmp_path, files) == []


def test_unpinned_runtime_silent_with_python_version_file(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": PINNED_REQUIREMENTS, ".python-version": "3.12.4\n"}
    assert run_rule(UnpinnedRuntimeVersionRule, tmp_path, files) == []


def test_unpinned_runtime_silent_with_pinned_docker_base(tmp_path: Path) -> None:
    files = {
        "app.py": APP,
        "requirements.txt": PINNED_REQUIREMENTS,
        "Dockerfile": "FROM python:3.12-slim\nUSER app\nCMD [\"python\", \"app.py\"]\n",
    }
    assert run_rule(UnpinnedRuntimeVersionRule, tmp_path, files) == []


def test_unpinned_runtime_flags_node_without_engines(tmp_path: Path) -> None:
    manifest = json.dumps({"name": "demo", "dependencies": {"express": "4.18.2"}})
    files = {"index.js": "console.log(1)\n", "package.json": manifest}
    findings = run_rule(UnpinnedRuntimeVersionRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-004"]
    assert "Node" in findings[0].description


# ----------------------------------------------------------------- VG-DEPS-005


def test_dependency_health_is_always_reported_when_manifests_exist(tmp_path: Path) -> None:
    files = {"app.py": APP, "requirements.txt": PINNED_REQUIREMENTS}
    findings = run_rule(DependencyHealthUnverifiedRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEPS-005"]
    assert findings[0].autofix_safety.value == "informational"
    assert "pip-audit" in findings[0].description


def test_dependency_health_names_npm_audit_for_node(tmp_path: Path) -> None:
    files = {"index.js": "console.log(1)\n", "package.json": PINNED_PACKAGE_JSON}
    findings = run_rule(DependencyHealthUnverifiedRule, tmp_path, files)
    assert "npm audit" in findings[0].description


def test_dependency_health_silent_without_manifests(tmp_path: Path) -> None:
    assert run_rule(DependencyHealthUnverifiedRule, tmp_path, {"README.md": "# hi\n"}) == []


# --------------------------------------------------------------------- pack-level


def test_pack_registers_every_rule_id_in_order() -> None:
    assert [rule.id for rule in RULES] == [f"VG-DEPS-{n:03d}" for n in range(1, 6)]


def test_shared_fixture_app_trips_every_rule() -> None:
    from conftest import FIXTURES, make_context

    ctx = make_context(FIXTURES / "dependencies_vulnerable")
    fired = {
        rule_cls.id
        for rule_cls in RULES
        if (rule := rule_cls()).applicable(ctx) and rule.detect(ctx)
    }
    assert fired == {f"VG-DEPS-{n:03d}" for n in range(1, 6)}


def test_no_rule_raises_on_junk_manifests(tmp_path: Path) -> None:
    ctx = context_from(
        tmp_path,
        {
            "requirements.txt": "\x00\x01 -e .\ngit+https://example.invalid/x#egg=y\n===\n",
            "package.json": "{",
            "pyproject.toml": "[[[",
            "app.py": "def broken(:\n",
        },
    )
    for rule_cls in RULES:
        rule = rule_cls()
        findings = rule.detect(ctx) if rule.applicable(ctx) else []
        assert isinstance(findings, list)
