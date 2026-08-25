"""External tool adapters — INTERFACES.md §4.

Adapters are optional, so nothing here requires a tool to be installed: parsing is
exercised against canned JSON, and the ``available() is False`` path is asserted for
every shipped adapter.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conftest import context_from
from vibeguard.adapters import ADAPTERS, ToolAdapter, build_adapters
from vibeguard.adapters.bandit import BanditAdapter
from vibeguard.adapters.base import SKIP_LOCAL_ONLY
from vibeguard.adapters.checkov import CheckovAdapter
from vibeguard.adapters.detect_secrets import DetectSecretsAdapter
from vibeguard.adapters.hadolint import HadolintAdapter
from vibeguard.adapters.npm_audit import NpmAuditAdapter
from vibeguard.adapters.pip_audit import PipAuditAdapter
from vibeguard.adapters.semgrep import SemgrepAdapter
from vibeguard.adapters.trivy import TrivyAdapter
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.models import Category, Severity
from vibeguard.engine.orchestrator import Engine
from vibeguard.rules.topics import topic_ids

FLASK_REPO = {
    "requirements.txt": "flask==3.0.0\n",
    "app.py": "from flask import Flask\napp = Flask(__name__)\n",
    "Dockerfile": "FROM python:3.11-slim\nUSER app\nCMD [\"python\", \"app.py\"]\n",
}


def ctx(tmp_path: Path, files: dict[str, str] | None = None, **config: Any):
    return context_from(tmp_path, files or FLASK_REPO, VibeguardConfig(**config))


def stub_json(adapter: ToolAdapter, payload: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the subprocess call with canned tool output."""
    monkeypatch.setattr(
        type(adapter),
        "exec",
        lambda self, args, context, **kw: subprocess.CompletedProcess(
            args, 0, json.dumps(payload), ""
        ),
    )


# ------------------------------------------------------------------- contract


def test_every_adapter_is_registered_and_constructible():
    adapters = build_adapters()
    assert len(adapters) == len(ADAPTERS)
    assert {a.name for a in adapters} == {
        "bandit",
        "detect-secrets",
        "pip-audit",
        "npm-audit",
        "hadolint",
        "trivy",
        "checkov",
        "semgrep",
    }


@pytest.mark.parametrize("cls", ADAPTERS, ids=lambda c: c.name)
def test_adapter_metadata_is_well_formed(cls: type[ToolAdapter]):
    adapter = cls()
    assert adapter.name and adapter.command
    assert isinstance(adapter.category, Category)
    assert adapter.timeout == 300
    assert adapter.topics, f"{adapter.name} declares no checklist topics"
    assert adapter.topics <= set(topic_ids()), f"{adapter.name} claims unknown topics"


@pytest.mark.parametrize("cls", ADAPTERS, ids=lambda c: c.name)
def test_unavailable_adapter_never_raises(cls: type[ToolAdapter], monkeypatch, tmp_path):
    adapter = cls()
    monkeypatch.setattr("vibeguard.adapters.base.shutil.which", lambda _: None)
    assert adapter.available() is False
    # And a run against a missing binary still yields [] rather than an exception.
    assert adapter.run(ctx(tmp_path)) == []


@pytest.mark.parametrize("cls", ADAPTERS, ids=lambda c: c.name)
def test_garbage_tool_output_yields_no_findings(cls: type[ToolAdapter], monkeypatch, tmp_path):
    adapter = cls()
    monkeypatch.setattr(
        cls,
        "exec",
        lambda self, args, context, **kw: subprocess.CompletedProcess(args, 0, "not json", ""),
    )
    assert adapter.run(ctx(tmp_path)) == []


def test_exec_survives_a_missing_executable(tmp_path):
    adapter = BanditAdapter()
    assert adapter.exec(["definitely-not-a-real-binary-xyz"], ctx(tmp_path)) is None


def test_exec_survives_a_timeout(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=300)

    monkeypatch.setattr(subprocess, "run", boom)
    assert BanditAdapter().exec(["bandit"], ctx(tmp_path)) is None


def test_parse_json_tolerates_a_banner_prefix():
    assert ToolAdapter.parse_json('Scanning...\n{"results": []}') == {"results": []}
    assert ToolAdapter.parse_json("") is None


def test_rule_ids_follow_the_vg_ext_convention():
    assert BanditAdapter().rule_id("B608") == "VG-EXT-bandit-B608"
    assert TrivyAdapter().rule_id("CVE-2024-1 ").startswith("VG-EXT-trivy-CVE-2024-1")


# ----------------------------------------------------------------- local_only


@pytest.mark.parametrize(
    "cls", [c for c in ADAPTERS if c.requires_network], ids=lambda c: c.name
)
def test_network_adapters_are_skipped_under_local_only(cls: type[ToolAdapter], tmp_path):
    adapter = cls()
    assert adapter.skip_reason(ctx(tmp_path, local_only=True)) == SKIP_LOCAL_ONLY
    assert adapter.skip_reason(ctx(tmp_path, local_only=False)) is None


@pytest.mark.parametrize(
    "cls", [c for c in ADAPTERS if not c.requires_network], ids=lambda c: c.name
)
def test_offline_adapters_run_under_local_only(cls: type[ToolAdapter], tmp_path):
    assert cls().skip_reason(ctx(tmp_path, local_only=True)) is None


def test_report_records_why_an_adapter_was_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("vibeguard.adapters.base.shutil.which", lambda _: None)
    report = Engine(VibeguardConfig(local_only=True)).audit(
        context_from(tmp_path, FLASK_REPO).root
    )
    joined = " ".join(report.adapters_used)
    assert "semgrep (skipped:" in joined
    assert SKIP_LOCAL_ONLY in joined
    assert "bandit (skipped: not installed)" in joined


# -------------------------------------------------------------- applicability


def test_bandit_only_applies_to_python(tmp_path):
    assert BanditAdapter().applicable(ctx(tmp_path)) is True
    js = {"package.json": '{"name": "x", "dependencies": {"express": "4.0.0"}}'}
    assert BanditAdapter().applicable(ctx(tmp_path / "js", js)) is False


def test_npm_audit_requires_a_lockfile(tmp_path):
    package = '{"name": "x", "dependencies": {"express": "^4.0.0"}}'
    assert NpmAuditAdapter().applicable(ctx(tmp_path, {"package.json": package})) is False
    with_lock = {"package.json": package, "package-lock.json": '{"lockfileVersion": 3}'}
    assert NpmAuditAdapter().applicable(ctx(tmp_path / "b", with_lock)) is True


def test_hadolint_requires_a_dockerfile(tmp_path):
    assert HadolintAdapter().applicable(ctx(tmp_path)) is True
    no_docker = {"requirements.txt": "flask\n", "app.py": "import flask\n"}
    assert HadolintAdapter().applicable(ctx(tmp_path / "b", no_docker)) is False


def test_pip_audit_requires_a_python_manifest(tmp_path):
    assert PipAuditAdapter().applicable(ctx(tmp_path)) is True
    js = {"package.json": '{"name": "x"}'}
    assert PipAuditAdapter().applicable(ctx(tmp_path / "b", js)) is False


def test_checkov_requires_iac_or_containers(tmp_path):
    assert CheckovAdapter().applicable(ctx(tmp_path)) is True
    plain = {"app.py": "print(1)\n"}
    assert CheckovAdapter().applicable(ctx(tmp_path / "b", plain)) is False


# ------------------------------------------------------------------- parsing


def test_bandit_output_is_mapped(tmp_path, monkeypatch):
    adapter = BanditAdapter()
    stub_json(
        adapter,
        {
            "results": [
                {
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions",
                    "filename": "./app.py",
                    "line_number": 12,
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                    "issue_text": "Possible SQL injection vector.",
                    "code": "12 query = 'SELECT * FROM t WHERE id=%s' % uid",
                    "more_info": "https://bandit.readthedocs.io/B608",
                },
                "garbage-entry",
            ]
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "VG-EXT-bandit-B608"
    assert finding.severity is Severity.MEDIUM
    assert finding.file == "app.py"
    assert finding.line == 12
    assert finding.references == ["https://bandit.readthedocs.io/B608"]


def test_detect_secrets_output_is_mapped_and_redacted(tmp_path, monkeypatch):
    adapter = DetectSecretsAdapter()
    stub_json(
        adapter,
        {
            "results": {
                "config.py": [
                    {"type": "AWS Access Key", "line_number": 3, "hashed_secret": "abc"},
                    {"type": "Base64 High Entropy String", "line_number": 9},
                ]
            }
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 2
    assert findings[0].severity is Severity.CRITICAL  # known provider format
    assert findings[1].severity is Severity.HIGH
    assert all(f.category is Category.SECRETS for f in findings)
    assert all(f.evidence[0].redact for f in findings)


def test_pip_audit_output_is_mapped(tmp_path, monkeypatch):
    adapter = PipAuditAdapter()
    stub_json(
        adapter,
        {
            "dependencies": [
                {
                    "name": "flask",
                    "version": "0.12",
                    "vulns": [
                        {
                            "id": "PYSEC-2019-179",
                            "fix_versions": ["1.0"],
                            "description": "denial of service",
                        }
                    ],
                },
                {"name": "clean", "version": "1.0", "vulns": []},
            ]
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "VG-EXT-pip-audit-PYSEC-2019-179"
    assert findings[0].category is Category.DEPENDENCIES
    assert "1.0" in findings[0].recommended_followup


def test_pip_audit_accepts_the_legacy_list_format(tmp_path, monkeypatch):
    adapter = PipAuditAdapter()
    stub_json(
        adapter,
        [{"name": "jinja2", "version": "2.0", "vulns": [{"id": "GHSA-x", "fix_versions": []}]}],
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM  # no fix published


NPM_REPO = {
    "package.json": '{"name": "x", "dependencies": {"lodash": "4.17.0"}}',
    "package-lock.json": '{"lockfileVersion": 3}',
}


def test_npm_audit_v7_output_is_mapped(tmp_path, monkeypatch):
    adapter = NpmAuditAdapter()
    stub_json(
        adapter,
        {
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "critical",
                    "range": "<4.17.21",
                    "fixAvailable": True,
                    "via": [
                        {
                            "source": 1065,
                            "title": "Prototype pollution",
                            "url": "https://npmjs.com/advisories/1065",
                        }
                    ],
                }
            }
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path, NPM_REPO))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].rule_id == "VG-EXT-npm-audit-1065"


def test_npm_audit_v6_output_is_mapped(tmp_path, monkeypatch):
    adapter = NpmAuditAdapter()
    stub_json(
        adapter,
        {
            "advisories": {
                "1065": {
                    "id": 1065,
                    "module_name": "lodash",
                    "severity": "moderate",
                    "title": "Prototype pollution",
                    "vulnerable_versions": "<4.17.21",
                    "patched_versions": ">=4.17.21",
                    "url": "https://npmjs.com/advisories/1065",
                }
            }
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path, NPM_REPO))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_hadolint_output_is_mapped(tmp_path, monkeypatch):
    adapter = HadolintAdapter()
    stub_json(
        adapter,
        [
            {
                "code": "DL3008",
                "message": "Pin versions in apt get install",
                "file": "Dockerfile",
                "line": 4,
                "level": "warning",
            }
        ],
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].category is Category.CONTAINERS
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].line == 4


def test_trivy_output_covers_vulns_secrets_and_misconfig(tmp_path, monkeypatch):
    adapter = TrivyAdapter()
    stub_json(
        adapter,
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1",
                            "PkgName": "flask",
                            "InstalledVersion": "0.12",
                            "FixedVersion": "1.0",
                            "Severity": "HIGH",
                            "Title": "rce",
                            "PrimaryURL": "https://avd.aquasec.com/CVE-2023-1",
                        }
                    ],
                },
                {
                    "Target": "config.py",
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Severity": "CRITICAL",
                            "StartLine": 2,
                            "Match": "AKIAIOSFODNN7EXAMPLE",
                            "Title": "AWS key",
                        }
                    ],
                },
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "root user",
                            "Description": "runs as root",
                            "Severity": "MEDIUM",
                            "CauseMetadata": {"StartLine": 1},
                            "Resolution": "add USER",
                        }
                    ],
                },
            ]
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    by_category = {f.category for f in findings}
    assert by_category == {Category.DEPENDENCIES, Category.SECRETS, Category.DEPLOYMENT}
    secret = next(f for f in findings if f.category is Category.SECRETS)
    assert "AKIAIOSFODNN7EXAMPLE" not in secret.evidence[0].snippet


def test_checkov_output_is_mapped(tmp_path, monkeypatch):
    adapter = CheckovAdapter()
    stub_json(
        adapter,
        [
            {
                "check_type": "dockerfile",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_DOCKER_3",
                            "check_name": "Ensure that a user is created",
                            "file_path": "/Dockerfile",
                            "file_line_range": [1, 8],
                            "guideline": "https://docs.bridgecrew.io/CKV_DOCKER_3",
                        }
                    ],
                    "passed_checks": [{"check_id": "CKV_DOCKER_2"}],
                },
            }
        ],
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].file == "Dockerfile"
    assert findings[0].line == 1


def test_semgrep_output_is_mapped(tmp_path, monkeypatch):
    adapter = SemgrepAdapter()
    stub_json(
        adapter,
        {
            "results": [
                {
                    "check_id": "python.flask.security.audit.sql-injection",
                    "path": "app.py",
                    "start": {"line": 7},
                    "extra": {
                        "message": "Detected SQL statement built from user input",
                        "severity": "ERROR",
                        "lines": "cur.execute(q)",
                        "metadata": {"shortlink": "https://sg.run/abc"},
                    },
                }
            ]
        },
        monkeypatch,
    )
    findings = adapter.run(ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].rule_id == "VG-EXT-semgrep-sql-injection"


# -------------------------------------------------------------- engine merge


class _FakeAdapter(ToolAdapter):
    name = "fake"
    command = "fake"
    topics = {"security.sql-injection"}

    def __init__(self, findings=None):
        self._findings = findings or []

    def available(self) -> bool:
        return True

    def run(self, context):
        return list(self._findings)


def test_engine_merges_adapter_findings_and_records_them(tmp_path):
    repo = context_from(tmp_path, FLASK_REPO).root
    adapter = _FakeAdapter()
    finding = adapter.make_finding(
        native_id="X1",
        title="fake finding",
        description="d",
        why_it_matters="w",
        severity=Severity.HIGH,
        file="app.py",
        line=2,
        snippet="unique-adapter-snippet",
    )
    engine = Engine(adapters=[_FakeAdapter([finding])])
    report = engine.audit(repo)
    assert any(f.rule_id == "VG-EXT-fake-X1" for f in report.findings)
    assert any(entry.startswith("fake (") for entry in report.adapters_used)


def test_adapter_corroborates_rather_than_duplicates_a_builtin(tmp_path):
    """A built-in and an adapter reporting the same line yield one finding."""
    repo = context_from(
        tmp_path,
        {**FLASK_REPO, "settings.py": 'SECRET_KEY = "hunter2hunter2hunter2"\n'},
    ).root
    baseline = Engine(adapters=[]).audit(repo)
    builtin = [f for f in baseline.findings if f.evidence and f.evidence[0].snippet]
    if not builtin:
        pytest.skip("no snippet-bearing built-in finding to corroborate")
    target = builtin[0]
    adapter = _FakeAdapter()
    duplicate = adapter.make_finding(
        native_id="DUP",
        title="same thing",
        description="d",
        why_it_matters="w",
        severity=Severity.HIGH,
        file=target.evidence[0].file,
        line=target.line,
        snippet=target.evidence[0].snippet,
    )
    report = Engine(adapters=[_FakeAdapter([duplicate])]).audit(repo)
    assert not any(f.rule_id == "VG-EXT-fake-DUP" for f in report.findings)
    merged = next(f for f in report.findings if f.id == target.id)
    assert any("corroborated by fake" in e.note for e in merged.evidence)


def test_a_crashing_adapter_never_breaks_the_scan(tmp_path):
    class Exploding(_FakeAdapter):
        name = "boom"

        def run(self, context):
            raise RuntimeError("tool exploded")

    repo = context_from(tmp_path, FLASK_REPO).root
    report = Engine(adapters=[Exploding()]).audit(repo)
    assert any("boom (skipped: run error)" in entry for entry in report.adapters_used)
