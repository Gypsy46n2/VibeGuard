"""Repro-test generation and the repair loop's use of it (vibeguard.testing)."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from tests.conftest import make_context, make_finding, write_repo

from vibeguard.core.events import EventBus
from vibeguard.core.models import Category, Confidence, Finding, FixStatus, Severity
from vibeguard.testing import (
    REPRO_DIRNAME,
    ReproRunner,
    generate_repro_test,
    repro_path,
    supported_rule_ids,
)
from vibeguard.testing.repro import TEMPLATES

# --------------------------------------------------------------------- fixtures

TIMEOUT_APP = """\
import requests


def fetch(url):
    return requests.get(url)
"""

TIMEOUT_APP_FIXED = """\
import requests


def fetch(url):
    return requests.get(url, timeout=30)
"""

TLS_APP = """\
import requests

resp = requests.get("https://example.com", verify=False)
"""

RANDOM_APP = """\
import random

def make_token():
    token = random.choice("abcdef")
    return token
"""

SQLI_APP = """\
def get(cur, user_id):
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""

DOCKERFILE_ROOT = """\
FROM python:3.12-slim
COPY . /app
CMD ["python", "app.py"]
"""


def _finding(rule_id: str, file: str, snippet: str, line: int = 1) -> Finding:
    return make_finding(
        rule_id=rule_id,
        fingerprint=f"{abs(hash((rule_id, file, snippet))):064x}"[:64],
        file=file,
        line=line,
        snippet=snippet,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )


def _write_and_run(root: Path, finding: Finding) -> tuple[str, subprocess.CompletedProcess]:
    repro = generate_repro_test(finding)
    assert repro is not None, f"no template rendered for {finding.rule_id}"
    destination = root / repro.path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(repro.content, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", repro.path, "-q", "-p", "no:cacheprovider"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return repro.path, proc


# -------------------------------------------------------------------- generation


def test_the_supported_rules_are_the_documented_curated_subset():
    assert supported_rule_ids() == [
        "VG-API-001",
        "VG-CTR-001",
        "VG-CTR-002",
        "VG-SEC-001",
        "VG-SEC-002",
        "VG-SEC-011",
        "VG-SEC-018",
    ]


def test_the_path_follows_the_documented_naming(tmp_path: Path):
    finding = _finding("VG-API-001", "app.py", "requests.get(url)")
    assert repro_path(finding) == (
        f"{REPRO_DIRNAME}/test_vg_api_001_{finding.fingerprint[:12]}.py"
    )


def test_an_unsupported_rule_generates_nothing():
    assert generate_repro_test(_finding("VG-OBS-001", "app.py", "print(x)")) is None


def test_a_finding_with_no_file_generates_nothing():
    finding = make_finding(rule_id="VG-API-001", file=None, line=None)
    assert generate_repro_test(finding) is None


def test_a_python_template_is_not_used_for_another_language():
    assert generate_repro_test(_finding("VG-API-001", "client.js", "requests.get(u)")) is None


def test_the_dockerfile_templates_require_a_dockerfile():
    assert generate_repro_test(_finding("VG-CTR-001", "app.py", "x")) is None
    assert generate_repro_test(_finding("VG-CTR-001", "docker/Dockerfile", "FROM x")) is not None


def test_the_generated_test_does_not_import_vibeguard():
    """It must keep working in a repo that never installs us."""
    for rule_id, target, snippet in (
        ("VG-API-001", "app.py", "requests.get(url)"),
        ("VG-SEC-018", "app.py", "verify=False"),
        ("VG-CTR-001", "Dockerfile", "FROM x"),
    ):
        repro = generate_repro_test(_finding(rule_id, target, snippet))
        assert repro is not None
        assert not re.search(r"^\s*(?:import|from)\s+vibeguard", repro.content, re.M)


@pytest.mark.parametrize("rule_id", sorted(TEMPLATES))
def test_every_template_renders_valid_python(rule_id: str):
    target = "Dockerfile" if rule_id.startswith("VG-CTR") else (
        "app.js" if rule_id == "VG-SEC-002" else "app.py"
    )
    repro = generate_repro_test(_finding(rule_id, target, "some snippet"))
    assert repro is not None
    compile(repro.content, repro.path, "exec")


# ------------------------------------------------------------------- behaviour


@pytest.mark.parametrize(
    ("rule_id", "target", "content", "snippet"),
    [
        ("VG-API-001", "app.py", TIMEOUT_APP, "requests.get(url)"),
        ("VG-SEC-018", "app.py", TLS_APP, 'resp = requests.get("https://example.com", '
                                          "verify=False)"),
        ("VG-SEC-011", "app.py", RANDOM_APP, 'token = random.choice("abcdef")'),
        ("VG-SEC-001", "app.py", SQLI_APP,
         'cur.execute(f"SELECT * FROM users WHERE id = {user_id}")'),
        ("VG-CTR-001", "Dockerfile", DOCKERFILE_ROOT, "FROM python:3.12-slim"),
        ("VG-CTR-002", "Dockerfile", DOCKERFILE_ROOT, "FROM python:3.12-slim"),
    ],
)
def test_the_generated_test_fails_on_the_defect(
    tmp_path: Path, rule_id: str, target: str, content: str, snippet: str
):
    write_repo(tmp_path, {target: content})
    _path, proc = _write_and_run(tmp_path, _finding(rule_id, target, snippet, line=5))
    assert proc.returncode == 1, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    ("rule_id", "target", "content", "snippet"),
    [
        ("VG-API-001", "app.py", TIMEOUT_APP_FIXED, "requests.get(url)"),
        ("VG-SEC-018", "app.py", TLS_APP.replace("False", "True"),
         'resp = requests.get("https://example.com", verify=False)'),
        ("VG-SEC-011", "app.py", RANDOM_APP.replace("random.choice", "secrets.choice"),
         'token = random.choice("abcdef")'),
        ("VG-SEC-001", "app.py",
         'def get(cur, user_id):\n    cur.execute("SELECT * FROM users WHERE id = ?",'
         " (user_id,))\n",
         'cur.execute(f"SELECT * FROM users WHERE id = {user_id}")'),
        ("VG-CTR-001", "Dockerfile", DOCKERFILE_ROOT + "USER appuser\n",
         "FROM python:3.12-slim"),
        ("VG-CTR-002", "Dockerfile", DOCKERFILE_ROOT + "HEALTHCHECK CMD curl -f /health\n",
         "FROM python:3.12-slim"),
    ],
)
def test_the_generated_test_passes_once_the_defect_is_repaired(
    tmp_path: Path, rule_id: str, target: str, content: str, snippet: str
):
    write_repo(tmp_path, {target: content})
    _path, proc = _write_and_run(tmp_path, _finding(rule_id, target, snippet, line=5))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_an_unrelated_defect_of_the_same_rule_does_not_fail_the_test(tmp_path: Path):
    """The anchor is what keeps a per-finding fix from being blamed for its neighbour."""
    write_repo(
        tmp_path,
        {
            "app.py": "import requests\n\n"
            "a = requests.get(first_url, timeout=30)\n"
            "b = requests.get(second_url)\n"
        },
    )
    # The finding is about the *first* call, which now has its timeout.
    _path, proc = _write_and_run(
        tmp_path, _finding("VG-API-001", "app.py", "requests.get(first_url)", line=3)
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_missing_target_file_fails_loudly_rather_than_passing(tmp_path: Path):
    write_repo(tmp_path, {"other.py": "x = 1\n"})
    _path, proc = _write_and_run(
        tmp_path, _finding("VG-API-001", "app.py", "requests.get(url)")
    )
    assert proc.returncode == 1
    assert "is missing" in proc.stdout


# ---------------------------------------------------------------------- runner


def test_the_runner_keeps_a_test_that_reproduces_the_defect(tmp_path: Path):
    ctx = make_context(write_repo(tmp_path, {"app.py": TIMEOUT_APP}))
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe("repro.*", lambda name, _payload: seen.append(name))
    runner = ReproRunner(events=bus)

    repro = runner.prepare(ctx, _finding("VG-API-001", "app.py", "requests.get(url)", line=5))

    assert repro is not None
    assert (tmp_path / repro.path).is_file()
    assert seen == ["repro.generated", "repro.result"]

    # After the repair the same test passes, which is what licenses a FIXED verdict.
    (tmp_path / "app.py").write_text(TIMEOUT_APP_FIXED, encoding="utf-8")
    assert runner.confirm(ctx, repro) is True


def test_a_test_that_passes_before_the_fix_is_discarded(tmp_path: Path):
    """It reproduces nothing, so it must not become evidence for anything."""
    ctx = make_context(write_repo(tmp_path, {"app.py": TIMEOUT_APP_FIXED}))
    runner = ReproRunner()

    repro = runner.prepare(ctx, _finding("VG-API-001", "app.py", "requests.get(url)", line=5))

    assert repro is None
    assert not (tmp_path / REPRO_DIRNAME).exists() or not list(
        (tmp_path / REPRO_DIRNAME).glob("*.py")
    )


def test_repro_generation_can_be_switched_off(tmp_path: Path):
    ctx = make_context(write_repo(tmp_path, {"app.py": TIMEOUT_APP}))
    runner = ReproRunner(enabled=False)
    assert runner.prepare(ctx, _finding("VG-API-001", "app.py", "requests.get(url)")) is None


def test_an_unsupported_rule_is_a_silent_skip(tmp_path: Path):
    ctx = make_context(write_repo(tmp_path, {"app.py": TIMEOUT_APP}))
    assert ReproRunner().prepare(ctx, _finding("VG-DEP-001", "app.py", "flask")) is None


# ------------------------------------------------------------- engine integration


def test_engine_fix_records_the_repro_test_and_its_verdict(tmp_path: Path):
    from vibeguard.core.config import VibeguardConfig
    from vibeguard.engine.orchestrator import Engine

    root = write_repo(
        tmp_path,
        {
            "app.py": TIMEOUT_APP,
            "requirements.txt": "flask==3.0.0\nrequests==2.32.3\n",
        },
    )
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=root,
        check=True,
    )

    report = Engine(VibeguardConfig()).fix(root, "safe")
    timeout = next(f for f in report.findings if f.rule_id == "VG-API-001")

    assert timeout.fix is not None
    assert timeout.fix.status is FixStatus.FIXED
    assert timeout.fix.repro_test == repro_path(timeout)
    step = next(s for s in timeout.fix.validation if s.name == "tests:repro")
    assert step.passed and not step.skipped
    assert "no longer true" in step.detail
    assert "timeout=30" in (root / "app.py").read_text(encoding="utf-8")


def test_disabling_repro_tests_leaves_the_fix_status_logic_unchanged(tmp_path: Path):
    from vibeguard.core.config import FixConfig, VibeguardConfig
    from vibeguard.engine.orchestrator import Engine

    root = write_repo(tmp_path, {"app.py": TIMEOUT_APP})
    config = VibeguardConfig(fix=FixConfig(allow_no_git=True, repro_tests=False))
    report = Engine(config).fix(root, "safe")
    timeout = next(f for f in report.findings if f.rule_id == "VG-API-001")

    assert timeout.fix is not None
    assert timeout.fix.repro_test is None
    assert not [s for s in timeout.fix.validation if s.name == "tests:repro"]
