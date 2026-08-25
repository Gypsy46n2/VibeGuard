"""Positive and negative coverage for the deployment pack (VG-DEP-001..006)."""

from __future__ import annotations

from pathlib import Path

from conftest import context_from, run_rule
from vibeguard.rules.deployment import RULES
from vibeguard.rules.deployment.ci import (
    DeployWithoutTestsRule,
    NoCiConfigurationRule,
    SecretExposedInCiRule,
)
from vibeguard.rules.deployment.environments import (
    NoEnvironmentSeparationRule,
    NoRollbackProcedureRule,
    ProductionEnvFileCommittedRule,
)

APP = "import os\n\nprint('hello')\n"

DEPLOY_NO_TESTS = """\
name: deploy
on:
  push:
    branches: [main]
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: kubectl apply -f k8s/
"""

DEPLOY_WITH_TESTS = """\
name: ci
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest -q
  ship:
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - run: kubectl apply -f k8s/
"""

LEAKY_WORKFLOW = """\
name: build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "token is ${{ secrets.NPM_TOKEN }}"
"""

SAFE_WORKFLOW = """\
name: build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
      - run: pytest -q
"""


def _ids(findings: list) -> list[str]:
    return sorted({f.rule_id for f in findings})


# ------------------------------------------------------------------ VG-DEP-001


def test_no_ci_configuration_fires(tmp_path: Path) -> None:
    findings = run_rule(NoCiConfigurationRule, tmp_path, {"app.py": APP})
    assert [f.rule_id for f in findings] == ["VG-DEP-001"]


def test_no_ci_configuration_silent_with_workflow(tmp_path: Path) -> None:
    files = {"app.py": APP, ".github/workflows/ci.yml": DEPLOY_WITH_TESTS}
    assert run_rule(NoCiConfigurationRule, tmp_path, files) == []


def test_no_ci_configuration_silent_with_gitlab_ci(tmp_path: Path) -> None:
    files = {"app.py": APP, ".gitlab-ci.yml": "stages: [test]\n"}
    assert run_rule(NoCiConfigurationRule, tmp_path, files) == []


# ------------------------------------------------------------------ VG-DEP-002


def test_deploy_without_tests_fires(tmp_path: Path) -> None:
    files = {"app.py": APP, ".github/workflows/deploy.yml": DEPLOY_NO_TESTS}
    findings = run_rule(DeployWithoutTestsRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEP-002"]
    assert "ship" in findings[0].evidence[0].note


def test_deploy_with_tests_is_silent(tmp_path: Path) -> None:
    files = {"app.py": APP, ".github/workflows/ci.yml": DEPLOY_WITH_TESTS}
    assert run_rule(DeployWithoutTestsRule, tmp_path, files) == []


def test_deploy_on_manual_dispatch_only_is_silent(tmp_path: Path) -> None:
    workflow = DEPLOY_NO_TESTS.replace(
        "on:\n  push:\n    branches: [main]", "on: workflow_dispatch"
    )
    files = {"app.py": APP, ".github/workflows/deploy.yml": workflow}
    assert run_rule(DeployWithoutTestsRule, tmp_path, files) == []


def test_deploy_rule_survives_malformed_workflow(tmp_path: Path) -> None:
    files = {"app.py": APP, ".github/workflows/bad.yml": "on: [push\njobs: {{{\n"}
    assert run_rule(DeployWithoutTestsRule, tmp_path, files) == []


# ------------------------------------------------------------------ VG-DEP-003


def test_secret_exposed_in_ci_fires_and_redacts(tmp_path: Path) -> None:
    files = {"app.py": APP, ".github/workflows/build.yml": LEAKY_WORKFLOW}
    findings = run_rule(SecretExposedInCiRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEP-003"]
    assert "prints a secret" in findings[0].evidence[0].note


def test_secret_passed_via_env_is_silent(tmp_path: Path) -> None:
    files = {"app.py": APP, ".github/workflows/build.yml": SAFE_WORKFLOW}
    assert run_rule(SecretExposedInCiRule, tmp_path, files) == []


def test_secret_written_to_github_env_is_silent(tmp_path: Path) -> None:
    workflow = LEAKY_WORKFLOW.replace(
        'run: echo "token is ${{ secrets.NPM_TOKEN }}"',
        'run: echo "TOKEN=${{ secrets.NPM_TOKEN }}" >> $GITHUB_ENV',
    )
    files = {"app.py": APP, ".github/workflows/build.yml": workflow}
    assert run_rule(SecretExposedInCiRule, tmp_path, files) == []


def test_set_x_with_secrets_is_flagged(tmp_path: Path) -> None:
    workflow = LEAKY_WORKFLOW.replace(
        'run: echo "token is ${{ secrets.NPM_TOKEN }}"',
        "run: set -x && ./deploy.sh\n        env:\n          TOKEN: ${{ secrets.NPM_TOKEN }}",
    )
    files = {"app.py": APP, ".github/workflows/build.yml": workflow}
    findings = run_rule(SecretExposedInCiRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEP-003"]


# ------------------------------------------------------------------ VG-DEP-004


def test_no_environment_separation_fires(tmp_path: Path) -> None:
    files = {"app.py": "DATABASE_URL = 'postgres://localhost/app'\n", "README.md": "# app\n"}
    findings = run_rule(NoEnvironmentSeparationRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEP-004"]


def test_environment_switch_in_source_is_silent(tmp_path: Path) -> None:
    files = {"app.py": "import os\n\nENV = os.environ.get('APP_ENV', 'dev')\n"}
    assert run_rule(NoEnvironmentSeparationRule, tmp_path, files) == []


def test_per_environment_config_file_is_silent(tmp_path: Path) -> None:
    files = {"app.py": APP, "config/production.yaml": "debug: false\n"}
    assert run_rule(NoEnvironmentSeparationRule, tmp_path, files) == []


# ------------------------------------------------------------------ VG-DEP-005


def test_production_env_file_fires(tmp_path: Path) -> None:
    files = {"app.py": APP, ".env.production": "DB_PASSWORD=hunter2\n"}
    findings = run_rule(ProductionEnvFileCommittedRule, tmp_path, files)
    assert [f.rule_id for f in findings] == ["VG-DEP-005"]
    assert findings[0].file == ".env.production"


def test_production_env_example_is_silent(tmp_path: Path) -> None:
    files = {"app.py": APP, ".env.production.example": "DB_PASSWORD=\n"}
    assert run_rule(ProductionEnvFileCommittedRule, tmp_path, files) == []


def test_prod_tfvars_and_secrets_yaml_are_flagged(tmp_path: Path) -> None:
    files = {"app.py": APP, "infra/prod.tfvars": "region = \"eu\"\n", "secrets.yaml": "a: b\n"}
    findings = run_rule(ProductionEnvFileCommittedRule, tmp_path, files)
    assert len(findings) == 2


# ------------------------------------------------------------------ VG-DEP-006


def _deploying_project() -> dict[str, str]:
    return {
        "app.py": APP * 700,
        "requirements.txt": "flask==3.0.0\n",
        "Dockerfile": "FROM python:3.12-slim\nUSER app\nCMD [\"python\", \"app.py\"]\n",
    }


def test_no_rollback_procedure_fires(tmp_path: Path) -> None:
    findings = run_rule(NoRollbackProcedureRule, tmp_path, _deploying_project())
    assert [f.rule_id for f in findings] == ["VG-DEP-006"]
    assert findings[0].autofix_safety.value == "informational"


def test_rollback_runbook_is_silent(tmp_path: Path) -> None:
    files = _deploying_project()
    files["DEPLOY.md"] = "# Deploy\n\nTo roll back run `kubectl rollout undo deploy/api`.\n"
    assert run_rule(NoRollbackProcedureRule, tmp_path, files) == []


def test_no_rollback_rule_silent_when_nothing_deploys(tmp_path: Path) -> None:
    files = {"app.py": APP * 700, "requirements.txt": "flask==3.0.0\n"}
    assert run_rule(NoRollbackProcedureRule, tmp_path, files) == []


# --------------------------------------------------------------------- pack-level


def test_pack_registers_every_rule_id_in_order() -> None:
    assert [rule.id for rule in RULES] == [f"VG-DEP-{n:03d}" for n in range(1, 7)]


def test_shared_fixture_app_trips_the_expected_rules() -> None:
    from conftest import FIXTURES, make_context

    ctx = make_context(FIXTURES / "deployment_vulnerable")
    fired = {
        rule_cls.id
        for rule_cls in RULES
        if (rule := rule_cls()).applicable(ctx) and rule.detect(ctx)
    }
    assert {"VG-DEP-002", "VG-DEP-003", "VG-DEP-005"} <= fired
    assert "VG-DEP-001" not in fired  # the fixture does have a workflow


def test_no_rule_raises_on_a_junk_repo(tmp_path: Path) -> None:
    junk = "\x00\x01: [unclosed\n\t\tbad\n"
    ctx = context_from(
        tmp_path,
        {
            ".github/workflows/x.yml": junk,
            ".gitlab-ci.yml": junk,
            "docker-compose.yml": junk,
            "app.py": "def broken(:\n",
        },
    )
    for rule_cls in RULES:
        rule = rule_cls()
        findings = rule.detect(ctx) if rule.applicable(ctx) else []
        assert isinstance(findings, list)


def test_every_finding_carries_a_followup(tmp_path: Path) -> None:
    files = {
        "app.py": APP,
        ".env.production": "DB_PASSWORD=hunter2\n",
        ".github/workflows/deploy.yml": DEPLOY_NO_TESTS,
    }
    ctx = context_from(tmp_path, files)
    for rule_cls in RULES:
        rule = rule_cls()
        if not rule.applicable(ctx):
            continue
        for finding in rule.detect(ctx):
            assert finding.recommended_followup.strip()
            assert _ids([finding])
