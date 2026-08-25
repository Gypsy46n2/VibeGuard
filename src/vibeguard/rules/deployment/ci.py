"""VG-DEP-001, VG-DEP-002, VG-DEP-003 — CI pipeline presence and safety."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.deployment._ci import ci_files, github_workflows, run_steps, workflow_jobs

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DeployWithoutTestsRule", "NoCiConfigurationRule", "SecretExposedInCiRule"]


class NoCiConfigurationRule(ProjectRule):
    """No continuous-integration configuration anywhere in the tree."""

    id: ClassVar[str] = "VG-DEP-001"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "No CI configuration"
    description: ClassVar[str] = (
        "No CI configuration was found (.github/workflows, .gitlab-ci.yml, Jenkinsfile, "
        ".circleci/config.yml, azure-pipelines.yml, .drone.yml, bitbucket-pipelines.yml)."
    )
    why_it_matters: ClassVar[str] = (
        "Every push goes out unverified: nothing runs the tests, the linter, or a build "
        "before code lands on the main branch. Breakage is discovered by users rather than "
        "by a machine, and 'it works on my laptop' becomes the only integration test the "
        "project has."
    )
    references: ClassVar[list[str]] = [
        "https://docs.github.com/actions/using-workflows/about-workflows",
        "https://docs.gitlab.com/ee/ci/quick_start/",
    ]
    topics: ClassVar[set[str]] = {
        "deployment.ci-cd-pipelines",
        "deployment.build-reproducibility",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    recommended_followup: ClassVar[str] = (
        "Add one pipeline that runs on every push and pull request: install dependencies "
        "from the lockfile, run the linter, and run the test suite — e.g. a single "
        "`.github/workflows/ci.yml`. Then make it a required check on the default branch."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        found = ci_files(ctx)
        if found:
            return None
        return (
            self.description,
            "searched for .github/workflows/*.y(a)ml, .gitlab-ci.yml, Jenkinsfile, "
            ".circleci/config.yml, azure-pipelines.yml, .drone.yml, "
            "bitbucket-pipelines.yml",
        )


_DEPLOY = re.compile(
    r"(kubectl\s+apply|docker\s+push|helm\s+(upgrade|install)|flyctl?\s+deploy|"
    r"vercel\s+[^\n]*--prod|serverless\s+deploy|sls\s+deploy|aws\s+s3\s+sync|"
    r"aws\s+ecs\s+update-service|heroku\b|terraform\s+apply|\bdeploy\b|"
    r"actions/deploy|deploy-action|appleboy/ssh-action)",
    re.IGNORECASE,
)
_TEST = re.compile(
    r"(pytest|\btox\b|nox\b|unittest|npm\s+(run\s+)?test|yarn\s+test|pnpm\s+(run\s+)?test|"
    r"\bjest\b|vitest|playwright\s+test|cypress\s+run|go\s+test|cargo\s+test|"
    r"mvn\s+(test|verify)|gradle\s+test|\brspec\b|phpunit|make\s+test|"
    r"\bcoverage\s+run)",
    re.IGNORECASE,
)


def _triggers(workflow: dict[str, Any]) -> Any:
    """The workflow ``on:`` block (PyYAML parses the bare key ``on`` as ``True``)."""
    if "on" in workflow:
        return workflow["on"]
    return workflow.get(True)


def _pushes_to_default_branch(workflow: dict[str, Any]) -> bool:
    triggers = _triggers(workflow)
    if isinstance(triggers, str):
        return triggers == "push"
    if isinstance(triggers, list):
        return "push" in [str(item) for item in triggers]
    if not isinstance(triggers, dict):
        return False
    if "push" not in triggers:
        return False
    push = triggers["push"]
    if not isinstance(push, dict):
        return True
    branches = push.get("branches") or push.get("branches-ignore")
    if branches is None:
        return True
    names = {str(item).lower() for item in branches} if isinstance(branches, list) else set()
    return bool(names & {"main", "master", "trunk", "release", "*", "**"})


def _step_text(step: dict[str, Any]) -> str:
    return f"{step.get('uses', '')}\n{step.get('run', '')}\n{step.get('name', '')}"


class DeployWithoutTestsRule(Rule):
    """A push-triggered workflow that deploys without running any tests."""

    id: ClassVar[str] = "VG-DEP-002"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Deployment workflow that skips tests"
    description: ClassVar[str] = (
        "A CI workflow triggered by pushes to the default branch deploys or publishes "
        "without running a test step first."
    )
    why_it_matters: ClassVar[str] = (
        "The pipeline is a straight pipe from a developer's keyboard to production: a typo "
        "that breaks startup, a bad migration, or a deleted endpoint ships automatically "
        "and is discovered by users. Because nothing gates the deploy, the mean time to "
        "detection is however long it takes someone to complain."
    )
    references: ClassVar[list[str]] = [
        "https://docs.github.com/actions/using-jobs/using-jobs-in-a-workflow",
        "https://docs.github.com/actions/deployment/about-deployments",
    ]
    topics: ClassVar[set[str]] = {
        "deployment.ci-cd-pipelines",
        "deployment.dangerous-workflows",
        "testing.smoke-tests",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel, workflow in github_workflows(ctx):
            if len(findings) >= 3:
                break
            if not _pushes_to_default_branch(workflow):
                continue
            jobs = workflow_jobs(workflow)
            if not jobs:
                continue
            deploy_jobs: list[str] = []
            has_test = False
            for job_id, job in jobs.items():
                for step in run_steps(job):
                    text = _step_text(step)
                    if _TEST.search(text):
                        has_test = True
                    elif _DEPLOY.search(text):
                        deploy_jobs.append(job_id)
            if has_test or not deploy_jobs:
                continue
            name = str(workflow.get("name") or rel)
            findings.append(
                self.make_finding(
                    file=rel,
                    evidence=[
                        Evidence(
                            file=rel,
                            note=(
                                f"workflow `{name}` runs on push and deploys in job(s) "
                                f"{', '.join(sorted(set(deploy_jobs)))}; no test step found"
                            ),
                        )
                    ],
                    description=(
                        f"{rel}: workflow `{name}` deploys on every push to the default "
                        "branch and runs no tests beforehand."
                    ),
                    recommended_followup=(
                        "Add a `test` job that runs the suite and make the deploy job "
                        "`needs: [test]`, so a red build blocks the release. Gate the "
                        "deploy on the default branch only "
                        "(`if: github.ref == 'refs/heads/main'`)."
                    ),
                )
            )
        return findings


_SECRET_REF = re.compile(r"(\$\{\{\s*secrets\.\w+|\$\{?[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|KEY)\w*)")
_PRINTS = re.compile(r"(^|[;&|]|\s)(echo|printf|printenv|env|set\s+-x|cat)\b")
_REDIRECT = re.compile(r">>?\s*\$?\w")
_MASK = re.compile(r"add-mask|::add-mask::")
_URL_WITH_SECRET = re.compile(r"https?://[^\s\"']*\$\{\{\s*secrets\.", re.IGNORECASE)


class SecretExposedInCiRule(Rule):
    """A CI step that prints a secret into the build log."""

    id: ClassVar[str] = "VG-DEP-003"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Secret exposed in CI output"
    description: ClassVar[str] = (
        "A CI step echoes, dumps, or interpolates a secret into a command whose output "
        "lands in the build log."
    )
    why_it_matters: ClassVar[str] = (
        "Build logs are far more widely readable than the secret store — on public "
        "repositories they are world-readable, and they are retained for months. A secret "
        "printed once is a secret leaked permanently, and the only real remediation is "
        "rotating it. Secrets in URLs additionally leak to proxy and server access logs."
    )
    references: ClassVar[list[str]] = [
        "https://docs.github.com/actions/security-guides/using-secrets-in-github-actions",
        "https://owasp.org/www-project-top-ten/",
    ]
    topics: ClassVar[set[str]] = {
        "deployment.dangerous-workflows",
        "secrets.environment-secrets",
        "security.secret-leakage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in ci_files(ctx):
            if len(findings) >= 5:
                break
            text = ctx.read(rel)
            if not text or "secret" not in text.lower():
                continue
            for index, raw in enumerate(text.splitlines(), start=1):
                if len(findings) >= 5:
                    break
                note = self._offence(raw)
                if note is None:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=index,
                        evidence=[
                            Evidence(file=rel, line=index, snippet=raw.strip()[:200], note=note)
                        ],
                        description=f"{rel}:{index} {note}.",
                        recommended_followup=(
                            "Never print a secret: pass it to the tool through `env:` and "
                            "let the tool read it, drop `set -x`/`printenv` from steps that "
                            "hold secrets, and put credentials in a header or a file rather "
                            "than in a URL. Rotate anything that has already been logged."
                        ),
                        redact_evidence=True,
                    )
                )
        return findings

    @staticmethod
    def _offence(raw: str) -> str | None:
        line = raw.strip()
        if not line or line.startswith("#") or len(line) > 1000:
            return None
        if _MASK.search(line):
            return None
        if _URL_WITH_SECRET.search(line):
            return "interpolates a secret into a URL, which leaks into logs and proxies"
        if "set -x" in line:
            return "enables `set -x`, which traces every command (secrets included) into the log"
        if not _SECRET_REF.search(line):
            if re.search(r"(^|\s)(printenv|env)\s*($|\|)", line):
                return "dumps the whole environment, printing every secret exported to the step"
            return None
        if _REDIRECT.search(line):
            return None
        if _PRINTS.search(line):
            return "prints a secret value to the build log"
        return None
