"""VG-DEP-004, VG-DEP-005, VG-DEP-006 — environment separation and rollback readiness."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

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
from vibeguard.rules._support import ProjectRule, source_files
from vibeguard.rules.containers._parse import dockerfiles, k8s_documents
from vibeguard.rules.deployment._ci import ci_files

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "NoEnvironmentSeparationRule",
    "NoRollbackProcedureRule",
    "ProductionEnvFileCommittedRule",
]

_CONFIG_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".yml", ".yaml")

_ENV_SWITCH = re.compile(
    r"\b(APP_ENV|NODE_ENV|FLASK_ENV|RAILS_ENV|DJANGO_SETTINGS_MODULE|ASPNETCORE_ENVIRONMENT|"
    r"ENVIRONMENT|DEPLOY_ENV|VIBE_ENV|STAGE|PY_ENV|ENV_NAME)\b"
)
_FEATURE_FLAGS = re.compile(
    r"(launchdarkly|unleash|flagsmith|split\.io|configcat|flipper|growthbook|"
    r"feature_flags?|featureFlags?|FEATURE_[A-Z0-9_]+)",
    re.IGNORECASE,
)
_ENV_FILE = re.compile(
    r"^(\.env\.(dev|development|staging|stage|test|prod|production|local)|"
    r"(dev|development|staging|stage|prod|production)\.(env|ya?ml|json|toml|tfvars)|"
    r"values-(dev|staging|prod|production)\.ya?ml|"
    r"(settings|config)_(dev|development|staging|prod|production)\.py)$",
    re.IGNORECASE,
)
_ENV_DIR = {"environments", "envs", "overlays", "deploy"}


class NoEnvironmentSeparationRule(ProjectRule):
    """A single hardcoded configuration with no dev/staging/prod distinction."""

    id: ClassVar[str] = "VG-DEP-004"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No environment separation"
    description: ClassVar[str] = (
        "The project carries one hardcoded configuration: no per-environment config files, "
        "no environment-driven settings switch, no CI environments, and no feature flags."
    )
    why_it_matters: ClassVar[str] = (
        "With one configuration there is nowhere safe to try a change: developers test "
        "against production data, and a debug setting left enabled locally ships straight "
        "to real users. It also couples release to deploy — the only way to turn a feature "
        "on is to push code, and the only way to turn it off is an emergency revert."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/config",
        "https://martinfowler.com/articles/feature-toggles.html",
    ]
    topics: ClassVar[set[str]] = {
        "deployment.environment-separation",
        "deployment.feature-flags",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    recommended_followup: ClassVar[str] = (
        "Introduce one switch — read `APP_ENV` (or `NODE_ENV`) at startup and load "
        "`config/<env>.yaml` from it — and give staging its own values file and its own "
        "CI environment. Add a simple feature-flag lookup so risky changes can be turned "
        "off without a redeploy."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        signals: list[str] = []
        for rel in ctx.files:
            posix = PurePosixPath(rel)
            if _ENV_FILE.match(posix.name):
                signals.append(f"per-environment config file {rel}")
                break
            if any(part.lower() in _ENV_DIR for part in posix.parts[:-1]):
                signals.append(f"per-environment directory {rel}")
                break
        if not signals:
            for rel in source_files(ctx, _CONFIG_SUFFIXES, limit=300):
                text = ctx.read(rel)
                if _ENV_SWITCH.search(text):
                    signals.append(f"environment switch referenced in {rel}")
                    break
                if _FEATURE_FLAGS.search(text):
                    signals.append(f"feature-flag mechanism referenced in {rel}")
                    break
        if not signals:
            for rel in ci_files(ctx):
                if re.search(r"^\s*environment:", ctx.read(rel), re.MULTILINE):
                    signals.append(f"CI environment declared in {rel}")
                    break
        if signals:
            return None
        return (
            self.description,
            "searched for .env.<env>/values-<env>.yaml/environments/ files, "
            "APP_ENV/NODE_ENV-style switches in source, CI `environment:` blocks, and "
            "feature-flag SDKs",
        )


_PROD_FILES = re.compile(
    r"^(\.env\.prod(uction)?|prod(uction)?\.env|\.env\.live|"
    r"prod(uction)?\.tfvars|secrets\.ya?ml|secrets\.env)$",
    re.IGNORECASE,
)
_HARMLESS = (".example", ".sample", ".template", ".dist", ".enc", ".sops")


class ProductionEnvFileCommittedRule(Rule):
    """A production environment or secrets file living in the repository."""

    id: ClassVar[str] = "VG-DEP-005"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Production environment file committed"
    description: ClassVar[str] = (
        "A production environment or secrets file is present in the repository tree."
    )
    why_it_matters: ClassVar[str] = (
        "Anyone who can read the repository — every contributor, every CI job, every fork, "
        "and anyone who obtains a clone — now holds the production credentials, and git "
        "history keeps them even after the file is deleted. This is the most common route "
        "from 'someone got read access to the repo' to 'someone owns the production "
        "database'."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/config",
        "https://docs.github.com/code-security/secret-scanning/about-secret-scanning",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.environment-secrets",
        "deployment.environment-separation",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in ctx.files:
            if len(findings) >= 5:
                break
            name = PurePosixPath(rel).name
            if name.lower().endswith(_HARMLESS) or not _PROD_FILES.match(name):
                continue
            findings.append(
                self.make_finding(
                    file=rel,
                    evidence=[
                        Evidence(
                            file=rel,
                            note=f"{rel} is a production environment/secrets file in the tree",
                        )
                    ],
                    description=(
                        f"{rel} is committed to the repository, so production configuration "
                        "(and any credentials in it) is readable by everyone with repo access."
                    ),
                    recommended_followup=(
                        f"Delete `{rel}` from the working tree, add it to `.gitignore`, and "
                        "purge it from git history (`git filter-repo`). Move the values into "
                        "the deployment platform's secret store and rotate every credential "
                        "the file contained."
                    ),
                    redact_evidence=True,
                )
            )
        return findings


_ROLLBACK_DOC = re.compile(
    r"(rollback|roll back|runbook|run book|incident response)", re.IGNORECASE
)
_DEPLOY_DOC = re.compile(r"^#{1,3}\s*(deploy|deployment|release|operations)", re.IGNORECASE)
_STRATEGY = re.compile(r"(rollingUpdate|blue[-_ ]?green|canary|argo\s*rollouts|flagger)", re.I)
_VERSIONED = re.compile(r"(github\.sha|GIT_SHA|CI_COMMIT_SHA|\$\{?VERSION|:v?\d+\.\d+\.\d+)")


class NoRollbackProcedureRule(ProjectRule):
    """A project that deploys but documents no way back."""

    id: ClassVar[str] = "VG-DEP-006"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No documented rollback or deployment procedure"
    description: ClassVar[str] = (
        "The project deploys somewhere, but no runbook or deploy document describes how to "
        "roll back, artifacts are not versioned, and no rolling/blue-green/canary strategy "
        "is configured."
    )
    why_it_matters: ClassVar[str] = (
        "When a release breaks production, recovery time is whatever it takes someone to "
        "improvise — under pressure, at night, possibly without the person who set the "
        "deploy up. Immutable, versioned artifacts and one written command turn a "
        "multi-hour outage into a two-minute one. This is a review item rather than a "
        "defect: small projects can reasonably accept the risk, deliberately."
    )
    references: ClassVar[list[str]] = [
        "https://sre.google/sre-book/release-engineering/",
        "https://martinfowler.com/bliki/BlueGreenDeployment.html",
    ]
    topics: ClassVar[set[str]] = {
        "deployment.rollback-procedures",
        "deployment.deployment-scripts",
        "deployment.zero-downtime",
        "deployment.blue-green",
        "deployment.canary",
        "deployment.rolling",
        "iac.configuration-drift",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Write a short DEPLOY.md: the exact command that deploys, the exact command that "
        "rolls back, and how to verify. Tag images with the commit sha instead of `latest` "
        "so the previous artifact still exists, and set `strategy.rollingUpdate` (or a "
        "blue-green target group) so a rollback does not need a rebuild."
    )

    def _deploys(self, ctx: ScanContext) -> str:
        if dockerfiles(ctx):
            return "a Dockerfile"
        if k8s_documents(ctx):
            return "Kubernetes manifests"
        if any(PurePosixPath(rel).name.lower() == "procfile" for rel in ctx.files):
            return "a Procfile"
        if ctx.tech.iac:
            return "infrastructure-as-code (" + ", ".join(sorted(ctx.tech.iac)) + ")"
        for rel in ci_files(ctx):
            if re.search(r"(deploy|kubectl apply|docker push)", ctx.read(rel), re.IGNORECASE):
                return f"a CI deploy step in {rel}"
        return ""

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        target = self._deploys(ctx)
        if not target:
            return None

        for rel in ctx.files:
            if PurePosixPath(rel).suffix.lower() not in {".md", ".rst", ".txt"}:
                continue
            text = ctx.read(rel)
            if _ROLLBACK_DOC.search(text):
                return None
            if any(_DEPLOY_DOC.match(line) for line in text.splitlines()[:400]):
                return None

        haystacks = list(ci_files(ctx)) + [rel for rel, _doc in k8s_documents(ctx)]
        for rel in haystacks[:60]:
            text = ctx.read(rel)
            if _STRATEGY.search(text) or _VERSIONED.search(text):
                return None

        return (
            f"The project deploys ({target}) but no rollback runbook, versioned artifact "
            "scheme, or rolling/blue-green/canary strategy was found, so recovering from a "
            "bad release has to be improvised.",
            (
                f"deploy target: {target}; searched docs for rollback/runbook sections, "
                "CI and manifests for rollingUpdate/blue-green/canary and for "
                "sha- or semver-tagged artifacts"
            ),
        )
