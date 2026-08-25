"""VG-SCR-009 — no secret-management mechanism in use."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule, source_files
from vibeguard.rules.secrets._common import (
    CODE_SUFFIXES,
    CONFIG_SUFFIXES,
    is_env_template,
    scan_text,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoSecretManagementRule"]

#: Evidence that secrets are handled by something purpose-built.
_MANAGED_STORE_TOKENS = (
    "hashicorp",
    "hvac",
    "vaultclient",
    "vault_addr",
    "vault.read",
    "secretsmanager",
    "secrets_manager",
    "secret-manager",
    "secretmanager",
    "get_secret_value",
    "ssm.get_parameter",
    "parameter_store",
    "parameterstore",
    "client-secrets-manager",
    "google-cloud-secret-manager",
    "keyvault",
    "key-vault",
    "azure-identity",
    "doppler",
    "1password",
    "op://",
    "onepassword",
    "sops",
    "sealedsecret",
    "sealed-secret",
    "external-secrets",
    "externalsecret",
    "secretkeyref",
    "infisical",
    "berglas",
    "chamber",
    "credstash",
)

_ENV_LOOKUP = re.compile(
    r"os\.environ|os\.getenv|\bgetenv\s*\(|process\.env|Deno\.env|import\.meta\.env"
)
_ENV_SCAN_LIMIT = 200
#: Below this many environment lookups the project has no configuration surface
#: worth managing, so the advisory would be noise.
_MIN_ENV_LOOKUPS = 3


class NoSecretManagementRule(ProjectRule):
    """The project reads secrets from the environment but has nothing managing them."""

    id: ClassVar[str] = "VG-SCR-009"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No secret-management mechanism in use"
    description: ClassVar[str] = (
        "The project depends on secrets but shows no managed secret store and no "
        "documented `.env` workflow."
    )
    why_it_matters: ClassVar[str] = (
        "Without somewhere secrets officially live, they end up copied into chat "
        "messages, screenshots, and half a dozen `.env` files that drift apart, and "
        "nobody can answer \"who has this key and when was it last rotated?\". The "
        "first incident then costs days, because every credential has to be rotated "
        "by hand across environments nobody has an inventory of."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/config",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.secret-store-migration",
        "secrets.environment-secrets",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Pick one home for secrets and write it down: for a small project, commit a "
        "`.env.example` listing every required key, add `.env` to `.gitignore`, and "
        "set the real values in your host's environment settings. Once more than one "
        "person or environment is involved, move to a managed store (AWS Secrets "
        "Manager, GCP Secret Manager, Azure Key Vault, Vault, or Doppler)."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            return self._check(ctx)
        except Exception:  # pragma: no cover - defensive
            return None

    def _check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if self._has_managed_store(ctx):
            return None
        if self._has_documented_dotenv_workflow(ctx):
            return None

        env_lookups, dotenv_files = self._config_surface(ctx)
        if env_lookups < _MIN_ENV_LOOKUPS and not dotenv_files:
            return None

        bits: list[str] = []
        if env_lookups:
            bits.append(f"{env_lookups} environment lookup(s) in source")
        if dotenv_files:
            bits.append(f"{len(dotenv_files)} .env file(s)")
        note = (
            "secret sources: "
            + ", ".join(bits)
            + "; no vault/secretsmanager/secretmanager/keyvault/doppler/sops/"
            "sealed-secret signal and no .env.example + .gitignore pair"
        )
        return (
            "The project loads secrets from the environment but nothing manages them: "
            "no managed secret store was detected and there is no documented `.env` "
            "workflow (a committed `.env.example` plus a `.gitignore` entry).",
            note,
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _has_managed_store(ctx: ScanContext) -> bool:
        if {"vault", "aws-secrets-manager", "sops"} & {
            item.lower() for item in ctx.tech.secret_mechanisms
        }:
            return True
        rels = source_files(ctx, CODE_SUFFIXES + CONFIG_SUFFIXES, skip_tests=False)
        rels += [rel for rel in ctx.tech.manifest_files if rel not in set(rels)]
        haystack = scan_text(ctx, rels, limit=_ENV_SCAN_LIMIT)
        return any(token in haystack for token in _MANAGED_STORE_TOKENS)

    @staticmethod
    def _has_documented_dotenv_workflow(ctx: ScanContext) -> bool:
        has_template = any(is_env_template(rel) for rel in ctx.files)
        if not has_template:
            return False
        gitignore = ctx.read(".gitignore")
        return any(
            line.strip().lstrip("/").startswith(".env")
            for line in gitignore.splitlines()
            if line.strip() and not line.strip().startswith("#")
        )

    @staticmethod
    def _config_surface(ctx: ScanContext) -> tuple[int, list[str]]:
        lookups = 0
        for rel in source_files(ctx, CODE_SUFFIXES)[:_ENV_SCAN_LIMIT]:
            lookups += len(_ENV_LOOKUP.findall(ctx.read(rel)))
        dotenv = [
            rel
            for rel in ctx.files
            if PurePosixPath(rel).name.lower().startswith(".env") and not is_env_template(rel)
        ]
        return lookups, dotenv
