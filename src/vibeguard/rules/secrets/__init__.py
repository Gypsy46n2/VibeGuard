"""VibeGuard secrets rule pack — credentials that must never live in a repository.

Every rule here reports *where* a credential is, never *what* it is: the SECRETS
category makes :meth:`Rule.make_finding` redact every evidence snippet, and the
rules keep snippets short on top of that.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.secrets.cloud import AwsCredentialsRule, GcpAzureCredentialsRule
from vibeguard.rules.secrets.connections import DatabaseUrlCredentialsRule, SigningSecretRule
from vibeguard.rules.secrets.files import EnvFileCommittedRule, PrivateKeyCommittedRule
from vibeguard.rules.secrets.management import NoSecretManagementRule
from vibeguard.rules.secrets.tokens import ApiKeyRule, PasswordRule

RULES: list[type[Rule]] = [
    AwsCredentialsRule,  # VG-SCR-001
    GcpAzureCredentialsRule,  # VG-SCR-002
    ApiKeyRule,  # VG-SCR-003
    PasswordRule,  # VG-SCR-004
    PrivateKeyCommittedRule,  # VG-SCR-005
    EnvFileCommittedRule,  # VG-SCR-006
    DatabaseUrlCredentialsRule,  # VG-SCR-007
    SigningSecretRule,  # VG-SCR-008
    NoSecretManagementRule,  # VG-SCR-009
]

__all__ = [
    "ApiKeyRule",
    "AwsCredentialsRule",
    "DatabaseUrlCredentialsRule",
    "EnvFileCommittedRule",
    "GcpAzureCredentialsRule",
    "NoSecretManagementRule",
    "PasswordRule",
    "PrivateKeyCommittedRule",
    "RULES",
    "SigningSecretRule",
]
