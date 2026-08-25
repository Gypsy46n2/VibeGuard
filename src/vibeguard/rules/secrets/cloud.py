"""VG-SCR-001 / VG-SCR-002 — hardcoded cloud provider credentials."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules.secrets._common import SecretRegexRule

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["AwsCredentialsRule", "GcpAzureCredentialsRule"]


class AwsCredentialsRule(SecretRegexRule):
    """Long-lived AWS access keys pasted into source or config."""

    id: ClassVar[str] = "VG-SCR-001"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Hardcoded AWS credentials"
    description: ClassVar[str] = (
        "An AWS access key id or secret access key is written directly into a tracked "
        "file instead of being supplied by the environment or an IAM role."
    )
    why_it_matters: ClassVar[str] = (
        "A long-lived AWS key in a repository is a standing invitation: bots scrape "
        "public and leaked repositories continuously and use found keys within minutes "
        "to spin up compute for crypto mining or to read every S3 bucket the key can "
        "reach. Because the key stays valid until someone revokes it, the exposure "
        "outlives the commit that introduced it, and rewriting history does not help."
    )
    references: ClassVar[list[str]] = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "https://cwe.mitre.org/data/definitions/798.html",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.cloud-credentials",
        "secrets.api-keys-in-repo",
        "security.hardcoded-credentials",
        "security.secret-leakage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"(?P<value>(?:AKIA|ASIA)[0-9A-Z]{16})"),
        re.compile(
            r"(?i)\baws[_\-]?secret[_\-]?access[_\-]?key\b\s*[:=]+\s*"
            r"['\"]?(?P<value>[A-Za-z0-9/+=_\-]{20,})['\"]?"
        ),
        re.compile(
            r"(?i)\baws[_\-]?session[_\-]?token\b\s*[:=]+\s*"
            r"['\"]?(?P<value>[A-Za-z0-9/+=_\-]{40,})['\"]?"
        ),
    )
    min_value_length: ClassVar[int] = 16
    recommended_followup: ClassVar[str] = (
        "Revoke the key in the AWS IAM console first (rotation, not deletion from the "
        "file, is what stops the exposure), then read credentials from the default "
        "provider chain: an instance/task IAM role in production, or `AWS_PROFILE` "
        "locally. Never pass keys to `boto3.client(...)` as literals."
    )

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"AWS credential material is hardcoded at {relpath}:{line_no}."


class GcpAzureCredentialsRule(SecretRegexRule):
    """Google and Azure credential material pasted into source or config."""

    id: ClassVar[str] = "VG-SCR-002"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Hardcoded GCP or Azure cloud credentials"
    description: ClassVar[str] = (
        "A Google API key, OAuth token, inline service-account JSON, or Azure storage "
        "account key / client secret is embedded in a tracked file."
    )
    why_it_matters: ClassVar[str] = (
        "A service-account key or storage account key is the whole identity: whoever "
        "holds it can read and delete the data that identity can reach, and the bill "
        "for anything it spins up lands on your account. Google and Azure keys are "
        "rarely scoped tightly in vibe-coded projects, so one leaked file usually "
        "means full project access rather than one narrow permission."
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/docs/authentication/application-default-credentials",
        "https://learn.microsoft.com/azure/key-vault/general/overview",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.cloud-credentials",
        "security.hardcoded-credentials",
        "security.secret-leakage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"(?P<value>AIza[0-9A-Za-z\-_]{35})"),
        re.compile(r"(?P<value>ya29\.[0-9A-Za-z\-_]{20,})"),
        re.compile(r"(?i)\"type\"\s*:\s*\"(?P<value>service_account)\""),
        re.compile(r"(?i)\bAccountKey\s*=\s*(?P<value>[A-Za-z0-9+/=]{24,})"),
        re.compile(
            r"(?i)\bazure[_\-]?client[_\-]?secret\b\s*[:=]+\s*"
            r"['\"]?(?P<value>[^'\"\s,;]{12,})['\"]?"
        ),
    )
    min_value_length: ClassVar[int] = 12
    recommended_followup: ClassVar[str] = (
        "Delete the key in the provider console (GCP: IAM & Admin > Service Accounts > "
        "Keys; Azure: rotate the storage key or client secret), then authenticate with "
        "Workload Identity / Application Default Credentials on GCP or a Managed "
        "Identity plus Key Vault on Azure so no key material lives in the repository."
    )

    def accepts(self, ctx: ScanContext, relpath: str, line: str, match: re.Match[str]) -> bool:
        value = (match.groupdict().get("value") or "").strip()
        if value == "service_account":
            # Only a real key file: the JSON must also carry the private key itself.
            return "private_key" in ctx.read(relpath)
        return super().accepts(ctx, relpath, line, match)

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"Cloud credential material is hardcoded at {relpath}:{line_no}."
