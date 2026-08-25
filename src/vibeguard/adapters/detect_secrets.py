"""detect-secrets adapter (Yelp, Apache-2.0) — high-entropy and keyword secret scan."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DetectSecretsAdapter"]

#: Detector types whose hits are almost always real credentials.
_HIGH_SIGNAL = {
    "AWS Access Key",
    "Azure Storage Account access key",
    "GitHub Token",
    "GitLab Token",
    "Private Key",
    "Slack Token",
    "Stripe Access Key",
    "Twilio API Key",
    "SendGrid API Key",
    "JSON Web Token",
}


class DetectSecretsAdapter(ToolAdapter):
    """Runs ``detect-secrets scan`` and maps each hit onto a SECRETS finding."""

    name: ClassVar[str] = "detect-secrets"
    command: ClassVar[str] = "detect-secrets"
    description: ClassVar[str] = "Entropy and keyword based secret scanning"
    category: ClassVar[Category] = Category.SECRETS
    topics: ClassVar[set[str]] = {
        "secrets.api-keys-in-repo",
        "secrets.passwords-in-repo",
        "secrets.tokens-in-repo",
        "secrets.private-keys-in-repo",
        "secrets.database-credentials",
        "secrets.cloud-credentials",
        "security.hardcoded-credentials",
        "security.secret-leakage",
    }

    def run(self, ctx: ScanContext) -> list[Finding]:
        payload = self.exec_json(["detect-secrets", "scan", "--all-files"], ctx)
        if not isinstance(payload, dict):
            return []
        results = payload.get("results")
        if not isinstance(results, dict):
            return []
        findings: list[Finding] = []
        for path, hits in results.items():
            if not isinstance(hits, list):
                continue
            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                secret_type = str(hit.get("type") or "secret")
                high = secret_type in _HIGH_SIGNAL
                findings.append(
                    self.make_finding(
                        native_id=secret_type,
                        title=f"Potential secret in repository ({secret_type})",
                        description=(
                            f"detect-secrets matched a {secret_type!r} pattern in {path}. "
                            "The value itself is never printed by VibeGuard."
                        ),
                        why_it_matters=(
                            "A credential committed to version control is compromised the "
                            "moment the repository is shared, forked, or leaked; git history "
                            "keeps it reachable even after the line is deleted."
                        ),
                        severity=Severity.CRITICAL if high else Severity.HIGH,
                        confidence=Confidence.HIGH if high else Confidence.MEDIUM,
                        category=Category.SECRETS,
                        file=str(path),
                        line=hit.get("line_number") if isinstance(hit.get("line_number"), int)
                        else None,
                        snippet=str(hit.get("hashed_secret") or ""),
                        references=["https://github.com/Yelp/detect-secrets"],
                        recommended_followup=(
                            "Rotate the credential, remove it from git history, and load it "
                            "from the environment or a secret manager instead."
                        ),
                        autofix_safety=AutofixSafety.MANUAL_CHANGE_REQUIRED,
                        redact_evidence=True,
                    )
                )
        return findings
