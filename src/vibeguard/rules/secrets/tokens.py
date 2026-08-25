"""VG-SCR-003 / VG-SCR-004 — hardcoded API keys, tokens, and passwords."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules.secrets._common import SecretRegexRule

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ApiKeyRule", "PasswordRule"]

_KEY_NAMES = (
    r"api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|"
    r"refresh[_\-]?token|client[_\-]?secret|bearer[_\-]?token|private[_\-]?token"
)


class ApiKeyRule(SecretRegexRule):
    """Generic key/token assignments plus well-known provider token prefixes."""

    id: ClassVar[str] = "VG-SCR-003"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Hardcoded API key or access token"
    description: ClassVar[str] = (
        "An API key or access token is assigned a literal value in a tracked file "
        "instead of being read from the environment or a secret store."
    )
    why_it_matters: ClassVar[str] = (
        "Anyone who can read the repository — including every future collaborator, "
        "every CI log that echoes the file, and anyone who gets a copy of a laptop "
        "backup — can call the third-party service as you and run up your bill or read "
        "your customers' data. Provider tokens are rarely scoped, so a leaked key "
        "usually grants everything the account can do, and it stays valid until it is "
        "explicitly rotated."
    )
    references: ClassVar[list[str]] = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://docs.github.com/code-security/secret-scanning/about-secret-scanning",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.api-keys-in-repo",
        "secrets.tokens-in-repo",
        "security.hardcoded-credentials",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        # quoted assignment in source or config
        re.compile(rf"(?i)\b(?:{_KEY_NAMES})\b\s*[:=]+\s*['\"](?P<value>[^'\"\s]{{12,}})['\"]"),
        # provider prefixes, wherever they appear
        re.compile(r"(?P<value>sk-(?:live|test|proj|ant|or)?-?[A-Za-z0-9_\-]{20,})"),
        re.compile(r"(?P<value>gh[pous]_[A-Za-z0-9]{20,})"),
        re.compile(r"(?P<value>github_pat_[A-Za-z0-9_]{20,})"),
        re.compile(r"(?P<value>xox[baprs]-[A-Za-z0-9\-]{10,})"),
        re.compile(r"(?P<value>glpat-[A-Za-z0-9\-_]{16,})"),
        re.compile(r"(?P<value>SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})"),
        re.compile(r"(?P<value>npm_[A-Za-z0-9]{30,})"),
        re.compile(r"(?P<value>hf_[A-Za-z0-9]{20,})"),
        re.compile(
            r"(?i)\bauthorization\b\s*[:=]+\s*['\"]?bearer\s+(?P<value>[A-Za-z0-9\-._~+/=]{16,})"
        ),
    )
    bare_patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(rf"(?i)\b(?:{_KEY_NAMES})\b\s*[:=]\s*(?P<value>[^\s'\"#,;]{{12,}})\s*$"),
    )
    min_value_length: ClassVar[int] = 12
    #: Documentation, type hints, and header *names* are not credentials.
    line_negative: ClassVar[re.Pattern[str] | None] = re.compile(
        r"(?i)(?:^\s*(?:type|interface)\b|:\s*str\s*$|\bAnnotated\b|"
        r"\bdescription\s*=|\bhelp\s*=|\bexample[s]?\s*[:=])"
    )
    recommended_followup: ClassVar[str] = (
        "Rotate the token at the provider, then read it at start-up — "
        "`API_KEY = os.environ[\"API_KEY\"]` in Python or `process.env.API_KEY` in "
        "Node — and add the file that held it to `.gitignore` if it was a config file."
    )

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"A literal API key or token is assigned at {relpath}:{line_no}."


class PasswordRule(SecretRegexRule):
    """Password assignments with a literal value, in source and in config files."""

    id: ClassVar[str] = "VG-SCR-004"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Hardcoded password"
    description: ClassVar[str] = (
        "A password is assigned a literal value in source code or a configuration "
        "file rather than being injected from the environment at run time."
    )
    why_it_matters: ClassVar[str] = (
        "A password committed to the repository is a password shared with everyone who "
        "ever clones it, and it is almost never rotated afterwards — the same string "
        "usually ends up protecting the production database months later. Because it "
        "lives in git history, deleting the line does not remove the exposure; the "
        "credential itself has to be changed everywhere it is used."
    )
    references: ClassVar[list[str]] = [
        "https://cwe.mitre.org/data/definitions/259.html",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.passwords-in-repo",
        "security.hardcoded-credentials",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            r"(?i)\b[a-z0-9_\-]*(?:password|passwd|pwd)\b\s*[:=]+\s*"
            r"['\"](?P<value>[^'\"\s]{4,})['\"]"
        ),
    )
    bare_patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            r"(?i)^\s*[A-Za-z0-9_\-]*(?:password|passwd|pwd)\s*[:=]\s*"
            r"(?P<value>[^\s'\"#,;]{4,})\s*$"
        ),
    )
    min_value_length: ClassVar[int] = 4
    #: Reading a password from a request, prompt, or hashing it is not a hardcoded one.
    line_negative: ClassVar[re.Pattern[str] | None] = re.compile(
        r"(?i)(?:request\.|req\.|\.form\b|\.json\b|body\.|params\.|argv|input\s*\(|"
        r"getpass|prompt|\bhash|\bverify|check_password|\bbcrypt|\bcompare|"
        r"password\s*[:=]\s*(?:str|None|Optional|password)\b)"
    )
    recommended_followup: ClassVar[str] = (
        "Change the password on the account it protects, then read it from the "
        "environment (`os.environ[\"DB_PASSWORD\"]` / `process.env.DB_PASSWORD`) and "
        "supply it through your deployment platform's secret settings."
    )

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"A literal password is assigned at {relpath}:{line_no}."
