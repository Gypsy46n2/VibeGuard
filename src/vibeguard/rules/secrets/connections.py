"""VG-SCR-007 / VG-SCR-008 — credentials in connection strings and signing keys."""

from __future__ import annotations

import logging
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    js_calls,
    py_calls,
    source_files,
    strip_quotes,
)
from vibeguard.rules.secrets._common import (
    SecretRegexRule,
    is_placeholder,
    is_string_literal,
    looks_like_env_lookup,
    split_call_args,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DatabaseUrlCredentialsRule", "SigningSecretRule"]

log = logging.getLogger(__name__)


_DB_SCHEMES = (
    r"postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|"
    r"mssql|clickhouse|cockroachdb|couchdb|elasticsearch"
)


class DatabaseUrlCredentialsRule(SecretRegexRule):
    """A database/broker URL that carries a real username and password."""

    id: ClassVar[str] = "VG-SCR-007"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Database connection string with an embedded password"
    description: ClassVar[str] = (
        "A connection URL in a tracked file contains an inline `user:password@` pair "
        "rather than assembling credentials from the environment."
    )
    why_it_matters: ClassVar[str] = (
        "A connection string is a complete set of directions to your data plus the key "
        "to the door. Anyone who reads the file — or a log line, error page, or CI "
        "transcript that echoes it — can connect directly to the database and read, "
        "modify, or drop everything in it, bypassing every check your application "
        "performs. Connection URLs also leak easily because they get printed in "
        "stack traces."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/backing-services",
        "https://cwe.mitre.org/data/definitions/798.html",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.database-credentials",
        "security.hardcoded-credentials",
        "security.secret-leakage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            rf"(?i)\b(?:{_DB_SCHEMES})://[^\s:/@'\"]+:(?P<value>[^\s/@'\"]{{4,}})@",
        ),
    )
    min_value_length: ClassVar[int] = 4
    recommended_followup: ClassVar[str] = (
        "Rotate the database password, then build the URL at run time from a single "
        "environment variable — `DATABASE_URL = os.environ[\"DATABASE_URL\"]` — and "
        "store that variable in your deployment platform's secret settings, not in the "
        "repository."
    )

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"A connection URL carries an inline password at {relpath}:{line_no}."


_SIGNING_NAMES = (
    r"secret[_\-]?key|jwt[_\-]?secret(?:[_\-]?key)?|session[_\-]?secret|"
    r"token[_\-]?secret|signing[_\-]?(?:key|secret)|app[_\-]?secret|cookie[_\-]?secret"
)

_JWT_PY_CALLS = ("jwt.encode", "jwt.decode", "jose.jwt.encode")
_JWT_JS_HINTS = ("jwt.sign", "jsonwebtoken.sign", "jwt.verify")


class SigningSecretRule(SecretRegexRule):
    """Application / JWT signing secrets written as literals.

    Regex covers ``SECRET_KEY = "..."`` style settings; tree-sitter covers the
    ``jwt.encode(payload, "literal")`` and ``jwt.sign(payload, 'literal')`` forms
    where the key is a positional string argument.
    """

    id: ClassVar[str] = "VG-SCR-008"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Hardcoded application or JWT signing secret"
    description: ClassVar[str] = (
        "The key used to sign sessions or JSON Web Tokens is a literal in the source "
        "tree instead of a value loaded from the environment."
    )
    why_it_matters: ClassVar[str] = (
        "The signing key is the only thing that proves a session cookie or JWT was "
        "issued by your application. Once it is readable in the repository, anyone can "
        "mint a token that claims to be any user — including an administrator — and "
        "your server will accept it as genuine. No password check, rate limit, or "
        "audit log stands in the way, and rotating the key logs every real user out."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        "https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY",
    ]
    topics: ClassVar[set[str]] = {
        "security.jwt-handling",
        "secrets.tokens-in-repo",
        "security.hardcoded-credentials",
        "security.session-management",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(rf"(?i)\b(?:{_SIGNING_NAMES})\b\s*[:=]+\s*['\"](?P<value>[^'\"\s]{{4,}})['\"]"),
    )
    bare_patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            rf"(?i)^\s*[A-Za-z0-9_\-]*(?:{_SIGNING_NAMES})\s*[:=]\s*"
            rf"(?P<value>[^\s'\"#,;]{{4,}})\s*$"
        ),
    )
    min_value_length: ClassVar[int] = 4
    recommended_followup: ClassVar[str] = (
        "Generate a fresh random key (`python -c \"import secrets; "
        "print(secrets.token_urlsafe(48))\"`), set it as `SECRET_KEY` in the "
        "environment, and load it with `os.environ[\"SECRET_KEY\"]` so start-up fails "
        "loudly when it is missing."
    )

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"A signing secret is hardcoded at {relpath}:{line_no}."

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings = super().detect(ctx)
        seen = {(f.file, f.line) for f in findings}
        for finding in self._call_findings(ctx, limit=self.max_total - len(findings)):
            key = (finding.file, finding.line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
        return findings

    def _call_findings(self, ctx: ScanContext, limit: int) -> list[Finding]:
        """AST pass: ``jwt.encode(payload, "literal")`` / ``jwt.sign(payload, 'lit')``."""
        out: list[Finding] = []
        if limit <= 0:
            return out
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(out) >= limit:
                break
            suffix = PurePosixPath(rel).suffix.lower()
            is_python = suffix in PY_SUFFIXES
            try:
                sites = py_calls(ctx, rel) if is_python else js_calls(ctx, rel)
            except Exception:  # pragma: no cover - defensive
                # Broad by design: the rule/repository boundary. A scan must never
                # die on one unreadable input — but it must not go quiet either.
                log.debug("call extraction failed for %s", rel, exc_info=True)
                continue
            for site in sites:
                if len(out) >= limit:
                    break
                name = site.name.replace(" ", "")
                hints = _JWT_PY_CALLS if is_python else _JWT_JS_HINTS
                if not any(name.endswith(hint) or name == hint for hint in hints):
                    continue
                args = split_call_args(site.args)
                if len(args) < 2 or not is_string_literal(args[1]):
                    continue
                if looks_like_env_lookup(site.args):
                    continue
                value = strip_quotes(args[1])
                if is_placeholder(value):
                    continue
                out.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=f"{name}(..., <literal signing key>)",
                        description=(
                            f"The signing key passed to `{name}` at {rel}:{site.line} is a "
                            "string literal."
                        ),
                        recommended_followup=self.recommended_followup,
                        redact_evidence=True,
                    )
                )
        return out
