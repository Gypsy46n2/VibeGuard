"""VG-SEC-017 — unsafe JWT handling."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import Category, Confidence, Finding, ScaleClass, Severity
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    js_calls,
    py_calls,
    source_files,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["UnsafeJwtHandlingRule"]

_MAX = 6

_VERIFY_OFF = re.compile(
    r"verify\s*=\s*False|['\"]verify_signature['\"]\s*:\s*(False|false)|"
    r"['\"]verify['\"]\s*:\s*(False|false)|verify_signature\s*=\s*False",
)
_ALG_NONE = re.compile(r"['\"]none['\"]", re.IGNORECASE)
_HAS_ALGORITHMS = re.compile(r"\balgorithms\s*[:=]")
_HAS_EXPIRY = re.compile(r"\bexpiresIn\b|['\"]exp['\"]\s*:|\bexp\s*=|\.exp\b|timedelta")


class UnsafeJwtHandlingRule(Rule):
    """JWTs decoded without signature/algorithm checks, or issued without expiry."""

    id: ClassVar[str] = "VG-SEC-017"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Unsafe JWT handling"
    description: ClassVar[str] = (
        "A JSON Web Token is decoded with verification disabled, without pinning the "
        "permitted algorithms, or is issued with no expiry claim."
    )
    why_it_matters: ClassVar[str] = (
        "A JWT is only an identity claim if its signature is checked against an algorithm "
        "you chose: skip verification, accept `alg: none`, or leave the algorithm open and "
        "anyone can mint a token that says they are an administrator. Tokens without an "
        "expiry never stop working, so a single leaked token is a permanent back door that "
        "logging out does not close."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        "https://pyjwt.readthedocs.io/en/stable/api.html#jwt.decode",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "security.jwt-handling",
        "security.jwt-expiration",
        "security.jwt-rotation",
        "security.api-authentication",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for suffixes, extractor in ((PY_SUFFIXES, py_calls), (JS_SUFFIXES, js_calls)):
            for rel in source_files(ctx, suffixes):
                if len(findings) >= _MAX:
                    break
                for call in extractor(ctx, rel):
                    if len(findings) >= _MAX:
                        break
                    problem = self._problem(call)
                    if problem is None:
                        continue
                    findings.append(
                        self.make_finding(
                            file=rel,
                            line=call.line,
                            snippet=f"{call.name}{call.args}"[:200],
                            description=f"{rel}:{call.line}: {problem}",
                            recommended_followup=(
                                "Always verify: "
                                "`jwt.decode(token, key, algorithms=['RS256'])` / "
                                "`jwt.verify(token, key, { algorithms: ['RS256'] })`, and "
                                "issue short-lived tokens (`exp` / `expiresIn: '15m'`) with "
                                "a refresh flow for longer sessions."
                            ),
                            redact_evidence=True,
                        )
                    )
        return findings

    def _problem(self, call: CallSite) -> str | None:
        name = call.name
        if "jwt" not in name.lower():
            return None
        args = call.args
        base = call.base
        if base in {"decode", "verify"}:
            if _VERIFY_OFF.search(args):
                return f"`{name}` decodes the token with signature verification disabled"
            if _ALG_NONE.search(args):
                return f"`{name}` accepts the `none` algorithm"
            if not _HAS_ALGORITHMS.search(args):
                return f"`{name}` does not pin an `algorithms` list"
            return None
        if base in {"encode", "sign"} and args and not _HAS_EXPIRY.search(args):
            return f"`{name}` issues a token with no expiry claim"
        return None
