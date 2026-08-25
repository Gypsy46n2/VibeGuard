"""VG-SEC-014 / VG-SEC-015 — security headers and CORS configuration."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.security._taint import config_files

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["MissingSecurityHeadersRule", "PermissiveCorsRule"]

_TEXT_SUFFIXES = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml",
    ".conf", ".toml", ".ini", ".cfg", ".txt", ".html", ".tf", ".env",
)
_TEXT_NAMES = ("dockerfile", "nginx.conf", "caddyfile", "httpd.conf", "procfile", ".htaccess")

_SERVER_SIGNAL = re.compile(
    r"Flask\s*\(|FastAPI\s*\(|django|express\s*\(|createServer\s*\(|"
    r"app\.listen\s*\(|uvicorn|gunicorn|Koa\s*\(|NestFactory",
    re.IGNORECASE,
)
_HEADER_SIGNAL = re.compile(
    r"\bhelmet\b|flask[_-]talisman|Talisman\s*\(|SecurityMiddleware|SECURE_HSTS|"
    r"SECURE_SSL_REDIRECT|SECURE_CONTENT_TYPE_NOSNIFF|Content-Security-Policy|"
    r"X-Content-Type-Options|Strict-Transport-Security|X-Frame-Options|"
    r"add_header\s+X-|Permissions-Policy|Referrer-Policy",
    re.IGNORECASE,
)


class MissingSecurityHeadersRule(ProjectRule):
    """A web server with no security-header or CSP configuration anywhere."""

    id: ClassVar[str] = "VG-SEC-014"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No security headers or Content Security Policy"
    description: ClassVar[str] = (
        "The project serves HTTP but sets no security headers: no helmet, no "
        "flask-talisman, no Django SecurityMiddleware/SECURE_* settings, and no explicit "
        "Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, or "
        "X-Frame-Options anywhere — including reverse-proxy config in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "These headers are the browser-side half of your defences: CSP contains the "
        "damage of an XSS bug, HSTS stops a downgrade to plain HTTP on hostile Wi-Fi, and "
        "X-Frame-Options stops your app being framed and clickjacked. They cost one "
        "configuration line each and are the first thing an external security review "
        "checks."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "security.security-headers",
        "security.csp",
        "security.waf-readiness",
        "security.ddos-readiness",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED
    recommended_followup: ClassVar[str] = (
        "Add the framework's header middleware — `app.use(helmet())` for Express, "
        "`Talisman(app)` for Flask, `SecurityMiddleware` plus `SECURE_HSTS_SECONDS` and "
        "`SECURE_CONTENT_TYPE_NOSNIFF` for Django — then tighten the generated "
        "Content-Security-Policy to your own asset origins."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        server = False
        for rel in config_files(ctx, suffixes=_TEXT_SUFFIXES, names=_TEXT_NAMES):
            text = ctx.read(rel)
            if not text:
                continue
            if _HEADER_SIGNAL.search(text):
                return None
            if not server and _SERVER_SIGNAL.search(text):
                server = True
        if not server:
            return None
        return (
            "An HTTP server was detected but no security-header middleware or explicit "
            "header configuration was found in application code, framework settings, or "
            "reverse-proxy configuration.",
            "searched for helmet, flask-talisman, Django SecurityMiddleware/SECURE_*, and "
            "literal Content-Security-Policy / X-Content-Type-Options / "
            "Strict-Transport-Security / X-Frame-Options headers",
        )


_CORS_PATTERNS = (
    re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*"),
    re.compile(r"CORS\s*\(\s*[^)]*origins\s*=\s*['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"CORS\s*\(\s*app\s*\)", re.IGNORECASE),
    re.compile(r"['\"]origins['\"]\s*:\s*\[?\s*['\"]\*['\"]"),
    re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]"),
    re.compile(r"\borigin\s*:\s*(true|['\"]\*['\"])"),
    re.compile(r"\bcors\s*\(\s*\)"),
    re.compile(
        r"Access-Control-Allow-Origin[^\n]*(req\.headers\.origin|"
        r"request\.headers\.get\(\s*['\"]Origin)",
        re.IGNORECASE,
    ),
)
_CREDENTIALS = re.compile(
    r"credentials\s*[:=]\s*(true|True)|supports_credentials\s*=\s*True|"
    r"allow_credentials\s*=\s*True|Access-Control-Allow-Credentials",
)
_MAX = 6


class PermissiveCorsRule(Rule):
    """Wildcard or reflected CORS origins, especially alongside credentials."""

    id: ClassVar[str] = "VG-SEC-015"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Permissive CORS configuration"
    description: ClassVar[str] = (
        "Cross-origin access is granted to any origin — a `*` wildcard, `origin: true`, "
        "or the request's own Origin header reflected back."
    )
    why_it_matters: ClassVar[str] = (
        "CORS is what stops a random website from reading your API's responses in a "
        "logged-in user's browser. Open it to every origin — especially with credentials "
        "allowed — and any page the user visits can call your API as them and read the "
        "result, turning a single visit into full account data disclosure."
    )
    references: ClassVar[list[str]] = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.cors"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in config_files(ctx, suffixes=_TEXT_SUFFIXES, names=_TEXT_NAMES):
            if len(findings) >= _MAX:
                break
            text = ctx.read(rel)
            if not text:
                continue
            lines = text.splitlines()
            for index, line in enumerate(lines):
                if len(findings) >= _MAX or len(line) > 800:
                    continue
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*")):
                    continue
                if not any(pattern.search(line) for pattern in _CORS_PATTERNS):
                    continue
                window = "\n".join(lines[max(0, index - 4) : index + 5])
                credentials = bool(_CREDENTIALS.search(window))
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=index + 1,
                        severity=Severity.HIGH if credentials else Severity.MEDIUM,
                        snippet=stripped[:200],
                        description=(
                            f"{rel}:{index + 1} allows any origin to call this API"
                            + (
                                " while also allowing credentials, which browsers only "
                                "honour for a named origin and which exposes "
                                "session-authenticated data."
                                if credentials
                                else "."
                            )
                        ),
                        recommended_followup=(
                            "Replace the wildcard with an explicit list of trusted origins "
                            "(`CORS(app, origins=['https://app.example.com'])`, "
                            "`cors({ origin: ['https://app.example.com'], credentials: true })`) "
                            "and drive that list from configuration per environment."
                        ),
                    )
                )
        return findings
