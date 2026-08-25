"""VG-SEC-006 — no CSRF protection for session-authenticated forms."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.security._taint import config_files

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["MissingCsrfProtectionRule"]

_SUFFIXES = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".html",
    ".jinja",
    ".j2",
    ".txt",
    ".json",
    ".cfg",
    ".toml",
)

_SESSION_AUTH = re.compile(
    r"flask[_-]login|login_user\s*\(|LoginManager\s*\(|from\s+flask\s+import[^\n]*\bsession\b|"
    r"\bsession\[[^\]]+\]\s*=|django\.contrib\.sessions|SessionMiddleware|"
    r"express-session|cookie-session|req\.session\s*\.|SESSION_COOKIE_|"
    r"set_cookie\(\s*['\"](session|sid|sessionid|auth)",
)
_STATE_CHANGING = re.compile(
    r"methods\s*=\s*\[[^\]]*['\"]POST|@app\.(post|put|patch|delete)\b|"
    r"@router\.(post|put|patch|delete)\b|\b(app|router)\.(post|put|patch|delete)\s*\(|"
    r"<form[^>]*method\s*=\s*['\"]?post",
    re.IGNORECASE,
)
_CSRF_PROTECTION = re.compile(
    r"CSRFProtect|flask[_-]wtf|csrf_token|CsrfViewMiddleware|django\.middleware\.csrf|"
    r"\bcsurf\b|csrf-csrf|doubleCsrf|csrfProtection|X-CSRF-Token|"
    r"SESSION_COOKIE_SAMESITE\s*=\s*['\"]Strict|SameSite\s*=\s*Strict|"
    r"sameSite\s*:\s*['\"]strict",
    re.IGNORECASE,
)

class MissingCsrfProtectionRule(ProjectRule):
    """Session cookies plus state-changing routes, but no CSRF defence anywhere."""

    id: ClassVar[str] = "VG-SEC-006"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No CSRF protection for session-authenticated requests"
    description: ClassVar[str] = (
        "The application authenticates with a session cookie and exposes state-changing "
        "routes or HTML forms, but no CSRF token, CSRF middleware, or SameSite=Strict "
        "session cookie was found."
    )
    why_it_matters: ClassVar[str] = (
        "Browsers attach session cookies to any request to your domain, including ones "
        "triggered by a page the attacker controls. Without a CSRF defence, a logged-in "
        "user who merely visits a malicious page can have their email changed, funds "
        "transferred, or account deleted — no phishing form or stolen password needed."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://flask-wtf.readthedocs.io/en/stable/csrf.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.csrf", "security.session-management"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    recommended_followup: ClassVar[str] = (
        "Enable the framework's CSRF middleware (Flask-WTF `CSRFProtect(app)`, Django's "
        "`CsrfViewMiddleware` plus `{% csrf_token %}`, or `csrf-csrf` double-submit in "
        "Express) and set the session cookie to `SameSite=Lax` or `Strict` as defence in "
        "depth."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        session = False
        state_changing = False
        protected = False
        evidence = ""
        names = ("requirements.txt", "package.json")
        for rel in config_files(ctx, suffixes=_SUFFIXES, names=names):
            text = ctx.read(rel)
            if not text:
                continue
            if _CSRF_PROTECTION.search(text):
                protected = True
                break
            match = _SESSION_AUTH.search(text)
            if match:
                session = True
                if not evidence:
                    evidence = f"{rel}: {match.group(0)[:60]}"
            if _STATE_CHANGING.search(text):
                state_changing = True
        # A bearer/JWT-only API never presents a session cookie, so ``session`` stays
        # False for it and the rule does not fire.
        if protected or not session or not state_changing:
            return None
        return (
            "Session-cookie authentication and state-changing routes were found, but no "
            "CSRF token, CSRF middleware, or SameSite=Strict session cookie is configured "
            "anywhere in the repository.",
            f"session auth signal: {evidence or 'session cookie usage'}; "
            "searched for CSRFProtect/flask-wtf, django csrf middleware, csurf/csrf-csrf, "
            "and SameSite=Strict",
        )
