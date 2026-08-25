"""VG-SEC-016 — session cookies without Secure, HttpOnly, or SameSite."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    Patch,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._fixes import (
    append_arguments,
    append_object_properties,
    is_python,
    line_at,
    locate_call,
    replace_line,
    replace_node,
    whole_file_patch,
)
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    js_calls,
    node_text,
    py_calls,
    source_files,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["InsecureSessionCookieRule"]

_MAX = 6

_FLAG_PATTERNS = {
    "Secure": re.compile(r"\bsecure\s*[:=]\s*(True|true)", re.IGNORECASE),
    "HttpOnly": re.compile(r"\bhttp_?only\s*[:=]\s*(True|true)", re.IGNORECASE),
    "SameSite": re.compile(r"\bsame_?site\s*[:=]\s*['\"](Lax|Strict)['\"]", re.IGNORECASE),
}
_EXPLICIT_OFF = re.compile(
    r"\b(secure|http_?only)\s*[:=]\s*(False|false)|\bsame_?site\s*[:=]\s*['\"]?(none|None)",
    re.IGNORECASE,
)
_SETTINGS_OFF = re.compile(
    r"^\s*(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE)\s*=\s*False\s*$"
    r"|^\s*SESSION_COOKIE_SAMESITE\s*=\s*['\"]?(None|none)",
    re.MULTILINE,
)

#: What the repair adds, per language, for each missing protection.
_PY_FLAG_ARGS: dict[str, str] = {
    "Secure": "secure=True",
    "HttpOnly": "httponly=True",
    "SameSite": 'samesite="Lax"',
}
_JS_FLAG_PROPS: dict[str, str] = {
    "Secure": "secure: true",
    "HttpOnly": "httpOnly: true",
    "SameSite": "sameSite: 'lax'",
}


def _missing(text: str, flag: str) -> bool:
    """True when ``flag`` is not already set to a protective value in ``text``."""
    return not _FLAG_PATTERNS[flag].search(text)


class InsecureSessionCookieRule(Rule):
    """A cookie set without the Secure, HttpOnly, and SameSite protections."""

    id: ClassVar[str] = "VG-SEC-016"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Session cookie without Secure, HttpOnly, or SameSite"
    description: ClassVar[str] = (
        "A cookie is set without one or more of the Secure, HttpOnly, and SameSite "
        "attributes, or with them explicitly disabled."
    )
    why_it_matters: ClassVar[str] = (
        "Without HttpOnly, any cross-site scripting bug can read the session cookie and "
        "hand the attacker a logged-in session. Without Secure, the cookie travels in "
        "clear text over any accidental plain-HTTP request. Without SameSite, the browser "
        "attaches it to cross-site requests, which is what makes CSRF work at all."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.cookie-security", "security.session-management"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for suffixes, extractor in ((PY_SUFFIXES, py_calls), (JS_SUFFIXES, js_calls)):
            for rel in source_files(ctx, suffixes):
                if len(findings) >= _MAX:
                    break
                for call in extractor(ctx, rel):
                    if len(findings) >= _MAX:
                        break
                    finding = self._check_call(rel, call)
                    if finding is not None:
                        findings.append(finding)
        findings.extend(self._settings(ctx, _MAX - len(findings)))
        return findings[:_MAX]

    def _check_call(self, rel: str, call: CallSite) -> Finding | None:
        base = call.base
        args = call.args
        if base == "set_cookie" or (base == "cookie" and call.name.startswith(("res.", "reply."))):
            pass
        elif base in {"session", "cookieSession"} and "cookie" in args:
            pass
        else:
            return None
        missing = [name for name, pattern in _FLAG_PATTERNS.items() if not pattern.search(args)]
        disabled = bool(_EXPLICIT_OFF.search(args))
        if not missing and not disabled:
            return None
        detail = (
            "explicitly disables a cookie protection"
            if disabled
            else "does not set " + ", ".join(missing)
        )
        return self.make_finding(
            file=rel,
            line=call.line,
            snippet=f"{call.name}{args}"[:200],
            description=(
                f"`{call.name}(...)` at {rel}:{call.line} {detail}. Session cookies need "
                "Secure, HttpOnly, and SameSite."
            ),
            recommended_followup=(
                "Set every flag on the cookie: "
                "`response.set_cookie('session', value, secure=True, httponly=True, "
                "samesite='Lax')` or `res.cookie('sid', value, { secure: true, "
                "httpOnly: true, sameSite: 'lax' })`."
            ),
        )

    def _settings(self, ctx: ScanContext, budget: int) -> list[Finding]:
        out: list[Finding] = []
        if budget <= 0:
            return out
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(out) >= budget:
                break
            text = ctx.read(rel)
            if "SESSION_COOKIE" not in text and "CSRF_COOKIE" not in text:
                continue
            for index, line in enumerate(text.splitlines()):
                if len(out) >= budget:
                    break
                if line.strip().startswith("#") or not _SETTINGS_OFF.search(line):
                    continue
                out.append(
                    self.make_finding(
                        file=rel,
                        line=index + 1,
                        snippet=line.strip()[:200],
                        description=(
                            f"{rel}:{index + 1} turns off a session-cookie protection in "
                            "framework settings."
                        ),
                        recommended_followup=(
                            "Set `SESSION_COOKIE_SECURE = True`, "
                            "`SESSION_COOKIE_HTTPONLY = True`, and "
                            "`SESSION_COOKIE_SAMESITE = 'Lax'` for every non-local "
                            "environment."
                        ),
                    )
                )
        return out

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Add the missing cookie protections, and only those.

        Three shapes are repaired: a framework settings line that switches a
        protection off, a Python ``set_cookie(...)`` call, and an Express
        ``res.cookie(name, value, { … })`` call that already passes an options object.
        A call that *explicitly* disables a flag is left alone — that is a decision
        someone made, and the finding asks them to revisit it rather than having it
        silently reversed.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no:
            return None
        text = ctx.read(rel)
        line = line_at(text, line_no)
        if line is None:
            return None

        if _SETTINGS_OFF.search(line):
            repaired = self._repair_settings(line)
            if repaired == line:
                return None
            return whole_file_patch(
                finding,
                rel,
                text,
                replace_line(text, line_no, repaired),
                description=f"Turn the session-cookie protection back on at {rel}:{line_no}.",
                scope="security",
                summary="restore session cookie protections",
            )

        new_text = (
            self._repair_python_call(ctx, rel, line_no, text)
            if is_python(rel)
            else self._repair_js_call(ctx, rel, line_no, text)
        )
        if new_text is None:
            return None
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=(
                f"Set Secure, HttpOnly, and SameSite on the cookie written at "
                f"{rel}:{line_no}."
            ),
            scope="security",
            summary="set Secure, HttpOnly, and SameSite on the session cookie",
        )

    @staticmethod
    def _repair_settings(line: str) -> str:
        repaired = re.sub(r"(_SECURE|_HTTPONLY)(\s*=\s*)False\b", r"\1\2True", line)
        return re.sub(
            r"(SESSION_COOKIE_SAMESITE\s*=\s*)['\"]?(None|none)['\"]?", r"\1'Lax'", repaired
        )

    def _repair_python_call(
        self, ctx: ScanContext, rel: str, line_no: int, text: str
    ) -> str | None:
        call = locate_call(
            [c for c in py_calls(ctx, rel) if c.base == "set_cookie"], line_no
        )
        if call is None:
            return None
        if _EXPLICIT_OFF.search(call.args) or "**" in call.args:
            return None
        additions = [_PY_FLAG_ARGS[name] for name in _PY_FLAG_ARGS if _missing(call.args, name)]
        args_node = call.node.child_by_field_name("arguments")
        if not additions or args_node is None:
            return None
        rewritten = append_arguments(node_text(text.encode("utf-8"), args_node), additions)
        if rewritten is None:
            return None
        return replace_node(text, args_node, rewritten)

    def _repair_js_call(
        self, ctx: ScanContext, rel: str, line_no: int, text: str
    ) -> str | None:
        call = locate_call([c for c in js_calls(ctx, rel) if c.base == "cookie"], line_no)
        if call is None:
            return None
        if _EXPLICIT_OFF.search(call.args):
            return None
        args_node = call.node.child_by_field_name("arguments")
        if args_node is None:
            return None
        source = text.encode("utf-8")
        options = [
            child
            for child in getattr(args_node, "named_children", [])
            if child.type == "object"
        ]
        if len(options) != 1:
            # No options object to extend: appending one would change the call's shape
            # in ways this rule cannot prove safe for every cookie helper.
            return None
        original = node_text(source, options[0])
        additions = [
            _JS_FLAG_PROPS[name] for name in _JS_FLAG_PROPS if _missing(original, name)
        ]
        if not additions:
            return None
        rewritten = append_object_properties(original, additions)
        if rewritten is None:
            return None
        return replace_node(text, options[0], rewritten)
