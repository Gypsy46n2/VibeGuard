"""VG-SEC-005 / VG-SEC-013 — request-derived URLs in outbound calls and redirects."""

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
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    js_calls,
    node_text,
    py_calls,
    source_files,
)
from vibeguard.rules.security._taint import block_text, first_arg, is_tainted

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["OpenRedirectRule", "ServerSideRequestForgeryRule"]

_MAX = 6

_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
_PY_CLIENT_PREFIXES = ("requests.", "httpx.", "session.", "client.", "aiohttp.")
_ALLOWLIST = re.compile(
    r"allow_?list|white_?list|ALLOWED_(HOSTS|DOMAINS|ORIGINS|URLS)|is_safe_url|"
    r"url_has_allowed_host_and_scheme|urlparse\([^)]*\)\.(hostname|netloc)\s+in\b|"
    r"\.startswith\(\s*['\"]/",
    re.IGNORECASE,
)


def _guarded(source: bytes, call: CallSite) -> bool:
    """True when the enclosing function contains an allowlist/containment check."""
    return bool(_ALLOWLIST.search(block_text(source, call.node)))


class ServerSideRequestForgeryRule(Rule):
    """An outbound HTTP request whose URL comes from request input."""

    id: ClassVar[str] = "VG-SEC-005"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Outbound request to a user-controlled URL"
    description: ClassVar[str] = (
        "The server fetches a URL that is taken from request input, with no allowlist "
        "of permitted hosts nearby."
    )
    why_it_matters: ClassVar[str] = (
        "Your server can reach places the internet cannot: cloud metadata endpoints that "
        "hand out credentials, internal admin panels, databases on the private network. "
        "If a user chooses the URL, they borrow that reach — SSRF is how a number of "
        "large cloud breaches started."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/918.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.ssrf"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in py_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if not self._is_py_fetch(call):
                    continue
                arg = first_arg(call.node)
                if arg is None or not is_tainted(source, arg):
                    continue
                if _guarded(source, call):
                    continue
                findings.append(self._finding(rel, call, node_text(source, arg)))
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if not self._is_js_fetch(call):
                    continue
                arg = first_arg(call.node)
                if arg is None or not is_tainted(source, arg):
                    continue
                if _guarded(source, call):
                    continue
                findings.append(self._finding(rel, call, node_text(source, arg)))
        return findings

    def _is_py_fetch(self, call: CallSite) -> bool:
        name = call.name
        if name in {"urlopen", "urllib.request.urlopen"} or name.endswith(".urlopen"):
            return True
        if call.base not in _HTTP_VERBS:
            return False
        return name.startswith(_PY_CLIENT_PREFIXES) or ".client." in name

    def _is_js_fetch(self, call: CallSite) -> bool:
        name = call.name
        if name in {"fetch", "axios", "got", "superagent"}:
            return True
        return name.startswith(("axios.", "got.", "http.request", "https.request")) and (
            call.base in _HTTP_VERBS or call.base == "request"
        )

    def _finding(self, rel: str, call: CallSite, url_text: str) -> Finding:
        return self.make_finding(
            file=rel,
            line=call.line,
            snippet=f"{call.name}({url_text.strip()[:180]})",
            description=(
                f"`{call.name}(...)` at {rel}:{call.line} fetches a URL derived from request "
                "input. This is a heuristic: it matches request-shaped expressions and "
                "locals assigned from them, and is suppressed when an allowlist check "
                "appears in the same function."
            ),
            recommended_followup=(
                "Resolve the URL and compare its host against an explicit allowlist before "
                "fetching, reject non-http(s) schemes and private/link-local addresses "
                "(169.254.169.254 in particular), and disable redirect following."
            ),
        )


_REDIRECT_NAMES = {"redirect", "HttpResponseRedirect", "RedirectResponse"}


class OpenRedirectRule(Rule):
    """A redirect target taken from request input without an allowlist check."""

    id: ClassVar[str] = "VG-SEC-013"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Open redirect"
    description: ClassVar[str] = (
        "A redirect sends the browser to a location taken from request input with no "
        "check that the destination belongs to this site."
    )
    why_it_matters: ClassVar[str] = (
        "A link that starts on your domain and silently lands on an attacker's is the "
        "classic phishing setup: the victim sees your brand in the URL they clicked and "
        "trusts the login form that follows. Open redirects also let attackers smuggle "
        "OAuth codes and password-reset tokens off your site."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/601.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.open-redirects"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for suffixes, extractor in ((PY_SUFFIXES, py_calls), (JS_SUFFIXES, js_calls)):
            for rel in source_files(ctx, suffixes):
                if len(findings) >= _MAX:
                    break
                source = ctx.read(rel).encode("utf-8")
                for call in extractor(ctx, rel):
                    if len(findings) >= _MAX:
                        break
                    if call.base not in _REDIRECT_NAMES:
                        continue
                    arg = first_arg(call.node)
                    if arg is None or not is_tainted(source, arg):
                        continue
                    if _guarded(source, call):
                        continue
                    findings.append(
                        self.make_finding(
                            file=rel,
                            line=call.line,
                            snippet=f"{call.name}({node_text(source, arg).strip()[:180]})",
                            description=(
                                f"`{call.name}(...)` at {rel}:{call.line} redirects to a "
                                "request-supplied target without validating it."
                            ),
                            recommended_followup=(
                                "Accept only relative paths, or map a short key to a known "
                                "destination. In Django use "
                                "`url_has_allowed_host_and_scheme(next, allowed_hosts=...)`; "
                                "in Express compare the parsed host to an allowlist."
                            ),
                        )
                    )
        return findings
