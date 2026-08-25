"""VG-NET-002 — a fresh TCP+TLS connection for every outbound request."""

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
    in_loop,
    js_calls,
    py_calls,
    source_files,
)
from vibeguard.rules.api._http import py_handlers

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoConnectionReuseRule"]

_MAX_FINDINGS = 6

_PY_ONESHOT = re.compile(r"^(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)$")
_PY_POOLED = re.compile(
    r"requests\.Session\s*\(|httpx\.(?:Async)?Client\s*\(|aiohttp\.ClientSession\s*\(|"
    r"HTTPAdapter\s*\(|urllib3\.PoolManager\s*\(|ConnectionPool\s*\("
)
_JS_RAW_REQUEST = re.compile(r"^(?:https?|http2)\.(?:request|get)$")
_JS_KEEPALIVE = re.compile(
    r"keepAlive\s*:\s*true|new\s+(?:https?\.)?Agent\s*\(|globalAgent|"
    r"undici|Pool\s*\(|setGlobalDispatcher"
)


class NoConnectionReuseRule(Rule):
    """One-shot HTTP calls in hot paths where a pooled client belongs."""

    id: ClassVar[str] = "VG-NET-002"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "New HTTP connection per request (no connection reuse)"
    description: ClassVar[str] = (
        "A module-level HTTP call is made inside a loop or a request handler instead of "
        "through a pooled session/client, so every call opens a new TCP connection and "
        "repeats the TLS handshake."
    )
    why_it_matters: ClassVar[str] = (
        "A fresh connection costs a TCP handshake plus a TLS negotiation before a single "
        "byte of useful data moves — often more time than the request itself. In a loop or "
        "a hot handler that overhead dominates your latency, and the discarded sockets pile "
        "up in TIME_WAIT until the machine runs out of ephemeral ports and calls start "
        "failing for no visible reason."
    )
    references: ClassVar[list[str]] = [
        "https://requests.readthedocs.io/en/latest/user/advanced/#session-objects",
        "https://nodejs.org/api/http.html#new-agentoptions",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "network.connection-reuse",
        "network.keep-alive",
        "network.http11",
        "performance.network-bottlenecks",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._python(ctx))
        if len(findings) < _MAX_FINDINGS:
            findings.extend(self._javascript(ctx))
        return findings[:_MAX_FINDINGS]

    # ----------------------------------------------------------------- python
    def _python(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(out) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or ("requests." not in text and "httpx." not in text):
                continue
            if _PY_POOLED.search(text):
                continue
            handler_spans = [
                (h.node.start_byte, h.node.end_byte)
                for h in py_handlers(ctx, rel)
                if h.node is not None
            ]
            for call in py_calls(ctx, rel):
                if len(out) >= _MAX_FINDINGS:
                    break
                if not _PY_ONESHOT.match(call.name):
                    continue
                looped = in_loop(call.node)
                in_handler = any(
                    start <= call.node.start_byte < end for start, end in handler_spans
                )
                if not (looped or in_handler):
                    continue
                where = "a loop" if looped else "a request handler"
                out.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{call.name}{call.args}"[:400],
                        description=(
                            f"{call.name}() at {rel}:{call.line} runs inside {where} without "
                            "a shared Session, so each call opens a new connection."
                        ),
                        recommended_followup=(
                            "Create one `requests.Session()` (or `httpx.Client()`) at module "
                            "or application scope, reuse it for these calls, and let it keep "
                            "connections alive across requests."
                        ),
                    )
                )
        return out

    # ------------------------------------------------------------- javascript
    def _javascript(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(out) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or ("http.request" not in text and "https.request" not in text):
                continue
            if _JS_KEEPALIVE.search(text):
                continue
            for call in js_calls(ctx, rel):
                if len(out) >= _MAX_FINDINGS:
                    break
                if not _JS_RAW_REQUEST.match(call.name):
                    continue
                if "agent" in call.args:
                    continue
                out.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{call.name}{call.args}"[:400],
                        description=(
                            f"{call.name}() at {rel}:{call.line} passes no keep-alive agent, "
                            "so Node opens and discards a connection per request."
                        ),
                        recommended_followup=(
                            "Create one agent — `new https.Agent({ keepAlive: true, "
                            "maxSockets: 50 })` — and pass it as the `agent` option (or set "
                            "a global undici dispatcher) so sockets are reused."
                        ),
                    )
                )
        return out
