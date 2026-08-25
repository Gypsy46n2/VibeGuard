"""VG-API-001 / VG-API-002 — outbound HTTP calls that can hang forever."""

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
    locate_call,
    replace_node,
    whole_file_patch,
)
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    block_of,
    js_calls,
    node_text,
    py_calls,
    source_files,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["HttpTimeoutJsRule", "HttpTimeoutPythonRule"]

_MAX_FINDINGS = 10

#: Seconds used by the VG-API-001 repair — long enough for a slow-but-alive upstream,
#: short enough that a hung one cannot pin a worker indefinitely.
_DEFAULT_TIMEOUT = 30

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request")

# requests.get( / httpx.post( / urllib.request.urlopen( / urlopen(
_PY_MODULE_CALL = re.compile(
    r"^(?:requests|httpx)\.(?:" + "|".join(_HTTP_METHODS) + r")$",
)
_PY_URLOPEN = re.compile(r"(?:^|\.)urlopen$")
# session.get( / client.post( / http.request( — only trusted when the file really
# builds a requests/httpx/aiohttp client, otherwise it is somebody's own object.
_PY_CLIENT_CALL = re.compile(
    r"^(?:session|sess|client|http|s|_session|_client)\.(?:" + "|".join(_HTTP_METHODS) + r")$",
)
_PY_CLIENT_SOURCE = re.compile(
    r"requests\.Session\s*\(|httpx\.(?:Async)?Client\s*\(|aiohttp\.ClientSession\s*\("
)
_TIMEOUT_KW = re.compile(r"\btimeout\s*=")
# A default configured on the session/client rather than on the individual call.
_SESSION_TIMEOUT = re.compile(
    r"(?:Session|Client|ClientSession|HTTPAdapter)\s*\([^)]*timeout\s*=|"
    r"\.timeout\s*=|ClientTimeout\s*\(|timeout\s*=\s*DEFAULT_TIMEOUT"
)

_JS_AXIOS = re.compile(r"^axios(?:\.(?:" + "|".join(_HTTP_METHODS) + r"|create))?$")
_JS_FETCH = re.compile(r"(?:^|\.)fetch$")
_JS_TIMEOUT_KEY = re.compile(r"\btimeout\s*:")
_JS_ABORT = re.compile(r"\bsignal\s*:|AbortSignal\.timeout|AbortController|\btimeout\s*:")
_JS_AXIOS_INSTANCE_TIMEOUT = re.compile(r"axios\.create\s*\([^)]*\btimeout\s*:", re.DOTALL)


class HttpTimeoutPythonRule(Rule):
    """Outbound Python HTTP calls with neither a per-call nor a session timeout."""

    id: ClassVar[str] = "VG-API-001"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Outbound HTTP request without a timeout (Python)"
    description: ClassVar[str] = (
        "An outbound HTTP call passes no timeout= and no session-level default timeout is "
        "configured, so the request can block indefinitely."
    )
    why_it_matters: ClassVar[str] = (
        "requests, httpx and urllib wait forever by default. When the far end stops "
        "answering — a hung load balancer, a dropped packet, a dependency under load — the "
        "worker thread handling your user's request is stuck too. A handful of such calls "
        "exhausts the worker pool and the whole app stops responding, even to healthy "
        "traffic."
    )
    references: ClassVar[list[str]] = [
        "https://requests.readthedocs.io/en/latest/user/advanced/#timeouts",
        "https://www.python-httpx.org/advanced/timeouts/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "api.timeouts",
        "network.network-timeouts",
        "performance.dependency-latency",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.SAFE_AUTOFIX

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or ("requests" not in text and "httpx" not in text
                            and "urlopen" not in text and "aiohttp" not in text):
                continue
            source = text.encode("utf-8")
            client_file = bool(_PY_CLIENT_SOURCE.search(text))
            if _SESSION_TIMEOUT.search(text):
                # A module-wide default timeout is configured; trust it.
                continue
            for call in py_calls(ctx, rel):
                if len(findings) >= _MAX_FINDINGS:
                    break
                name = call.name
                is_module = bool(_PY_MODULE_CALL.match(name)) or bool(_PY_URLOPEN.search(name))
                is_client = client_file and bool(_PY_CLIENT_CALL.match(name))
                if not (is_module or is_client):
                    continue
                if _TIMEOUT_KW.search(call.args):
                    continue
                if _SESSION_TIMEOUT.search(block_of(source, call.node)):
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{name}{call.args}"[:400],
                        description=(
                            f"{name}() at {rel}:{call.line} passes no timeout= and no "
                            "session-level default timeout is in scope, so it can block "
                            "forever."
                        ),
                        recommended_followup=(
                            "Pass an explicit timeout, e.g. "
                            f"`{name}(..., timeout=(3.05, 10))` for requests, or build the "
                            "client once with `httpx.Client(timeout=httpx.Timeout(10.0, "
                            "connect=3.0))`."
                        ),
                    )
                )
        return findings

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Add ``timeout=30`` to the reported call.

        Preconditions (all required, else no patch): the finding's line still holds
        exactly one matching call, its argument list is a plain parenthesised list with
        no ``**kwargs`` (which could already carry a timeout), and no ``timeout=`` is
        present. Only the argument list is rewritten — nothing else in the file moves.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no:
            return None
        text = ctx.read(rel)
        if not text:
            return None
        call = locate_call([c for c in py_calls(ctx, rel) if self._is_target(c)], line_no)
        if call is None:
            return None
        line_no = call.line
        source = text.encode("utf-8")
        args_node = call.node.child_by_field_name("arguments")
        if args_node is None:
            return None
        args_text = node_text(source, args_node)
        if not (args_text.startswith("(") and args_text.endswith(")")):
            return None
        if "**" in args_text or "*" in args_text.replace("**", ""):
            return None
        new_args = append_arguments(args_text, [f"timeout={_DEFAULT_TIMEOUT}"])
        if new_args is None:
            return None
        new_text = replace_node(text, args_node, new_args)
        if new_text is None:  # pragma: no cover - defensive
            return None
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=(
                f"Add `timeout={_DEFAULT_TIMEOUT}` to `{call.name}(...)` at {rel}:{line_no} "
                "so the call cannot block forever."
            ),
            scope="api",
            summary=f"bound {call.name}() with an explicit timeout",
        )

    @staticmethod
    def _is_target(call: CallSite) -> bool:
        if _TIMEOUT_KW.search(call.args):
            return False
        return bool(
            _PY_MODULE_CALL.match(call.name)
            or _PY_URLOPEN.search(call.name)
            or _PY_CLIENT_CALL.match(call.name)
        )


class HttpTimeoutJsRule(Rule):
    """axios calls without ``timeout`` and fetch calls without an abort signal."""

    id: ClassVar[str] = "VG-API-002"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Outbound HTTP request without a timeout (JavaScript)"
    description: ClassVar[str] = (
        "An axios call configures no timeout, or a fetch call passes no AbortSignal, so the "
        "request has no upper bound. The fetch half of this rule is low confidence: a "
        "signal may be supplied from a variable this rule cannot follow."
    )
    why_it_matters: ClassVar[str] = (
        "Node's fetch and axios both wait indefinitely unless told otherwise. A single slow "
        "upstream then pins request handlers, event-loop callbacks and sockets open until "
        "the process runs out of them, turning one sick dependency into a full outage. "
        "Users see a spinner that never resolves rather than a fast, honest error."
    )
    references: ClassVar[list[str]] = [
        "https://axios-http.com/docs/req_config",
        "https://developer.mozilla.org/en-US/docs/Web/API/AbortSignal/timeout_static",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"api.timeouts", "network.network-timeouts"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): add `timeout: 10000` to the axios config / `signal:
    # AbortSignal.timeout(10000)` to the fetch init object.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or ("axios" not in text and "fetch" not in text):
                continue
            axios_default = bool(_JS_AXIOS_INSTANCE_TIMEOUT.search(text)) or (
                "axios.defaults.timeout" in text
            )
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX_FINDINGS:
                    break
                if _JS_AXIOS.match(call.name):
                    if axios_default or _JS_TIMEOUT_KEY.search(call.args):
                        continue
                    kind, hint, confidence = (
                        "axios",
                        "add `timeout: 10000` (ms) to the request config, or create one "
                        "instance with `axios.create({ timeout: 10000 })` and use it "
                        "everywhere",
                        Confidence.MEDIUM,
                    )
                elif _JS_FETCH.search(call.name):
                    if _JS_ABORT.search(call.args):
                        continue
                    kind, hint, confidence = (
                        "fetch",
                        "pass `{ signal: AbortSignal.timeout(10000) }` in the fetch init "
                        "object so the request is aborted instead of hanging",
                        Confidence.LOW,
                    )
                else:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{call.name}{call.args}"[:400],
                        confidence=confidence,
                        description=(
                            f"{kind} call at {rel}:{call.line} has no request timeout"
                            + (
                                " (low confidence: an AbortSignal may be supplied "
                                "indirectly)."
                                if kind == "fetch"
                                else "."
                            )
                        ),
                        recommended_followup=hint,
                    )
                )
        return findings
