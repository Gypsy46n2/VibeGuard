"""VG-PERF-001 — synchronous blocking calls in a request handler or coroutine."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

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
    js_calls,
    node_text,
    py_calls,
    source_files,
    walk,
)
from vibeguard.rules.api._http import js_handlers, py_handlers

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["BlockingCallInHandlerRule"]

_MAX_FINDINGS = 10

_PY_BLOCKING = re.compile(
    r"^(?:time\.sleep|subprocess\.(?:run|call|check_call|check_output|Popen)|os\.system|"
    r"requests\.(?:get|post|put|patch|delete|head|request))$"
)
_JS_BLOCKING = re.compile(
    r"^(?:fs\.(?:readFileSync|writeFileSync|appendFileSync|readdirSync)|"
    r"(?:child_process\.)?execSync|(?:child_process\.)?spawnSync|"
    r"execFileSync|crypto\.pbkdf2Sync|deasync)$"
)


def _spans(nodes: list[Any]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for node in nodes:
        if node is None:
            continue
        try:
            out.append((node.start_byte, node.end_byte))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


def _inside(spans: list[tuple[int, int]], node: Any) -> bool:
    try:
        offset = node.start_byte
    except Exception:  # pragma: no cover - defensive
        return False
    return any(start <= offset < end for start, end in spans)


class BlockingCallInHandlerRule(Rule):
    """Work that stops the worker (or the event loop) while a user waits."""

    id: ClassVar[str] = "VG-PERF-001"
    category: ClassVar[Category] = Category.PERFORMANCE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Blocking call inside a request handler"
    description: ClassVar[str] = (
        "A synchronous blocking call — sleep, a synchronous HTTP request, a subprocess, or "
        "synchronous file I/O — runs inside an HTTP handler or an async function."
    )
    why_it_matters: ClassVar[str] = (
        "While that call blocks, the worker thread (or, in async code, the entire event "
        "loop) can do nothing else — so one slow shell-out or upstream call stalls every "
        "other user on the same process, not just the one who triggered it. Tail latency "
        "climbs first, then health checks start timing out and the orchestrator restarts "
        "instances that were merely waiting."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/library/asyncio-dev.html#running-blocking-code",
        "https://nodejs.org/en/learn/asynchronous-work/dont-block-the-event-loop",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "performance.latency",
        "performance.p50-latency",
        "performance.p95-latency",
        "performance.p99-latency",
        "performance.tail-latency",
        "concurrency.event-loop-blocking",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._python(ctx, _MAX_FINDINGS))
        if len(findings) < _MAX_FINDINGS:
            findings.extend(self._javascript(ctx, _MAX_FINDINGS - len(findings)))
        return findings[:_MAX_FINDINGS]

    # ----------------------------------------------------------------- python
    def _python(self, ctx: ScanContext, budget: int) -> list[Finding]:
        out: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(out) >= budget:
                break
            text = ctx.read(rel)
            if not text:
                continue
            handler_spans = _spans([h.node for h in py_handlers(ctx, rel)])
            async_spans = self._async_spans(ctx, rel, text)
            if not handler_spans and not async_spans:
                continue
            for call in py_calls(ctx, rel):
                if len(out) >= budget:
                    break
                if not _PY_BLOCKING.match(call.name):
                    continue
                if _inside(async_spans, call.node):
                    where = "an async def coroutine (this blocks the event loop)"
                elif _inside(handler_spans, call.node):
                    where = "an HTTP request handler"
                else:
                    continue
                out.append(self._finding(rel, call.line, f"{call.name}{call.args}", where))
        return out

    @staticmethod
    def _async_spans(ctx: ScanContext, rel: str, text: str) -> list[tuple[int, int]]:
        if "async def" not in text:
            return []
        tree = ctx.ast(rel)
        if tree is None:
            return []
        source = text.encode("utf-8")
        try:
            root: Any = tree.root_node
        except Exception:  # pragma: no cover - defensive
            return []
        spans: list[tuple[int, int]] = []
        for node in walk(root):
            if node.type != "function_definition":
                continue
            if node_text(source, node).lstrip().startswith("async "):
                spans.append((node.start_byte, node.end_byte))
        return spans

    # ------------------------------------------------------------- javascript
    def _javascript(self, ctx: ScanContext, budget: int) -> list[Finding]:
        out: list[Finding] = []
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(out) >= budget:
                break
            text = ctx.read(rel)
            if not text or "Sync" not in text:
                continue
            handler_spans = _spans([h.node for h in js_handlers(ctx, rel)])
            if not handler_spans:
                continue
            for call in js_calls(ctx, rel):
                if len(out) >= budget:
                    break
                if not _JS_BLOCKING.match(call.name):
                    continue
                if not _inside(handler_spans, call.node):
                    continue
                out.append(
                    self._finding(
                        rel,
                        call.line,
                        f"{call.name}{call.args}",
                        "an express route handler (this blocks the Node event loop)",
                    )
                )
        return out

    # ------------------------------------------------------------------ build
    def _finding(self, rel: str, line: int, snippet: str, where: str) -> Finding:
        return self.make_finding(
            file=rel,
            line=line,
            snippet=snippet[:400],
            description=f"A blocking call at {rel}:{line} runs inside {where}.",
            recommended_followup=(
                "Move the work off the request path: use the async client "
                "(`httpx.AsyncClient`, `aiofiles`, `fs.promises`), wrap unavoidable "
                "synchronous work in `asyncio.to_thread(...)` / a worker thread, or hand "
                "long jobs to a background queue and return immediately."
            ),
        )
