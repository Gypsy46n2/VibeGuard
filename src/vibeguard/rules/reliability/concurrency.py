"""VG-REL-003 and VG-REL-004 — how the process spends its concurrency budget.

* **VG-REL-003** a blocking call inside asynchronous code.
* **VG-REL-004** concurrency fanned out with no upper bound.
"""

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
    calls,
    enclosing_function,
    in_loop,
    node_text,
    source_files,
)
from vibeguard.rules.reliability._common import (
    CODE_SUFFIXES,
    MAX_FINDINGS,
    function_name,
    is_async,
    is_handler,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["BlockingCallInAsyncRule", "UnboundedConcurrencyRule"]

#: Calls that park the whole thread / event loop.
_BLOCKING = {
    "time.sleep": "time.sleep() blocks the event loop",
    "subprocess.run": "subprocess.run() blocks until the child exits",
    "subprocess.call": "subprocess.call() blocks until the child exits",
    "subprocess.check_output": "subprocess.check_output() blocks until the child exits",
    "subprocess.check_call": "subprocess.check_call() blocks until the child exits",
    "os.system": "os.system() blocks until the child exits",
    "open": "open() performs blocking file I/O",
    "fs.readfilesync": "fs.readFileSync() performs blocking file I/O",
    "fs.writefilesync": "fs.writeFileSync() performs blocking file I/O",
    "readfilesync": "fs.readFileSync() performs blocking file I/O",
    "writefilesync": "fs.writeFileSync() performs blocking file I/O",
    "execsync": "execSync() blocks until the child exits",
    "child_process.execsync": "execSync() blocks until the child exits",
    "execfilesync": "execFileSync() blocks until the child exits",
    "spawnsync": "spawnSync() blocks until the child exits",
}
_SYNC_HTTP = re.compile(r"^(requests|urllib\.request|urllib3|httplib2)\.")
_SYNC_HTTP_BASES = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}


def _blocking_reason(name: str) -> str | None:
    lowered = name.lower()
    reason = _BLOCKING.get(lowered)
    if reason:
        return reason
    if _SYNC_HTTP.match(lowered) and lowered.rsplit(".", 1)[-1] in _SYNC_HTTP_BASES:
        return f"{name}() is a synchronous HTTP call"
    return None


class BlockingCallInAsyncRule(Rule):
    """Synchronous I/O or sleeps inside an ``async`` function or a JS handler."""

    id: ClassVar[str] = "VG-REL-003"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Blocking call inside async code"
    description: ClassVar[str] = (
        "A synchronous call — sleep, blocking HTTP, file I/O, or a subprocess — runs "
        "inside asynchronous code, so it parks the event loop instead of yielding."
    )
    why_it_matters: ClassVar[str] = (
        "An async server handles thousands of requests on one thread by never blocking it. "
        "A single synchronous call freezes that thread for its whole duration: while one "
        "request waits two seconds on a slow HTTP call, *every* other request is queued "
        "behind it, health checks time out, and the platform may restart what looks like a "
        "hung process. The symptom — sporadic latency spikes across unrelated endpoints — "
        "is notoriously hard to trace back to the one blocking line."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/library/asyncio-dev.html#running-blocking-code",
        "https://nodejs.org/en/learn/asynchronous-work/dont-block-the-event-loop",
    ]
    topics: ClassVar[set[str]] = {
        "concurrency.event-loop-blocking",
        "concurrency.worker-starvation",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text:
                continue
            source = text.encode("utf-8")
            for site in calls(ctx, rel):
                if len(findings) >= MAX_FINDINGS:
                    break
                reason = _blocking_reason(site.name)
                if reason is None:
                    continue
                func = enclosing_function(site.node)
                if func is None:
                    continue
                # Blocking calls only matter on an event loop. Synchronous WSGI/Flask
                # handlers run on their own thread, so `open()` there is not a defect;
                # the JS `*Sync` family always runs on the single Node loop.
                js_sync = site.name.lower().endswith("sync")
                if not (is_async(source, func) or (js_sync and is_handler(source, func))):
                    continue
                where = function_name(source, func) or "an async function"
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=node_text(source, site.node)[:200],
                        description=(
                            f"{reason}, and it is called from {where} in {rel} "
                            f"(line {site.line})."
                        ),
                        recommended_followup=(
                            "Use the async equivalent (`await asyncio.sleep(...)`, "
                            "`httpx.AsyncClient`, `aiofiles`, `asyncio.create_subprocess_exec`, "
                            "`fs.promises.readFile`) or push the blocking work off the loop "
                            "with `await asyncio.to_thread(fn, ...)` / a worker thread."
                        ),
                    )
                )
        return findings


_LIMITED = re.compile(
    r"\bSemaphore\s*\(|\bp-?limit\b|\bpLimit\s*\(|\bpMap\s*\(|\bbottleneck\b|"
    r"\bchunk\w*\s*\(|\bbatch\w*\s*\(|\bislice\s*\(|\bmax_workers\s*=|\bconcurrency\s*:|"
    r"\blimit\s*:\s*\d+|\bqueue\s*\(\s*\d+",
    re.IGNORECASE,
)
_DYNAMIC_SPREAD = re.compile(r"\*\s*[\[(]|\*\s*\w+")
_MAP_FANOUT = re.compile(r"\.map\s*\(|\bfor\s+\w+\s+of\b")
_THREAD_CTORS = {"thread", "process", "threading.thread", "multiprocessing.process"}


class UnboundedConcurrencyRule(Rule):
    """Fan-out whose width is the size of the input, with no limit."""

    id: ClassVar[str] = "VG-REL-004"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Unbounded concurrency"
    description: ClassVar[str] = (
        "Work is fanned out across every item of a dynamically sized collection — via "
        "`Promise.all(items.map(...))`, `asyncio.gather(*[...])`, or a thread created per "
        "loop iteration — with no cap on how many run at once."
    )
    why_it_matters: ClassVar[str] = (
        "The concurrency is whatever the input size happens to be. Ten items is fine; the "
        "day someone uploads ten thousand, the process opens ten thousand sockets or "
        "threads at once — exhausting file descriptors, memory, and the downstream "
        "service's rate limit simultaneously. It usually takes down the dependency before "
        "it takes down you, so the outage looks like someone else's fault."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/library/asyncio-sync.html#semaphore",
        "https://github.com/sindresorhus/p-limit",
    ]
    topics: ClassVar[set[str]] = {
        "concurrency.unbounded-concurrency",
        "concurrency.thread-process-exhaustion",
        "concurrency.worker-starvation",
        "concurrency.unbounded-queues",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or _LIMITED.search(text):
                continue
            source = text.encode("utf-8")
            for site in calls(ctx, rel):
                if len(findings) >= MAX_FINDINGS:
                    break
                detail = self._unbounded(site, source)
                if detail is None:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=node_text(source, site.node)[:200],
                        description=f"{detail} in {rel} (line {site.line}).",
                        recommended_followup=(
                            "Bound the fan-out: wrap the coroutine in an "
                            "`asyncio.Semaphore(n)`, use `p-limit`/`pMap` with a "
                            "concurrency option in JS, or process the collection in fixed "
                            "size batches instead of all at once. Use a pool "
                            "(`ThreadPoolExecutor(max_workers=n)`) rather than creating a "
                            "thread per item."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _unbounded(site: object, source: bytes) -> str | None:
        name = site.name.lower()  # type: ignore[attr-defined]
        args = site.args  # type: ignore[attr-defined]
        if name in {"asyncio.gather", "gather"} and _DYNAMIC_SPREAD.search(args):
            return "asyncio.gather() awaits an unpacked, dynamically sized collection"
        if name in {"promise.all", "promise.allsettled"} and _MAP_FANOUT.search(args):
            return "Promise.all() awaits one promise per element of a dynamic collection"
        if name in _THREAD_CTORS and in_loop(site.node):  # type: ignore[attr-defined]
            return f"{name}() creates a new OS thread/process on every loop iteration"
        if name in {"asyncio.create_task", "asyncio.ensure_future"} and in_loop(
            site.node  # type: ignore[attr-defined]
        ):
            return "a task is scheduled on every loop iteration with no concurrency limit"
        return None
