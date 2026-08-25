"""VG-REL-005 and VG-REL-006 — process-local state that outlives a request.

* **VG-REL-005** a module-level container that only ever grows.
* **VG-REL-006** shared mutable state mutated from handlers without a lock, plus
  nested lock acquisitions (a deadlock waiting to happen).
"""

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
    calls,
    enclosing_function,
    in_loop,
    node_text,
    source_files,
    walk,
)
from vibeguard.rules.reliability._common import (
    CODE_SUFFIXES,
    MAX_FINDINGS,
    function_name,
    has_long_running_process,
    is_handler,
    module_level,
    root_of,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["UnboundedCacheRule", "SharedMutableStateRule"]

_CONTAINER_LITERALS = {"dictionary", "list", "set", "object", "array"}
_CONTAINER_CALLS = {
    "dict",
    "list",
    "set",
    "defaultdict",
    "collections.defaultdict",
    "ordereddict",
    "collections.ordereddict",
    "map",
    "weakmap",
    "counter",
    "collections.counter",
}
_GROW_BASES = {"append", "add", "update", "setdefault", "extend", "insert", "push", "set"}
_EVICTION = re.compile(
    r"lru_cache\s*\(\s*maxsize\s*=\s*\d|\bmaxsize\s*=\s*\d|\bmaxlen\s*=|\bcachetools\b|"
    r"\bTTLCache\b|\bLRUCache\b|\bexpire\w*\s*[=(]|\bttl\b|\bevict\w*|\bdeque\s*\(|"
    r"\bdel\s+\w+\[|\.pop\s*\(|\.clear\s*\(|\.delete\s*\(|\blru-cache\b|\bquick-lru\b",
    re.IGNORECASE,
)


def _module_containers(ctx: ScanContext, rel: str, source: bytes) -> dict[str, int]:
    """``name -> line`` for every module-level dict/list/set/Map/array."""
    root = root_of(ctx, rel)
    out: dict[str, int] = {}
    if root is None:
        return out
    for node in walk(root):
        if node.type not in {"assignment", "variable_declarator"}:
            continue
        if not module_level(node):
            continue
        try:
            target = node.child_by_field_name("left") or node.child_by_field_name("name")
            value = node.child_by_field_name("right") or node.child_by_field_name("value")
        except (AttributeError, TypeError, ValueError):  # pragma: no cover
            # Narrow on purpose: these are the shapes a tree-sitter binding
            # mismatch takes, and this runs per node so it must stay silent.
            continue
        if target is None or value is None or target.type != "identifier":
            continue
        kind = value.type
        if kind == "new_expression":
            kind = "call"
        if kind not in _CONTAINER_LITERALS and kind not in {"call", "call_expression"}:
            continue
        if kind in {"call", "call_expression"}:
            callee = node_text(source, value).split("(", 1)[0].strip().removeprefix("new ")
            if callee.lower() not in _CONTAINER_CALLS:
                continue
        out[node_text(source, target)] = node.start_point[0] + 1
    return out


class UnboundedCacheRule(Rule):
    """A module-level container written from request code, never evicted."""

    id: ClassVar[str] = "VG-REL-005"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Unbounded in-memory cache or accumulator"
    description: ClassVar[str] = (
        "A module-level dictionary, list, set, or Map is written to from a request handler "
        "or a loop, and nothing ever removes entries from it."
    )
    why_it_matters: ClassVar[str] = (
        "The container grows for the entire life of the process and is never garbage "
        "collected, because the module still references it. Memory use climbs request by "
        "request until the container or the platform kills the process — typically hours or "
        "days after deploy, which makes it look like a random crash rather than a leak. On "
        "a container platform this shows up as an OOMKill loop under exactly the traffic "
        "you most wanted to serve."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/library/functools.html#functools.lru_cache",
        "https://cachetools.readthedocs.io/en/latest/",
    ]
    topics: ClassVar[set[str]] = {
        "concurrency.memory-leaks",
        "concurrency.gc-pressure",
        "concurrency.gc-behavior",
        "performance.memory-usage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or _EVICTION.search(text):
                continue
            source = text.encode("utf-8")
            containers = _module_containers(ctx, rel, source)
            if not containers:
                continue
            for name, line_no in sorted(containers.items()):
                if len(findings) >= MAX_FINDINGS:
                    break
                site = self._growth_site(ctx, rel, source, name)
                if site is None:
                    continue
                where, grow_line, snippet = site
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=grow_line,
                        snippet=snippet[:200],
                        description=(
                            f"Module-level container {name!r} ({rel}:{line_no}) is written "
                            f"to from {where} ({rel}:{grow_line}) and nothing evicts "
                            "entries from it."
                        ),
                        recommended_followup=(
                            f"Give {name} an explicit bound — `cachetools.TTLCache(maxsize="
                            "..., ttl=...)`, `functools.lru_cache(maxsize=...)`, "
                            "`collections.deque(maxlen=...)`, or an `lru-cache` instance in "
                            "JS — or move the state into Redis with an expiry so it is "
                            "shared and bounded."
                        ),
                    )
                )
        return findings

    def _growth_site(
        self, ctx: ScanContext, rel: str, source: bytes, name: str
    ) -> tuple[str, int, str] | None:
        """First place ``name`` grows inside per-request code."""
        for site in calls(ctx, rel):
            base = site.base.lower()
            receiver = site.name.rsplit(".", 1)[0] if "." in site.name else ""
            if base not in _GROW_BASES or receiver != name:
                continue
            func = enclosing_function(site.node)
            if func is None:
                continue
            if not (is_handler(source, func) or in_loop(site.node)):
                continue
            where = function_name(source, func) or "a request-scoped function"
            return where, site.line, node_text(source, site.node)
        return self._subscript_site(ctx, rel, source, name)

    @staticmethod
    def _subscript_site(
        ctx: ScanContext, rel: str, source: bytes, name: str
    ) -> tuple[str, int, str] | None:
        root = root_of(ctx, rel)
        if root is None:
            return None
        for node in walk(root):
            if node.type not in {"assignment", "augmented_assignment"}:
                continue
            try:
                target = node.child_by_field_name("left")
            except (AttributeError, TypeError, ValueError):  # pragma: no cover
                # Narrow on purpose: these are the shapes a tree-sitter binding
                # mismatch takes, and this runs per node so it must stay silent.
                continue
            if target is None or target.type not in {"subscript", "member_expression"}:
                continue
            if not node_text(source, target).startswith(f"{name}["):
                continue
            func = enclosing_function(node)
            if func is None:
                continue
            if not (is_handler(source, func) or in_loop(node)):
                continue
            where = function_name(source, func) or "a request-scoped function"
            return where, node.start_point[0] + 1, node_text(source, node)
        return None


_LOCKING = re.compile(
    r"\bLock\s*\(|\bRLock\s*\(|\bSemaphore\s*\(|\bmutex\b|\bwith\s+\w*lock\w*\s*:|"
    r"\.acquire\s*\(|\bMutex\b|\basync-mutex\b|\bthreading\.local\b",
    re.IGNORECASE,
)
_LOCKISH = re.compile(r"lock|mutex|semaphore", re.IGNORECASE)
_SCALAR_LITERAL = {"integer", "float", "true", "false", "number"}


class SharedMutableStateRule(Rule):
    """Globals mutated from handlers, and nested lock acquisitions."""

    id: ClassVar[str] = "VG-REL-006"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Shared mutable state mutated from request handlers"
    description: ClassVar[str] = (
        "Module-level mutable state is reassigned from request or background-task code "
        "with no lock protecting it — or two locks are acquired one inside the other, "
        "which is how deadlocks are built."
    )
    why_it_matters: ClassVar[str] = (
        "Servers run many requests at once, across threads and across processes. An "
        "unsynchronised `counter += 1` loses updates when two requests interleave, and the "
        "value is per-process anyway, so it silently disagrees between workers and resets "
        "on every deploy. Nested lock acquisition is worse: the moment two code paths take "
        "the same two locks in opposite orders, both threads block forever and the process "
        "stops serving without ever crashing or logging anything."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/library/threading.html#lock-objects",
        "https://12factor.net/processes",
    ]
    topics: ClassVar[set[str]] = {
        "concurrency.race-conditions",
        "concurrency.thread-safety",
        "concurrency.deadlocks",
        "scaling.multi-instance-behavior",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_long_running_process(ctx)

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text:
                continue
            source = text.encode("utf-8")
            root = root_of(ctx, rel)
            if root is None:
                continue
            findings.extend(self._nested_locks(rel, source, root))
            if _LOCKING.search(text):
                continue
            findings.extend(self._unguarded_globals(rel, source, root))
        return findings[:MAX_FINDINGS]

    def _unguarded_globals(self, rel: str, source: bytes, root: Any) -> list[Finding]:
        scalars = {
            node_text(source, node.child_by_field_name("left")): node.start_point[0] + 1
            for node in walk(root)
            if node.type == "assignment"
            and module_level(node)
            and (node.child_by_field_name("right") is not None)
            and node.child_by_field_name("right").type in _SCALAR_LITERAL
            and (node.child_by_field_name("left") is not None)
            and node.child_by_field_name("left").type == "identifier"
        }
        out: list[Finding] = []
        for node in walk(root):
            if node.type != "global_statement":
                continue
            func = enclosing_function(node)
            if func is None or not is_handler(source, func):
                continue
            names = [part for part in node_text(source, node).split()[1:] if part != ","]
            declared = ", ".join(name.strip(",") for name in names) or "module state"
            where = function_name(source, func) or "a request-scoped function"
            line_no = node.start_point[0] + 1
            is_counter = any(name.strip(",") in scalars for name in names)
            hint = " (a module-level counter)" if is_counter else ""
            out.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=node_text(source, node)[:200],
                    description=(
                        f"{where} declares `global {declared}`{hint} and mutates it in "
                        f"{rel}:{line_no}; no lock guards the update."
                    ),
                    recommended_followup=(
                        "Move the state out of the process — Redis `INCR`, a database row, "
                        "or the cache layer — so it is correct across workers. If it must "
                        "stay in-process, guard every read-modify-write with a "
                        "`threading.Lock()` and document that the value is per-instance."
                    ),
                )
            )
            if len(out) >= 2:
                break
        return out

    def _nested_locks(self, rel: str, source: bytes, root: Any) -> list[Finding]:
        out: list[Finding] = []
        for node in walk(root):
            if node.type != "with_statement":
                continue
            header = node_text(source, node).split(":", 1)[0]
            if not _LOCKISH.search(header):
                continue
            inner = next(
                (
                    child
                    for child in walk(node)
                    if child is not node
                    and child.type == "with_statement"
                    and _LOCKISH.search(node_text(source, child).split(":", 1)[0])
                ),
                None,
            )
            if inner is None:
                continue
            line_no = node.start_point[0] + 1
            out.append(
                self.make_finding(
                    file=rel,
                    line=line_no,
                    snippet=node_text(source, node)[:200],
                    description=(
                        f"Two locks are acquired one inside the other at {rel}:{line_no}; "
                        "if any other code path takes them in the opposite order the "
                        "process deadlocks."
                    ),
                    recommended_followup=(
                        "Acquire the locks in one globally documented order everywhere, or "
                        "collapse them into a single lock. Where nesting is unavoidable, "
                        "use `acquire(timeout=...)` so a cycle fails loudly instead of "
                        "hanging."
                    ),
                )
            )
            break
        return out
