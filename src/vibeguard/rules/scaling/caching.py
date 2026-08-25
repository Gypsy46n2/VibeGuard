"""VG-SCALE-003 — in-process cache where a shared cache is needed."""

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
from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, RegexRule
from vibeguard.rules.scaling._signals import is_request_path, is_web_app

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["InProcessCacheRule"]

_PATTERNS = (
    re.compile(r"@(?:functools\.)?(?:lru_cache|cache)\b"),
    re.compile(r"\bfrom\s+cachetools\b|\bimport\s+cachetools\b|\b(?:TTL|LRU|LFU)Cache\("),
    re.compile(r"\bnew\s+NodeCache\(|require\(\s*[\"']node-cache[\"']\s*\)|"
               r"from\s+[\"']node-cache[\"']"),
    re.compile(r"\bmemoize(?:One)?\(|\blodash\.memoize\b"),
    re.compile(r"^_?[A-Za-z_]*(?:cache|CACHE)[A-Za-z_]*\s*(?::[^=]+)?=\s*"
               r"(?:\{\s*\}|dict\(\)|new Map\()"),
)

#: A shared cache tier makes the in-process cache a deliberate L1, not a mistake.
_SHARED_CACHE_TECH = {"redis", "memcached", "valkey", "elasticache", "dragonfly"}


class InProcessCacheRule(RegexRule):
    """Per-process memoisation standing in for a shared cache tier."""

    id: ClassVar[str] = "VG-SCALE-003"
    category: ClassVar[Category] = Category.SCALABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "In-process cache instead of a shared cache"
    description: ClassVar[str] = (
        "Data is cached inside the application process (lru_cache, cachetools, "
        "node-cache, or a module-level dict) and no shared cache tier exists."
    )
    why_it_matters: ClassVar[str] = (
        "Each instance builds and expires its own copy, so the same request can return "
        "different answers depending on which process serves it, and an invalidation on "
        "one instance leaves every other instance serving stale data. Cache hit rates also "
        "fall as you add instances — precisely when you need them most — and an unbounded "
        "in-process cache grows until the process is killed for using too much memory."
    )
    references: ClassVar[list[str]] = [
        "https://redis.io/docs/latest/develop/use/patterns/",
        "https://docs.python.org/3/library/functools.html#functools.lru_cache",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"scaling.cache-architecture"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = _PATTERNS
    suffixes: ClassVar[tuple[str, ...]] = PY_SUFFIXES + JS_SUFFIXES
    max_per_file: ClassVar[int] = 2
    max_total: ClassVar[int] = 5
    skip_non_code: ClassVar[bool] = True
    recommended_followup: ClassVar[str] = (
        "Put the cached value in Redis with an explicit TTL and an invalidation path "
        "(delete the key when the underlying row changes), and keep any in-process cache "
        "only as a short-lived L1 in front of it."
    )

    # M3 fix(): none — introducing Redis is an infrastructure change, not a code patch.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        # "Every instance keeps its own copy" is only a problem when there *are*
        # instances. A CLI or a library memoising a lookup table is not running
        # behind a load balancer, and telling it to adopt Redis is the kind of
        # disproportionate advice VibeGuard exists to avoid (DECISIONS.md D66).
        if not is_web_app(ctx):
            return []
        if _SHARED_CACHE_TECH & ctx.tech.all_technologies():
            return []
        return [f for f in super().detect(ctx) if is_request_path(ctx, f.file or "")]

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return (
            f"{relpath}:{line_no} caches data inside the application process and no shared "
            "cache (Redis, Memcached) was detected in the stack. Whether this matters "
            "depends on how consistent the cached value has to be across instances — "
            "VibeGuard cannot tell that from the source, so treat it as a question to "
            "answer rather than a defect."
        )


RULES: list[type[Rule]] = [InProcessCacheRule]
