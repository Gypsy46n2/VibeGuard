"""Private helpers shared by the scaling pack."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from vibeguard.rules._support import is_generated_path, is_test_path

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "WEB_FRAMEWORKS",
    "autoscaling_evidence",
    "grep_repo",
    "is_web_app",
]

WEB_FRAMEWORKS = {
    "flask",
    "fastapi",
    "django",
    "starlette",
    "sanic",
    "tornado",
    "bottle",
    "express",
    "koa",
    "hapi",
    "nest",
    "nestjs",
    "next",
    "nuxt",
    "rails",
}

_GREP_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".yml",
    ".yaml",
    ".tf",
    ".json",
    ".toml",
    ".txt",
    ".md",
    ".cfg",
    ".ini",
    ".sh",
}
_MAX_FILES = 800
_MAX_BYTES = 300_000


def is_web_app(ctx: ScanContext) -> bool:
    """True when a request-serving framework was detected."""
    return bool(WEB_FRAMEWORKS & ctx.tech.all_technologies())


def grep_repo(
    ctx: ScanContext,
    pattern: re.Pattern[str],
    *,
    skip_tests: bool = True,
    limit: int = _MAX_FILES,
) -> tuple[str, int, str] | None:
    """First ``(relpath, line_no, line)`` matching ``pattern``, or ``None``."""
    seen = 0
    for rel in ctx.files:
        if seen >= limit:
            break
        if PurePosixPath(rel).suffix.lower() not in _GREP_SUFFIXES:
            continue
        if is_generated_path(rel) or (skip_tests and is_test_path(rel)):
            continue
        seen += 1
        text = ctx.read(rel)
        if not text or len(text) > _MAX_BYTES or not pattern.search(text):
            continue
        for index, line in enumerate(text.splitlines()):
            if len(line) <= 1000 and pattern.search(line):
                return (rel, index + 1, line.strip()[:200])
        return (rel, 1, "")
    return None


_AUTOSCALING_RE = re.compile(
    r"HorizontalPodAutoscaler|autoscaling/v[12]|kind:\s*HorizontalPodAutoscaler|"
    r"aws_autoscaling_group|aws_appautoscaling|min_capacity|max_capacity|"
    r"autoscaling_(?:group|policy)|scaleTargetRef|min_instances|max_instances|"
    r"scale_to_zero|concurrency_limit|deployment\.replicas|replicas:\s*[2-9]",
    re.IGNORECASE,
)
_HEADROOM_RE = re.compile(
    r"resources:\s*\n\s*(?:limits|requests)|cpu_limit|memory_limit|"
    r"instance_type|machine_type|--workers\s|worker_processes|gunicorn.*-w\s*\d",
    re.IGNORECASE,
)


def autoscaling_evidence(ctx: ScanContext) -> str:
    """Describe any autoscaling or sizing headroom signal, else ``""``."""
    bits: list[str] = []
    hit = grep_repo(ctx, _AUTOSCALING_RE)
    if hit:
        bits.append(f"autoscaling config in {hit[0]}:{hit[1]}")
    headroom = grep_repo(ctx, _HEADROOM_RE)
    if headroom:
        bits.append(f"resource sizing in {headroom[0]}:{headroom[1]}")
    return "; ".join(bits)
