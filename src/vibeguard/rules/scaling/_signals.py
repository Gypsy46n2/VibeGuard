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
    "is_request_path",
    "is_web_app",
    "server_roots",
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


#: Constructing a server, or declaring a route on one. Importing a web framework is
#: not enough — a CLI that can *also* start a local UI imports one too.
_APP_CONSTRUCT = re.compile(
    r"\b(?:Flask|FastAPI|Sanic|Bottle|Starlette|Quart|Falcon)\s*\(|"
    r"\b(?:tornado\.)?web\.Application\s*\(|"
    r"\bexpress\s*\(\s*\)|\bnew\s+Koa\s*\(|\bfastify\s*\(|\bHapi\.server\s*\(|"
    r"\bhttp\.createServer\s*\(|\bNestFactory\.create\s*\(|"
    r"\b(?:app|server)\.(?:use|listen)\s*\(|"
    r"@(?:app|router|bp|blueprint|api|route)\.(?:route|get|post|put|patch|delete)\b|"
    r"@api_view\b|\bAPIRouter\s*\("
)
#: Django has no explicit construction call; these files *are* the server.
_DJANGO_FILES = {"manage.py", "urls.py", "views.py", "asgi.py", "wsgi.py"}
_APP_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def server_roots(ctx: ScanContext) -> tuple[str, ...]:
    """Directories that contain request-serving code, POSIX-relative to the scan root.

    ``""`` means the repository root itself — the normal shape for a flat app whose
    ``app.py`` or ``server.js`` sits at the top level, and it makes the whole tree
    count as the server.
    """
    cached = ctx._scratch.get("server_roots")
    if cached is not None:
        return cached
    roots: set[str] = set()
    seen = 0
    for rel in ctx.files:
        if seen >= _MAX_FILES:
            break
        path = PurePosixPath(rel)
        if path.suffix.lower() not in _APP_SUFFIXES or is_generated_path(rel):
            continue
        seen += 1
        if path.name.lower() in _DJANGO_FILES:
            roots.add(str(path.parent) if str(path.parent) != "." else "")
            continue
        text = ctx.read(rel)
        if text and len(text) <= _MAX_BYTES and _APP_CONSTRUCT.search(text):
            roots.add(str(path.parent) if str(path.parent) != "." else "")
    result = tuple(sorted(roots))
    ctx._scratch["server_roots"] = result
    return result


def is_request_path(ctx: ScanContext, relpath: str) -> bool:
    """True when ``relpath`` belongs to the part of the project that serves requests.

    The multi-instance arguments — "a second instance keeps its own copy", "a restart
    wipes every session" — only apply to code on the request path. A parser cache in a
    CLI's discovery layer is not that, even when the same repository happens to ship a
    small web UI somewhere else, and telling its author to adopt Redis is exactly the
    disproportionate advice VibeGuard promises not to give (DECISIONS.md D66).
    """
    if not is_web_app(ctx):
        return False
    roots = server_roots(ctx)
    if not roots:
        # A framework is declared but we cannot see where it is wired up. Narrowing
        # on a guess would silently drop true findings, so fall back to the whole tree.
        return True
    rel = str(relpath)
    return any(root == "" or rel == root or rel.startswith(f"{root}/") for root in roots)


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
