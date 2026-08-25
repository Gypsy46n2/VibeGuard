"""VG-SCALE-001 — application state kept in process memory."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
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
from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, source_files
from vibeguard.rules.scaling._signals import grep_repo, is_request_path, is_web_app

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["InProcessStateRule"]

_MAX_FINDINGS = 5

#: Names that betray shared, request-spanning state rather than a constant.
_STATE_NAME = (
    r"[A-Za-z_]*(?:session|sessions|cart|carts|cache|caches|counter|counters|"
    r"rate_?limit|ratelimits?|attempts|jobs|job_registry|tasks|task_registry|"
    r"users|tokens|otp|pending|queue|store|state)[A-Za-z_]*"
)
#: Module-level mutable container in Python (no indentation).
_PY_MODULE_STATE = re.compile(
    rf"^({_STATE_NAME})\s*(?::[^=]+)?=\s*(\{{\s*\}}|\[\s*\]|dict\(\)|list\(\)|set\(\)|"
    r"defaultdict\(|OrderedDict\(|TTLCache\(|LRUCache\()",
    re.IGNORECASE,
)
#: Module-level mutable container in JS/TS (no indentation).
_JS_MODULE_STATE = re.compile(
    rf"^(?:const|let|var)\s+({_STATE_NAME})\s*(?::[^=]+)?=\s*"
    r"(\{\s*\}|\[\s*\]|new Map\(|new Set\(|new NodeCache\()",
    re.IGNORECASE,
)

_PY_FLASK_SESSION = re.compile(r"\bsession\[|\bsession\.get\(|\bsession\.pop\(")
_PY_FILESYSTEM_SESSION = re.compile(
    r"SESSION_TYPE[\"']?\]?\s*[:=]\s*[\"'](?:filesystem|null|cachelib)[\"']", re.IGNORECASE
)
#: express-session invoked without a `store:` option.
_JS_EXPRESS_SESSION = re.compile(r"\bsession\s*\(\s*\{")

_SERVER_SIDE_STORE = re.compile(
    r"flask_session|flask-session|RedisSessionInterface|connect-redis|connect-mongo|"
    r"express-mysql-session|session-file-store|SESSION_TYPE\s*[:=]\s*[\"'](?:redis|"
    r"memcached|mongodb|sqlalchemy)[\"']|RedisStore|"
    r"django\.contrib\.sessions\.backends\.(?:db|cache|cached_db)",
    re.IGNORECASE,
)


def _mutated(text: str, name: str) -> bool:
    """True when ``name`` looks like it is written to somewhere in ``text``."""
    escaped = re.escape(name)
    mutation = re.compile(
        rf"\b{escaped}\s*\[[^\n]*\]\s*(?:=[^=]|\+=|-=)|"
        rf"\b{escaped}\.(?:append|add|update|push|set|setdefault|pop|extend|delete)\s*\(|"
        rf"del\s+{escaped}\s*\[",
    )
    return bool(mutation.search(text))


class InProcessStateRule(Rule):
    """Session, cart, cache, or counter state held in a single process's memory."""

    id: ClassVar[str] = "VG-SCALE-001"
    category: ClassVar[Category] = Category.SCALABILITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Application state kept in process memory"
    description: ClassVar[str] = (
        "Request-spanning state (sessions, carts, counters, job registries) lives in a "
        "module-level variable or a default in-memory session store."
    )
    why_it_matters: ClassVar[str] = (
        "This works perfectly until the day a second instance starts. Then half the "
        "requests land on a process that has never heard of the user's cart, logins drop "
        "at random, and rate limits count to N separately per instance. It also means a "
        "restart or redeploy silently wipes everyone's session, and the failure looks like "
        "a flaky bug rather than an architecture problem, so it is hard to diagnose."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/processes",
        "https://expressjs.com/en/resources/middleware/session.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "scaling.statelessness",
        "scaling.session-storage",
        "scaling.sticky-sessions",
        "scaling.horizontal-scaling",
        "scaling.multi-instance-behavior",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    # M3 fix(): none — moving state to Redis is an architecture change, not a patch.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        if not is_web_app(ctx):
            return []
        has_store = grep_repo(ctx, _SERVER_SIDE_STORE) is not None
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(findings) >= _MAX_FINDINGS:
                break
            if not is_request_path(ctx, rel):
                continue
            text = ctx.read(rel)
            if not text or len(text) > 400_000:
                continue
            is_py = PurePosixPath(rel).suffix.lower() in PY_SUFFIXES
            flask = "flask" in ctx.tech.all_technologies()
            findings.extend(
                self._scan_file(rel, text, is_py=is_py, has_store=has_store, flask=flask)
            )
        return findings[:_MAX_FINDINGS]

    # ------------------------------------------------------------------ helpers
    def _scan_file(
        self, rel: str, text: str, *, is_py: bool, has_store: bool, flask: bool
    ) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        module_re = _PY_MODULE_STATE if is_py else _JS_MODULE_STATE
        for index, line in enumerate(lines):
            if len(out) >= _MAX_FINDINGS or len(line) > 500:
                break
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            match = module_re.match(line)
            if match is None:
                continue
            name = match.group(1)
            if name.isupper() and not _mutated(text, name):
                continue  # a module constant, not shared state
            if not _mutated(text, name):
                continue
            out.append(
                self._finding(
                    rel,
                    index + 1,
                    stripped,
                    (
                        f"`{name}` is a module-level mutable container that is written to "
                        "from application code, so it holds request-spanning state inside "
                        "one process's memory. A second instance behind a load balancer "
                        "would keep its own separate copy."
                    ),
                    (
                        f"Move `{name}` into a shared store — Redis for sessions, carts, "
                        "counters and rate limits; the database for anything that must "
                        "survive a restart — and read it per request instead of holding "
                        "it in a module global."
                    ),
                )
            )
        if not has_store:
            out.extend(self._session_findings(rel, lines, is_py=is_py, flask=flask))
        return out

    def _session_findings(
        self, rel: str, lines: list[str], *, is_py: bool, flask: bool
    ) -> list[Finding]:
        out: list[Finding] = []
        for index, line in enumerate(lines):
            if out:
                break
            if len(line) > 500:
                continue
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            if is_py and _PY_FILESYSTEM_SESSION.search(line):
                out.append(
                    self._finding(
                        rel,
                        index + 1,
                        stripped,
                        (
                            "`SESSION_TYPE` is set to a per-process backend, so sessions "
                            "live on one instance's local disk or memory rather than in a "
                            "store every instance can reach."
                        ),
                        (
                            'Set `SESSION_TYPE = "redis"` and configure `SESSION_REDIS`, '
                            "so every instance reads the same sessions."
                        ),
                    )
                )
            elif is_py and flask and _PY_FLASK_SESSION.search(line) and "request." not in line:
                out.append(
                    self._finding(
                        rel,
                        index + 1,
                        stripped,
                        (
                            "Flask's `session` is used with the default client-side cookie "
                            "backend and no server-side session store was found anywhere "
                            "in the project. Session data is therefore held per process "
                            "(or per browser cookie), not in shared storage."
                        ),
                        (
                            "Add Flask-Session backed by Redis (`SESSION_TYPE = \"redis\"`) "
                            "so sessions survive a restart and are visible to every "
                            "instance."
                        ),
                    )
                )
            elif not is_py and _JS_EXPRESS_SESSION.search(line) and "store" not in line:
                out.append(
                    self._finding(
                        rel,
                        index + 1,
                        stripped,
                        (
                            "`express-session` is configured without a `store:` option, so "
                            "it falls back to the built-in MemoryStore — single-process, "
                            "wiped on restart, and explicitly documented as unsuitable for "
                            "production."
                        ),
                        (
                            "Pass a shared store, e.g. "
                            "`session({ store: new RedisStore({ client }), ... })` using "
                            "connect-redis."
                        ),
                    )
                )
        return out

    def _finding(
        self, rel: str, line_no: int, snippet: str, description: str, followup: str
    ) -> Finding:
        return self.make_finding(
            file=rel,
            line=line_no,
            snippet=snippet[:400],
            description=description,
            recommended_followup=followup,
        )


RULES: list[type[Rule]] = [InProcessStateRule]
