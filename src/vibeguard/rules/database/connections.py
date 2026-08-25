"""VG-DB-002 — a fresh database connection is opened for every request.

Deliberate scope note: ``sqlite3.connect`` is **not** treated as a finding. SQLite is
an in-process file database with no server to pool against, and opening a connection
per request is the pattern Flask's and Django's own documentation recommend. Flagging
it would be a false positive with no available remediation. Client/server drivers
(Postgres, MySQL, Mongo) are where pooling actually applies.
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
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    calls,
    enclosing_function,
    in_loop,
    node_text,
    source_files,
)
from vibeguard.rules.database._common import (
    MAX_FINDINGS,
    call_name,
    function_name,
    is_request_handler,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["ConnectionPerRequestRule"]

_CODE_SUFFIXES = PY_SUFFIXES + JS_SUFFIXES

#: Client/server driver constructors. ``sqlite3``/``aiosqlite`` are excluded on purpose.
_CONNECT_NAMES = {
    "psycopg2.connect",
    "psycopg.connect",
    "psycopg.asyncconnect",
    "asyncpg.connect",
    "pymysql.connect",
    "mysqldb.connect",
    "mysql.connector.connect",
    "mongoclient",
    "asynciomotorclient",
    "motor.motor_asyncio.asynciomotorclient",
    "pymongo.mongoclient",
    "mysql.createconnection",
    "createconnection",
}
_NEW_CONSTRUCTORS = {"client", "mongoclient", "connection", "pgclient", "pgconnection"}

_FACTORY_NAME = re.compile(
    r"(^|_)(conn|connect|connection|db|database|client|engine|session)(_|$)", re.IGNORECASE
)
_NULL_POOL = re.compile(r"poolclass\s*=\s*NullPool", re.IGNORECASE)
_EXPLICIT_POOL = re.compile(
    r"\bQueuePool\b|\bpool_size\s*=|\bcreatePool\s*\(|\bnew\s+Pool\s*\(|"
    r"\bconnection_pool\b|\bConnectionPool\b|\bpgbouncer\b|\bSessionLocal\b|"
    r"\bscoped_session\s*\(|\bmax_pool_size\s*=|\bmaxPoolSize\b",
    re.IGNORECASE,
)


def _is_connect_call(source: bytes, site: CallSite) -> str:
    """The constructor name when ``site`` opens a driver connection, else ""."""
    raw = call_name(source, site)
    name = raw.lower()
    if name in _CONNECT_NAMES:
        return raw
    node_type = getattr(site.node, "type", "")
    if node_type == "new_expression" and name.rsplit(".", 1)[-1] in _NEW_CONSTRUCTORS:
        return raw
    if name.endswith(".createconnection"):
        return raw
    return ""


class ConnectionPerRequestRule(Rule):
    """A driver connection constructed inside per-request code, with no pool."""

    id: ClassVar[str] = "VG-DB-002"
    category: ClassVar[Category] = Category.DATABASE
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Database connection opened per request without pooling"
    description: ClassVar[str] = (
        "A database connection is constructed inside request-scoped code rather than "
        "taken from a shared pool, so every request pays a full connect handshake."
    )
    why_it_matters: ClassVar[str] = (
        "Opening a Postgres or MySQL connection costs a TCP handshake, a TLS handshake, "
        "and authentication — tens of milliseconds added to every single request. Worse, "
        "databases cap the number of concurrent connections: under a traffic spike the "
        "app opens more connections than the server allows and every request starts "
        "failing with 'too many connections', including the healthy ones."
    )
    references: ClassVar[list[str]] = [
        "https://docs.sqlalchemy.org/en/20/core/pooling.html",
        "https://node-postgres.com/features/pooling",
    ]
    topics: ClassVar[set[str]] = {
        "database.connection-pooling",
        "concurrency.connection-leaks",
        "performance.database-bottlenecks",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, _CODE_SUFFIXES):
            if len(findings) >= MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text:
                continue
            source = text.encode("utf-8")
            sites = calls(ctx, rel)
            findings.extend(self._null_pool_findings(rel, source, sites))
            if _EXPLICIT_POOL.search(text):
                continue
            # A module-level connection is a singleton, not a per-request connect.
            if any(
                _is_connect_call(source, site) and enclosing_function(site.node) is None
                for site in sites
            ):
                continue
            for site in sites:
                if len(findings) >= MAX_FINDINGS:
                    break
                callee = _is_connect_call(source, site)
                if not callee:
                    continue
                func = enclosing_function(site.node)
                if func is None:
                    continue
                name = function_name(source, func)
                per_request = (
                    is_request_handler(source, func)
                    or bool(_FACTORY_NAME.search(name))
                    or in_loop(site.node)
                )
                if not per_request:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=site.line,
                        snippet=node_text(source, site.node)[:200],
                        description=(
                            f"{callee}(...) opens a new connection inside "
                            f"{name or 'a request-scoped function'}() in {rel}; no "
                            "connection pool was found in this module."
                        ),
                        recommended_followup=(
                            "Create the pool once at startup and hand connections out per "
                            "request — `create_engine(url, pool_size=..., max_overflow=...)` "
                            "with a scoped session (SQLAlchemy), `psycopg_pool."
                            "ConnectionPool`, or `new Pool({...})` from `pg` — and close "
                            "the checked-out connection in a `finally`."
                        ),
                    )
                )
        return findings

    def _null_pool_findings(
        self, rel: str, source: bytes, sites: list[CallSite]
    ) -> list[Finding]:
        """``create_engine(..., poolclass=NullPool)`` disables pooling explicitly."""
        out: list[Finding] = []
        for site in sites:
            if site.base.lower() != "create_engine" or not _NULL_POOL.search(site.args):
                continue
            out.append(
                self.make_finding(
                    file=rel,
                    line=site.line,
                    snippet=node_text(source, site.node)[:200],
                    description=(
                        f"create_engine(..., poolclass=NullPool) in {rel} (line "
                        f"{site.line}) turns pooling off, so every checkout opens a new "
                        "connection."
                    ),
                    recommended_followup=(
                        "Drop `poolclass=NullPool` and size the pool explicitly "
                        "(`pool_size`, `max_overflow`, `pool_pre_ping=True`). Keep "
                        "NullPool only when an external pooler such as pgbouncer already "
                        "sits in front of the database — and say so in a comment."
                    ),
                )
            )
            break
        return out
