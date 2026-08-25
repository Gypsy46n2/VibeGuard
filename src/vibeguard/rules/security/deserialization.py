"""VG-SEC-009 — insecure deserialization of untrusted data."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import Category, Confidence, Finding, ScaleClass, Severity
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    js_calls,
    node_text,
    py_calls,
    source_files,
)
from vibeguard.rules.security._taint import first_arg, has_literal_only, is_tainted

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["InsecureDeserializationRule"]

_MAX = 6

_PY_MODULES = ("pickle", "cPickle", "_pickle", "dill", "marshal", "shelve", "jsonpickle")
_PY_BASES = {"loads", "load", "decode", "open"}
_SAFE_LOADER = re.compile(r"Loader\s*=|safe_load|SafeLoader|CSafeLoader")
_JS_SINKS = {"unserialize", "runInNewContext", "runInThisContext", "runInContext"}


class InsecureDeserializationRule(Rule):
    """Untrusted bytes handed to a deserialiser that can construct arbitrary objects."""

    id: ClassVar[str] = "VG-SEC-009"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Insecure deserialization of untrusted data"
    description: ClassVar[str] = (
        "Data is deserialised with a mechanism that can instantiate arbitrary objects or "
        "evaluate code (pickle, marshal, shelve, yaml.load without a safe loader, "
        "eval/exec, node-serialize, vm.runInNewContext)."
    )
    why_it_matters: ClassVar[str] = (
        "These formats do not just carry data — they carry instructions for rebuilding "
        "objects, and rebuilding can execute code. If an attacker can influence the bytes "
        "(a cookie, a cache entry, an uploaded file, a queue message), they get remote "
        "code execution on your server with no memory-corruption tricks required."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        "https://docs.python.org/3/library/pickle.html#module-pickle",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.insecure-deserialization"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in py_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                reason = self._py_reason(source, call)
                if reason is None:
                    continue
                arg = first_arg(call.node)
                tainted = arg is not None and is_tainted(source, arg)
                findings.append(self._finding(rel, call, reason, tainted, source))
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if call.base not in _JS_SINKS:
                    continue
                arg = first_arg(call.node)
                if arg is None or has_literal_only(arg):
                    continue
                tainted = is_tainted(source, arg)
                findings.append(
                    self._finding(rel, call, f"`{call.name}` runs untrusted input", tainted, source)
                )
        return findings

    def _py_reason(self, source: bytes, call: CallSite) -> str | None:
        name = call.name
        if call.base in _PY_BASES and name.startswith(_PY_MODULES):
            if call.base == "open" and not name.startswith("shelve"):
                return None
            return f"`{name}` reconstructs arbitrary Python objects"
        if call.base == "load" and "yaml" in name:
            if _SAFE_LOADER.search(call.args):
                return None
            return "`yaml.load` without a safe Loader can construct arbitrary objects"
        if name in {"eval", "exec"}:
            arg = first_arg(call.node)
            if arg is None or has_literal_only(arg):
                return None
            if arg.type in {"string", "concatenated_string"}:
                return None
            return f"`{name}` evaluates a non-literal expression"
        return None

    def _finding(
        self, rel: str, call: CallSite, reason: str, tainted: bool, source: bytes
    ) -> Finding:
        arg = first_arg(call.node)
        snippet = f"{call.name}({node_text(source, arg).strip()[:150] if arg else ''})"
        return self.make_finding(
            file=rel,
            line=call.line,
            severity=Severity.CRITICAL if tainted else Severity.HIGH,
            snippet=snippet,
            description=(
                f"{rel}:{call.line}: {reason}"
                + (" and its input is request-derived." if tainted else ".")
            ),
            recommended_followup=(
                "Switch to a data-only format: `json.loads` / `yaml.safe_load` / "
                "`JSON.parse`. If a rich object graph is genuinely required, sign the "
                "payload (HMAC) and verify the signature before deserialising, and never "
                "deserialise anything that crossed a trust boundary unsigned."
            ),
        )
