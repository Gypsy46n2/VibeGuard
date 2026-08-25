"""VG-SEC-007 / VG-SEC-008 — command injection and path traversal."""

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
    js_calls,
    node_text,
    py_calls,
    source_files,
)
from vibeguard.rules.security._taint import (
    arg_nodes,
    block_text,
    first_arg,
    is_interpolated_js,
    is_interpolated_py,
    is_tainted,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["CommandInjectionRule", "PathTraversalRule"]

_MAX = 6

_PY_SHELL_DIRECT = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}
_PY_SUBPROCESS = {"call", "run", "Popen", "check_output", "check_call", "getoutput"}
_SHELL_TRUE = re.compile(r"shell\s*=\s*True")
_JS_SHELL_TRUE = re.compile(r"shell\s*:\s*true")


class CommandInjectionRule(Rule):
    """A shell command line built from interpolated or request-derived text."""

    id: ClassVar[str] = "VG-SEC-007"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Command injection via shell execution"
    description: ClassVar[str] = (
        "A command string that is interpolated or derived from request input is executed "
        "through a shell, so shell metacharacters in the value become extra commands."
    )
    why_it_matters: ClassVar[str] = (
        "A shell treats `;`, `|`, `&&` and backticks as instructions, not data. One "
        "semicolon in a filename or query parameter turns your image-resize call into "
        "arbitrary code running as the application user — the attacker reads your "
        "environment variables, your database credentials, and everything on disk."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/78.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.command-injection"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): shell=False with an argument list.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in py_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if not self._py_uses_shell(call):
                    continue
                arg = first_arg(call.node)
                if arg is None:
                    continue
                if not (is_interpolated_py(source, arg) or is_tainted(source, arg)):
                    continue
                findings.append(self._finding(rel, call, node_text(source, arg)))
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if not self._js_uses_shell(call):
                    continue
                arg = first_arg(call.node)
                if arg is None:
                    continue
                if not (is_interpolated_js(source, arg) or is_tainted(source, arg)):
                    continue
                findings.append(self._finding(rel, call, node_text(source, arg)))
        return findings

    def _py_uses_shell(self, call: CallSite) -> bool:
        if call.name in _PY_SHELL_DIRECT:
            return True
        if call.base in {"system", "popen"} and call.name.startswith("os."):
            return True
        if call.base in _PY_SUBPROCESS and "subprocess" in call.name:
            return bool(_SHELL_TRUE.search(call.args))
        return False

    def _js_uses_shell(self, call: CallSite) -> bool:
        if call.base in {"exec", "execSync"}:
            return True
        if call.base in {"spawn", "spawnSync", "execFile"}:
            return bool(_JS_SHELL_TRUE.search(call.args))
        return False

    def _finding(self, rel: str, call: CallSite, cmd: str) -> Finding:
        return self.make_finding(
            file=rel,
            line=call.line,
            snippet=f"{call.name}({cmd.strip()[:180]})",
            description=(
                f"`{call.name}(...)` at {rel}:{call.line} runs a shell command whose text is "
                "interpolated or request-derived."
            ),
            recommended_followup=(
                "Pass an argument list and keep the shell out of it: "
                "`subprocess.run(['convert', src, dst], shell=False, check=True)` or "
                "`execFile('convert', [src, dst])`. If a shell is unavoidable, validate the "
                "value against a strict allowlist first."
            ),
        )


_PY_FILE_SINKS = {"open", "send_file", "send_from_directory", "read_text", "read_bytes"}
_JS_FILE_SINKS = {
    "sendFile",
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "createReadStream",
}
_CONTAINMENT = re.compile(
    r"secure_filename|os\.path\.basename|Path\([^)]*\)\.name\b|\.resolve\(\)|"
    r"path\.resolve|path\.basename|path\.normalize|is_relative_to|"
    r"werkzeug\.utils\.secure_filename",
)


class PathTraversalRule(Rule):
    """A file path built from request input without a containment check."""

    id: ClassVar[str] = "VG-SEC-008"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "File path derived from request input"
    description: ClassVar[str] = (
        "A file is opened or served using a path that comes from request input, with no "
        "`secure_filename`, `basename`, or resolved-prefix check in the same function."
    )
    why_it_matters: ClassVar[str] = (
        "`../../etc/passwd` is a valid filename as far as the filesystem is concerned. "
        "Without a containment check a download endpoint will happily hand out your "
        "config files, SSH keys, or `.env` — and an upload path will happily overwrite "
        "them."
    )
    references: ClassVar[list[str]] = [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cwe.mitre.org/data/definitions/22.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.path-traversal", "security.file-upload"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for suffixes, extractor, sinks in (
            (PY_SUFFIXES, py_calls, _PY_FILE_SINKS),
            (JS_SUFFIXES, js_calls, _JS_FILE_SINKS),
        ):
            for rel in source_files(ctx, suffixes):
                if len(findings) >= _MAX:
                    break
                source = ctx.read(rel).encode("utf-8")
                for call in extractor(ctx, rel):
                    if len(findings) >= _MAX:
                        break
                    if call.base not in sinks:
                        continue
                    args = arg_nodes(call.node)
                    if not args:
                        continue
                    tainted = next(
                        (arg for arg in args[:2] if is_tainted(source, arg)),
                        None,
                    )
                    if tainted is None:
                        continue
                    if _CONTAINMENT.search(block_text(source, call.node)):
                        continue
                    findings.append(
                        self.make_finding(
                            file=rel,
                            line=call.line,
                            snippet=f"{call.name}({node_text(source, tainted).strip()[:180]})",
                            description=(
                                f"`{call.name}(...)` at {rel}:{call.line} builds a filesystem "
                                "path from request input and no containment check "
                                "(`secure_filename`, `basename`, resolved-prefix comparison) "
                                "appears in the enclosing function."
                            ),
                            recommended_followup=(
                                "Reduce the value to a bare filename "
                                "(`werkzeug.utils.secure_filename` / `path.basename`), join it "
                                "to a fixed base directory, then assert the resolved path is "
                                "still inside that directory before opening it."
                            ),
                        )
                    )
        return findings
