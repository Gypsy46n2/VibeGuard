"""VG-OBS-001 / VG-OBS-002 / VG-OBS-006 — logging hygiene."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    Patch,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._fixes import (
    ensure_python_import,
    finding_snippet,
    insert_lines,
    is_python,
    line_at,
    locate_line,
    python_import_anchor,
    replace_line,
    whole_file_patch,
)
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    ProjectRule,
    RegexRule,
    source_files,
)
from vibeguard.rules.observability._common import (
    CODE_SUFFIXES,
    has_server,
    haystack,
    is_frontend_path,
    source_file_count,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DebugLogLevelRule", "NoLoggingFrameworkRule", "PrintDiagnosticsRule"]

_PRINT_PY = re.compile(r"(?<![\w.])print\s*\(")
_CONSOLE_JS = re.compile(r"(?<![\w.$])console\s*\.\s*(?:log|debug|info)\s*\(")
_MAIN_GUARD = re.compile(r"^\s*if\s+__name__\s*==")
_CLI_IMPORT = re.compile(r"(?m)^\s*(?:import|from)\s+(?:argparse|click|typer|fire|rich)\b")
#: A whole ``print(...)`` statement on one line, with its indentation and arguments.
_PRINT_STATEMENT = re.compile(r"(\s*)print\((.*)\)\s*")
#: An existing module logger to reuse rather than declaring a second one.
_EXISTING_LOGGER = re.compile(
    r"(?m)^(\w+)\s*=\s*(?:logging|structlog)\.get_?[Ll]ogger\s*\("
)


def _existing_logger(text: str) -> str | None:
    match = _EXISTING_LOGGER.search(text)
    return match.group(1) if match else None


def _single_simple_argument(args: str) -> bool:
    """True when ``args`` is exactly one argument: no top-level comma, no kwargs."""
    if not args.strip() or "**" in args:
        return False
    if re.search(r"\b(?:file|sep|end|flush)\s*=", args):
        return False
    depth = 0
    quote = ""
    for index, char in enumerate(args):
        if quote:
            if char == quote and args[index - 1] != "\\":
                quote = ""
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                return False
        elif char == "," and depth == 0:
            return False
    return depth == 0 and not quote


_SCRIPT_DIRS = {"scripts", "script", "bin", "tools", "tool", "tasks", "hack", "notebooks"}
_SCRIPT_NAMES = {"setup.py", "manage.py", "cli.py", "__main__.py", "main.py", "conftest.py"}


class PrintDiagnosticsRule(Rule):
    """``print()`` / ``console.log()`` used as the diagnostics channel."""

    id: ClassVar[str] = "VG-OBS-001"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Diagnostics printed instead of logged"
    description: ClassVar[str] = (
        "Application code writes diagnostics with `print()` or `console.log()` instead "
        "of a logger."
    )
    why_it_matters: ClassVar[str] = (
        "Printed output has no severity, no timestamp, and no way to be turned off, so "
        "in production it either floods the log pipeline with noise or vanishes "
        "entirely depending on how the process is started. When something breaks at "
        "3am you cannot filter to errors, and prints of request or user objects "
        "routinely dump passwords and tokens into logs that many people can read."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/howto/logging.html",
        "https://12factor.net/logs",
    ]
    topics: ClassVar[set[str]] = {
        "observability.structured-logging",
        "observability.log-levels",
        "security.sensitive-data-exposure",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.SAFE_AUTOFIX

    max_total: ClassVar[int] = 10
    max_per_file: ClassVar[int] = 3

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, CODE_SUFFIXES):
            if len(findings) >= self.max_total:
                break
            suffix = PurePosixPath(rel).suffix.lower()
            is_python = suffix in PY_SUFFIXES
            if not is_python and suffix not in JS_SUFFIXES:
                continue
            if self._skip_file(ctx, rel, is_python=is_python):
                continue
            text = ctx.read(rel)
            if not text:
                continue
            pattern = _PRINT_PY if is_python else _CONSOLE_JS
            comment = "#" if is_python else "//"
            guard_line = self._main_guard_line(text) if is_python else None
            per_file = 0
            for index, line in enumerate(text.splitlines()):
                if per_file >= self.max_per_file or len(findings) >= self.max_total:
                    break
                stripped = line.strip()
                if not stripped or stripped.startswith((comment, "*", "/*")):
                    continue
                if guard_line is not None and index >= guard_line:
                    continue
                if not pattern.search(line):
                    continue
                per_file += 1
                call = "print()" if is_python else "console.log()"
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=index + 1,
                        snippet=stripped[:200],
                        description=(
                            f"{call} is used for diagnostics at {rel}:{index + 1} "
                            "instead of a logger."
                        ),
                        recommended_followup=(
                            "Create a module logger once "
                            "(`logger = logging.getLogger(__name__)` in Python, a "
                            "`pino`/`winston` instance in Node) and replace the call "
                            "with `logger.info(...)` or `logger.debug(...)` so the "
                            "message carries a level and can be filtered."
                        ),
                    )
                )
        return findings

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Turn one ``print(x)`` into ``logger.info(x)``, scaffolding the logger once.

        Python only, and only for a single-argument ``print`` on one line: Python's
        ``print(a, b)`` joins its arguments, while ``logger.info(a, b)`` treats the
        rest as ``%``-format arguments, so a multi-argument call is *not* a
        like-for-like rewrite. Calls with ``file=`` (already routed somewhere
        deliberate), ``**kwargs``, or a name conflict on ``logger`` are left alone.
        Script-shaped files and ``__main__`` blocks are already excluded by detection —
        a CLI is supposed to write to stdout.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no or not is_python(rel):
            return None
        text = ctx.read(rel)
        target = locate_line(
            text,
            line_no,
            matches=lambda candidate: bool(_PRINT_STATEMENT.fullmatch(candidate)),
            snippet=finding_snippet(finding),
        )
        line = line_at(text, target)
        if target is None or line is None:
            return None
        line_no = target
        match = _PRINT_STATEMENT.fullmatch(line)
        if match is None:  # pragma: no cover - guaranteed by locate_line
            return None
        indent, args = match.group(1), match.group(2)
        if not _single_simple_argument(args):
            return None
        logger_name = _existing_logger(text)
        if logger_name is None and re.search(r"(?m)^logger\s*=", text):
            return None  # `logger` is already bound to something else
        name = logger_name or "logger"
        new_text = replace_line(text, line_no, f"{indent}{name}.info({args})")
        if logger_name is None:
            new_text = ensure_python_import(new_text, "import logging", "logging")
            new_text = insert_lines(
                new_text,
                python_import_anchor(new_text),
                ["", f"{name} = logging.getLogger(__name__)"],
            )
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=(
                f"Log the diagnostic at {rel}:{line_no} through the module logger instead "
                "of printing it."
            ),
            scope="observability",
            summary="log diagnostics through the module logger",
        )

    @staticmethod
    def _main_guard_line(text: str) -> int | None:
        for index, line in enumerate(text.splitlines()):
            if _MAIN_GUARD.match(line):
                return index
        return None

    @staticmethod
    def _skip_file(ctx: ScanContext, rel: str, *, is_python: bool) -> bool:
        path = PurePosixPath(rel)
        if {part.lower() for part in path.parts[:-1]} & _SCRIPT_DIRS:
            return True
        if is_python:
            if path.name.lower() in _SCRIPT_NAMES:
                return True
            # A file that builds a CLI is *supposed* to write to stdout.
            return bool(_CLI_IMPORT.search(ctx.read(rel)))
        return is_frontend_path(rel)


_LOG_IMPORT = re.compile(
    r"(?m)^\s*(?:import\s+logging\b|from\s+logging\b|import\s+structlog\b|"
    r"from\s+structlog\b|from\s+loguru\b|import\s+loguru\b)"
)
_LOG_JS = (
    "winston",
    "pino",
    "bunyan",
    "log4js",
    "@nestjs/common",
    "consola",
    "signale",
)
_LOG_CONFIG_NAMES = {
    "logging.conf",
    "logging.ini",
    "logging.yaml",
    "logging.yml",
    "logging.json",
    "log4j2.xml",
    "logback.xml",
    "pino.config.js",
}


class NoLoggingFrameworkRule(ProjectRule):
    """A server project with no logging library imported anywhere."""

    id: ClassVar[str] = "VG-OBS-002"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No logging framework configured"
    description: ClassVar[str] = (
        "No logging library is imported and no logging configuration file exists, so "
        "the service has no controllable diagnostics channel."
    )
    why_it_matters: ClassVar[str] = (
        "When a request fails in production, logs are usually the only record of what "
        "happened. Without a logging framework there is no severity, no timestamp, and "
        "no way to raise or lower verbosity without editing code and redeploying, so "
        "every investigation starts by adding prints and shipping again — often hours "
        "after the users who hit the bug have gone."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/howto/logging.html",
        "https://12factor.net/logs",
    ]
    topics: ClassVar[set[str]] = {
        "observability.structured-logging",
        "observability.monitoring",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    recommended_followup: ClassVar[str] = (
        "Configure logging once at start-up — `logging.basicConfig(level=os.environ."
        "get(\"LOG_LEVEL\", \"INFO\"))` plus `logger = logging.getLogger(__name__)` per "
        "module in Python, or a `pino()` instance exported from one module in Node — "
        "and log to stdout so the platform collects it."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_server(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            # A single-module project is a script, not a service worth instrumenting.
            if source_file_count(ctx) < 2:
                return None
            for rel in source_files(ctx, CODE_SUFFIXES):
                text = ctx.read(rel)
                if _LOG_IMPORT.search(text):
                    return None
                lowered = text.lower()
                if any(name in lowered for name in _LOG_JS):
                    return None
            for rel in ctx.files:
                if PurePosixPath(rel).name.lower() in _LOG_CONFIG_NAMES:
                    return None
            text = haystack(ctx)
            if any(name in text for name in _LOG_JS):
                return None
        except Exception:  # pragma: no cover - defensive
            return None
        return (
            "No logging framework is imported anywhere in the project and no logging "
            "configuration file exists.",
            "searched for logging/structlog/loguru imports, winston/pino/bunyan usage, "
            "and logging.conf / logback.xml style configuration",
        )


class DebugLogLevelRule(RegexRule):
    """DEBUG pinned as the log level outside tests."""

    id: ClassVar[str] = "VG-OBS-006"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Debug log level hardcoded"
    description: ClassVar[str] = (
        "The log level is pinned to DEBUG in code or configuration rather than being "
        "read from the environment."
    )
    why_it_matters: ClassVar[str] = (
        "DEBUG logging in production multiplies log volume by ten or more, which shows "
        "up directly on the log-ingestion bill and slows request handling under load. "
        "Worse, debug lines routinely include full request bodies, SQL parameters, and "
        "authorization headers, so pinning DEBUG quietly turns your log store into a "
        "copy of your users' personal data."
    )
    references: ClassVar[list[str]] = [
        "https://docs.python.org/3/howto/logging.html#logging-levels",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    ]
    topics: ClassVar[set[str]] = {
        "observability.log-levels",
        "cost.excessive-logging",
        "security.sensitive-data-exposure",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    suffixes: ClassVar[tuple[str, ...]] = CODE_SUFFIXES + (
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".json",
    )
    patterns: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"basicConfig\s*\([^)]*level\s*=\s*(?:logging\.)?DEBUG"),
        re.compile(r"\.setLevel\s*\(\s*(?:logging\.)?[\"']?DEBUG"),
        re.compile(
            r"(?i)^\s*(?:-\s*)?(?:export\s+)?LOG(?:GING)?[_\-]?LEVEL\s*[:=]\s*['\"]?debug\b"
        ),
        re.compile(r"(?i)\b(?:log_?)?level\s*[:=]\s*['\"]debug['\"]"),
        re.compile(r"(?i)\bDEBUG\s*[:=]\s*(?:True|true|1)\s*$"),
    )
    #: An env-driven default is fine; so is a level chosen inside a test helper.
    negative: ClassVar[re.Pattern[str] | None] = re.compile(
        r"(?i)os\.environ|getenv|process\.env|Deno\.env|\bif\s+debug\b|--debug"
    )
    max_per_file: ClassVar[int] = 2
    max_total: ClassVar[int] = 8
    recommended_followup: ClassVar[str] = (
        "Read the level from configuration instead: "
        "`logging.basicConfig(level=os.environ.get(\"LOG_LEVEL\", \"INFO\"))`, and set "
        "`LOG_LEVEL=DEBUG` only in local development."
    )

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return f"The log level is pinned to DEBUG at {relpath}:{line_no}."
