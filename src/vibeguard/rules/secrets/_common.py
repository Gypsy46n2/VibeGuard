"""Helpers private to the secrets rule pack.

Everything here exists to bound false positives: placeholder values, environment
lookups, and ``.env`` templates are the three biggest sources of noise in secret
scanning, so each gets an explicit filter that every rule in the pack reuses.
"""

from __future__ import annotations

import logging
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import Finding
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    RegexRule,
    source_files,
    strip_quotes,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "CODE_SUFFIXES",
    "CONFIG_SUFFIXES",
    "SecretRegexRule",
    "is_env_template",
    "is_placeholder",
    "looks_like_env_lookup",
    "split_call_args",
]

log = logging.getLogger(__name__)


CODE_SUFFIXES: tuple[str, ...] = PY_SUFFIXES + JS_SUFFIXES
CONFIG_SUFFIXES: tuple[str, ...] = (
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".json",
    ".properties",
    ".sh",
    ".tf",
    ".tfvars",
)

# ------------------------------------------------------------------ placeholders

_PLACEHOLDER_WORDS = frozenset(
    {
        "",
        "abc",
        "abc123",
        "admin",
        "api_key",
        "apikey",
        "asdf",
        "bar",
        "baz",
        "changeit",
        "changeme",
        "change_me",
        "change-me",
        "credentials",
        "demo",
        "dev",
        "development",
        "dummy",
        "example",
        "fake",
        "foo",
        "guest",
        "here",
        "insecure",
        "key",
        "local",
        "localhost",
        "mysql",
        "n/a",
        "none",
        "not-a-secret",
        "notasecret",
        "notsecret",
        "null",
        "pass",
        "passwd",
        "password",
        "placeholder",
        "postgres",
        "pwd",
        "redis",
        "replaceme",
        "replace_me",
        "replace-me",
        "root",
        "sample",
        "secret",
        "string",
        "tbd",
        "test",
        "testing",
        "todo",
        "undefined",
        "unset",
        "user",
        "username",
        "value",
        "xxx",
        "yourkey",
        "your_key",
        "your-key",
    }
)

#: ``${VAR}``, ``<your key>``, ``{{ secret }}``, ``%(pw)s``, ``$SECRET``, ``xxxxxx``.
_TEMPLATED = re.compile(
    r"""^(?:
        [xX*.\-_?#]{3,}
      | <[^>]*>
      | \$\{[^}]*\}
      | \{\{[^}]*\}\}
      | \$\([^)]*\)
      | %\([^)]*\)s
      | \$[A-Za-z_][A-Za-z0-9_]*
      | \{[A-Za-z0-9_]*\}
    )$""",
    re.VERBOSE,
)

#: ``dev-secret``, ``my_api_key``, ``your-token``, ``test_password`` and friends.
_PLACEHOLDER_COMPOUND = re.compile(
    r"^(?:dev|devel|development|test|testing|local|fake|dummy|sample|demo|example|"
    r"placeholder|my|your|our|some|any|the|changeme|change|replace|insecure|temp|tmp|"
    r"default|super|top)[-_ ]?"
    r"(?:secret|secrets|key|keys|token|tokens|password|passwd|pwd|pass|value|apikey|"
    r"api[-_]?key|credential|credentials|auth|hash|salt|only|mode|env|here)[-_ ]?"
    r"(?:key|value|here|1|123)?$",
    re.IGNORECASE,
)

#: Substrings that mark a value as documentation rather than a live credential.
_PLACEHOLDER_SUBSTRINGS = (
    "example",
    "changeme",
    "change-me",
    "change_me",
    "replaceme",
    "replace-me",
    "replace_me",
    "yourkey",
    "your-key",
    "your_key",
    "your-api",
    "your_api",
    "youraccount",
    "placeholder",
    "xxxxxxxx",
    "redacted",
    "notasecret",
    "not-a-secret",
    "dummy",
    "<your",
    "insert-",
    "insert_",
)


def is_placeholder(value: str) -> bool:
    """True when ``value`` is documentation, a template, or an obvious dev stub."""
    text = strip_quotes(str(value or "")).strip()
    if not text or len(text) < 4:
        return True
    lowered = text.lower()
    if lowered in _PLACEHOLDER_WORDS:
        return True
    if _TEMPLATED.match(text) or _PLACEHOLDER_COMPOUND.match(text):
        return True
    if any(needle in lowered for needle in _PLACEHOLDER_SUBSTRINGS):
        return True
    # A single repeated character ("aaaaaaaa", "00000000") is never a real secret.
    return len(set(lowered)) <= 2


_ENV_LOOKUP = re.compile(
    r"""(?ix)
    os\.environ
  | os\.getenv
  | \bgetenv\s*\(
  | process\.env
  | Deno\.env
  | import\.meta\.env
  | \bconfig\s*\(
  | \bEnv\s*\(
  | \bSecret(?:Str|Manager|Client)\b
  | get_secret
  | \bvault\b
  | \bkeyring\b
  | secretKeyRef
  | \bfrom_env\b
    """
)


#: ``settings.jwt_secret``, ``conf.get`` — an attribute path, not a literal secret.
_CODE_REFERENCE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")


def looks_like_code_reference(value: str) -> bool:
    """True when ``value`` is a dotted attribute path or an identifier, not a literal.

    Only meaningful inside source files: in a ``.env`` or YAML file the same text is
    a value, not a name. Long values are exempt because real tokens (SendGrid keys,
    for instance) can look identifier-shaped.
    """
    text = str(value or "")
    return len(text) <= 40 and bool(_CODE_REFERENCE.match(text))


def looks_like_env_lookup(line: str) -> bool:
    """True when the value on ``line`` is read from the environment or a secret store."""
    return bool(_ENV_LOOKUP.search(line or ""))


_ENV_TEMPLATE_SUFFIXES = (
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".tpl",
    ".defaults",
    ".default",
)


def is_env_template(relpath: str) -> bool:
    """True for ``.env.example`` / ``.env.sample`` / ``.env.template`` style files."""
    name = PurePosixPath(str(relpath)).name.lower()
    if not name.startswith(".env") and "env" not in name:
        return False
    return name.endswith(_ENV_TEMPLATE_SUFFIXES) or "example" in name or "sample" in name


def is_dotenv(relpath: str) -> bool:
    """True for a ``.env``-family file (templates included)."""
    return PurePosixPath(str(relpath)).name.lower().startswith(".env")


def split_call_args(args: str) -> list[str]:
    """Split a call-argument string on top-level commas.

    ``'({"a": 1}, "key", algorithm="HS256")'`` -> ``['{"a": 1}', '"key"', ...]``.
    Returns ``[]`` for anything it cannot make sense of.
    """
    text = str(args or "").strip()
    if text.startswith("("):
        text = text[1:]
    if text.endswith(")"):
        text = text[:-1]
    out: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for char in text:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth <= 0:
            out.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        out.append(tail)
    return out


def is_string_literal(arg: str) -> bool:
    """True when ``arg`` is a bare quoted string (not a name or env lookup)."""
    text = str(arg or "").strip()
    if len(text) < 2 or text[0] not in "\"'`":
        return False
    return text[-1] == text[0]


# ------------------------------------------------------------------- base class

_COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "py": ("#",),
    "js": ("//", "*", "/*"),
    "conf": ("#", ";"),
}


def _is_comment_line(line: str, suffix: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if suffix in PY_SUFFIXES:
        return stripped.startswith(_COMMENT_PREFIXES["py"])
    if suffix in JS_SUFFIXES:
        return stripped.startswith(_COMMENT_PREFIXES["js"])
    return stripped.startswith(_COMMENT_PREFIXES["conf"])


class SecretRegexRule(RegexRule):
    """A :class:`RegexRule` whose patterns capture the credential in a ``value`` group.

    Matches are dropped when the captured value is a placeholder, when the line is
    really an environment lookup, or when the file is a ``.env`` template. Evidence
    is always redacted (the SECRETS category redacts anyway; this is belt and braces).
    """

    suffixes: ClassVar[tuple[str, ...]] = CODE_SUFFIXES + CONFIG_SUFFIXES
    redact_evidence: ClassVar[bool] = True
    max_per_file: ClassVar[int] = 3
    max_total: ClassVar[int] = 10
    #: Also scan ``.env``-family files (which have no useful suffix).
    scan_dotenv: ClassVar[bool] = True
    #: Reject captured values shorter than this.
    min_value_length: ClassVar[int] = 8
    #: Reject a match whose *line* matches this (context guard).
    line_negative: ClassVar[re.Pattern[str] | None] = None
    #: Patterns for *unquoted* ``KEY=value`` assignments. Only applied to config and
    #: ``.env`` files: in source code an unquoted value is a variable reference, not
    #: a credential, and matching it there is pure false-positive noise.
    bare_patterns: ClassVar[tuple[re.Pattern[str], ...]] = ()

    def files_to_scan(self, ctx: ScanContext) -> list[str]:
        rels = source_files(
            ctx,
            self.suffixes,
            skip_tests=self.skip_tests,
            skip_generated=self.skip_generated,
        )
        if self.scan_dotenv:
            seen = set(rels)
            rels = rels + [
                rel
                for rel in ctx.files
                if is_dotenv(rel) and rel not in seen and not is_env_template(rel)
            ]
        return [rel for rel in rels if not is_env_template(rel)]

    def accepts(self, ctx: ScanContext, relpath: str, line: str, match: re.Match[str]) -> bool:
        """Extra per-match guard; subclasses may narrow further."""
        value = strip_quotes(match.groupdict().get("value") or "")
        if len(value) < self.min_value_length or is_placeholder(value):
            return False
        if looks_like_env_lookup(line):
            return False
        suffix = PurePosixPath(relpath).suffix.lower()
        if suffix in CODE_SUFFIXES and looks_like_code_reference(value):
            return False
        return not (self.line_negative is not None and self.line_negative.search(line))

    def _first_match(self, line: str, *, code_file: bool) -> re.Match[str] | None:
        candidates = self.patterns if code_file else self.patterns + self.bare_patterns
        for pattern in candidates:
            match = pattern.search(line)
            if match is not None and match.groupdict().get("value"):
                return match
        return None

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in self.files_to_scan(ctx):
            if len(findings) >= self.max_total:
                break
            try:
                text = ctx.read(rel)
            except Exception:  # pragma: no cover - ctx.read already swallows OSError
                # Broad by design: the rule/repository boundary. A scan must never
                # die on one unreadable input — but it must not go quiet either.
                log.debug("unreadable file %s skipped", rel, exc_info=True)
                continue
            if not text:
                continue
            suffix = PurePosixPath(rel).suffix.lower()
            per_file = 0
            for index, line in enumerate(text.splitlines()):
                if per_file >= self.max_per_file or len(findings) >= self.max_total:
                    break
                if len(line) > 2000:
                    continue
                if self.skip_comments and _is_comment_line(line, suffix):
                    continue
                match = self._first_match(line, code_file=suffix in CODE_SUFFIXES)
                if match is None:
                    continue
                try:
                    if not self.accepts(ctx, rel, line, match):
                        continue
                except Exception:  # pragma: no cover - defensive
                    # Broad by design: the rule/repository boundary. A scan must never
                    # die on one unreadable input — but it must not go quiet either.
                    log.debug(
                        "%s guard raised on %s; dropping the match",
                        self.id,
                        rel,
                        exc_info=True,
                    )
                    continue
                line_no = index + 1
                per_file += 1
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=line_no,
                        snippet=line.strip()[:200],
                        description=self.describe(ctx, rel, line_no, line),
                        recommended_followup=self.followup(ctx, rel, line),
                        redact_evidence=True,
                    )
                )
        return findings


def contains_any(text: str, needles: tuple[str, ...] | frozenset[str]) -> bool:
    """True when ``text`` (already lowercased by the caller) holds any needle."""
    return any(needle in text for needle in needles)


def scan_text(ctx: ScanContext, relpaths: list[str], limit: int = 400) -> str:
    """Concatenate up to ``limit`` files, lowercased, for cheap signal searches."""
    chunks: list[str] = []
    for rel in relpaths[:limit]:
        chunk = ctx.read(rel)
        if chunk:
            chunks.append(chunk.lower())
    return "\n".join(chunks)
