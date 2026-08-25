"""VG-SEC-012 / VG-SEC-018 — debug mode and disabled TLS verification."""

from __future__ import annotations

import re
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
    finding_snippet,
    line_at,
    locate_line,
    replace_line,
    whole_file_patch,
)
from vibeguard.rules._support import is_non_code_line
from vibeguard.rules.security._taint import config_files

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DebugModeEnabledRule", "TlsVerificationDisabledRule"]

_MAX = 6
_CODE_SUFFIXES = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".yml", ".yaml", ".env",
    ".sh", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf", ".go",
)
_CODE_NAMES = ("dockerfile", "makefile", "procfile", ".env")

_COMMENT = re.compile(r"^\s*(#|//|\*|--)")


def _scan(
    ctx: ScanContext,
    patterns: tuple[re.Pattern[str], ...],
    negative: re.Pattern[str] | None = None,
    only: re.Pattern[str] | None = None,
) -> list[tuple[str, int, str]]:
    """Executing lines matching any pattern; returns (relpath, line_no, text).

    Comment lines are dropped, and so are lines made entirely of string content: a
    docstring or a wrapped prose string that *names* ``verify=False`` is documenting
    the defect, not committing it (DECISIONS.md D63).
    """
    hits: list[tuple[str, int, str]] = []
    for rel in config_files(ctx, suffixes=_CODE_SUFFIXES, names=_CODE_NAMES):
        if len(hits) >= _MAX:
            break
        if only is not None and not only.search(rel):
            continue
        text = ctx.read(rel)
        if not text:
            continue
        for index, line in enumerate(text.splitlines()):
            if len(hits) >= _MAX or len(line) > 800 or _COMMENT.match(line):
                continue
            if not any(pattern.search(line) for pattern in patterns):
                continue
            if negative is not None and negative.search(line):
                continue
            if is_non_code_line(ctx, rel, index + 1):
                continue
            hits.append((rel, index + 1, line.strip()[:200]))
    return hits


_DEBUG_PATTERNS = (
    re.compile(r"\.run\s*\([^)]*debug\s*=\s*True"),
    re.compile(r"\bapp\.debug\s*=\s*True"),
    re.compile(r"^\s*DEBUG\s*=\s*True\s*$"),
    re.compile(r"\bFLASK_DEBUG\s*[=:]\s*['\"]?(1|true|True)"),
    re.compile(r"\bFLASK_ENV\s*[=:]\s*['\"]?development"),
    re.compile(r"\berrorhandler\s*\(\s*\)"),
)
#: ``NODE_ENV=development`` is only a defect in an image/compose definition; in a
#: package.json dev script it is exactly right.
_NODE_ENV_PATTERNS = (re.compile(r"\bNODE_ENV\s*[=:]\s*['\"]?development"),)
_CONTAINER_FILES = re.compile(r"(dockerfile|docker-compose|compose\.ya?ml)", re.IGNORECASE)
_DEBUG_NEGATIVE = re.compile(r"getenv|os\.environ|process\.env|environ\.get|config\(")


class DebugModeEnabledRule(Rule):
    """Debug/development mode switched on in committed code or configuration."""

    id: ClassVar[str] = "VG-SEC-012"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Debug mode enabled"
    description: ClassVar[str] = (
        "Debug or development mode is hard-coded on, so error pages expose stack traces, "
        "source, and configuration — and in Flask's case an interactive console."
    )
    why_it_matters: ClassVar[str] = (
        "A debug error page hands a visitor your source code, environment variables, and "
        "database credentials the moment anything throws. The Werkzeug debugger goes "
        "further and offers a Python prompt inside your process; it has been used to take "
        "over servers found by simple internet-wide scans."
    )
    references: ClassVar[list[str]] = [
        "https://flask.palletsprojects.com/en/stable/debugging/",
        "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.sensitive-data-exposure"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): read the flag from the environment, default False.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        hits = _scan(ctx, _DEBUG_PATTERNS, _DEBUG_NEGATIVE)
        hits.extend(_scan(ctx, _NODE_ENV_PATTERNS, only=_CONTAINER_FILES)[: _MAX - len(hits)])
        return [
            self.make_finding(
                file=rel,
                line=line_no,
                snippet=text,
                description=(
                    f"{rel}:{line_no} enables debug/development mode unconditionally."
                ),
                recommended_followup=(
                    "Drive the flag from configuration and default it off: "
                    "`debug = os.getenv('FLASK_DEBUG', '0') == '1'`, "
                    "`DEBUG = os.environ.get('DJANGO_DEBUG') == 'true'`, and set "
                    "`NODE_ENV=production` in the production image."
                ),
            )
            for rel, line_no, text in hits
        ]


_TLS_PATTERNS = (
    re.compile(r"\bverify\s*=\s*False\b"),
    re.compile(r"ssl\._create_unverified_context"),
    re.compile(r"_create_default_https_context\s*=\s*ssl\._create_unverified_context"),
    re.compile(r"\bCERT_NONE\b"),
    re.compile(r"curl\s+(-[A-Za-z]*k|--insecure)\b"),
    re.compile(r"\brejectUnauthorized\s*:\s*false"),
    re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0"),
    re.compile(r"InsecureSkipVerify\s*:\s*true"),
    re.compile(r"\bstrictSSL\s*:\s*false"),
)

#: The two forms VG-SEC-018 can repair without also changing trust configuration.
_VERIFY_FALSE = re.compile(r"(\bverify\s*=\s*)False\b")
_REJECT_UNAUTHORIZED_FALSE = re.compile(r"(\brejectUnauthorized\s*:\s*)false\b")


class TlsVerificationDisabledRule(Rule):
    """Certificate validation switched off on an outbound TLS connection."""

    id: ClassVar[str] = "VG-SEC-018"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "TLS certificate verification disabled"
    description: ClassVar[str] = (
        "An outbound HTTPS connection skips certificate validation "
        "(`verify=False`, `rejectUnauthorized: false`, `curl -k`, `CERT_NONE`, "
        "`InsecureSkipVerify`), so the connection is encrypted but unauthenticated."
    )
    why_it_matters: ClassVar[str] = (
        "Encryption without verification protects nothing: anyone positioned between you "
        "and the server — a compromised router, a hostile Wi-Fi network, a misconfigured "
        "proxy — can present their own certificate, read the API keys and personal data "
        "you send, and alter the response you act on. It usually gets added to silence a "
        "certificate error and then ships to production."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "security.tls",
        "security.encryption-in-transit",
        "network.tls-config",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.make_finding(
                file=rel,
                line=line_no,
                snippet=text,
                description=(
                    f"{rel}:{line_no} disables TLS certificate verification for an "
                    "outbound connection."
                ),
                recommended_followup=(
                    "Remove the flag and make verification succeed instead: point the "
                    "client at the correct CA bundle (`verify='/path/ca.pem'`, "
                    "`NODE_EXTRA_CA_CERTS`, `certifi`) or fix the server's certificate "
                    "chain. Never disable verification outside a throwaway local test."
                ),
            )
            for rel, line_no, text in _scan(ctx, _TLS_PATTERNS)
        ]

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Turn verification back on where that is a one-token, local change.

        Only ``verify=False`` (Python requests/httpx) and ``rejectUnauthorized: false``
        (Node TLS options) are rewritten: both mean exactly "check the certificate"
        when flipped, and nothing else on the line moves. The other forms this rule
        detects — ``CERT_NONE``, ``curl -k``, ``InsecureSkipVerify``,
        ``NODE_TLS_REJECT_UNAUTHORIZED=0`` — need a CA bundle or a server-side
        certificate fix to accompany them, so they are reported, not patched.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no:
            return None
        text = ctx.read(rel)
        target = locate_line(
            text,
            line_no,
            matches=lambda candidate: bool(
                _VERIFY_FALSE.search(candidate) or _REJECT_UNAUTHORIZED_FALSE.search(candidate)
            ),
            snippet=finding_snippet(finding),
        )
        line = line_at(text, target)
        if target is None or line is None:
            return None
        line_no = target
        repaired = _VERIFY_FALSE.sub(r"\1True", line)
        repaired = _REJECT_UNAUTHORIZED_FALSE.sub(r"\1true", repaired)
        if repaired == line:
            return None
        return whole_file_patch(
            finding,
            rel,
            text,
            replace_line(text, line_no, repaired),
            description=(
                f"Re-enable TLS certificate verification at {rel}:{line_no}."
            ),
            scope="security",
            summary="re-enable TLS certificate verification",
        )
