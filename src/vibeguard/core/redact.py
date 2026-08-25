"""Secret redaction — INTERFACES.md §7.

Any token matching a secret pattern keeps its first 4 and last 4 characters; the
middle is replaced with ``****[REDACTED]****``. Implemented once, here, and applied
at the Finding-construction boundary so no renderer can leak a secret.
"""

from __future__ import annotations

import re

__all__ = ["redact", "mask_token", "SECRET_PATTERNS"]

MASK = "****[REDACTED]****"

# Patterns are matched against whole text; group "secret" (when present) marks the
# exact span to mask, otherwise the whole match is masked.
_PATTERN_SOURCES: list[str] = [
    # --- provider-specific key formats -------------------------------------
    r"(?P<secret>AKIA[0-9A-Z]{16})",  # AWS access key id
    r"(?P<secret>ASIA[0-9A-Z]{16})",  # AWS temporary access key id
    r"(?P<secret>sk-(?:live|test|proj|ant|or)?-?[A-Za-z0-9_\-]{16,})",  # OpenAI/Stripe-ish
    r"(?P<secret>rk_(?:live|test)_[A-Za-z0-9]{16,})",
    r"(?P<secret>pk_(?:live|test)_[A-Za-z0-9]{16,})",
    r"(?P<secret>gh[pousr]_[A-Za-z0-9]{20,})",  # GitHub tokens
    r"(?P<secret>github_pat_[A-Za-z0-9_]{20,})",
    r"(?P<secret>glpat-[A-Za-z0-9\-_]{16,})",  # GitLab PAT
    r"(?P<secret>xox[baprs]-[A-Za-z0-9\-]{10,})",  # Slack
    r"(?P<secret>SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})",  # SendGrid
    r"(?P<secret>AIza[0-9A-Za-z\-_]{35})",  # Google API key
    r"(?P<secret>ya29\.[0-9A-Za-z\-_]{20,})",  # Google OAuth token
    r"(?P<secret>npm_[A-Za-z0-9]{30,})",
    r"(?P<secret>dop_v1_[a-f0-9]{60,})",  # DigitalOcean
    r"(?P<secret>hf_[A-Za-z0-9]{20,})",  # HuggingFace
    r"(?P<secret>eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,})",  # JWT
    r"(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)",
    # --- assignment forms: key = "value" / key: value / KEY=value ----------
    r"(?i)\b(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?key|client[_\-]?secret"
    r"|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|private[_\-]?key|password"
    r"|passwd|pwd|token|secret|credentials?)\b\s*[:=]\s*"
    r"['\"]?(?P<secret>[A-Za-z0-9/+=_\-\.]{8,})['\"]?",
    # --- credentials embedded in URLs --------------------------------------
    r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:(?P<secret>[^\s/@]{4,})@",
    # --- Authorization headers ---------------------------------------------
    r"(?i)\bAuthorization\b\s*[:=]\s*['\"]?(?:Bearer|Basic|Token)\s+"
    r"(?P<secret>[A-Za-z0-9\-._~+/=]{8,})",
]

SECRET_PATTERNS: list[re.Pattern[str]] = [re.compile(src) for src in _PATTERN_SOURCES]


def mask_token(token: str) -> str:
    """Mask a single token, keeping the first and last 4 characters."""
    if len(token) <= 8:
        return MASK
    return f"{token[:4]}{MASK}{token[-4:]}"


def redact(s: str) -> str:
    """Return ``s`` with every recognised secret token masked.

    Idempotent: already-masked text contains ``[REDACTED]`` and is left alone.
    """
    if not s:
        return s
    spans: list[tuple[int, int]] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(s):
            if "secret" in match.groupdict() and match.group("secret") is not None:
                start, end = match.span("secret")
            else:  # pragma: no cover - all shipped patterns name their span
                start, end = match.span()
            if start < 0 or end <= start:
                continue
            if MASK in s[start:end]:
                continue
            spans.append((start, end))
    if not spans:
        return s
    # Merge overlapping spans, then rebuild the string right-to-left.
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    out = s
    for start, end in reversed(merged):
        out = out[:start] + mask_token(s[start:end]) + out[end:]
    return out
