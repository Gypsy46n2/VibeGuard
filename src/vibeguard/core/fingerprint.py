"""Line-number independent finding fingerprints — INTERFACES.md §7.

``fingerprint = sha256(f"{rule_id}|{relpath}|{normalize(snippet)}")`` where
``normalize`` collapses whitespace runs and lowercases. Project-level findings use
the relpath ``"."``.
"""

from __future__ import annotations

import hashlib
import re

__all__ = ["normalize", "fingerprint", "PROJECT_PATH"]

PROJECT_PATH = "."

_WHITESPACE = re.compile(r"\s+")


def normalize(snippet: str) -> str:
    """Strip whitespace and lowercase, so formatting churn does not move a fingerprint.

    Whitespace runs are removed outright (not collapsed to a single space) so that
    reindentation, line wrapping, and formatter churn all fingerprint identically.
    See docs/DECISIONS.md.
    """
    if not snippet:
        return ""
    return _WHITESPACE.sub("", snippet).lower()


def fingerprint(rule_id: str, relpath: str | None, snippet: str = "") -> str:
    """Return the hex sha256 fingerprint for a finding."""
    path = relpath or PROJECT_PATH
    payload = f"{rule_id}|{path}|{normalize(snippet)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
