"""Suppressions — INTERFACES.md §7, ARCHITECTURE.md §8.

Two sources, one meaning: *a human has looked at this finding and accepted it.*

``.vibeguard/suppressions.yml``
    A list of ``{fingerprint, rule_id, reason, author, created, expires?, note}``
    entries. ``reason`` must be one of the four :class:`SuppressionReason` values.
Inline comments
    ``# vibeguard: ignore=VG-SEC-001 reason="checked, internal only"`` on the finding's
    own line or the line directly above it.

A suppressed finding is excluded from scores and from the CI gate, but it is never
dropped: it stays in the report, in its own section, with the reason and the author
that justified it. An **expired** suppression is not honoured at all — the finding
comes back and the report carries a warning saying which entry lapsed.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

from vibeguard.baseline.store import vibeguard_dir
from vibeguard.core.models import Finding, SuppressionEntry, SuppressionReason

__all__ = [
    "SUPPRESSIONS_FILENAME",
    "INLINE_PATTERN",
    "SuppressionOutcome",
    "apply_suppressions",
    "inline_suppression_for",
    "load_suppressions",
    "suppressions_path",
]

log = logging.getLogger(__name__)

SUPPRESSIONS_FILENAME = "suppressions.yml"

#: ``vibeguard: ignore=VG-SEC-001[,VG-SEC-002] [reason="…"]`` in any comment syntax.
INLINE_PATTERN = re.compile(
    r"vibeguard:\s*ignore=(?P<rules>[A-Za-z0-9_\-]+(?:\s*,\s*[A-Za-z0-9_\-]+)*)"
    r"(?:[^\S\n]+reason=(?P<quote>[\"'])(?P<reason>[^\"']*)(?P=quote))?"
)

ReadFn = Callable[[str], str]


@dataclass
class SuppressionOutcome:
    """What the suppression pass did — every part of it reportable."""

    #: Entries that were honoured or are available to honour (file + inline).
    entries: list[SuppressionEntry] = field(default_factory=list)
    #: Entries that lapsed and were therefore ignored.
    expired: list[SuppressionEntry] = field(default_factory=list)
    #: Human-readable problems: expiries, malformed entries, unreadable files.
    warnings: list[str] = field(default_factory=list)
    #: Number of findings actually marked suppressed.
    suppressed: int = 0


def suppressions_path(root: str | Path) -> Path:
    return vibeguard_dir(root) / SUPPRESSIONS_FILENAME


# ------------------------------------------------------------------ file entries


def _coerce_datetime(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def load_suppressions(root: str | Path) -> tuple[list[SuppressionEntry], list[str]]:
    """Parse ``.vibeguard/suppressions.yml``. Returns (entries, warnings)."""
    path = suppressions_path(root)
    if not path.is_file():
        return [], []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return [], [f"{SUPPRESSIONS_FILENAME} could not be parsed and was ignored: {exc}"]
    if raw is None:
        return [], []
    if isinstance(raw, dict):  # tolerate `suppressions:` as a top-level key
        raw = raw.get("suppressions")
    if not isinstance(raw, list):
        return [], [f"{SUPPRESSIONS_FILENAME}: expected a list of suppression entries"]

    entries: list[SuppressionEntry] = []
    warnings: list[str] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            warnings.append(f"{SUPPRESSIONS_FILENAME}: entry {index} is not a mapping — ignored")
            continue
        rule_id = str(item.get("rule_id") or "").strip()
        fingerprint = str(item.get("fingerprint") or "").strip()
        if not rule_id and not fingerprint:
            warnings.append(
                f"{SUPPRESSIONS_FILENAME}: entry {index} names neither fingerprint nor "
                "rule_id — ignored"
            )
            continue
        try:
            reason = SuppressionReason(str(item.get("reason")))
        except ValueError:
            warnings.append(
                f"{SUPPRESSIONS_FILENAME}: entry {index} ({rule_id or fingerprint[:12]}) has "
                f"reason {item.get('reason')!r}, which is not one of "
                + "/".join(r.value for r in SuppressionReason)
                + " — ignored"
            )
            continue
        entries.append(
            SuppressionEntry(
                fingerprint=fingerprint,
                rule_id=rule_id,
                reason=reason,
                author=str(item.get("author") or ""),
                created=_coerce_datetime(item.get("created")),
                expires=_coerce_datetime(item.get("expires")),
                note=str(item.get("note") or ""),
            )
        )
    return entries, warnings


# ---------------------------------------------------------------------- matching


def _matches(entry: SuppressionEntry, finding: Finding) -> bool:
    if entry.fingerprint and entry.fingerprint not in {"*", ""}:
        return entry.fingerprint == finding.fingerprint
    return bool(entry.rule_id) and entry.rule_id == finding.rule_id


def _is_expired(entry: SuppressionEntry, now: datetime) -> bool:
    return entry.expires is not None and entry.expires <= now


def _describe(entry: SuppressionEntry) -> str:
    who = entry.author or "unknown author"
    what = entry.rule_id or entry.fingerprint[:12]
    return f"{what} ({who})"


# ------------------------------------------------------------------------ inline


def inline_suppression_for(finding: Finding, read: ReadFn) -> SuppressionEntry | None:
    """An inline ``vibeguard: ignore=`` comment on the finding's line or the one above.

    Only the two lines are scanned, deliberately: a suppression must sit where the
    reader of the code will see it, not somewhere else in the file.
    """
    if not finding.file or not finding.line:
        return None
    try:
        text = read(finding.file)
    except Exception:  # pragma: no cover - reader isolation
        # The reader is caller-supplied and may raise anything; an unreadable file
        # simply has no inline suppression on it.
        log.debug("suppression reader failed for %s", finding.file, exc_info=True)
        return None
    if not text:
        return None
    lines = text.splitlines()
    index = finding.line - 1
    if index < 0 or index >= len(lines):
        return None
    for candidate in (lines[index], lines[index - 1] if index > 0 else ""):
        match = INLINE_PATTERN.search(candidate)
        if not match:
            continue
        rules = {token.strip() for token in match.group("rules").split(",") if token.strip()}
        if finding.rule_id not in rules:
            continue
        text_reason = (match.group("reason") or "").strip()
        try:
            reason = SuppressionReason(text_reason)
            note = ""
        except ValueError:
            reason = SuppressionReason.ACCEPTED_RISK
            note = text_reason
        return SuppressionEntry(
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            reason=reason,
            author="inline",
            note=note or f"inline suppression at {finding.file}:{finding.line}",
        )
    return None


# ------------------------------------------------------------------------- apply


def apply_suppressions(
    findings: Sequence[Finding],
    root: str | Path,
    read: ReadFn,
    *,
    now: datetime | None = None,
    file_entries: Iterable[SuppressionEntry] | None = None,
    file_warnings: Iterable[str] | None = None,
) -> SuppressionOutcome:
    """Mark suppressed findings in place and report exactly what was honoured."""
    moment = now or datetime.now(UTC)
    if file_entries is None:
        loaded, warnings = load_suppressions(root)
    else:
        loaded, warnings = list(file_entries), list(file_warnings or [])

    outcome = SuppressionOutcome(warnings=list(warnings))
    live: list[SuppressionEntry] = []
    for entry in loaded:
        if _is_expired(entry, moment):
            outcome.expired.append(entry)
            outcome.warnings.append(
                f"suppression for {_describe(entry)} expired on "
                f"{entry.expires:%Y-%m-%d} and was ignored — the finding is live again"
            )
            continue
        live.append(entry)

    for finding in findings:
        entry = next((e for e in live if _matches(e, finding)), None)
        if entry is None:
            entry = inline_suppression_for(finding, read)
        if entry is None:
            continue
        finding.suppressed = True
        finding.suppression = entry
        outcome.suppressed += 1
        if entry not in outcome.entries:
            outcome.entries.append(entry)

    for entry in live:
        if entry not in outcome.entries:
            outcome.entries.append(entry)
            outcome.warnings.append(
                f"suppression for {_describe(entry)} matched no finding in this scan"
            )
    outcome.entries.extend(e for e in outcome.expired if e not in outcome.entries)
    return outcome
