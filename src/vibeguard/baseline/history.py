"""Scan history and the regression diff — INTERFACES.md §7, §8.

Every run can be persisted to ``.vibeguard/history/<UTC timestamp>.json`` as a full
:class:`ScanReport`. The next run reads that history and answers the only question a
returning user actually has: *did this get better or worse?*

``RegressionDiff`` classifies every fingerprint against the two immediately relevant
horizons — the previous run, and everything before it:

============  ==========================================================
new           not seen in the previous run, and never seen before it
unchanged     present in the previous run and still present now
resolved      present in the previous run, gone now
regressed     absent from the previous run, but present in an older one
============  ==========================================================

``regressed`` is the interesting column: it means something was fixed and then came
back, which is a different failure of process than a defect that was never addressed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from vibeguard.baseline.store import vibeguard_dir
from vibeguard.core.models import Finding, FixStatus, RegressionDiff, ScanReport

__all__ = [
    "HISTORY_DIRNAME",
    "history_dir",
    "history_files",
    "latest_history",
    "load_history_report",
    "open_fingerprints",
    "regression_against_history",
    "regression_diff",
    "timestamp_name",
    "write_history",
]

log = logging.getLogger(__name__)

HISTORY_DIRNAME = "history"


def history_dir(root: str | Path) -> Path:
    return vibeguard_dir(root) / HISTORY_DIRNAME


def timestamp_name(moment: datetime | None = None) -> str:
    """Filesystem-safe, lexicographically sortable UTC timestamp filename."""
    stamp = (moment or datetime.now(UTC)).astimezone(UTC)
    return stamp.strftime("%Y-%m-%dT%H-%M-%S.%fZ") + ".json"


def history_files(root: str | Path) -> list[Path]:
    """Stored history entries, oldest first."""
    directory = history_dir(root)
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.json") if p.is_file())


def load_history_report(path: Path) -> ScanReport | None:
    """Read one history entry, or None when it is missing or unreadable."""
    try:
        return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("history entry %s is not a readable report — ignored", path, exc_info=True)
        return None


def latest_history(root: str | Path) -> ScanReport | None:
    """The most recent stored report, or None."""
    for path in reversed(history_files(root)):
        report = load_history_report(path)
        if report is not None:
            return report
    return None


def write_history(report: ScanReport, root: str | Path, *, keep: int = 50) -> Path:
    """Persist ``report`` into the history directory, pruning to ``keep`` entries."""
    directory = history_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / timestamp_name(report.scan_date)
    suffix = 1
    while path.exists():  # two scans inside one microsecond: keep both, in order
        path = directory / (timestamp_name(report.scan_date)[:-5] + f"-{suffix}.json")
        suffix += 1
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if keep > 0:
        for stale in history_files(root)[:-keep]:
            try:
                stale.unlink()
            except OSError:  # pragma: no cover - best effort pruning
                log.warning("could not prune history entry %s", stale)
    return path


# ------------------------------------------------------------------- diffing


def _is_open(finding: Finding) -> bool:
    if finding.suppressed:
        return False
    return finding.fix is None or finding.fix.status is not FixStatus.FIXED


def open_fingerprints(findings: Iterable[Finding]) -> set[str]:
    """Fingerprints of the findings that are still open."""
    return {f.fingerprint for f in findings if _is_open(f)}


def regression_diff(
    findings: Sequence[Finding],
    previous: set[str],
    older: set[str],
) -> RegressionDiff:
    """Classify the current findings against the previous run and the runs before it."""
    current_open = [f for f in findings if _is_open(f)]
    current = {f.fingerprint for f in current_open}

    new: list[str] = []
    regressed: list[str] = []
    unchanged = 0
    seen: set[str] = set()
    for finding in current_open:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        if finding.fingerprint in previous:
            unchanged += 1
        elif finding.fingerprint in older:
            regressed.append(finding.id)
        else:
            new.append(finding.id)

    resolved = sorted(previous - current)
    return RegressionDiff(new=new, resolved=resolved, regressed=regressed, unchanged=unchanged)


def regression_against_history(
    findings: Sequence[Finding], root: str | Path
) -> RegressionDiff | None:
    """Diff ``findings`` against the stored history; None when there is no history."""
    paths = history_files(root)
    if not paths:
        return None
    reports = [load_history_report(path) for path in paths]
    valid = [report for report in reports if report is not None]
    if not valid:
        return None
    previous = open_fingerprints(valid[-1].findings)
    older: set[str] = set()
    for report in valid[:-1]:
        older |= open_fingerprints(report.findings)
    return regression_diff(findings, previous, older)
