"""Baseline, suppressions, history, and the regression diff — INTERFACES.md §7.

Fingerprints (``vibeguard.core.fingerprint``) are the shared key: a baseline is a set
of them, a suppression names one, and the regression diff is set arithmetic over them
between runs.
"""

from vibeguard.baseline.history import (
    HISTORY_DIRNAME,
    history_dir,
    history_files,
    latest_history,
    load_history_report,
    open_fingerprints,
    regression_against_history,
    regression_diff,
    write_history,
)
from vibeguard.baseline.store import (
    BASELINE_FILENAME,
    VIBEGUARD_DIRNAME,
    Baseline,
    apply_baseline,
    baseline_path,
    head_sha,
    load_baseline,
    save_baseline,
    vibeguard_dir,
)
from vibeguard.baseline.suppressions import (
    SUPPRESSIONS_FILENAME,
    SuppressionOutcome,
    apply_suppressions,
    inline_suppression_for,
    load_suppressions,
    suppressions_path,
)

__all__ = [
    "BASELINE_FILENAME",
    "HISTORY_DIRNAME",
    "SUPPRESSIONS_FILENAME",
    "VIBEGUARD_DIRNAME",
    "Baseline",
    "SuppressionOutcome",
    "apply_baseline",
    "apply_suppressions",
    "baseline_path",
    "head_sha",
    "history_dir",
    "history_files",
    "inline_suppression_for",
    "latest_history",
    "load_baseline",
    "load_history_report",
    "load_suppressions",
    "open_fingerprints",
    "regression_against_history",
    "regression_diff",
    "save_baseline",
    "suppressions_path",
    "vibeguard_dir",
    "write_history",
]
