"""The accepted-findings baseline — INTERFACES.md §7.

``.vibeguard/baseline.json`` is ``{created, head_sha, fingerprints: [...]}``. It
records the fingerprints a team has decided to live with *for now*: CI does not fail
on them, but they are still detected, still scored, and still printed in every report
marked ``baselined``. A baseline is a scheduling decision, never an erasure.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from vibeguard.core.models import Finding, FixStatus, ScanReport

__all__ = [
    "BASELINE_FILENAME",
    "VIBEGUARD_DIRNAME",
    "Baseline",
    "apply_baseline",
    "baseline_path",
    "head_sha",
    "load_baseline",
    "save_baseline",
    "vibeguard_dir",
]

log = logging.getLogger(__name__)

VIBEGUARD_DIRNAME = ".vibeguard"
BASELINE_FILENAME = "baseline.json"


class Baseline(BaseModel):
    """The on-disk baseline document."""

    created: datetime
    head_sha: str | None = None
    fingerprints: list[str] = Field(default_factory=list)

    def contains(self, fingerprint: str) -> bool:
        return fingerprint in set(self.fingerprints)


def vibeguard_dir(root: str | Path) -> Path:
    return Path(root) / VIBEGUARD_DIRNAME


def baseline_path(root: str | Path) -> Path:
    return vibeguard_dir(root) / BASELINE_FILENAME


def head_sha(root: str | Path) -> str | None:
    """Current ``HEAD`` sha, or None outside a git repository."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git missing
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and sha else None


def load_baseline(root: str | Path) -> Baseline | None:
    """Read the stored baseline, or None when there is none (or it is unreadable)."""
    path = baseline_path(root)
    if not path.is_file():
        return None
    try:
        return Baseline.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("baseline at %s is not readable — ignored", path, exc_info=True)
        return None


def save_baseline(root: str | Path, report: ScanReport) -> Path:
    """Store every open fingerprint in ``report`` as the accepted baseline.

    Suppressed findings are already accounted for by their suppression entry, and a
    finding that has been *fixed* is gone — writing either into the baseline would
    exempt something that needs no exemption.
    """
    fingerprints = sorted(
        finding.fingerprint
        for finding in report.findings
        if not finding.suppressed
        and (finding.fix is None or finding.fix.status is not FixStatus.FIXED)
    )
    baseline = Baseline(
        created=datetime.now(UTC),
        head_sha=head_sha(root),
        fingerprints=fingerprints,
    )
    path = baseline_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(json.loads(baseline.model_dump_json()), indent=2) + "\n", encoding="utf-8"
    )
    return path


def apply_baseline(findings: Iterable[Finding], baseline: Baseline | None) -> int:
    """Mark findings whose fingerprint is baselined. Returns how many were marked."""
    if baseline is None:
        return 0
    known = set(baseline.fingerprints)
    marked = 0
    for finding in findings:
        if finding.fingerprint in known:
            finding.baselined = True
            marked += 1
    return marked
