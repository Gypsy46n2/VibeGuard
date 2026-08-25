"""Repro-test generation — ARCHITECTURE.md §3 (``testing/``), §7 (the repair loop).

Deterministic and LLM-free: for a curated subset of fixable rules VibeGuard writes a
standalone pytest module that fails while the defect is present and passes once it is
repaired, runs it before and after the patch, and feeds the result into the validation
verdict. ``FixRecord.repro_test`` records the path.
"""

from vibeguard.testing.repro import (
    REPRO_DIRNAME,
    ReproTest,
    generate_repro_test,
    repro_path,
    supported_rule_ids,
)
from vibeguard.testing.runner import ReproOutcome, ReproRunner

__all__ = [
    "REPRO_DIRNAME",
    "ReproOutcome",
    "ReproRunner",
    "ReproTest",
    "generate_repro_test",
    "repro_path",
    "supported_rule_ids",
]
