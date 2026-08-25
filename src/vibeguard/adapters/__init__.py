"""External tool adapters — all optional (ARCHITECTURE.md §2, INTERFACES.md §4)."""

from __future__ import annotations

import logging

from vibeguard.adapters.bandit import BanditAdapter
from vibeguard.adapters.base import DEFAULT_TIMEOUT, SKIP_LOCAL_ONLY, ToolAdapter
from vibeguard.adapters.checkov import CheckovAdapter
from vibeguard.adapters.detect_secrets import DetectSecretsAdapter
from vibeguard.adapters.hadolint import HadolintAdapter
from vibeguard.adapters.npm_audit import NpmAuditAdapter
from vibeguard.adapters.pip_audit import PipAuditAdapter
from vibeguard.adapters.semgrep import SemgrepAdapter
from vibeguard.adapters.trivy import TrivyAdapter

__all__ = [
    "ADAPTERS",
    "DEFAULT_TIMEOUT",
    "SKIP_LOCAL_ONLY",
    "BanditAdapter",
    "CheckovAdapter",
    "DetectSecretsAdapter",
    "HadolintAdapter",
    "NpmAuditAdapter",
    "PipAuditAdapter",
    "SemgrepAdapter",
    "ToolAdapter",
    "TrivyAdapter",
    "build_adapters",
]

#: Every shipped adapter class, in the order the engine runs them.
ADAPTERS: tuple[type[ToolAdapter], ...] = (
    BanditAdapter,
    DetectSecretsAdapter,
    PipAuditAdapter,
    NpmAuditAdapter,
    HadolintAdapter,
    TrivyAdapter,
    CheckovAdapter,
    SemgrepAdapter,
)


log = logging.getLogger(__name__)


def build_adapters() -> list[ToolAdapter]:
    """Instantiate every adapter, skipping any that fails to construct.

    A broad catch on purpose: adapters wrap third-party tools whose constructors can
    fail in ways we do not enumerate, and one unavailable tool must never abort the
    scan. It is logged rather than swallowed, so `--verbose` shows which one dropped
    out and why.
    """
    instances: list[ToolAdapter] = []
    for cls in ADAPTERS:
        try:
            instances.append(cls())
        except Exception:  # pragma: no cover - defensive
            log.debug("adapter %s failed to construct; skipping", cls.__name__, exc_info=True)
    return instances
