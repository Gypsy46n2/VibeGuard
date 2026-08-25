"""VibeGuard database rule pack (populated in M2)."""

from __future__ import annotations

from vibeguard.core.rule import Rule

RULES: list[type[Rule]] = []

__all__ = ["RULES"]
