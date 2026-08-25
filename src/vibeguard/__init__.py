"""VibeGuard — audit, repair, and harden vibe-coded applications."""

from __future__ import annotations

__version__ = "0.3.0"

__all__ = ["__version__", "Engine", "VibeguardConfig"]


def __getattr__(name: str):  # pragma: no cover - thin lazy import shim
    if name == "Engine":
        from vibeguard.engine.orchestrator import Engine

        return Engine
    if name == "VibeguardConfig":
        from vibeguard.core.config import VibeguardConfig

        return VibeguardConfig
    raise AttributeError(name)
