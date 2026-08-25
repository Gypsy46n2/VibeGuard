"""Synchronous publish/subscribe event bus — INTERFACES.md §6.

Subscribers register against a pattern (``fnmatch`` style, e.g. ``"scan.*"`` or
``"*"``). Payloads must be JSON-serialisable dicts. Subscriber exceptions never
break the emitting pipeline.
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Callable
from typing import Any

__all__ = ["EventBus", "EVENT_NAMES", "Subscriber"]

log = logging.getLogger(__name__)

Subscriber = Callable[[str, dict[str, Any]], None]

#: Exact event names defined by INTERFACES.md §6.
EVENT_NAMES: tuple[str, ...] = (
    "scan.started",
    "scan.stage",
    "scan.issue_found",
    "scan.completed",
    "repair.started",
    "repair.completed",
    "repair.failed",
    "validation.started",
    "validation.completed",
    "report.generated",
)


class EventBus:
    """Minimal synchronous pub/sub."""

    def __init__(self) -> None:
        self._subscribers: list[tuple[str, Subscriber]] = []

    def subscribe(self, pattern: str, fn: Subscriber) -> Subscriber:
        """Subscribe ``fn`` to every event name matching ``pattern``."""
        self._subscribers.append((pattern, fn))
        return fn

    def unsubscribe(self, fn: Subscriber) -> None:
        self._subscribers = [(p, f) for (p, f) in self._subscribers if f is not fn]

    def emit(self, name: str, **payload: Any) -> None:
        """Emit ``name`` with ``payload`` to every matching subscriber."""
        for pattern, fn in list(self._subscribers):
            if fnmatch.fnmatchcase(name, pattern):
                try:
                    fn(name, payload)
                except Exception:  # pragma: no cover - subscriber isolation
                    log.warning("event subscriber failed for %s", name, exc_info=True)
