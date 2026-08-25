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

__all__ = [
    "EventBus",
    "ALL_EVENT_NAMES",
    "EVENT_NAMES",
    "EXTENSION_EVENT_NAMES",
    "Subscriber",
]

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

#: Names VibeGuard emits **in addition** to §6. The §6 tuple is the contract and is
#: never edited; these are additive, and a subscriber that only knows §6 keeps working
#: because it simply never matches them (DECISIONS.md D41).
#:
#: ``ai.external_send``
#:     Emitted immediately *before* a prompt is sent to a non-local AI provider.
#:     Payload: ``provider``, ``endpoint``, ``model``, ``characters``.
#: ``ai.blocked``
#:     Emitted when ``local_only`` refused a non-local provider.
#:     Payload: ``provider``, ``reason``, ``local_only``.
#: ``repro.generated`` / ``repro.result``
#:     Emitted by the repro-test generator (``vibeguard.testing``).
#:     Payload: ``finding``, ``rule_id``, ``path`` (+ ``phase``, ``passed`` for the
#:     result).
#: ``scan.discovery_progress``
#:     Emitted repeatedly *during* discovery, which is otherwise a silent minute on a
#:     large tree. Throttled to at most one event every 250 ms or 250 files, whichever
#:     comes first, so a subscriber cannot be flooded.
#:     Payload: ``phase`` (the ``scan.stage`` name this refines, e.g.
#:     ``"discovery.files"``), ``files`` (count processed so far), ``total`` (the
#:     denominator when one is known, else ``None``), and ``detail`` (a short
#:     human-readable note, usually the current path). Purely additive: a subscriber
#:     that only knows §6 never matches it (DECISIONS.md D41, D70).
EXTENSION_EVENT_NAMES: tuple[str, ...] = (
    "ai.external_send",
    "ai.blocked",
    "repro.generated",
    "repro.result",
    "scan.discovery_progress",
)

#: Every name VibeGuard can emit.
ALL_EVENT_NAMES: tuple[str, ...] = EVENT_NAMES + EXTENSION_EVENT_NAMES


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
