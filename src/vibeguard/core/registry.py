"""Rule discovery — built-in packs plus the ``vibeguard.rules`` entry-point group.

A rule pack is a module exposing ``RULES: list[type[Rule]]``. Built-in packs live at
``vibeguard.rules.<pack>``; third-party packs advertise themselves as::

    [project.entry-points."vibeguard.rules"]
    mypack = "mypack.rules:RULES"

The entry point may resolve either to a ``RULES`` list or to a module exposing one.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from importlib import metadata

from vibeguard.core.rule import Rule

__all__ = ["ENTRY_POINT_GROUP", "BUILTIN_PACKS", "RegisteredRule", "RuleRegistry"]

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "vibeguard.rules"

BUILTIN_PACKS: tuple[str, ...] = (
    "core",
    "secrets",
    "security",
    "api",
    "database",
    "reliability",
    "observability",
    "containers",
    "deployment",
    "dependencies",
    "disaster_recovery",
    "testing",
    "performance",
    "scaling",
    "cost",
    "network",
    "web",
    "devops",
    "python",
    "node",
)


@dataclass(frozen=True)
class RegisteredRule:
    """A rule class together with the pack it came from."""

    pack: str
    cls: type[Rule]

    @property
    def id(self) -> str:
        return self.cls.id


class RuleRegistry:
    """Discovers and holds rule classes."""

    def __init__(self) -> None:
        self._rules: dict[str, RegisteredRule] = {}

    # ------------------------------------------------------------- discovery
    def discover(self, packs: list[str] | None = None, *, include_plugins: bool = True) -> None:
        """Load ``packs`` (default: all built-ins) and, optionally, plugin packs."""
        for pack in packs if packs is not None else list(BUILTIN_PACKS):
            self._load_builtin(pack)
        if include_plugins:
            self._load_plugins()

    def _load_builtin(self, pack: str) -> None:
        module_name = f"vibeguard.rules.{pack}"
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            log.warning("rule pack %r not found (skipped)", pack)
            return
        self._register_from(pack, getattr(module, "RULES", []))

    def _load_plugins(self) -> None:
        try:
            entry_points = metadata.entry_points(group=ENTRY_POINT_GROUP)
        except Exception:  # pragma: no cover - defensive on odd environments
            log.warning("could not enumerate %s entry points", ENTRY_POINT_GROUP, exc_info=True)
            return
        for ep in entry_points:
            try:
                target = ep.load()
            except Exception:
                log.warning("failed to load rule plugin %r", ep.name, exc_info=True)
                continue
            rules = target if isinstance(target, list) else getattr(target, "RULES", [])
            self._register_from(ep.name, rules)

    def _register_from(self, pack: str, rules: object) -> None:
        if not isinstance(rules, (list, tuple)):
            log.warning("rule pack %r exposes a non-list RULES (ignored)", pack)
            return
        for cls in rules:
            self.register(pack, cls)

    def register(self, pack: str, cls: type[Rule]) -> None:
        """Register a single rule class, rejecting malformed or duplicate rules."""
        if not (isinstance(cls, type) and issubclass(cls, Rule)):
            log.warning("pack %r exposed a non-Rule object %r (ignored)", pack, cls)
            return
        rule_id = getattr(cls, "id", None)
        if not rule_id:
            log.warning("rule %r in pack %r has no id (ignored)", cls, pack)
            return
        if rule_id in self._rules:
            log.warning("duplicate rule id %s (pack %r) ignored", rule_id, pack)
            return
        self._rules[rule_id] = RegisteredRule(pack=pack, cls=cls)

    # ---------------------------------------------------------------- access
    @property
    def registered(self) -> list[RegisteredRule]:
        return sorted(self._rules.values(), key=lambda r: r.id)

    def rule_classes(self) -> list[type[Rule]]:
        return [entry.cls for entry in self.registered]

    def instantiate(self) -> list[Rule]:
        """Instantiate every registered rule, skipping ones that fail to construct."""
        instances: list[Rule] = []
        for entry in self.registered:
            try:
                instances.append(entry.cls())
            except Exception:
                log.warning("rule %s failed to instantiate (skipped)", entry.id, exc_info=True)
        return instances

    def pack_of(self, rule_id: str) -> str | None:
        entry = self._rules.get(rule_id)
        return entry.pack if entry else None

    def __len__(self) -> int:
        return len(self._rules)


def build_registry(packs: list[str] | None = None, *, include_plugins: bool = True) -> RuleRegistry:
    """Convenience constructor: a registry with discovery already run."""
    registry = RuleRegistry()
    registry.discover(packs, include_plugins=include_plugins)
    return registry
