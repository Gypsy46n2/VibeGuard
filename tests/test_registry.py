from __future__ import annotations

from typing import ClassVar

from vibeguard.core.models import Category, Confidence, Finding, Severity
from vibeguard.core.registry import BUILTIN_PACKS, ENTRY_POINT_GROUP, RuleRegistry, build_registry
from vibeguard.core.rule import Rule
from vibeguard.rules.core import NoTestSuiteRule


class _Dummy(Rule):
    id: ClassVar[str] = "VG-TEST-999"
    category: ClassVar[Category] = Category.MAINTAINABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "dummy"
    description: ClassVar[str] = "dummy"
    why_it_matters: ClassVar[str] = "dummy"

    def detect(self, ctx) -> list[Finding]:
        return []


def test_entry_point_group_name_is_contractual():
    assert ENTRY_POINT_GROUP == "vibeguard.rules"


def test_discovery_finds_builtin_packs():
    registry = build_registry(None)
    ids = [entry.id for entry in registry.registered]
    assert "VG-MAINT-001" in ids
    assert registry.pack_of("VG-MAINT-001") == "core"
    assert NoTestSuiteRule in registry.rule_classes()


def test_all_builtin_packs_import_cleanly():
    for pack in BUILTIN_PACKS:
        registry = RuleRegistry()
        registry.discover([pack], include_plugins=False)
        assert all(issubclass(entry.cls, Rule) for entry in registry.registered)


def test_unknown_pack_is_skipped_not_fatal():
    registry = RuleRegistry()
    registry.discover(["core", "does-not-exist"], include_plugins=False)
    assert len(registry) >= 1


def test_duplicate_and_invalid_rules_are_rejected():
    registry = RuleRegistry()
    registry.register("a", _Dummy)
    registry.register("b", _Dummy)  # duplicate id
    registry.register("c", object)  # type: ignore[arg-type]
    assert len(registry) == 1
    assert registry.pack_of("VG-TEST-999") == "a"


def test_instantiate_returns_rule_instances():
    registry = RuleRegistry()
    registry.register("core", _Dummy)
    instances = registry.instantiate()
    assert len(instances) == 1
    assert isinstance(instances[0], _Dummy)


def test_rule_ids_are_unique_across_builtin_packs():
    registry = build_registry(None, include_plugins=False)
    ids = [entry.id for entry in registry.registered]
    assert len(ids) == len(set(ids))
