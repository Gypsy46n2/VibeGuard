"""The authoritative topic registry (INTERFACES.md §11)."""

from __future__ import annotations

import pytest

from vibeguard.core.models import Category
from vibeguard.rules.topics import (
    all_topics,
    load_registry,
    sections,
    topic_by_id,
    topic_ids,
)


def test_registry_loads_from_package_data():
    registry = load_registry()
    assert len(registry) == 18
    assert {section.id for section in registry} >= {
        "api",
        "containers",
        "distributed",
        "concurrency",
        "database",
        "security",
        "secrets",
        "deployment",
        "observability",
        "disaster-recovery",
        "network",
        "performance",
        "scaling",
        "cost",
        "jobs",
        "dependencies",
        "iac",
        "testing",
    }


def test_every_section_declares_topics_and_a_valid_category():
    for section in sections():
        assert section.topics, section.id
        assert isinstance(section.category, Category)


def test_topic_ids_are_section_qualified_and_unique():
    ids = [topic.id for topic in all_topics()]
    assert len(ids) == len(set(ids))
    for topic in all_topics():
        assert topic.id == f"{topic.section}.{topic.slug}"


def test_registry_covers_the_documented_breadth():
    # INTERFACES.md §11 promises "≈240 items across 18 sections".
    assert 230 <= len(all_topics()) <= 320


@pytest.mark.parametrize(
    "topic_id",
    [
        "security.sql-injection",
        "secrets.private-keys-in-repo",
        "disaster-recovery.chaos-engineering",
        "performance.serverless-limits",
        "concurrency.gc-behavior",
        "network.cdn-configuration",
        "disaster-recovery.on-call-readiness",
        "disaster-recovery.postmortem-process",
    ],
)
def test_brief_topics_survive_into_the_registry(topic_id: str):
    topic = topic_by_id(topic_id)
    assert topic is not None
    assert topic.id in topic_ids()


def test_unknown_topic_lookup_returns_none():
    assert topic_by_id("nope.not-a-topic") is None
