"""Loader for the authoritative topic registry (``topics.yaml``) — INTERFACES.md §11.

``topics.yaml`` ships as package data. Every topic it declares must appear in every
``ScanReport.checklist``; the engine hard-fails a scan when one is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

import yaml

from vibeguard.core.models import Category

__all__ = [
    "TOPICS_FILENAME",
    "Topic",
    "Section",
    "load_registry",
    "all_topics",
    "topic_ids",
    "topic_by_id",
    "sections",
]

TOPICS_FILENAME = "topics.yaml"


@dataclass(frozen=True)
class Topic:
    """One checklist topic. ``id`` is ``"<section>.<slug>"``."""

    id: str
    slug: str
    name: str
    section: str
    section_name: str
    category: Category


@dataclass(frozen=True)
class Section:
    """A checklist section and the topics it owns."""

    id: str
    name: str
    category: Category
    topics: tuple[Topic, ...] = field(default_factory=tuple)


def _read_yaml() -> dict[str, Any]:
    resource = files("vibeguard.rules").joinpath(TOPICS_FILENAME)
    raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{TOPICS_FILENAME}: expected a mapping at the document root")
    return raw


@lru_cache(maxsize=1)
def load_registry() -> tuple[Section, ...]:
    """Parse ``topics.yaml`` into sections (cached for the process lifetime)."""
    raw = _read_yaml()
    raw_sections = raw.get("sections")
    if not isinstance(raw_sections, list) or not raw_sections:
        raise ValueError(f"{TOPICS_FILENAME}: 'sections' must be a non-empty list")

    parsed: list[Section] = []
    seen_topics: set[str] = set()
    for entry in raw_sections:
        if not isinstance(entry, dict):
            raise ValueError(f"{TOPICS_FILENAME}: every section must be a mapping")
        section_id = str(entry["id"])
        section_name = str(entry.get("name") or section_id)
        category = Category(str(entry["category"]))
        topics: list[Topic] = []
        for item in entry.get("topics") or []:
            if not isinstance(item, dict):
                raise ValueError(f"{TOPICS_FILENAME}: topics of {section_id} must be mappings")
            slug = str(item["id"])
            topic_id = f"{section_id}.{slug}"
            if topic_id in seen_topics:
                raise ValueError(f"{TOPICS_FILENAME}: duplicate topic id {topic_id!r}")
            seen_topics.add(topic_id)
            topics.append(
                Topic(
                    id=topic_id,
                    slug=slug,
                    name=str(item.get("name") or slug),
                    section=section_id,
                    section_name=section_name,
                    category=category,
                )
            )
        if not topics:
            raise ValueError(f"{TOPICS_FILENAME}: section {section_id!r} declares no topics")
        parsed.append(
            Section(id=section_id, name=section_name, category=category, topics=tuple(topics))
        )
    return tuple(parsed)


def sections() -> tuple[Section, ...]:
    """Every checklist section, in registry order."""
    return load_registry()


@lru_cache(maxsize=1)
def all_topics() -> tuple[Topic, ...]:
    """Every topic, in registry order."""
    return tuple(topic for section in load_registry() for topic in section.topics)


@lru_cache(maxsize=1)
def _index() -> dict[str, Topic]:
    return {topic.id: topic for topic in all_topics()}


def topic_ids() -> frozenset[str]:
    """The set of every declared topic id."""
    return frozenset(_index())


def topic_by_id(topic_id: str) -> Topic | None:
    """Look up a topic, or None when the id is unknown."""
    return _index().get(topic_id)
