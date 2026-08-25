"""Cross-pack contract tests: every built-in rule obeys INTERFACES.md §3 and §11.

These are the guard rails that keep 100+ hand-written rules honest — id format,
topic validity, metadata completeness, proportionality, and the hard requirement that
no rule may crash on hostile input.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import context_from

from vibeguard.adapters import build_adapters
from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.core.registry import BUILTIN_PACKS, build_registry
from vibeguard.core.rule import Rule
from vibeguard.rules.topics import all_topics, topic_ids

REGISTRY = build_registry(list(BUILTIN_PACKS), include_plugins=False)
RULES = REGISTRY.registered

#: INTERFACES.md §3: "VG-{CAT}-{NNN}"; CAT in SEC,SCR,DB,API,REL,PERF,OBS,CTR,DEP,DEPS,
#: TEST,SCALE,DR,MAINT,COST.
ID_RE = re.compile(
    r"^VG-(SEC|SCR|DB|API|REL|PERF|OBS|CTR|DEP|DEPS|TEST|SCALE|DR|MAINT|COST|NET)-\d{3}$"
)

IDS = [entry.id for entry in RULES]


def test_the_pack_set_is_populated():
    assert len(RULES) >= 55, f"only {len(RULES)} rules registered"


@pytest.mark.parametrize("entry", RULES, ids=lambda e: e.id)
def test_rule_id_format(entry):
    assert ID_RE.match(entry.id), entry.id


def test_rule_ids_are_unique():
    assert len(IDS) == len(set(IDS))


@pytest.mark.parametrize("entry", RULES, ids=lambda e: e.id)
def test_rule_metadata_is_complete(entry):
    cls = entry.cls
    assert isinstance(cls.category, Category)
    assert isinstance(cls.severity, Severity)
    assert isinstance(cls.confidence, Confidence)
    assert isinstance(cls.min_scale, ScaleClass)
    assert isinstance(cls.autofix_safety, AutofixSafety)
    assert cls.title and not cls.title.endswith("."), cls.id
    assert len(cls.description) > 20, cls.id
    assert len(cls.why_it_matters) > 60, f"{cls.id}: why_it_matters must explain the stakes"
    assert cls.references, f"{cls.id}: needs at least one reference"
    for url in cls.references:
        assert url.startswith("http"), f"{cls.id}: {url!r}"


@pytest.mark.parametrize("entry", RULES, ids=lambda e: e.id)
def test_rule_topics_are_declared_and_valid(entry):
    cls = entry.cls
    assert cls.topics, f"{cls.id} declares no checklist topics"
    unknown = set(cls.topics) - set(topic_ids())
    assert not unknown, f"{cls.id} claims topics absent from topics.yaml: {sorted(unknown)}"


@pytest.mark.parametrize("entry", RULES, ids=lambda e: e.id)
def test_fix_is_a_stub_until_m3(entry):
    """M3 owns repairs: no built-in rule may return a Patch yet."""
    assert entry.cls.fix is Rule.fix, f"{entry.id} overrides fix() — that lands in M3"


def test_adapter_topics_are_valid():
    for adapter in build_adapters():
        unknown = set(adapter.topics) - set(topic_ids())
        assert not unknown, f"{adapter.name}: {sorted(unknown)}"


# ------------------------------------------------------------- proportionality


LARGE_ONLY_TOPICS = {
    "disaster-recovery.chaos-engineering",
    "disaster-recovery.multi-region-readiness",
    "distributed.leader-election",
    "distributed.split-brain",
    "distributed.saga-patterns",
    "database.sharding-readiness",
    "scaling.multi-region-deployment",
}


@pytest.mark.parametrize("topic_id", sorted(LARGE_ONLY_TOPICS))
def test_distributed_scale_topics_are_gated_to_large_projects(topic_id: str):
    """Anti-overengineering: a toy app must never be told to shard or run chaos drills."""
    owners = [entry for entry in RULES if topic_id in entry.cls.topics]
    if not owners:
        pytest.skip(f"{topic_id} has no detector; it falls back to REVIEW_REQUIRED")
    assert all(
        entry.cls.min_scale is ScaleClass.LARGE for entry in owners
    ), f"{topic_id} is claimed by a rule that fires below LARGE scale: {[o.id for o in owners]}"


# ----------------------------------------------------------------- robustness


HOSTILE_FILES: dict[str, str] = {
    "empty.py": "",
    "broken.py": "def f(:\n    return ???\n",
    "unicode.py": "# 🙈🙉🙊 ünïcødé\nx = '𝕊𝕄'\n",
    "nul.js": "const a = 1;\n\\u0000\n",
    "huge_line.py": "x = '" + ("A" * 30_000) + "'\n",
    "broken.json": "{not: json,,,}",
    "broken.yaml": "a: [1, 2\n  b: :::\n",
    "docker-compose.yml": "services:\n  - not-a-mapping\n",
    "Dockerfile": "FROM\nRUN\nCOPY\nUSER\n",
    ".github/workflows/ci.yml": "on: [push\njobs: {",
    "package.json": "{",
    "requirements.txt": "\x00\x01 not a requirement ===\n",
    "pyproject.toml": "[tool.\n",
    "deep/nested/path/with/a/very/long/name/module.py": "import os\n" * 500,
    "weird.py": "async def f():\n    return [x for x in range(10)]\n",
    "no_extension": "just text",
    "settings.py": "SECRET_KEY = ''\nDEBUG = None\n",
    "k8s.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec: null\n",
    "migrations/0001_init.py": "operations = [\n",
    "index.ts": "export const x = `${'`'}`;\n",
}


@pytest.fixture(scope="module")
def hostile_ctx(tmp_path_factory):
    root = tmp_path_factory.mktemp("hostile")
    return context_from(root, HOSTILE_FILES)


@pytest.mark.parametrize("entry", RULES, ids=lambda e: e.id)
def test_no_rule_crashes_on_hostile_input(entry, hostile_ctx):
    rule = entry.cls()
    if not rule.applicable(hostile_ctx):
        return
    findings = rule.detect(hostile_ctx)
    assert isinstance(findings, list)
    for finding in findings:
        assert finding.rule_id == entry.id
        assert finding.fingerprint


@pytest.mark.parametrize("entry", RULES, ids=lambda e: e.id)
def test_no_rule_crashes_on_an_empty_repository(entry, tmp_path_factory):
    root = tmp_path_factory.mktemp("empty")
    ctx = context_from(root, {"README.md": "# nothing here\n"})
    rule = entry.cls()
    if rule.applicable(ctx):
        assert isinstance(rule.detect(ctx), list)


def test_rules_do_not_report_on_their_own_test_fixtures(tmp_path: Path):
    """Fixture and test trees are excluded, so a rule cannot flag its own examples."""
    ctx = context_from(
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "tests/fixtures/bad.py": 'password = "hunter2hunter2"\nimport os\nos.system(x)\n',
            "tests/test_app.py": 'API_KEY = "sk-live-abcdefghijklmnop"\n',
        },
    )
    for entry in RULES:
        rule = entry.cls()
        if not rule.applicable(ctx):
            continue
        for finding in rule.detect(ctx):
            assert not (finding.file or "").startswith(
                ("tests/", "test/")
            ), f"{entry.id} reported on a test file: {finding.file}"


# ------------------------------------------------------------------- coverage


def test_topic_coverage_is_broad_and_reported(capsys):
    """Report how many topics have a real detector versus the honest fallback."""
    claimed: set[str] = set()
    for entry in RULES:
        claimed |= set(entry.cls.topics)
    for adapter in build_adapters():
        claimed |= set(adapter.topics)

    total = len(all_topics())
    covered = len(claimed & set(topic_ids()))
    uncovered = sorted(set(topic_ids()) - claimed)
    with capsys.disabled():
        print(
            f"\ntopic coverage: {covered}/{total} topics have >=1 detector "
            f"({covered * 100 // total}%); {len(uncovered)} fall back to REVIEW_REQUIRED"
        )
        if uncovered:
            print("  fallback topics: " + ", ".join(uncovered))
    assert covered >= total * 0.6, f"only {covered}/{total} topics have a detector"
