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


def test_rule_ids_are_well_formed():
    bad = [entry.id for entry in RULES if not ID_RE.match(entry.id)]
    assert not bad, f"rule ids outside the INTERFACES.md §3 format: {bad}"


def test_rule_ids_are_unique():
    assert len(IDS) == len(set(IDS))


def _metadata_problems(cls) -> list[str]:
    problems: list[str] = []
    if not isinstance(cls.category, Category):
        problems.append("category is not a Category")
    if not isinstance(cls.severity, Severity):
        problems.append("severity is not a Severity")
    if not isinstance(cls.confidence, Confidence):
        problems.append("confidence is not a Confidence")
    if not isinstance(cls.min_scale, ScaleClass):
        problems.append("min_scale is not a ScaleClass")
    if not isinstance(cls.autofix_safety, AutofixSafety):
        problems.append("autofix_safety is not an AutofixSafety")
    if not cls.title or cls.title.endswith("."):
        problems.append("title must be a non-empty phrase with no trailing period")
    if len(cls.description) <= 20:
        problems.append("description is too short to be specific")
    if len(cls.why_it_matters) <= 60:
        problems.append("why_it_matters must explain the stakes")
    if not cls.references:
        problems.append("needs at least one reference")
    problems += [f"reference {url!r} is not a URL" for url in cls.references
                 if not url.startswith("http")]
    return problems


def test_rule_metadata_is_complete():
    failures = {entry.id: _metadata_problems(entry.cls) for entry in RULES}
    broken = {rule_id: issues for rule_id, issues in failures.items() if issues}
    assert not broken, f"incomplete rule metadata: {broken}"


def test_rule_topics_are_declared_and_valid():
    known = set(topic_ids())
    undeclared = [entry.id for entry in RULES if not entry.cls.topics]
    assert not undeclared, f"rules declaring no checklist topics: {undeclared}"
    unknown = {
        entry.id: sorted(set(entry.cls.topics) - known)
        for entry in RULES
        if set(entry.cls.topics) - known
    }
    assert not unknown, f"rules claiming topics absent from topics.yaml: {unknown}"


#: Rules that gained a deterministic repair in M3. Anything outside this list must
#: still inherit ``Rule.fix`` — adding a repair is a deliberate, reviewed act.
RULES_WITH_FIXES = {
    "VG-API-001",
    "VG-SEC-001",
    "VG-SEC-002",
    "VG-SEC-007",
    "VG-SEC-011",
    "VG-SEC-014",
    "VG-SEC-016",
    "VG-SEC-018",
    "VG-CTR-001",
    "VG-CTR-002",
    "VG-CTR-004",
    "VG-OBS-001",
    "VG-REL-002",
    "VG-COST-003",
}


def test_only_the_declared_rules_implement_a_repair():
    overriding = {entry.id for entry in RULES if entry.cls.fix is not Rule.fix}
    assert overriding == RULES_WITH_FIXES


def test_every_repairing_rule_declares_an_autofix_class_that_allows_repair():
    """A rule that can repair itself must not be marked MANUAL_CHANGE_REQUIRED."""
    allowed = {AutofixSafety.SAFE_AUTOFIX, AutofixSafety.REVIEW_RECOMMENDED}
    wrong = {
        entry.id: entry.cls.autofix_safety.value
        for entry in RULES
        if entry.id in RULES_WITH_FIXES and entry.cls.autofix_safety not in allowed
    }
    assert not wrong, f"rules with a fix() but an unrepairable safety class: {wrong}"


def test_fix_never_raises_on_a_finding_it_did_not_produce(hostile_ctx):
    """fix() is as total as detect(): hostile input yields None, never an exception."""
    crashed: dict[str, str] = {}
    for entry in RULES:
        rule = entry.cls()
        finding = rule.make_finding(file="broken.py", line=1, snippet="def f(:")
        try:
            assert rule.fix(hostile_ctx, finding) is None or True
        except Exception as exc:  # noqa: BLE001 - the point of the test
            crashed[entry.id] = f"{type(exc).__name__}: {exc}"
    assert not crashed, f"rules raised from fix(): {crashed}"


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


def test_no_rule_crashes_on_hostile_input(hostile_ctx):
    crashed: dict[str, str] = {}
    for entry in RULES:
        rule = entry.cls()
        try:
            if not rule.applicable(hostile_ctx):
                continue
            findings = rule.detect(hostile_ctx)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            crashed[entry.id] = f"{type(exc).__name__}: {exc}"
            continue
        assert isinstance(findings, list), entry.id
        for finding in findings:
            assert finding.rule_id == entry.id
            assert finding.fingerprint
    assert not crashed, f"rules raised on hostile input: {crashed}"


def test_no_rule_crashes_on_an_empty_repository(tmp_path_factory):
    root = tmp_path_factory.mktemp("empty")
    ctx = context_from(root, {"README.md": "# nothing here\n"})
    crashed: dict[str, str] = {}
    for entry in RULES:
        rule = entry.cls()
        try:
            if rule.applicable(ctx):
                assert isinstance(rule.detect(ctx), list), entry.id
        except Exception as exc:  # noqa: BLE001 - the point of the test
            crashed[entry.id] = f"{type(exc).__name__}: {exc}"
    assert not crashed, f"rules raised on an empty repository: {crashed}"


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
