# Extending and embedding VibeGuard

Four extension points, in rough order of how often they get used:

1. [Third-party rule packs](#1-third-party-rule-packs) — `vibeguard.rules` entry point
2. [Tool adapters](#2-tool-adapters) — orchestrate an external scanner
3. [AI providers](#3-ai-providers) — choosing and configuring one, and the privacy gate
4. [Embedding](#4-embedding) — the library API, the JSON-lines event stream, `plugin.json`

For writing the rules themselves, see [RULES.md](RULES.md).

---

## 1. Third-party rule packs

A rule pack is any importable module exposing `RULES: list[type[Rule]]`, advertised
under the `vibeguard.rules` entry-point group. The registry
(`vibeguard.core.registry`) discovers it at runtime; installing your package is the
only wiring step. The entry point may resolve to the list itself or to a module that
exposes one.

### A complete minimal pack

```
vibeguard-acme/
├── pyproject.toml
└── src/vibeguard_acme/
    ├── __init__.py
    └── rules.py
```

**`pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "vibeguard-acme"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["vibeguard>=0.2"]

[project.entry-points."vibeguard.rules"]
acme = "vibeguard_acme.rules"

[tool.hatch.build.targets.wheel]
packages = ["src/vibeguard_acme"]
```

**`src/vibeguard_acme/rules.py`**

```python
"""ACME house rules."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety, Category, Confidence, Finding, ScaleClass, Severity,
)
from vibeguard.core.rule import Rule

if TYPE_CHECKING:
    from vibeguard.discovery.context import ScanContext

_STAGING_HOST = re.compile(r"https?://[\w.-]*staging\.acme\.internal")


class StagingUrlInProductionCodeRule(Rule):
    """A staging hostname hard-coded in shipped source."""

    id: ClassVar[str] = "ACME-SEC-001"
    category: ClassVar[Category] = Category.DEPLOYMENT
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Staging hostname hard-coded in application source"
    description: ClassVar[str] = (
        "A staging.acme.internal URL appears in source that ships to production."
    )
    why_it_matters: ClassVar[str] = (
        "Production traffic silently reaching staging is how test data ends up in "
        "customer accounts and how staging outages become production outages. The "
        "host is also unreachable from production networks, so the failure mode is a "
        "hang rather than an error."
    )
    references: ClassVar[list[str]] = ["https://runbooks.acme.internal/envs"]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"deployment.environment-separation"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in ctx.files_matching(".py", ".js", ".ts"):
            if len(findings) >= 10:
                break
            for number, line in enumerate(ctx.read(rel).splitlines(), start=1):
                match = _STAGING_HOST.search(line)
                if not match:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=number,
                        snippet=line.strip()[:200],
                        description=f"{rel}:{number} hard-codes {match.group(0)}.",
                        recommended_followup=(
                            "Read the base URL from configuration and set it per "
                            "environment."
                        ),
                    )
                )
                break
        return findings


RULES = [StagingUrlInProductionCodeRule]
```

Then:

```bash
pip install -e vibeguard-acme
vibeguard rules --pack acme     # ACME-SEC-001 is now registered
vibeguard audit .
```

### Rules of the road

* **Prefix your ids.** `ACME-…`, not `VG-…`. Ids appear in baselines and suppression
  files that outlive your package; a collision with a built-in is silently ignored by
  the registry (first registration wins) and the resulting gap is very hard to spot.
* **Declare `topics` from `topics.yaml`** if your rule covers one, so it counts towards
  the checklist. Unknown topic ids are ignored, not an error.
* **A pack that fails to import is logged and skipped**, never fatal — but that means a
  broken plugin degrades coverage silently. Test yours.
* **`--packs` selects built-ins only.** Plugin packs load whenever they are installed.
* Everything in [RULES.md](RULES.md) applies: bounded output, never raise, never write,
  and `min_scale` set honestly.

---

## 2. Tool adapters

An adapter wraps an external scanner. It must never crash a scan: `available()` never
raises, and `run()` swallows subprocess, timeout, and parse failures and returns `[]`.

```python
from typing import ClassVar

from vibeguard.adapters.base import ToolAdapter
from vibeguard.core.models import Category, Finding, Severity


class AcmeScanAdapter(ToolAdapter):
    name: ClassVar[str] = "acmescan"
    description: ClassVar[str] = "ACME's internal SAST"
    command: ClassVar[str] = "acmescan"          # probed on PATH by available()
    category: ClassVar[Category] = Category.SECURITY
    topics: ClassVar[set[str]] = {"security.sql-injection"}
    technologies: ClassVar[set[str]] = {"python"}
    requires_network: ClassVar[bool] = False     # True => skipped under --local-only
    timeout: ClassVar[int] = 300

    #: Native severity -> ours. Every adapter owns this mapping explicitly.
    _SEVERITY = {"blocker": Severity.CRITICAL, "major": Severity.HIGH,
                 "minor": Severity.MEDIUM, "info": Severity.LOW}

    def run(self, ctx) -> list[Finding]:
        # exec_json runs with a timeout and returns None on *any* failure —
        # non-zero exit, timeout, unparseable output. Never raises.
        payload = self.exec_json([self.command, "--json", "."], ctx)
        return [
            self.make_finding(
                native_id=item["rule"],
                file=item["path"],
                line=item["line"],
                snippet=item["excerpt"],
                title=item["title"],
                description=item["message"],
                why_it_matters=item.get("rationale", "Reported by acmescan."),
                severity=self._SEVERITY.get(item["severity"], Severity.MEDIUM),
            )
            for item in (payload or {}).get("results", [])
        ]
```

Findings get rule ids `VG-EXT-{tool}-{native_id}`. Because a fingerprint embeds the
rule id, a built-in and an adapter can never share one; the engine instead merges
across sources on `(evidence file, normalised snippet)`, keeps the built-in finding,
and annotates it `corroborated by acmescan (VG-EXT-acmescan-…)`. Nothing is dropped
silently.

Set `requires_network = True` for anything that phones home — a registry ruleset
download, an advisory API, a vulnerability-database refresh. Under `--local-only` it is
skipped and `ScanReport.adapters_used` records *why*, so a report never implies
coverage it did not have.

There is no entry-point group for adapters yet; add yours to
`vibeguard/adapters/__init__.py::build_adapters()`, or pass
`Engine(config, adapters=[...])` when embedding.

---

## 3. AI providers

**AI is optional and off by default.** Every built-in rule is deterministic; the whole
MVP pipeline runs with `provider = "null"`. A rule opts in with `requires_ai = True`,
and when no provider is available the engine *skips it* — a rule that needs a model has
no deterministic half to substitute — and the report carries a warning saying the scan
was deterministic-only. It never quietly implies coverage.

### Configuration

```toml
# .vibeguard.toml
[vibeguard]
local_only = false

[ai]
provider    = "null"              # null | anthropic | openai_compatible
endpoint    = ""                  # openai_compatible only
model       = ""
api_key_env = ""                  # name of the env var, never the key itself
```

| Provider | `endpoint` | `model` default | `api_key_env` default | Local? |
|---|---|---|---|---|
| `null` | — | — | — | yes (nothing leaves) |
| `anthropic` | optional base URL | `claude-sonnet-5` | `ANTHROPIC_API_KEY` | **no** |
| `openai_compatible` | `http://localhost:11434/v1` | `llama3.1` | none | computed |

`openai_compatible` is a plain `POST {endpoint}/chat/completions`, which covers OpenAI,
**Ollama** (`http://localhost:11434/v1`), **LM Studio**
(`http://localhost:1234/v1`), **vLLM**, and most agent gateways with one code path.

The key is always read from the environment by *name*. VibeGuard never stores, logs, or
reports a key.

### `is_local` is computed, not configured

```toml
[ai]
provider = "openai_compatible"
endpoint = "http://localhost:11434/v1"   # is_local = true
# endpoint = "https://api.openai.com/v1" # is_local = false
```

A provider is local when its endpoint host is `localhost`, `127.0.0.1`, `::1`,
`0.0.0.0`, or a `*.local` mDNS name. The check is name-based on purpose: a DNS lookup
would itself be a network call, and a hostile resolver could make a remote host *look*
local. When in doubt the answer is "not local", which makes `--local-only` refuse a
provider rather than quietly permit one.

### The `local_only` gate

`vibeguard.ai.factory.get_provider()` is the only way the rest of the codebase obtains
a provider, so the gate cannot be walked around:

```
local_only && !provider.is_local  ->  ai.blocked event + NullProvider + a report warning
```

The refusal is total. No rule gets a degraded remote provider; it gets none at all, and
the run continues deterministically.

### Nothing leaves without saying so

`AIGateway.complete()` is the single call site for completions. Before any prompt goes
to a non-local provider it emits `ai.external_send` **and prints a notice to stderr**:

```
vibeguard: sending code to a remote AI provider: anthropic (anthropic) —
1843 characters of your code and findings are being sent now. Use --local-only to forbid this.
```

`ScanReport.ai_used` is set from whether a completion actually came back — a configured
provider that was never called, or that failed, does not count as "AI used".

### Using it from a rule

```python
class ArchitecturalReviewRule(Rule):
    requires_ai: ClassVar[bool] = True

    def detect(self, ctx):
        # Guaranteed by the engine: requires_ai rules only run with a provider.
        answer = ctx.ai.complete(system="You are a code auditor.", prompt=...)
        ...
```

From a rule that is *optionally* AI-assisted, use `ctx.ai_available()` and
`ctx.ai.try_complete(...)`, which returns `None` instead of raising, and fall back to
the deterministic answer.

---

## 4. Embedding

### Library API

```python
from vibeguard import Engine, VibeguardConfig

config = VibeguardConfig.load("path/to/repo")      # reads .vibeguard.toml
report = Engine(config).audit("path/to/repo")      # -> ScanReport

report.overall_before          # 0-100 heuristic
report.findings                # list[Finding]
report.checklist               # 279 ChecklistItems, always complete
report.model_dump_json()       # the canonical schema (INTERFACES.md §8)
```

`Engine.audit()` **never writes to the repository being scanned**. It reads
`.vibeguard/` (baseline, suppressions, history) and returns the diff on the report, but
persistence is the caller's job:

```python
from vibeguard.baseline import write_history
from vibeguard.reporting import write_reports

write_reports(report, root, {"json", "md", "html"})
write_history(report, root, keep=50)
```

The diagram renderers are importable on their own, so a host can embed the pictures
without the surrounding document. All four are pure functions of a `ScanReport`, pure
stdlib, and deterministic:

```python
from vibeguard.reporting.diagram import (
    mermaid_architecture,   # str  — a `flowchart LR` block, no fences
    svg_architecture,       # str  — inline SVG, fixed viewBox, no script or asset
    svg_scores,             # str  — category scores as horizontal bars
    svg_checklist,          # str  — one stacked bar per checklist section
    graph_is_trivial,       # bool — <=1 node and no edges: render a note instead
)

svg = svg_architecture(report)      # drop straight into your own page
```

They are what the markdown report's **Architecture** section and the HTML report's
**Architecture & health at a glance** section are built from, and what
`vibeguard graph PATH --format mermaid|svg` prints. Node colour comes from the
category score that governs each node kind — the mapping is a table in the
`vibeguard.reporting.diagram` module docstring.

Other entry points: `Engine(config).fix(path, "safe" | "interactive", confirm=fn)` and
`Engine(config).ci(path) -> (report, exit_code)`. Constructor injection points —
`events`, `registry`, `adapters`, `ai` — make the engine straightforward to test and to
restrict.

### Events

```python
from vibeguard.core.events import EventBus

bus = EventBus()
bus.subscribe("scan.*", lambda name, data: ...)     # fnmatch patterns; "*" for all
report = Engine(config, events=bus).audit(path)
```

Subscribers are synchronous, and an exception in one never breaks the emitting
pipeline. On the CLI, `--output jsonl` streams the same events to stdout as one JSON
object per line:

```json
{"event": "scan.issue_found", "ts": "2026-08-25T16:28:20+00:00", "data": {"finding": {...}}}
```

The first ten names are normative ([INTERFACES.md §6](INTERFACES.md)); the rest are
additive extensions, and a subscriber that only knows §6 simply never matches them.

| Event | Payload keys | When |
|---|---|---|
| `scan.started` | `repo`, `mode` | Once, before discovery. |
| `scan.stage` | `stage` | Progress: `discovery.files`, `detect:VG-SEC-001`, `adapter:bandit`, `scoring`, … |
| `scan.issue_found` | `finding` (the full serialised `Finding`) | Per finding, as it is produced. |
| `scan.completed` | `repo`, `mode`, `findings`, `counts`, `overall` | Once, after scoring. |
| `repair.started` | `finding`, `rule_id`, `files`, `summary` | Before a patch is written. |
| `repair.completed` | `finding`, `rule_id`, `status`, `commit` | After a patch is validated and committed. |
| `repair.failed` | `finding`, `rule_id`, `status`, `detail` | Patch abandoned or rolled back. |
| `validation.started` | `finding`, `rule_id`, `files` | Before the ladder runs for a patch. |
| `validation.completed` | `finding`, `rule_id`, `status`, `steps` | After it, with every `ValidationStep`. |
| `report.generated` | `path`, `format`, `paths` | After the report files are written. |
| `ai.external_send` | `provider`, `endpoint`, `model`, `characters` | **Before** a prompt leaves the machine. |
| `ai.blocked` | `provider`, `reason`, `local_only` | `local_only` refused a non-local provider. |
| `repro.generated` | `finding`, `rule_id`, `path`, `describes` | A repro test was written. |
| `repro.result` | `finding`, `rule_id`, `path`, `phase` (`before`/`after`), `passed`, `detail` | A repro test was run. `passed: null` means inconclusive. |
| `scan.discovery_progress` | `phase`, `files`, `total` (may be `null`), `detail` | Repeatedly *during* discovery, refining the current `scan.stage`. Throttled to at most one event per 250 files or 250 ms (DECISIONS.md D70). |

Payloads are JSON-serialisable dicts. Treat them as additive: new keys may appear.

### `plugin.json`

The repository-root [`plugin.json`](../plugin.json) is the agent-host manifest
(ARCHITECTURE.md §10.3). It names the entry command, the argv for each mode and whether
it writes, the exit codes, the artifacts produced, the privacy posture, and the full
event table above — so a host that can spawn a subprocess and read JSON lines can drive
VibeGuard from that file alone, without importing anything.

### CI surfaces

* **GitHub Action** — [`action.yml`](../action.yml), a composite action with
  `path` / `fail-on` / `local-only` / `baseline` inputs that uploads the report as a
  workflow artifact and fails the job afterwards, so exit 1 never costs you the report.
* **pre-commit** — [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) exposes
  `vibeguard-ci` (gates) and `vibeguard-audit` (informational). Both are
  repository-scoped rather than file-scoped: VibeGuard's rules are cross-file by
  nature, and a per-file invocation would answer them wrongly.
* **Docker** — `docker run --rm -v "$PWD":/repo ghcr.io/vibeguard/vibeguard audit /repo`.
