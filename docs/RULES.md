# Writing a rule

A rule is one claim about a repository, stated precisely enough that VibeGuard can
check it, explain it, and sometimes repair it. This guide is the practical companion
to the normative `Rule` contract in [INTERFACES.md §3](INTERFACES.md).

The house style, in one sentence: **a rule earns the right to say something is wrong,
and a `fix()` earns the right to change the code — neither is granted by default.**

---

## 1. The anatomy of a rule

```python
"""VG-API-001 — outbound HTTP calls that can hang forever."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety, Category, Confidence, Finding, Patch, ScaleClass, Severity,
)
from vibeguard.core.rule import Rule

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext


class HttpTimeoutPythonRule(Rule):
    """Outbound Python HTTP calls with neither a per-call nor a session timeout."""

    id: ClassVar[str] = "VG-API-001"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Outbound HTTP request without a timeout (Python)"
    description: ClassVar[str] = "..."
    why_it_matters: ClassVar[str] = "..."
    references: ClassVar[list[str]] = ["https://requests.readthedocs.io/..."]
    technologies: ClassVar[set[str]] = set()          # empty = any stack
    topics: ClassVar[set[str]] = {"api.timeouts", "network.network-timeouts"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.SAFE_AUTOFIX

    def detect(self, ctx: ScanContext) -> list[Finding]: ...
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None: ...
```

### The id

`VG-{CAT}-{NNN}`, where `CAT` is one of `SEC, SCR, DB, API, REL, PERF, OBS, CTR, DEP,
DEPS, TEST, SCALE, DR, MAINT, COST`. Ids are permanent: they appear in commit messages,
suppression files, and baselines that outlive any refactor. Take the next free number
in the pack and never reuse one.

### severity × confidence

These multiply into the score, so they are not decoration.

| | Use it when |
|---|---|
| `CRITICAL` | Remote compromise or total data loss follows directly. SQLi, RCE, leaked live credentials. |
| `HIGH` | Serious, exploitable, or an outage waiting for traffic. |
| `MEDIUM` | Real, bounded, usually a hardening gap. |
| `LOW` | Worth doing; nobody gets paged. |
| `INFO` | The absence of a practice, not a defect. Pair with `INFORMATIONAL`. |

Confidence describes *the detector*, not the defect: `HIGH` when the pattern cannot
plausibly be anything else, `MEDIUM` when a reasonable codebase might have a benign
version, `LOW` for heuristics. Confidence attenuates the score, so an honest `LOW` is
much better than an overconfident `HIGH`.

### `why_it_matters`

Write it in consequences, not vocabulary. The reader is the person who vibe-coded the
app and does not know what a CSPRNG is:

> These generators are built for simulations, not secrets: their output follows from
> internal state an attacker can reconstruct after seeing a handful of values. Once
> reconstructed, every future password-reset link, session id, or one-time code is
> predictable, and accounts can be taken over without any password ever being guessed.

Not: *"`random` is not cryptographically secure (CWE-338)."*

### `technologies` and `min_scale` — the proportionality contract

`applicable()` defaults to *technology match ∧ scale match*. `technologies` is matched
case-insensitively against every token discovered by `TechProfile.all_technologies()`;
an empty set means "any stack".

`min_scale` is the anti-overengineering mechanism, and it is the single most
frequently mis-set field on a new rule. The question is not "is this good practice?"
It is **"would a competent engineer, looking at a project of this size, call its
absence a defect?"**

| Scale | Set `min_scale` here when the advice only makes sense with… |
|---|---|
| `TOY` | Nothing. It is a defect in a 50-line script too — SQLi, a leaked key, `verify=False`. |
| `SMALL` | A real user or a deploy target: no backups, no CI, unpinned dependencies. |
| `MEDIUM` | Operations: health endpoints, correlation ids, SLOs, structured logging. |
| `LARGE` | Multiple teams or services: sharding, meshes, multi-region, chaos testing. |

`VG-OBS-004` (*no health-check endpoint*) is `MEDIUM` for exactly this reason. A
weekend project with no `/healthz` is not broken; a system with an orchestrator
restarting it is.

`min_scale` bounds the project; it does not bound *which part of the project* an
argument applies to. If a rule reasons from "a second instance behind a load balancer
would…", it needs a request path to point at, not merely a web framework in the
manifest — a CLI that ships a small local web UI has one of those. `VG-SCALE-001` and
`VG-SCALE-003` use `scaling._signals.is_request_path(ctx, rel)` for this (DECISIONS.md
D66). The general form of the question: *what has to be true of this code for my
`why_it_matters` paragraph to be true?* Gate on that, not on a proxy for it.

If your rule fires on the wrong sort of project, the fix is usually `min_scale` — and
occasionally an override:

```python
def applicable(self, ctx: ScanContext) -> bool:
    return super().applicable(ctx) and ctx.exists("Dockerfile")

# Explain the refusal, so the checklist's NOT_APPLICABLE row has a reason.
not_applicable_note: ClassVar[str] = "no Dockerfile in this repository"
```

### `topics`

Every rule declares the master-checklist topics it evaluates (`topics.yaml`, 279 of
them across 18 sections). This is how a report can promise it accounted for
everything. A topic with no detector is reported `review_required`, never `pass` — so
adding a rule and *forgetting* its topics silently leaves a gap. `tests/test_topics.py`
asserts every declared topic exists.

### `autofix_safety`

| Value | Meaning | Applied by |
|---|---|---|
| `SAFE_AUTOFIX` | A provably behaviour-preserving edit exists. | `fix --safe` and `--interactive` |
| `REVIEW_RECOMMENDED` | A good edit exists, but a human should see the diff. | `fix --interactive` only |
| `MANUAL_CHANGE_REQUIRED` | No template can preserve intent. | never |
| `INFORMATIONAL` | Reports an absence, not a defect. | never — the repair loop skips it entirely |

This is a claim about *the repair*, not the severity. Declaring `SAFE_AUTOFIX` without
implementing `fix()` is legitimate and means "a safe fix is known to exist".

---

## 2. Detection

Pick the lowest tier that settles the question:

1. **File and manifest presence, config parsing.** `ctx.exists()`, `ctx.files_matching()`,
   the Dockerfile/compose parsers in `rules/containers/_parse.py`.
2. **Regex with a context window.** Use the shared `RegexRule` base and the helpers in
   `rules/_support.py`.
3. **tree-sitter AST.** `ctx.ast(relpath)` returns a cached parse for `.py`, `.js`,
   `.ts` and friends, or `None`. `py_calls(ctx, rel)` / `js_calls(ctx, rel)` give you
   `CallSite` objects with `.name`, `.base`, `.args`, `.line`, `.node`.
4. **An external adapter.** If a mature tool already answers it, orchestrate the tool.
5. **An LLM.** Only for architectural reasoning and cross-file dataflow a parser cannot
   settle. Set `requires_ai = True`; the engine will skip the rule when no provider is
   available and the report will say the scan was degraded. Never use a model for what
   a parser does.

Rules must never raise on normal input, must be bounded (cap findings per rule — the
built-ins use 3–10), and must never write anything.

### A *mention* is not an occurrence

Any rule at tier 2 will, sooner or later, match its own subject inside a docstring, a
comment, or a prose string. Ours did: `VG-SEC-018` reported itself four times, because
its `description` has to contain the literal words `verify=False`.

`rules/_support` exports the cure:

```python
from vibeguard.rules._support import is_non_code_line, is_non_code_span

if is_non_code_line(ctx, rel, line_no):
    continue                                   # the whole line is string/comment content
```

`is_non_code_line` is true only when a line carries **no executable tokens at all** —
a docstring body, a wrapped prose string, a block comment. That definition is what
makes it safe to switch on: `SECRET_KEY = "hunter2"` and
`headers.update({"Access-Control-Allow-Origin": "*"})` both carry code, so rules whose
subject genuinely *is* a string value keep working untouched.

`RegexRule` exposes the same thing as `skip_non_code: ClassVar[bool] = True`, opt-in
per rule.

`is_non_code_span(ctx, rel, line_no, match.start(), match.end())` is stricter: it asks
whether the *match* sits inside one string. Use it only where the reading is
unambiguous — `print(` inside a string literal is the word "print", never a call. Do
**not** use it where a string can legitimately carry the defect: `curl -k` inside a
shell command string, a `SELECT *` inside a query, a credential inside a connection
string.

If you find yourself reaching for either helper on every line of a rule, that is a
signal the rule belongs at tier 3 instead: an AST rule that inspects real call nodes
never had this problem in the first place.

### Whose project is this file describing?

`ctx.files` is everything scanned, including `tests/`, `examples/`, and `vendor/`.
Detection rules should keep scanning all of it — a real vulnerability in a test file is
still a vulnerability, and `source_files(..., skip_tests=True)` is available when a
particular rule wants otherwise.

But a rule that makes a claim about **the project as a whole** — "this project is
orchestrated with Kubernetes", "these are its declared dependencies", "there is no
lockfile" — must read primary files only, or a fixture Deployment manifest will make
that claim for it:

```python
if ctx.is_fixture(rel):
    continue                       # material this project carries, not what it is
```

See DECISIONS.md D64. Discovery already applies the split to the tech profile and the
scale class, so `ctx.tech` and `ctx.scale` need no extra care.

### `make_finding`

Never construct a `Finding` directly. `Rule.make_finding()` computes the fingerprint,
redacts secrets, and stamps the id:

```python
self.make_finding(
    file=rel,
    line=call.line,
    snippet=f"{call.name}{call.args}"[:400],
    description=f"{call.name}() at {rel}:{call.line} passes no timeout=...",
    recommended_followup="Pass an explicit timeout, e.g. `requests.get(..., timeout=(3.05, 10))`.",
)
```

Two things about `snippet` are load-bearing:

* The **fingerprint** is `sha256(rule_id | path | normalised snippet)`. It is what
  makes baselines and suppressions survive reformatting — so the snippet must be the
  *defect*, not the whole function, and must not contain line numbers or anything else
  that changes for unrelated reasons.
* Two findings with the same normalised snippet in the same file **are the same
  finding** and deduplicate. Include enough to distinguish genuinely different
  occurrences.

Redaction is automatic for `Category.SECRETS`; pass `redact_evidence=True` or set
`Evidence.redact` anywhere else a value might be sensitive. It happens *after*
fingerprinting, so extending the redaction patterns never moves a baseline.

---

## 3. Writing a `fix()`

The four house rules, from `rules/_fixes.py`:

1. **Provable or nothing.** If the preconditions for a safe edit are not met, return
   `None`. Detection still reports the finding; we simply do not guess.
2. **Nothing beyond the remediation.** No reformatting, no import sorting, no drive-by
   cleanups. The diff must contain only the fix.
3. **Idempotent.** Re-running on already-fixed content produces no patch.
4. **Recompute from disk.** The patch is built from the file *as it is right now*, and
   carries the sha256 of exactly that content.

```python
def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
    rel, line_no = finding.file, finding.line
    if not rel or not line_no:
        return None
    text = ctx.read(rel)                        # current disk content

    # Re-locate the defect: an earlier fix to this file may have shifted it.
    target = locate_line(
        text, line_no,
        matches=lambda line: bool(_VERIFY_FALSE.search(line)),
        snippet=finding_snippet(finding),
    )
    line = line_at(text, target)
    if target is None or line is None:
        return None                             # ambiguous — leave it unfixed

    repaired = _VERIFY_FALSE.sub(r"\1True", line)
    if repaired == line:
        return None                             # already fixed: idempotent

    return whole_file_patch(
        finding, rel, text, replace_line(text, target, repaired),
        description="Re-enable TLS certificate verification at ...",
        scope="security",
        summary="re-enable TLS certificate verification",
    )
```

`whole_file_patch` produces a `FileEdit` carrying `old_content_sha256`. The fixer
engine re-reads the file and compares that sha immediately before writing: a file that
changed underneath aborts its own fix rather than being clobbered. `commit_message` is
built for you as `fix(scope): summary [VG-XXX-NNN]`.

### Re-locating, not trusting, line numbers

`locate_line` and `locate_call` accept the recorded line when it still matches the
defect, otherwise take a *unique* match within twelve lines, and return `None` when the
target is ambiguous. Editing the wrong line is far worse than leaving a finding
unrepaired. Never index into `text.splitlines()` with `finding.line` directly.

### What you may not repair

The fixer engine refuses, **in every mode and regardless of flags**, anything whose
category is `DATABASE` or whose declared topics start with `database.`, `iac.`,
`kubernetes.`, or contain `migration`, `schema`, `auth`, `backup`, or
`encryption-at-rest`. A wrong edit there is not a bad diff, it is data loss or an
outage. Such findings get `REQUIRES_REVIEW` with the remediation instructions.

### Repro tests

If your rule's defect can be checked as a property of the artifact — "this call has a
`timeout=`", "this Dockerfile has a `USER`" — add a template to
`vibeguard/testing/repro.py`. The repair loop will generate the test, confirm it
**fails** before the patch, and require it to **pass** after; that is what upgrades an
otherwise-`UNVERIFIED` edit to `FIXED`. Templates must:

* import nothing from `vibeguard` (they outlive us in the user's repository);
* anchor on `SNIPPET` (the finding's normalised snippet) so a neighbouring unrepaired
  defect of the same rule cannot fail them;
* use the standard library only — `ast` for Python, plain text scanning otherwise.

A rule with no template is a silent skip and its status logic is unchanged.

---

## 4. Registering it

```python
# src/vibeguard/rules/api/__init__.py
from vibeguard.rules.api.timeouts import HttpTimeoutJsRule, HttpTimeoutPythonRule

RULES = [HttpTimeoutPythonRule, HttpTimeoutJsRule, ...]
```

Packs are organised by *concern*, not by language (`security`, `api`, `database`,
`containers`, …) — "an HTTP call with no timeout" belongs to `api` whatever language it
is written in. Add the pack to `BUILTIN_PACKS` and `DEFAULT_PACKS` if it is new.

Third-party packs use the `vibeguard.rules` entry point instead — see
[PLUGINS.md](PLUGINS.md).

---

## 5. Testing conventions

Tests live in `tests/test_rules_<pack>.py` and use the helpers in `tests/conftest.py`:

```python
from tests.conftest import run_rule

SOURCE = """\
import requests

def fetch(url):
    return requests.get(url)
"""


def test_a_call_without_a_timeout_is_reported(tmp_path):
    findings = run_rule(HttpTimeoutPythonRule, tmp_path, {"app.py": SOURCE})
    assert [f.line for f in findings] == [4]


def test_an_explicit_timeout_is_accepted(tmp_path):
    assert not run_rule(
        HttpTimeoutPythonRule, tmp_path,
        {"app.py": SOURCE.replace("get(url)", "get(url, timeout=5)")},
    )
```

`run_rule` writes the files, runs real discovery, applies the applicability gate, and
returns `[]` when the gate rejects the fixture — which is exactly what a proportionality
test wants to assert.

Every rule needs at least:

1. **A positive test** on realistic code, asserting the line and something about the
   message.
2. **A negative test** on the *correct* version of the same code. This is the one that
   catches false positives, and it is not optional.
3. **A proportionality test** if the rule has a `min_scale` above `TOY` or non-empty
   `technologies`.
4. **For `fix()`:** apply the patch to the fixture, assert the exact resulting text,
   assert re-running produces `None` (idempotence), and assert `fix()` returns `None`
   when its preconditions are absent.

Repo-wide contract tests you must not break:

* `tests/test_rules_contract.py` — ids unique and well-formed, every field populated,
  `why_it_matters` long enough to be an explanation, and an **explicit allow-list of
  the rules permitted to implement `fix()`**. Adding a repair is a deliberate,
  reviewed act: add your rule to that list in the same commit.
* `tests/test_topics.py` — every declared topic exists in `topics.yaml`.
* `tests/test_examples.py` — the shipped example app still produces its headline
  findings.

Run them:

```bash
PYTHONMALLOC=malloc python -m pytest -q
ruff check .
```
