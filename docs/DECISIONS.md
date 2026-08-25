# Decision log

Conservative interpretations of the binding contracts in `docs/INTERFACES.md`.
`ARCHITECTURE.md` and `INTERFACES.md` are never edited to accommodate the code; any
ambiguity is resolved here instead.

## M1 — core skeleton

### D1. `ScanContext` lives in `vibeguard/discovery/context.py`

INTERFACES.md §2 lists `ScanContext` in the core-models block, but it depends on
`VibeguardConfig` (§9) and on the discovery profiles, which would create an import
cycle inside `core`. It is implemented in `vibeguard.discovery.context` and re-exported
lazily from `vibeguard.core.models` via a module `__getattr__`, so
`from vibeguard.core.models import ScanContext` remains valid. Nothing is redefined.

### D2. `normalize()` removes whitespace rather than collapsing it

§7 says fingerprints use "normalize strips whitespace runs and lowercases". "Strips" is
read literally: whitespace runs are removed, not replaced by a single space. This is the
more conservative choice for the stated goal (line-number and formatting independence) —
reindentation and line wrapping then fingerprint identically.

### D3. Fingerprints are computed from the raw snippet, before redaction

`make_finding` computes the fingerprint from the snippet as the rule saw it, then
redacts the evidence that is stored. Redacted text never leaves the process
un-fingerprinted, and baselines stay stable when the redaction pattern set is extended.

### D4. `Evidence` carries an explicit `redact` flag

§7 refers to "any Evidence flagged `redact=True`" while the §2 model listing does not
show the field. The field is added (default `False`) since §7 requires it.

### D5. Config `exclude` extends the built-in defaults

§9 shows `exclude = ["**/node_modules/**", "**/.venv/**"]` as an example value. A
project listing its own excludes almost certainly means "also skip these", so file
values are unioned with the defaults instead of replacing them. `.gitignore` is always
applied on top, per §9.

### D6. `Severity` gained an `.order` property

§1 declares only `ScaleClass` as ordered, but the CI `fail_on` threshold (§9, §11)
requires severity comparison. `Severity.order` mirrors `ScaleClass.order`; no values or
names change.

### D7. Scoring of inapplicable categories

§8 says a category with no applicable rules is `applicable=False` and is excluded from
the overall score. Such categories are still emitted in `scores_before` (so the report
schema is complete) with `score=100`, `finding_count=0`, and `applicable=False`.

### D8. `Engine.audit` never writes to the scanned repository

Writing `vibeguard-report.json` is the CLI's job, not the engine's, so library embedders
(§10.2) get a pure function. `.vibeguard/history/` persistence lands with M4.

### D9. Scoring lives in `vibeguard/reporting/scoring.py`

ARCHITECTURE.md §3 places scoring under `reporting/`; the engine imports it from there
rather than owning a second copy.

### D10. Stub commands exit 0 (M1)

`fix`, `report`, and `baseline` print the milestone that implements them and exit `0`.
Exit `2` is reserved for genuine execution errors (§11).

## M2 — detection

### D11. Rule packs are organised by concern, not only by language

INTERFACES.md does not fix the pack list; ARCHITECTURE.md §6 names a language-oriented
set (`core, secrets, web, security, database, devops, node, python, …`) while §3 lays the
tree out by concern (`security/ database/ api/ containers/ deployment/ observability/
reliability/ dependencies/ performance/ secrets/`). M2 follows §3, because a rule like
"outbound HTTP call without a timeout" belongs to *api* regardless of language, and adds
the concern packs the checklist needs: `api, reliability, observability, containers,
deployment, dependencies, disaster_recovery, testing, performance, scaling, cost,
network`. The §6 language packs (`web, devops, python, node`) stay registered and empty,
reserved for genuinely language-specific rules in later milestones. `BUILTIN_PACKS` and
`DEFAULT_PACKS` list both sets, so `--packs` keeps working and no pack disappears.

### D12. Checklist status for advisory findings

§11 defines REVIEW_REQUIRED as "findings needing manual review, or the topic is
applicable but has no automated detector yet", and FAIL as "open unfixed findings". A
finding is treated as *needing manual review* when its `autofix_safety` is
`INFORMATIONAL` (or `NOT_APPLICABLE`) — that is, the rule reports an absence of evidence
("no metrics configured", "no chaos testing") rather than a defect. If any open finding
on a topic is a real defect, the topic is FAIL. This keeps "you have no SLOs" out of the
same bucket as "you have SQL injection" without ever converting either one into PASS.

### D13. Adapter corroboration is matched on evidence, not fingerprint

§4 says adapter findings "dedup vs built-ins … by fingerprint in the engine", but §7
defines the fingerprint as `sha256(rule_id | relpath | normalized_snippet)` — the rule id
is part of it, so a built-in and an adapter can never produce the same fingerprint. The
engine therefore dedups *within* each source by fingerprint (as specified) and merges
*across* sources on `(evidence file, normalised snippet)`: the built-in finding is kept,
and the adapter's agreement is recorded as a `corroborated by <tool>` note on the
evidence. Nothing is dropped silently.

### D14. `local_only` skips network-touching adapters, and the report says so

ARCHITECTURE.md §9 gates the AI layer on `local_only`; the same principle is applied to
adapters that leave the machine: `semgrep --config auto` (downloads the registry
ruleset), `pip-audit` (PyPI advisory API), `npm audit` (npm registry) and `trivy` (vuln
DB refresh) declare `requires_network = True` and are skipped under `local_only`.
`ScanReport.adapters_used` records every adapter that did not run together with the
reason (`local_only: tool contacts a remote service`, `not installed`, `run error`), so
a report never implies coverage it did not have.

### D15. `ScanContext` is not mutated by the checklist derivation

The checklist is derived from three inputs — the registered rules (with their
applicability verdict), the adapters that actually ran, and the findings — rather than
from rule bookkeeping during detection. This keeps `Engine.audit` a pure function of the
repository (D8) and leaves a clean seam for M3: once the repair loop attaches
`FixRecord`s to findings, the same derivation reports FIXED topics with their validation
evidence, with no further engine changes.

### D16. Rules never implement `fix()` in M2 (superseded by D17)

INTERFACES.md §3 makes `fix()` optional and ARCHITECTURE.md §12 assigns repairs to M3.
Rules that were designed with a deterministic template patch in mind carry a
`# M3 fix(): …` comment naming the exact edit, and a contract test asserts that no
built-in rule overrides `Rule.fix` yet — so "SAFE_AUTOFIX" in M2 means "a safe fix is
known to exist", never "a fix was applied".

## M3 — repair, git safety, validation

### D17. Fourteen rules implement `fix()`; the rest stay detect-only

D16's contract test ("no rule overrides `fix()`") is replaced by an explicit allow-list:
`test_only_the_declared_rules_implement_a_repair` asserts that exactly the fourteen rules
M2 flagged with a `# M3 fix():` comment (plus VG-SEC-014's helmet case) override
`Rule.fix`, and that each of them is classified `SAFE_AUTOFIX` or `REVIEW_RECOMMENDED`.
Adding a repair therefore stays a deliberate, reviewed act rather than something a rule
can acquire by accident. The remaining M2 markers name repairs whose "right" edit is a
product decision (retry backoff, DR volumes, CI steps, Redis adoption); they stay
comments.

### D18. `GitSafety.commit` returns `str | None`

INTERFACES.md §5 types it as `-> str`. In the `--allow-no-git` fallback mode
(ARCHITECTURE.md §7) there is no commit to return, and inventing a fake sha would put a
lie in `FixRecord.commit_sha`. The return type is widened to `str | None`; `None` means
"applied, backed up as `<file>.orig`, not committed", and the CLI prints `—` for it.

### D19. A dirty worktree means *tracked* modifications

`preflight()` runs `git status --porcelain --untracked-files=no`. Untracked files cannot
be clobbered by `git checkout -- <path>` and are never staged (commits are
pathspec-limited to the patch's own files), while requiring a repository with zero
untracked files would refuse almost every real project — including one that just ran
`vibeguard audit` and has a `vibeguard-report.json` sitting there.

### D20. `PARTIALLY_FIXED` is reserved, not emitted

INTERFACES.md §5 lists it among the statuses. With one finding per patch and whole-file
edits, a rollback is all-or-nothing, so the honest mapping is: rolled back → `FAILED`,
applied but no validator could confirm it → `UNVERIFIED`, applied and validated →
`FIXED`. Emitting `PARTIALLY_FIXED` would require inventing a partial outcome that the
repair loop never actually produces. The status stays in the enum for multi-file repairs
in later milestones.

### D21. Baseline failures are excluded from post-fix verdicts, visibly

Before the first patch the ladder runs once over the untouched repository. Any validator
that fails there is recorded in `ValidationEngine.baseline_failures`; when the same
validator fails after a fix, the step is rewritten as `skipped=True` with the detail
`excluded — this validator already failed at baseline (…)`, and the exclusion is repeated
in `FixRecord.residual_risk`. A project whose test suite was already red therefore cannot
mark our fix `FAILED` — and cannot silently borrow a green verdict either. Every other
non-skipped failure (including `lint`) stops the ladder and fails the fix: our patches
must not introduce new violations, and pre-existing ones are already excluded.

### D22. `[fix]` config gains `deep_validate` and two timeouts

INTERFACES.md §9 shows `[fix] allow_no_git` as the section's only documented key, but §7
requires a container-build rung gated on a flag and per-rung timeouts. `FixConfig` gains
`deep_validate` (default `false`, set by `fix --deep-validate`),
`validation_timeout_full` (600s) and `validation_timeout_targeted` (120s). Defaults
preserve the documented behaviour exactly.

### D23. `startup` is skipped, and says why

Booting an unknown application needs its ports, environment, and dependencies. Rather
than fake a smoke test, the `startup` validator always returns `skipped=True` with the
reason, so the gap is visible in every report instead of being quietly absent from the
ladder.

### D24. Destructive domains are refused in every mode

ARCHITECTURE.md §7 forbids destructive DB/schema/infra/auth changes outside interactive
approval; VibeGuard goes further and refuses them in *all* modes, because none of the M3
rules has a provably safe repair in those domains. The test is
`FixerEngine.destructive_reason`: category `DATABASE`, or any declared topic starting
`database.` / `iac.` / `kubernetes.`, or containing `migration`, `schema`, `auth`,
`backup`, or `encryption-at-rest`. Such findings get `REQUIRES_REVIEW` with instructions.

### D25. `vibeguard fix` defaults to `--safe` with a printed notice

The brief allows either refusing without a mode flag or defaulting to safe. Defaulting is
chosen — the safe mode applies only `SAFE_AUTOFIX` repairs, so the default is the
conservative one — and the CLI prints `no mode given — running --safe …` so nobody is
surprised about which mode ran. `--safe --interactive` together is an error (exit 2).

### D26. Line numbers are re-located, never trusted blindly

A finding records the line it was detected at, but an earlier fix to the same file may
have shifted it. `locate_line`/`locate_call` accept the recorded line when it still
matches the defect, otherwise take a *unique* match within twelve lines, and return
`None` when the target is ambiguous. Editing the wrong line is far worse than leaving a
finding unrepaired.

### D27. A dependency entry is not evidence of use (VG-SEC-014)

`package.json` is excluded from VG-SEC-014's "headers are configured somewhere" search:
listing `helmet` proves it is installed, not that it is ever applied. This makes
"installed but never called" detectable — and it is exactly the case the rule can repair
by wiring `app.use(helmet())` into the single Express entrypoint.

### D28. Advisory findings get no `FixRecord`

`INFORMATIONAL` / `NOT_APPLICABLE` findings (D12's "absence of evidence" reports) are
skipped by the repair loop entirely rather than stamped `REQUIRES_REVIEW`, so the
checklist's advisory handling from M2 keeps working unchanged and the repair table shows
only findings the fixer genuinely considered.

### D29. The `build` rung never installs anything

`npm run build` runs when the script exists and npm is present. A Python package is only
built when the `build` module is already importable in the environment; otherwise the rung
is skipped with that reason. Validation must never mutate the developer's environment to
prove a point.

## M4 — reporting, baseline, suppressions, history

M4 began from an uncommitted, half-finished attempt that crashed mid-run. Every file
it left behind was reviewed rather than trusted. `baseline/{__init__,store,suppressions,
history}.py` and `reporting/{common,markdown,html,writer}.py` were **kept** with
targeted corrections (noted below); the modifications to `core/config.py`,
`core/models.py`, `engine/checklist.py` and `reporting/__init__.py` were **kept** and
extended. Nothing was rewritten wholesale. The engine wiring, the whole CLI surface,
and all of the tests are new.

### D30. VibeGuard's own output is excluded from the scan

The draft excluded `**/.vibeguard/**`. That was not enough: `vibeguard-report.md`
names every defect it found, in prose, so on the *next* run a rule asking "is a backup
configured anywhere in this repository?" answers yes on the strength of our own
sentence about backups being absent. Six findings disappeared on the second scan of an
unchanged repository before this was fixed. `vibeguard-report.{json,md,html}` join
`.vibeguard/` in `DEFAULT_EXCLUDES`: **the previous run's findings must never become
this run's evidence.**

### D31. A topic whose only findings are suppressed is PASS, with the waiver on the row

INTERFACES.md §8 excludes suppressed findings from scoring but does not say what the
checklist should do with them. The same reasoning applies: a human looked at the
finding and accepted it, so it is not an *open* defect and `FAIL` would be wrong.
`REVIEW_REQUIRED` would be worse — it asks for a review that already happened. The
topic therefore reads `PASS`, and never silently: `ChecklistItem.note` gains
`"N suppressed finding(s) excluded (accepted_risk, …)"`, so the verdict and the reason
it was reachable sit on the same row. The PASS note also now says "no *open* findings"
rather than "no findings", which was a small lie in exactly this case.

### D32. The engine reads `.vibeguard/`; only the caller writes it

D8 says `Engine.audit` never writes to the scanned repository. M4 needs history
persistence, which is a write. Rather than weaken D8, the split is by *responsibility*:
the engine **reads** the baseline, the suppressions, and the stored history, and
attaches the resulting `RegressionDiff` to the report; the CLI **writes** the new
history entry (`_persist_history`) alongside the report files. `Engine(config).audit()`
therefore stays a pure function of the repository — `test_the_engine_does_not_write_to_
the_repository` asserts it — and library embedders opt into persistence by calling
`vibeguard.baseline.write_history` themselves. `[history] enabled/keep` configures the
CLI's behaviour (`keep = 0` disables pruning).

### D33. `--output` is one comma-separated list of everything a run produces

The M1 `--output` was a single enum mixing terminal formats with file formats. M4 needs
three files and two terminal modes at once, so it becomes a list: `table` (rich
summary), `json` (echo to stdout), `jsonl` (event stream, §6), `md`/`html` (write the
file), `all` (= `table,json,md,html`). The default is `table,md`.
`vibeguard-report.json` is written **unconditionally** — §8 calls it canonical, so it
is not something a flag should be able to switch off — which is what makes the default
the documented "json + md" pair. An unknown format is exit 2, not a silent no-op.

### D34. `regressed` is measured against two horizons, not the whole history

INTERFACES.md §7 says the diff "compares latest two by fingerprint sets", which yields
new/resolved/unchanged but cannot express *regressed*. The exact semantics implemented:
a fingerprint is **unchanged** if it was open in the previous run and is open now;
**resolved** if it was open in the previous run and is not open now; **regressed** if
it is open now, was *not* open in the previous run, but was open in some run before
that; **new** otherwise. So `regressed` means "fixed, then came back" — a different
failure of process from a defect that was never addressed — and one run of clean
history is enough to distinguish them. `resolved` is reported as fingerprints (the
findings no longer exist, so they have no ids); the other three are finding ids.

### D35. A baseline is a scheduling decision and is priced as one

`Finding.baselined` marks the finding, and that is *all* it does to the report: the
finding is still detected, still listed, still scored (INTERFACES.md §8 excludes only
*suppressed* findings from scoring). It is excluded from the CI gate, and only while
`[ci] use_baseline` is on — `--no-baseline` brings every baselined finding straight
back into the gate and the report carries a warning saying so. `save_baseline` stores
only findings that are neither suppressed nor `FIXED`: exempting something that needs
no exemption would quietly grow the baseline every run.

### D36. An expired suppression is ignored, and its lapse is reported

`expires` in the past means the entry is not honoured at all — the finding is live
again — and `ScanReport.warnings` carries "…expired on YYYY-MM-DD and was ignored".
The lapsed entry still appears in `ScanReport.suppressions`, so the audit trail
survives the expiry rather than vanishing with it. A suppression that matched no
finding in this scan is also reported, so stale entries are visible instead of
accumulating.

### D37. An inline suppression must be visible from the code it excuses

`# vibeguard: ignore=VG-XXX-NNN reason="…"` is honoured only on the finding's own line
or the line directly above it. Scanning the whole file would let a waiver sit hundreds
of lines from what it waives. A `reason=` value that is one of the four
`SuppressionReason` values is used as the reason; any other text becomes the entry's
`note` with reason `accepted_risk`, so a human sentence is preserved rather than
rejected.

### D38. `ScanReport` gains `baseline_validation` and `warnings`

The M3 notes flagged that `ValidationEngine.baseline_steps` was computed but never
serialised, which made D21's exclusions invisible to anyone reading the report rather
than the terminal. `ScanReport.baseline_validation` now carries the pre-fix ladder, and
both renderers print it with an explicit "these validators already failed on the
untouched repository, so their post-fix results are excluded" note. `ScanReport.warnings`
carries the non-fatal problems (expired suppressions, unreadable memory files) that
previously went only to the log.

### D39. Repair outcomes are counted with the full `FixStatus` vocabulary

The draft's renderer collapsed the seven statuses into four buckets
(fixed/partial/review/none). `repair_counts` now seeds **every** `FixStatus` at zero
plus a `no_repair_record` bucket for findings the repair loop never considered (audit
mode, or D28's advisory findings), and `ScanReport.counts` does the same for its
`status:*` keys — a reader can tell "no fix failed" from "this report does not track
failures".

### D40. Reference URLs are printed as text, never as links

The HTML report inlines its CSS and its ~20-line filter script and contains no `href`,
`src`, `@import`, or `<link>` at all. It is routinely read from a CI artifact store or
an air-gapped machine, so "self-contained" is enforced by construction and asserted by
`test_html_is_self_contained` rather than promised. The filter box hides itself under
`<noscript>`; everything else (collapsing via `<details>`, colour, tables) is pure
CSS/HTML, so the document is fully usable with scripting off.

## M5 — AI layer, repro tests, examples, packaging, docs

### D41. VibeGuard emits four event names beyond INTERFACES.md §6

§6 lists ten names and calls them exact. They are never edited or reordered;
`EVENT_NAMES` still holds precisely those ten. The AI gateway and the repro-test
runner need to announce things §6 could not have named, so `EXTENSION_EVENT_NAMES`
adds `ai.external_send`, `ai.blocked`, `repro.generated`, and `repro.result`, and
`ALL_EVENT_NAMES` is their union. Additive is safe: a subscriber written against §6
matches its patterns and simply never sees the new names. Every one of them is
documented, with its payload keys, in `plugin.json` and `docs/PLUGINS.md`.

### D42. `is_local` is computed from the endpoint, never configured

INTERFACES.md §10 declares `is_local` as an attribute of `AIProvider`. Letting a
config file *assert* it would make the `local_only` gate a promise rather than a
check, so `OpenAICompatibleProvider` derives it from the endpoint host
(`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `*.local`), `AnthropicProvider` hardcodes
`False`, and `NullProvider` hardcodes `True`. The host check is deliberately
name-based: resolving DNS would itself be a network call, and a hostile resolver could
make a remote host look local. Anything unrecognised is *not* local, so the gate errs
towards refusing a provider rather than permitting one.

### D43. One gateway owns every completion, and `ai_used` means "a completion came back"

ARCHITECTURE.md §9 requires the CLI to say so before code leaves the machine. Rather
than trust each call site to remember, `AIGateway.complete()` is the only path to a
provider: it emits `ai.external_send` and prints the notice *before* invoking a
non-local provider (`test_the_notice_precedes_the_request` asserts the ordering), and
sets `used = True` only *after* a completion has actually been returned. So
`ScanReport.ai_used` is false for a provider that was configured but never called, or
called and failed — the report describes what happened, not what was intended.

### D44. A `requires_ai` rule without a provider does not run at all

The alternative — running it in some degraded mode — would put a rule's name in the
"detectors that ran" column without the analysis behind it. Instead `select_rules`
skips it, `_gate_reason` reports `requires an AI provider (none available —
deterministic run)` on the checklist's NOT_APPLICABLE rows, and `ScanReport.warnings`
names every skipped rule. Coverage that was not obtained is never implied.

### D45. A repro test is anchored to one finding, not to a file

A file-scoped property ("no call in this file lacks a timeout") would fail after a
correct fix whenever a second, unrepaired defect of the same rule remained in the same
file — rolling back a good patch. Every generated test therefore carries `SNIPPET`, the
normalised snippet of the finding it was generated for, and only counts a defect whose
text overlaps it. This is exactly per-finding by construction: a fingerprint is
`rule|path|normalised snippet`, so two occurrences with identical text *are* one
finding.

### D46. A repro test that passes before the fix is discarded

`ReproRunner.prepare` runs the generated test *before* the patch and returns it only
when it fails. Passing means the template did not capture this defect — a template
gap, a shape it does not model — and keeping it would let a meaningless green tick
become the evidence for `FIXED`. An inconclusive run (no pytest, a timeout, a
collection error) is treated the same way. Both cases delete the file and proceed
without repro evidence, which is the pre-M5 behaviour exactly.

### D47. The repro result is a `ValidationStep` named `tests:repro`

INTERFACES.md §5 passes `repro_passed` to `verdict()` separately from `steps`, and §5's
step-name vocabulary is the ladder's. Passing the flag alone would leave the evidence
invisible in the report, so the outcome is *also* appended as a step named
`tests:repro` — not one of the ladder's eight names, because it is not a ladder rung.
A passing repro step therefore satisfies "≥1 non-skipped pass", which is the intended
consequence: a Dockerfile repair that no rung could confirm is now `FIXED` on the
strength of a test that failed before it and passes after, instead of `UNVERIFIED`.

### D48. The ladder's pytest rungs ignore `.vibeguard/`

Generated repro tests live in the scanned repository and are failing by design until
their fix lands. Collected by a bare `pytest`, one pending repair would mark every
later fix as having broken the project's test suite. Both pytest rungs pass
`--ignore=.vibeguard`: our own scaffolding is never counted as the project's tests.

### D49. Example secrets are fabricated but not "EXAMPLE"-shaped

The secrets pack correctly treats any value containing `example`, `changeme`,
`placeholder` and friends as documentation rather than a credential. Filling
`examples/vulnerable-app` exclusively with such values would have made a secrets
scanner demo in which no secret is found. The committed `.env` keeps recognisable
documentation placeholders (including AWS's own `AKIAIOSFODNN7EXAMPLE`), while the
values that exist to demonstrate detection — the JWT signing secret, the admin
password — are fabricated strings that match nothing real and are labelled as
fabricated in a comment beside them.

### D50. `examples/repaired-app` is generated, and only its path is edited

It was produced by copying the vulnerable app, `git init`, and
`vibeguard fix . --safe`; the result was copied back verbatim, including the report and
the generated repro tests. The single edit is the absolute scratch path inside
`vibeguard-report.{md,json}`, rewritten to `examples/repaired-app`. The example's
README says so. Nothing else about the run — the counts, the statuses, the residual
risks — is touched, because an example that quietly improves on the real behaviour is
worse than no example.

### D51. `ruff` does not lint `examples/`

The vulnerable app is broken on purpose and the repro tests under
`examples/repaired-app/.vibeguard/repro/` are machine-generated. Linting them would be
linting test data, and "fixing" them would delete the findings
`tests/test_examples.py` asserts on. `[tool.ruff] extend-exclude = ["examples"]`.

### D52. VibeGuard's own image has no HEALTHCHECK, and says why

`VG-CTR-002` wants a HEALTHCHECK on a runnable image, and our Dockerfile does not have
one. It is a one-shot CLI: there is no long-running process for a probe to ask about,
and the rule only fires on images with a server-shaped CMD. The Dockerfile carries that
reasoning as a comment rather than leaving a reader to wonder whether we forgot. Every
other container rule we ship *is* honoured: pinned slim base, dependencies installed
before the source is copied, no build toolchain in the final layer, and a uid-10001
non-root user.

### D53. Self-audit in CI is informational

`vibeguard audit .` on this repository is noisy by construction: a codebase whose
purpose is to hold patterns for insecure code is full of the strings those rules match.
The `dogfood` job runs it with `continue-on-error` so the output is archived and
readable without gating the build, and gates instead on
`vibeguard ci examples/vulnerable-app` — where a *failure* is the expected result, and
a following step asserts the gate really did fail. Gating on a scan we know to be
noisy would train everyone to ignore it.

### D54. The report shows the architecture before it shows the numbers

Both rendered reports open with a picture: markdown with an `## Architecture` section
carrying a mermaid `flowchart LR`, HTML with an "Architecture & health at a glance"
section of three inline SVGs. A reader who has never seen the codebase needs to know
*what it is* before a score means anything, and the graph is the one part of the report
that answers that. Mermaid was chosen for markdown because GitHub and GitLab render it
natively with no toolchain; SVG for HTML because a mermaid block in an HTML file would
need a script and a CDN, which D40's self-containment forbids.

### D55. Node colour maps to one category score, and an unmeasured node is grey

Each architecture node takes the colour of the single category score that governs it —
database nodes from `database`, caches from `performance`, brokers and workers from
`reliability`, external services and entrypoints from `api`, and the application itself
from the overall readiness score. It is coarse on purpose: a diagram is a glance, and a
node coloured by an average of everything would say nothing. Bands are 85+/60-84/<60.

A node whose category has no applicable rules — or a report with no scores at all, as a
discovery-only `vibeguard graph` produces — is drawn grey, never green. Green is a
claim that we measured something and it was fine; we did not, so we do not make it.
Scores come from `scores_after` when the run repaired anything, so a fix report's
diagram shows the repaired state rather than the state it started in.

### D56. Hostile node labels are escaped into mermaid entities, not stripped

Node labels come from the scanned repository — a hostname, a directory name, whatever
a `docker-compose.yml` happened to contain. A label like `evil "label" [x]-->` would
otherwise close its own node and inject syntax into the diagram. Every character
mermaid reads as structure is replaced with its `#NN;` entity form rather than deleted,
so the label still renders as written and the flowchart cannot be rewritten by the code
under audit. The escape table applies `#` first, since every other replacement
introduces one.

### D57. The SVG layout is four hand-laid columns, capped at thirty nodes

No graphviz, no layout library, no new runtime dependency: nodes are bucketed into
entrypoints / app+services / data+infrastructure / external, stacked in each column,
and joined by elbow paths. It is not a good general graph layout and does not try to
be — the graphs discovery infers are shallow and almost always a hub with spokes. Past
thirty nodes the diagram stops being readable, so the remainder collapses into a single
"and N more…" node and the edges to dropped nodes are omitted rather than dangling.

### D58. `vibeguard graph` runs discovery and nothing else

The command exists to be fast enough to run on a whim, so it builds the `ScanContext`
and stops — no rule selection, no detection, no adapters. Colouring therefore comes
from `.vibeguard/history/` if a scan is recorded there, and is neutral if not. A
`graph` invocation never writes a report, never records history, and never fails a
build; it prints a diagram to stdout or the file named by `--out`.
