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
