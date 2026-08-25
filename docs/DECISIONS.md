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

### D16. Rules never implement `fix()` in M2

INTERFACES.md §3 makes `fix()` optional and ARCHITECTURE.md §12 assigns repairs to M3.
Rules that were designed with a deterministic template patch in mind carry a
`# M3 fix(): …` comment naming the exact edit, and a contract test asserts that no
built-in rule overrides `Rule.fix` yet — so "SAFE_AUTOFIX" in M2 means "a safe fix is
known to exist", never "a fix was applied".
