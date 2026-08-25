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

### D10. Stub commands exit 0

`fix`, `report`, and `baseline` print the milestone that implements them and exit `0`.
Exit `2` is reserved for genuine execution errors (§11).
