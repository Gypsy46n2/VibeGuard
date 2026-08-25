# Scoring

Restates the formula in `docs/INTERFACES.md` §8, which is normative. Implemented in
`src/vibeguard/reporting/scoring.py`.

**This is a heuristic, not science.** It exists to make trends legible ("secrets went
from 40 to 95"), not to rank projects against each other.

## Inputs

Severity weight `w`:

| severity | weight |
|---|---|
| critical | 0.40 |
| high | 0.25 |
| medium | 0.10 |
| low | 0.04 |
| info | 0.01 |

Confidence factor `c`:

| confidence | factor |
|---|---|
| high | 1.0 |
| medium | 0.7 |
| low | 0.4 |

## Per-category score

```
category_score = round(100 · Π over open findings in the category (1 − w · c))
```

floored at 0. Suppressed findings are excluded from both the product and the reported
`finding_count`. A category with no applicable rules for this project is reported with
`applicable = false` and is excluded from the overall score — this is the
proportionality mechanism: a toy app is never marked down for lacking rules that were
never applicable to it.

Worked example — one critical (high confidence) and one medium (medium confidence)
security finding:

```
100 · (1 − 0.40·1.0) · (1 − 0.10·0.7) = 100 · 0.60 · 0.93 = 55.8 → 56
```

## Overall score

```
overall = round(weighted mean of applicable category scores)
```

with `security` and `secrets` counted twice. With no applicable categories the overall
score is 100.

## Reported fields

`ScanReport.scores_before` / `overall_before` are computed pre-repair;
`scores_after` / `overall_after` are populated only by fix modes (M3+) and are `null`
for a plain audit.
