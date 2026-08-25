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
never applicable to it. Such a category is still emitted in `scores_before`, so the
schema is complete, carrying `score = 100` and `finding_count = 0`; consumers must
read `applicable`, not the score, to tell "clean" from "not assessed".

**Baselined findings still count.** `.vibeguard/baseline.json` exempts a finding from
the CI *gate*; it does not erase it. It is still detected, still listed, and still
priced into the score. Only a suppression — which records a reason, an author, and a
date — removes a finding from the product. A baseline that improved the score would be
a way to buy a number instead of fixing the code.

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
`scores_after` / `overall_after` are populated only by fix modes and are `null` for a
plain audit. "After" is computed over the findings that remain once every finding whose
`FixRecord.status` is `FIXED` is treated as closed — and only `FIXED`, which is itself
gated on validation evidence. An `UNVERIFIED` or `REQUIRES_REVIEW` repair improves
nothing on the scoreboard, because it has not been shown to improve anything in the
code.

Expect the "after" number to move less than the repair count suggests. The formula is
multiplicative, so removing four medium findings while one critical remains barely
shifts the category: `1 − 0.40` dominates the product. That is intended — a category
with an unfixed SQL injection in it should not read as healthy because the timeouts
were tidied up.

## What this number is not

It is not a benchmark, a grade, a certification, or something to put in a sales deck.
Two projects with the same score are not comparable: the categories that applied to
each are different, and a score of 100 in a category can mean "no defects found" or
"the rules that would have found them were bounded at ten findings each". Use the
trend within one repository, and read the findings.
