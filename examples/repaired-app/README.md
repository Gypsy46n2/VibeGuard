# NoteNest after `vibeguard fix --safe`

> **Still do not deploy this.** Most of the defects in `../vulnerable-app/` are still
> here. That is the point of this directory: it shows exactly how far an automated,
> evidence-gated repair pass gets — and where it stops and hands you the work.

## How this directory was produced

Really, not by hand:

```bash
cp -r examples/vulnerable-app /tmp/repaired && cd /tmp/repaired
git init && git add -A && git commit -m "initial: NoteNest as generated"
vibeguard fix . --safe -o table,md,html
```

The result was copied back verbatim, including `vibeguard-report.md`,
`vibeguard-report.json`, and the generated repro tests under `.vibeguard/repro/`. The
only edit is that the absolute scratch path in the two reports was rewritten to
`examples/repaired-app`.

## What changed

| Metric | before | after |
|---|---|---|
| Findings | 77 | 72 |
| Overall readiness | 55/100 | 57/100 |
| `api` category score | 47/100 | 80/100 |
| Repairs applied and validated | — | 5 |

Five findings, all `VG-API-001` (*outbound HTTP request without a timeout*), each on
its own commit:

```
fix(api): bound requests.post() with an explicit timeout [VG-API-001]
fix(api): bound requests.get()  with an explicit timeout [VG-API-001]
fix(api): bound requests.post() with an explicit timeout [VG-API-001]
fix(api): bound requests.get()  with an explicit timeout [VG-API-001]
fix(api): bound requests.post() with an explicit timeout [VG-API-001]
```

The diff is nothing but the remediation — five `, timeout=30` arguments in `app.py`
and `integrations.py`. No reformatting, no import churn, no drive-by cleanups.

### The evidence behind "FIXED"

Each of the five is marked `FIXED` because a generated repro test failed before the
patch and passes after it. They are in this directory:

```
.vibeguard/repro/test_vg_api_001_06206740c4ea.py   ...and four more
```

Each parses its target module with `ast`, finds the reported call, and asserts it now
passes a `timeout=`. They import nothing from vibeguard — run them with plain pytest:

```bash
cd examples/repaired-app && python -m pytest .vibeguard/repro -q     # 5 passed
```

Revert one of the timeouts and the corresponding test goes red again. That is the
whole claim: `FIXED` means *something failed, we changed the code, and now it passes*.

## What VibeGuard deliberately did not do

`vibeguard-report.md` lists all of it. The shape of it:

| Outcome | Count | What it means |
|---|---|---|
| `fixed` | 5 | Applied, committed, validated |
| `requires_review` | 28 | Refused on purpose — see below |
| `not_attempted` | 38 | Mostly review-recommended repairs awaiting `--interactive` |
| *(no record)* | 6 | Advisory findings ("no metrics configured") the repair loop never considers |

**Refused in every mode, regardless of flags** — schema, migration, authentication,
backup, and infrastructure-state changes. `VG-SEC-019` (`/admin/export` with no auth
check) is a good example: adding a decorator that *looks* like authentication would be
worse than leaving the hole visible. `VG-DB-006` (no migration tooling) and `VG-DR-001`
(no backups) are product decisions, not diffs.

**Manual by declaration** — `VG-SEC-003` (`| safe` in the template), `VG-SEC-005`
(SSRF), `VG-SEC-010` (MD5 passwords), `VG-SCR-006` (committed `.env`). Fixing MD5
password hashing means a migration path for existing users; no template patch can
invent one.

**Waiting for `--interactive`** — these have a deterministic patch that VibeGuard will
apply once you have looked at the diff. Running `vibeguard fix . --interactive` and
approving everything on the same starting tree produces **11 fixed** instead of 5:

| Rule | Repair | Repro-verified |
|---|---|---|
| `VG-API-001` ×5 | add `timeout=30` | yes |
| `VG-CTR-001` | create `appuser`, `USER appuser` | yes |
| `VG-CTR-002` | add a `HEALTHCHECK` | yes |
| `VG-CTR-004` | copy the manifest before `pip install` | no — unverified, honestly |
| `VG-SEC-001` | parameterise the query in `db.py` | yes |
| `VG-SEC-011` | `secrets.token_urlsafe` for session tokens | yes |
| `VG-SEC-016` | `Secure`, `HttpOnly`, `SameSite` on the cookie | no template for this rule |
| `VG-SEC-018` | `verify=False` → `verify=True` | yes |

Note that overall readiness still only reaches 58/100 there. Three of the four SQL
injections need a human — the login query interpolates *two* values into one
statement, and VibeGuard will not guess at a rewrite it cannot prove.

## Reading the report

```bash
less examples/repaired-app/vibeguard-report.md
vibeguard report examples/repaired-app -o html    # re-render, no rescan
```
