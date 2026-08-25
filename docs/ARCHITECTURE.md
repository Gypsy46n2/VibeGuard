# VibeGuard — Architecture

> **Product:** `vibeguard` — audits, repairs, hardens, tests, and reports on vibe-coded
> applications, bringing them closer to production grade.
>
> **Pipeline:** Detect → Explain → Repair → Test → Validate → Report
>
> **Prime directives:**
> 1. Never claim FIXED without validation evidence.
> 2. Never make high-risk changes without approval.
> 3. Never overengineer — recommendations proportional to the project.

## 1. Language & runtime choice

**Python ≥3.11**, packaged with `pyproject.toml` (hatchling), CLI via `typer`, models via
`pydantic v2`. Rationale:

- The scanner ecosystem we orchestrate is Python-native or subprocess-friendly
  (bandit, detect-secrets, checkov, sqlfluff, pip-audit, semgrep).
- `tree-sitter` bindings give fast multi-language AST access for our own rules.
- AI provider abstraction (Anthropic / OpenAI-compatible / Ollama) is trivial in Python.
- Plugin loading via entry points (`importlib.metadata`) is a mature pattern.

Distribution: `pip install vibeguard` / `pipx install vibeguard` / Docker image.

## 2. Ecosystem research — reuse, don't rebuild

Deterministic tools are preferred over LLM analysis wherever they exist. VibeGuard
**orchestrates** them through subprocess adapters (no license contamination — we invoke
CLIs, we do not vendor code) and normalizes their output into our `Finding` model.

| Domain | Tool | License | Integration |
|---|---|---|---|
| Multi-lang SAST | semgrep | LGPL-2.1 (engine), rules vary | optional adapter, subprocess + `--json` |
| Python SAST | bandit | Apache-2.0 | optional adapter |
| Secrets | detect-secrets (Yelp) | Apache-2.0 | optional adapter; plus built-in regex/entropy scanner (always available) |
| Secrets (alt) | gitleaks | MIT | optional adapter |
| Dependencies (Python) | pip-audit | Apache-2.0 | optional adapter |
| Dependencies (JS) | `npm audit --json` | bundled w/ npm | optional adapter |
| Containers/IaC | trivy | Apache-2.0 | optional adapter |
| IaC | checkov | Apache-2.0 | optional adapter |
| Dockerfile | hadolint | GPL-3.0 | **subprocess-only** adapter (GPL: never vendor) |
| Lint/format | ruff, eslint | MIT | validation stage |
| AST | tree-sitter + language packs | MIT | library dependency for built-in rules |

Design consequence: **every external tool is optional.** VibeGuard ships built-in
rules (regex + AST + config parsing) that work with zero external installs; when an
external tool is present on PATH (or installed via the `[scanners]` extra) its findings
are merged and deduplicated against built-ins via fingerprints. `vibeguard doctor`
reports which adapters are live.

## 3. Repository structure

```
vibeguard/
├── pyproject.toml
├── README.md
├── docs/
│   ├── ARCHITECTURE.md          # this file
│   ├── INTERFACES.md            # binding contracts (models, ABCs, schemas, events)
│   ├── RULES.md                 # rule authoring guide
│   ├── PLUGINS.md               # plugin development guide
│   └── SCORING.md               # exact scoring formula
├── src/vibeguard/
│   ├── core/                    # models, config, events, context, registry
│   ├── discovery/               # tech detection + architecture graph
│   ├── engine/                  # orchestrator: scan/fix pipelines
│   ├── rules/                   # built-in rule packs (data + logic)
│   │   ├── security/ database/ api/ containers/ deployment/
│   │   ├── observability/ reliability/ dependencies/ performance/
│   │   └── secrets/
│   ├── adapters/                # external tool adapters (semgrep, bandit, trivy, ...)
│   ├── fixers/                  # repair engine + git safety
│   ├── validation/              # validation engine (syntax→tests→build ladder)
│   ├── testing/                 # test bootstrap + repro-test generation
│   ├── reporting/               # md/html/json renderers, scoring, dashboard data
│   ├── baseline/                # fingerprints, baselines, suppressions, regression diff
│   ├── ai/                      # provider abstraction (local-only aware)
│   ├── integrations/           # CI helpers (GitHub Actions, GitLab, pre-commit)
│   └── cli.py
├── tests/                       # vibeguard's own test suite
├── examples/
│   ├── vulnerable-app/          # deliberately broken Flask+SQLite app
│   └── repaired-app/            # same app post-vibeguard
├── .github/workflows/ci.yml
├── Dockerfile
└── action.yml                   # GitHub Action wrapper
```

## 4. Pipeline

```
vibeguard <cmd> PATH
  └─ Engine.run(mode)
       1. Discovery      → TechProfile + ArchitectureGraph   (discovery/)
       2. Rule selection → applicable rules only (tech-gated) (core/registry)
       3. Detection      → built-in rules ∥ adapters → [Finding]
       4. Dedup/merge    → fingerprint-based                  (baseline/)
       5. Baseline/suppressions applied
       6. (fix modes) Git safety → branch → per-finding repair loop:
            classify → (repro test) → apply patch → validate → commit or rollback
       7. Scoring + report generation
       8. History persisted to .vibeguard/history/ for regression diff
```

Every stage emits structured events (`scan.started`, `scan.issue_found`,
`repair.started`, `repair.completed`, `repair.failed`, `validation.started`,
`validation.completed`, `report.generated`) through a synchronous `EventBus` that the
CLI renders and that API/plugin hosts can subscribe to.

## 5. Discovery & proportionality

`discovery/` produces:

- **TechProfile** — languages, frameworks (frontend/backend), DBs, ORMs, package
  managers, containers, CI/CD, IaC, test frameworks, caches, brokers, workers,
  serverless, websockets, auth mechanisms, secret mechanisms. Detected from manifest
  files, lockfiles, imports, config files.
- **ArchitectureGraph** — nodes (services, DBs, queues, external APIs, entrypoints) and
  edges, inferred from configs/imports. Used for cross-file reasoning and reporting.
- **ScaleProfile** — heuristic size class (`toy | small | medium | large`) from LOC,
  service count, infra present, data sensitivity signals. **Every rule declares the
  minimum scale class it applies to** — this is the anti-overengineering mechanism.
  A small CRUD app never gets told to adopt Kafka, k8s, sharding, or service meshes;
  rules for distributed patterns require evidence the pattern is already in use or the
  scale demands it.

Rule applicability = tech match ∧ scale match ∧ file-presence preconditions. Rules that
don't apply report nothing (or `NOT_APPLICABLE` in deep audits).

## 6. Rules

A rule is a Python class registered in a **rule pack** (see INTERFACES.md for the ABC).
Declares: id (`VG-SEC-001` style), category, severity, confidence, description,
why-it-matters, references, technologies, min scale, autofix safety level
(`SAFE_AUTOFIX | REVIEW_RECOMMENDED | MANUAL_CHANGE_REQUIRED | INFORMATIONAL`), and
implements `detect(ctx) -> list[Finding]` and optionally `fix(ctx, finding) -> Patch`.

Rule packs (namespaced, individually enable/disable-able, all in this repo for now):
`core, secrets, web, security, database, devops, node, python, react, nextjs, django,
fastapi, flask, express, go, rust, dotnet`. MVP ships `core, secrets, security,
database, web, devops, python, node` (see roadmap).

Detection techniques by tier (prefer lowest that suffices):
1. File/manifest presence & config parsing (yaml/toml/json/ini/dockerfile parsing)
2. Regex with context windows
3. tree-sitter AST queries (Python, JS/TS)
4. External tool adapters
5. LLM analysis (only for: architectural reasoning, cross-file dataflow the ASTs can't
   settle, repair planning, test generation, explanation. Never for what a parser does.)

## 7. Repair, git safety, validation

**Git safety (fixers/git_safety.py):** refuse to fix a dirty worktree (offer stash or
abort); record HEAD; create `vibeguard/fix-YYYY-MM-DD[-N]`; baseline report + baseline
tests before touching anything; one logical commit per fix
(`fix(security): ... [VG-SEC-001]`); rollback the working tree on validation failure.
Non-git directories: audit-only unless `--allow-no-git` (then writes a `.orig` backup
per file).

**Repair loop per finding:** classify → if behavior-affecting, generate/locate a repro
test and confirm it fails → apply patch (deterministic template patch preferred; LLM
patch only for complex repairs, and diff-reviewed) → run validation ladder → commit on
pass, rollback on fail. Destructive DB/schema/infra/auth changes are never applied
outside `--interactive` approval, regardless of flags.

**Validation ladder (validation/):** applicable subset of: syntax parse → compile/type
check (tsc/mypy if configured) → lint → targeted tests → full test suite → build →
container build → app startup smoke. Result statuses:
`FIXED | ATTEMPTED | PARTIALLY_FIXED | UNVERIFIED | FAILED | REQUIRES_REVIEW`.
`FIXED` requires: patch applied ∧ all applicable validators pass ∧ (repro test existed
→ now passes). Anything less is downgraded honestly.

## 8. Reporting, scoring, baseline

- Outputs: `vibeguard-report.json` (canonical, schema in INTERFACES.md),
  `vibeguard-report.md`, `vibeguard-report.html` (self-contained, category dashboard).
- Secrets are **always redacted** (`sk-live-…a4f2` → `sk-l****[REDACTED]****a4f2`)
  at the Finding-creation boundary, so no renderer can leak them.
- **Scoring** (docs/SCORING.md): per-category 0–100 = `100 · Π(1 − w(sev)·conf)` over
  open findings in that category, floored at 0; overall = weighted mean of applicable
  categories. Explicitly documented as a heuristic, not science.
- **Fingerprints:** `sha256(rule_id + relpath + normalized_snippet)` — line-number
  independent, survives unrelated edits; powers baselines, suppressions, and the
  regression diff (`N new / N resolved / N regressed / N unchanged`).
- **Suppressions:** `.vibeguard/suppressions.yml` entries require fingerprint, reason
  (`false_positive | accepted_risk | temporary | not_applicable`), author, date,
  optional expiry. Inline `# vibeguard: ignore=VG-XXX-NNN reason="..."` also honored.
  All suppressions are listed in reports (auditable).

## 9. AI layer & privacy

`ai/` defines `AIProvider` (complete/analyze/patch interfaces) with implementations:
`anthropic`, `openai_compatible` (covers OpenAI, Ollama, LM Studio, vLLM, agent
gateways), `null` (deterministic-only). Selected via config/env.

`--local-only`: hard gate in the provider factory — only providers whose endpoint
resolves to localhost/configured-local are constructible; any rule requesting AI
otherwise degrades to deterministic-only and the report notes it. Any time code would
leave the machine, the CLI says so explicitly before sending.

**AI is always optional.** The entire MVP pipeline works with `provider: null`.

## 10. Interfaces for embedding

1. CLI (`vibeguard ...`) — human + CI use.
2. Library: `from vibeguard import Engine; Engine(config).audit(path)` returns the
   report object; events via subscription.
3. Agent-plugin: thin JSON-lines mode (`--output jsonl`) streaming events, so an agent
   host renders progress live; plus a `plugin.json` manifest.
4. Local web UI (`vibeguard ui`, optional `[ui]` extra): a FastAPI app that uses the
   Engine as a library and bridges the EventBus onto Server-Sent Events. The JSON
   report + event stream are still the whole contract — the UI adds no data of its
   own beyond the diagrams our renderers already produce. Loopback-only, safe-mode
   repairs only (D61, D62).

## 11. CLI surface

```
vibeguard audit  PATH [--deep] [--packs ...] [--local-only] [--output md|json|html|jsonl]
                      [--report-dir DIR] [--no-write]
vibeguard fix    PATH [--safe | --interactive] [--local-only] [--allow-no-git]
                      [--report-dir DIR]
vibeguard report PATH [--report-dir DIR]     # re-render last scan
vibeguard ci     PATH [--fail-on high] [--baseline] [--report-dir DIR] [--no-write]
vibeguard baseline create|show PATH [--report-dir DIR]
vibeguard doctor                 # which adapters/validators are available
vibeguard rules  [--pack X]      # list rules with applicability
vibeguard ui     [PATH] [--port 8321] [--no-browser]   # local web UI, 127.0.0.1 only
```

Config: `.vibeguard.toml` at repo root (packs, thresholds, suppressor policy, AI
provider, validators, `report_dir`), overridable by flags. `--report-dir` relocates
every written artefact — reports and `.vibeguard/` state alike — and `--no-write`
suppresses all of them (D59, D60).

## 12. Roadmap

- **M1 – Core skeleton:** core models/config/events, discovery, registry, CLI scaffold,
  engine walking a no-op pipeline end to end.
- **M2 – Detection:** built-in rule packs covering the MVP-25 issue list (SQLi, XSS,
  SSRF, CSRF, authz/authn, secrets, deps, CORS, timeouts, retries, input validation,
  N+1, indexes, pooling, leaks, docker, health checks, logging, backups, migrations,
  API versioning, missing tests, CI safety) + adapters (bandit, detect-secrets,
  pip-audit, npm-audit, hadolint, trivy, semgrep — all optional).
- **M3 – Repair & validation:** git safety, fixer engine with template patches for the
  SAFE_AUTOFIX subset, validation ladder, honest statuses.
- **M4 – Reporting & memory:** renderers, scoring, baseline/suppression/regression.
- **M5 – Product polish:** example vulnerable+repaired apps, own test suite, docs,
  GitHub Action, Dockerfile, README.
- Post-MVP: more language packs, k8s/IaC depth, LLM-assisted cross-file analysis,
  PR-comment integration, web dashboard.
