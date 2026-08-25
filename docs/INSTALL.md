# Installing VibeGuard

VibeGuard needs **Python ≥3.11** and nothing else. Every built-in rule is regex, AST,
or config parsing; it runs with zero external installs and zero network access. The
optional extras below only *add* coverage — they never gate it.

## Install matrix

| Method | Command | Use it when |
|---|---|---|
| **pipx** *(recommended)* | `pipx install vibeguard` | You want the CLI on your PATH without touching a project's environment. |
| pip | `pip install git+https://github.com/Gypsy46n2/VibeGuard.git` | Inside a project virtualenv, or when you also embed the library. |
| pip + scanners | `pip install "vibeguard[scanners]"` | You want bandit / detect-secrets / pip-audit / checkov / semgrep merged in. |
| pip + AI | `pip install "vibeguard[ai]"` | You want the `anthropic` SDK or an OpenAI-compatible endpoint. |
| pip + web UI | `pip install "vibeguard[ui]"` | You would rather click than type. Adds `vibeguard ui` — see below. |
| pip, everything | `pip install "vibeguard[scanners,ai,ui,dev]"` | Contributing. |
| Docker | `docker run --rm -v "$PWD":/repo vibeguard (local build: docker build -t vibeguard .) audit /repo` | No Python on the machine, or a hermetic CI step. |
| From source | `git clone … && pip install -e ".[dev]"` | Developing rules. |
| GitHub Action | `uses: Gypsy46n2/VibeGuard@main` | CI. See [PLUGINS.md](PLUGINS.md#ci-surfaces). |
| pre-commit | `- repo: https://github.com/Gypsy46n2/VibeGuard` with `id: vibeguard-ci` | Gate before the commit lands. |

Verify:

```bash
vibeguard --version
vibeguard doctor
```

## Extras in detail

### `[scanners]` — optional external tools

```bash
pip install "vibeguard[scanners]"
```

Installs `bandit`, `detect-secrets`, `pip-audit`, `checkov`, and `semgrep` into the
same environment. VibeGuard invokes each as a **subprocess** and normalises its output
into `Finding`s — no source is vendored, so no licence is inherited.

Adapters that are not installed are simply skipped, and `ScanReport.adapters_used`
records that they were, so a report never implies coverage it did not have.

### `[ui]` — the local web UI

```bash
pip install "vibeguard[ui]"
vibeguard ui                 # http://127.0.0.1:8321/, opens your browser
vibeguard ui ~/code/my-app   # start the folder picker there
vibeguard ui . --port 9000 --no-browser
```

Adds `fastapi` and `uvicorn`, and nothing else — the front end is one self-contained
HTML file inside the wheel, with no CDN, no webfont and no build step. The server binds
`127.0.0.1` only and may browse your home directory plus the `PATH` you gave it;
everything else is refused. Repairs from the UI are **safe mode only**, and require an
explicit confirmation before anything is written.

Without the extra, `vibeguard ui` exits 2 and tells you what to install. Every other
command is unaffected — nothing in the core import graph reaches into `vibeguard.ui`.

### Tools installed separately

Two adapters wrap binaries that do not come from PyPI:

| Adapter | Install | Notes |
|---|---|---|
| `hadolint` | `brew install hadolint`, or the [release binary](https://github.com/hadolint/hadolint/releases), or `docker run --rm -i hadolint/hadolint` | GPL-3.0 — invoked as a subprocess only, never vendored. |
| `trivy` | `brew install trivy`, `apt install trivy`, or the [release binary](https://github.com/aquasecurity/trivy/releases) | Refreshes a vulnerability database over the network. |
| `npm audit` | ships with `npm` | Only applies to projects with a `package.json`. |

### `[ai]` — optional AI providers

```bash
pip install "vibeguard[ai]"     # anthropic + httpx
```

The default provider is `null` and the entire pipeline works without a model. For a
**fully local** setup, run [Ollama](https://ollama.com) and point VibeGuard at it — no
extra install beyond `httpx`, and nothing leaves the machine:

```toml
# .vibeguard.toml
[ai]
provider = "openai_compatible"
endpoint = "http://localhost:11434/v1"
model    = "llama3.1"
```

Configuration, the `local_only` gate, and the external-send notice are documented in
[PLUGINS.md §3](PLUGINS.md#3-ai-providers).

### `[dev]`

`pytest` and `ruff` — needed to run VibeGuard's own suite, and used by the validation
ladder when they are present in a scanned project's environment.

## `vibeguard doctor`

`doctor` answers "what will actually run here?" without touching the network:

```
                                vibeguard doctor
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ check                   ┃ status        ┃ detail                             ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ python                  │ ok            │ 3.12.7 (requires >= 3.11)          │
│ vibeguard               │ ok            │ 0.2.0                              │
│ git                     │ available     │ git version 2.55.0                 │
│ tree-sitter             │ available     │ AST rules enabled                  │
│ adapter: bandit         │ not installed │ optional — install with the        │
│                         │               │ [scanners] extra                   │
│ adapter: npm-audit      │ available     │ /usr/bin/npm · 11.19.0 · network   │
│                         │               │ required (skipped under            │
│                         │               │ --local-only)                      │
│ ai provider             │ deterministic │ null (no AI provider is            │
│                         │               │ configured)                        │
└─────────────────────────┴───────────────┴────────────────────────────────────┘
```

What each row means for you:

* **git — missing.** `vibeguard audit`, `report`, and `ci` are unaffected.
  `vibeguard fix` refuses to run: without a repository there is no branch, no
  per-fix commit, and no rollback. Pass `--allow-no-git` to fix anyway, in which case
  every edited file gets a `.orig` backup instead.
* **tree-sitter — missing.** AST-based rules degrade to regex, which means more false
  positives and some missed findings. tree-sitter is a core dependency, so this
  should only happen on an unusual platform.
* **adapter — not installed.** That tool's findings are absent. Built-in rules still
  cover the same topics; the adapters corroborate and extend them.
* **network required.** Under `--local-only` that adapter is skipped, and the report
  says so.
* **ai provider.** `deterministic` is the default and is a perfectly good answer.

## Configuration

`.vibeguard.toml` at the repository root; every value is overridable by a CLI flag.

```toml
[vibeguard]
packs      = ["security", "secrets", "api", "database", "containers"]  # default: all
exclude    = ["docs/generated/**"]     # extends the built-in excludes, never replaces
local_only = false
report_dir = "../vibeguard-out"        # default: the scanned repository itself.
                                       # Relative paths resolve against this file.

[ai]
provider    = "null"            # null | anthropic | openai_compatible
endpoint    = ""
model       = ""
api_key_env = ""                # the *name* of an env var, never a key

[ci]
fail_on      = "high"           # critical | high | medium | low | info
use_baseline = true

[fix]
allow_no_git               = false
deep_validate              = false   # adds the container-build rung
repro_tests                = true    # generate + gate on repro tests
validation_timeout_full    = 600
validation_timeout_targeted = 120

[history]
enabled = true
keep    = 50                    # 0 keeps everything
```

`.gitignore` is always honoured on top of `exclude`, and VibeGuard's own outputs
(`.vibeguard/`, `vibeguard-report.*`) are always excluded — a previous run's findings
must never become this run's evidence.

### Scanning without leaving anything behind

Auditing never modifies the code it reads. What it does write — the report files and
`.vibeguard/` — can be moved or switched off entirely:

| Flag | Commands | Effect |
|---|---|---|
| `--report-dir DIR` | `audit`, `fix`, `ci`, `report`, `baseline create\|show` | Every written artefact goes to `DIR` instead of the repository: `vibeguard-report.{json,md,html}`, `DIR/.vibeguard/history/`, `DIR/.vibeguard/baseline.json`. `DIR` is created if missing. Overrides `report_dir` in the config file. |
| `--no-write` | `audit`, `ci` | Writes nothing at all — no reports, no history, and not even the `--report-dir` itself. The terminal table and `-o jsonl`/`-o json` still work, and `ci` still gates. |

Because history moves with the reports, the regression diff compares against
whichever directory the run was given: `vibeguard audit . --report-dir /tmp/out` twice
in a row diffs the second run against the first, and `vibeguard report . --report-dir
/tmp/out` re-renders it — all without the repository ever being written to. Pass the
same `--report-dir` consistently, or put `report_dir` in `.vibeguard.toml` so you
cannot forget. `.vibeguard.toml` and `.vibeguard/suppressions.yml` are authored
content and are always *read* from the scanned repository; only writes relocate.

A `--no-write` run records nothing, so it is invisible to the next run's regression
diff — the output says so rather than leaving you to notice.

## Troubleshooting

**`vibeguard fix` exits 3.** The worktree has uncommitted changes to tracked files.
Commit or stash them; VibeGuard will not risk mixing your work with its patches.
Untracked files are fine.

**A scan is slow.** External adapters dominate. Try `--packs` to narrow the run, or
`--local-only` to skip everything that touches the network.

**Findings vanished between two runs of unchanged code.** Check that
`vibeguard-report.md` is not being scanned — a report names every defect it found, in
prose. It is excluded by default; a custom `exclude` list *extends* the defaults rather
than replacing them, so this should not be reachable. If you see it, please file a bug.

**pytest segfaults at interpreter shutdown** while running VibeGuard's own suite on
some CPython builds. Run with `PYTHONMALLOC=malloc`, which is what CI does.

## Uninstall

```bash
pipx uninstall vibeguard        # or: pip uninstall vibeguard
```

VibeGuard's state in a scanned project is just `.vibeguard/` and the
`vibeguard-report.*` files. Delete them and no trace remains — the fix branch and its
commits are ordinary git, and yours to keep or drop.
