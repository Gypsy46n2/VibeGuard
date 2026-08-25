# VibeGuard — Binding Interface Contracts

This document is **normative**. All modules must implement these exact names, types,
and semantics. Shared types live in `vibeguard.core.models` — no module redefines them.
Python ≥3.11, pydantic v2. All paths in models are POSIX-style relative to repo root.

## 1. Enums (`vibeguard/core/models.py`)

```python
class Severity(str, Enum):        CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"
class Confidence(str, Enum):      HIGH="high"; MEDIUM="medium"; LOW="low"
class AutofixSafety(str, Enum):   SAFE_AUTOFIX="safe_autofix"; REVIEW_RECOMMENDED="review_recommended"; MANUAL_CHANGE_REQUIRED="manual_change_required"; INFORMATIONAL="informational"; NOT_APPLICABLE="not_applicable"
class FixStatus(str, Enum):       FIXED="fixed"; ATTEMPTED="attempted"; PARTIALLY_FIXED="partially_fixed"; UNVERIFIED="unverified"; FAILED="failed"; REQUIRES_REVIEW="requires_review"; NOT_ATTEMPTED="not_attempted"
class Category(str, Enum):        SECURITY="security"; SECRETS="secrets"; DATABASE="database"; API="api"; RELIABILITY="reliability"; PERFORMANCE="performance"; OBSERVABILITY="observability"; CONTAINERS="containers"; DEPLOYMENT="deployment"; DEPENDENCIES="dependencies"; TESTING="testing"; SCALABILITY="scalability"; DISASTER_RECOVERY="disaster_recovery"; MAINTAINABILITY="maintainability"; COST="cost"
class ScaleClass(str, Enum):      TOY="toy"; SMALL="small"; MEDIUM="medium"; LARGE="large"   # ordered; comparable via .order property
class SuppressionReason(str, Enum): FALSE_POSITIVE="false_positive"; ACCEPTED_RISK="accepted_risk"; TEMPORARY="temporary"; NOT_APPLICABLE="not_applicable"
```

## 2. Core models

```python
class Evidence(BaseModel):
    file: str; line: int | None = None; end_line: int | None = None
    snippet: str = ""            # REDACTED at construction if rule.category==SECRETS or redact=True
    note: str = ""

class Finding(BaseModel):
    id: str                      # "{rule_id}:{fingerprint[:12]}", assigned by engine
    rule_id: str                 # e.g. "VG-SEC-001"
    category: Category
    severity: Severity
    confidence: Confidence
    title: str
    description: str             # what is wrong, specific to this occurrence
    why_it_matters: str
    evidence: list[Evidence]
    file: str | None; line: int | None
    autofix_safety: AutofixSafety
    fingerprint: str             # sha256 hex, see §7
    references: list[str] = []
    recommended_followup: str = ""
    suppressed: bool = False
    suppression: SuppressionEntry | None = None
    fix: FixRecord | None = None # populated by fixer engine

class Patch(BaseModel):
    finding_id: str
    file_edits: list[FileEdit]   # FileEdit: {path, old_content_sha256, new_content}  (whole-file replace; engine verifies sha before write)
    description: str
    commit_message: str          # conventional-commit style, must end with " [{rule_id}]"

class ValidationStep(BaseModel):
    name: str                    # "syntax" | "typecheck" | "lint" | "tests:targeted" | "tests:full" | "build" | "container_build" | "startup"
    passed: bool; skipped: bool = False; detail: str = ""

class FixRecord(BaseModel):
    status: FixStatus
    patch_summary: str = ""
    original_snippet: str = ""; repaired_snippet: str = ""   # redacted same as Evidence
    commit_sha: str | None = None
    validation: list[ValidationStep] = []
    repro_test: str | None = None       # path of generated repro test if any
    residual_risk: str = ""

class TechProfile(BaseModel):
    languages: dict[str, int]           # name -> file count
    frameworks: list[str]; frontend: list[str]; backend: list[str]
    databases: list[str]; orms: list[str]; package_managers: list[str]
    containers: list[str]; ci_cd: list[str]; iac: list[str]
    test_frameworks: list[str]; caches: list[str]; brokers: list[str]
    workers: list[str]; serverless: list[str]; realtime: list[str]   # websocket/sse
    auth: list[str]; secret_mechanisms: list[str]; external_services: list[str]
    manifest_files: list[str]

class ArchNode(BaseModel):  id: str; kind: str; label: str; meta: dict = {}
class ArchEdge(BaseModel):  src: str; dst: str; kind: str
class ArchitectureGraph(BaseModel): nodes: list[ArchNode]; edges: list[ArchEdge]

class ScaleProfile(BaseModel):
    scale: ScaleClass; loc: int; service_count: int
    has_sensitive_data: bool; rationale: str

class ScanContext(BaseModel):        # passed to every rule; arbitrary types allowed
    root: Path; files: list[str]     # relative, filtered by .gitignore + binary excl.
    tech: TechProfile; graph: ArchitectureGraph; scale: ScaleProfile
    config: VibeguardConfig
    def read(self, relpath) -> str   # cached file reader
    def ast(self, relpath) -> Tree | None    # cached tree-sitter parse (py/js/ts), None if unsupported
```

## 3. Rule interface (`vibeguard/core/rule.py`)

```python
class Rule(ABC):
    id: ClassVar[str]                # "VG-{CAT}-{NNN}"; CAT in SEC,SCR,DB,API,REL,PERF,OBS,CTR,DEP,DEPS,TEST,SCALE,DR,MAINT,COST
    category: ClassVar[Category]; severity: ClassVar[Severity]; confidence: ClassVar[Confidence]
    title: ClassVar[str]; description: ClassVar[str]; why_it_matters: ClassVar[str]
    references: ClassVar[list[str]] = []
    technologies: ClassVar[set[str]] = set()   # empty = any; matched against TechProfile fields (lowercased)
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    requires_ai: ClassVar[bool] = False

    def applicable(self, ctx: ScanContext) -> bool   # default: tech ∧ scale gate; override for extra preconditions
    @abstractmethod
    def detect(self, ctx: ScanContext) -> list[Finding]     # construct via self.make_finding(...) helper (computes fingerprint, redacts)
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None: return None
```

Rule packs: `vibeguard/rules/<pack>/__init__.py` exposes `RULES: list[type[Rule]]`.
Registry (`core/registry.py`) discovers built-in packs plus entry-point group
`vibeguard.rules` for third-party plugins.

## 4. Adapter interface (`vibeguard/adapters/base.py`)

```python
class ToolAdapter(ABC):
    name: ClassVar[str]                       # "bandit", "trivy", ...
    def available(self) -> bool               # shutil.which / import check; NEVER raises
    def applicable(self, ctx) -> bool
    @abstractmethod
    def run(self, ctx) -> list[Finding]       # subprocess w/ timeout (default 300s), JSON output parsed; failures -> log + [] (never crash the scan)
```

Adapter findings use rule_ids `VG-EXT-{tool}-{native_id}` and must map native severity
to our enums; dedup vs built-ins happens by fingerprint in the engine.

## 5. Fixer, validation, git safety

```python
class GitSafety:            # fixers/git_safety.py
    def preflight(self) -> GitState          # raises DirtyWorktreeError unless allowed; records head_sha
    def create_fix_branch(self) -> str       # "vibeguard/fix-YYYY-MM-DD[-N]"
    def commit(self, patch: Patch) -> str    # returns sha
    def rollback_working_tree(self) -> None  # git checkout -- affected paths

class Validator(ABC):       # validation/base.py
    name: ClassVar[str]     # matches ValidationStep.name values
    def available(self, ctx) -> bool
    def run(self, ctx, changed_files: list[str]) -> ValidationStep

class ValidationEngine:
    def validate(self, ctx, changed_files) -> list[ValidationStep]   # runs ladder in §7-order, stops early on hard failure
    def verdict(self, steps, repro_passed: bool | None) -> FixStatus # FIXED only if no failures ∧ ≥1 non-skipped pass ∧ repro (if any) passed

class FixerEngine:
    def repair(self, ctx, findings, mode: Literal["safe","interactive"]) -> list[Finding]
    # safe: only SAFE_AUTOFIX; interactive: prompt per REVIEW_RECOMMENDED via typer.confirm
    # loop per finding: patch = rule.fix(); apply (sha-checked); validate; commit|rollback; attach FixRecord
```

## 6. Events (`vibeguard/core/events.py`)

```python
class EventBus:  # sync pub/sub; subscribe(pattern, fn); emit(name, **payload)
```
Event names (exact): `scan.started`, `scan.stage` (payload: stage), `scan.issue_found`
(payload: finding), `scan.completed`, `repair.started`, `repair.completed`,
`repair.failed`, `validation.started`, `validation.completed`, `report.generated`.
Payloads are JSON-serializable dicts; `--output jsonl` streams
`{"event": name, "ts": iso8601, "data": {...}}` per line to stdout.

## 7. Fingerprints, redaction, baseline

- `fingerprint = sha256(f"{rule_id}|{relpath}|{normalize(snippet)}")` where
  `normalize` strips whitespace runs and lowercases. If no snippet, use
  `f"{rule_id}|{relpath}|"`; project-level findings use relpath `"."`.
- `redact(s)`: any token matching secret patterns → keep first 4 + last 4 chars,
  middle → `****[REDACTED]****`. Applied in `make_finding` for SECRETS category and any
  Evidence flagged `redact=True`. Implemented once in `core/redact.py`.
- Baseline file `.vibeguard/baseline.json`: `{created, head_sha, fingerprints: [...]}`.
- Suppressions `.vibeguard/suppressions.yml`:
  `- fingerprint, rule_id, reason (SuppressionReason), author, created, expires?, note`.
- History: `.vibeguard/history/<iso-ts>.json` = full ScanReport; regression diff
  compares latest two by fingerprint sets.

## 8. Report schema (`vibeguard-report.json`)

```python
class CategoryScore(BaseModel): category: Category; score: int; applicable: bool; finding_count: int
class ScanReport(BaseModel):
    schema_version: Literal["1"]
    repo: str; scan_date: datetime; vibeguard_version: str
    mode: str                      # audit|fix-safe|fix-interactive|ci
    tech: TechProfile; scale: ScaleProfile; graph: ArchitectureGraph
    findings: list[Finding]        # includes suppressed (marked)
    scores_before: list[CategoryScore]; scores_after: list[CategoryScore] | None
    overall_before: int; overall_after: int | None
    counts: dict[str, int]         # severities, statuses, suppressed
    regression: RegressionDiff | None   # {new: [ids], resolved: [fps], regressed: [ids], unchanged: int}
    adapters_used: list[str]; validators_used: list[str]
    ai_used: bool; local_only: bool
    suppressions: list[SuppressionEntry]
```

Scoring (docs/SCORING.md must restate): weights w = {critical:.40, high:.25,
medium:.10, low:.04, info:.01}; confidence factor c = {high:1.0, medium:.7, low:.4};
`category_score = round(100 * Π_open_findings (1 − w·c))` floor 0; suppressed findings
excluded; category with no applicable rules → `applicable=False`, excluded from
overall; `overall = round(mean(applicable category scores))` with SECURITY and SECRETS
double-weighted.

## 9. Config (`.vibeguard.toml` → `core/config.py: VibeguardConfig`)

```toml
[vibeguard]
packs = ["core","secrets","security","database","web","devops","python","node"]
exclude = ["**/node_modules/**", "**/.venv/**"]        # + .gitignore always
local_only = false
[ai]      provider = "null"   # null|anthropic|openai_compatible ; endpoint, model, api_key_env
[ci]      fail_on = "high"    # min severity that fails CI ; use_baseline = true
[fix]     allow_no_git = false
```

CLI flags override config. Engine construction:
`Engine(config).audit(path) / .fix(path, mode) / .ci(path)` → `ScanReport`.

## 10. AI provider (`vibeguard/ai/base.py`)

```python
class AIProvider(ABC):
    name: ClassVar[str]; is_local: bool
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str
class NullProvider(AIProvider): ...   # raises AIUnavailable; rules with requires_ai skip + report notes degraded
def get_provider(config) -> AIProvider   # enforces local_only: non-local provider + local_only=True -> returns NullProvider + warning event
```

## 11. Master audit checklist (completeness guarantee)

`src/vibeguard/rules/topics.yaml` is the authoritative registry of every audit topic
from the product brief (≈240 items across 18 sections, incl. chaos engineering,
serverless limits, incident/on-call/postmortem readiness, GC behavior, CDN config).
**Every ScanReport must account for every topic** — no category may be silently
skipped.

```python
class ChecklistStatus(str, Enum):
    PASS="pass"; FAIL="fail"; FIXED="fixed"; REVIEW_REQUIRED="review_required"; NOT_APPLICABLE="not_applicable"

class ChecklistItem(BaseModel):
    topic_id: str                # "<section>.<slug>" e.g. "security.sql-injection"
    section: str; name: str; category: Category
    status: ChecklistStatus
    detectors: list[str]         # rule ids + adapter names that declare this topic
    technologies: list[str]      # techs the mapped detectors apply to (informational)
    finding_ids: list[str] = []  # findings attributed to this topic
    fixes: list[str] = []        # finding ids with FixRecord.status == FIXED
    validation: str = ""         # summary of validation evidence for fixes
    note: str = ""               # esp. for REVIEW_REQUIRED with no automated detector
```

Rule ABC gains `topics: ClassVar[set[str]] = set()` (topic_ids it evaluates);
ToolAdapter gains the same. Engine derives the checklist after detection/repair:

- **NOT_APPLICABLE** — no mapped detector is applicable to this stack/scale (e.g. no
  k8s topics for a compose-only app), or topic's preconditions absent. `note` explains.
- **PASS** — ≥1 mapped detector ran and produced no open findings.
- **FAIL** — open unfixed findings attributed to the topic.
- **FIXED** — all attributed findings have FixRecord.status == FIXED (validation
  summary required).
- **REVIEW_REQUIRED** — findings needing manual review, or the topic is applicable
  but has **no automated detector yet** (`note: "no automated detector — manual
  review required"`). This is the honest fallback; it is never converted to PASS.

`ScanReport` gains `checklist: list[ChecklistItem]`. All three report renderers must
include the full checklist (md/html: per-section tables with status rollups; json:
verbatim). The engine hard-fails a scan if any topic in topics.yaml is missing from
the produced checklist (self-check).

## 12. Exit codes (CLI)

`0` ok / below threshold; `1` findings ≥ fail_on threshold (ci mode); `2` execution
error; `3` dirty-worktree refusal.
