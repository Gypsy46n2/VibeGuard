"""Shared VibeGuard data model — normative per docs/INTERFACES.md §1–§2, §5, §7, §8.

No other module may redefine these types.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = [
    "ArchEdge",
    "ArchNode",
    "ArchitectureGraph",
    "AutofixSafety",
    "Category",
    "CategoryScore",
    "ChecklistItem",
    "ChecklistStatus",
    "Confidence",
    "Evidence",
    "FileEdit",
    "Finding",
    "FixRecord",
    "FixStatus",
    "GitState",
    "Patch",
    "RegressionDiff",
    "ScaleClass",
    "ScaleProfile",
    "ScanReport",
    "Severity",
    "SuppressionEntry",
    "SuppressionReason",
    "TechProfile",
    "ValidationStep",
]


# --------------------------------------------------------------------------- enums


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def order(self) -> int:
        """Higher is more severe."""
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER: dict[Severity, int] = {}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AutofixSafety(str, Enum):
    SAFE_AUTOFIX = "safe_autofix"
    REVIEW_RECOMMENDED = "review_recommended"
    MANUAL_CHANGE_REQUIRED = "manual_change_required"
    INFORMATIONAL = "informational"
    NOT_APPLICABLE = "not_applicable"


class FixStatus(str, Enum):
    FIXED = "fixed"
    ATTEMPTED = "attempted"
    PARTIALLY_FIXED = "partially_fixed"
    UNVERIFIED = "unverified"
    FAILED = "failed"
    REQUIRES_REVIEW = "requires_review"
    NOT_ATTEMPTED = "not_attempted"


class Category(str, Enum):
    SECURITY = "security"
    SECRETS = "secrets"
    DATABASE = "database"
    API = "api"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    OBSERVABILITY = "observability"
    CONTAINERS = "containers"
    DEPLOYMENT = "deployment"
    DEPENDENCIES = "dependencies"
    TESTING = "testing"
    SCALABILITY = "scalability"
    DISASTER_RECOVERY = "disaster_recovery"
    MAINTAINABILITY = "maintainability"
    COST = "cost"


class ScaleClass(str, Enum):
    TOY = "toy"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"

    @property
    def order(self) -> int:
        return _SCALE_ORDER[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, ScaleClass):
            return self.order >= other.order
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, ScaleClass):
            return self.order > other.order
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, ScaleClass):
            return self.order <= other.order
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, ScaleClass):
            return self.order < other.order
        return NotImplemented


_SCALE_ORDER: dict[ScaleClass, int] = {
    ScaleClass.TOY: 0,
    ScaleClass.SMALL: 1,
    ScaleClass.MEDIUM: 2,
    ScaleClass.LARGE: 3,
}

_SEVERITY_ORDER.update(
    {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
)


class ChecklistStatus(str, Enum):
    """Status of one master-checklist topic — INTERFACES.md §11."""

    PASS = "pass"
    FAIL = "fail"
    FIXED = "fixed"
    REVIEW_REQUIRED = "review_required"
    NOT_APPLICABLE = "not_applicable"


class SuppressionReason(str, Enum):
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    TEMPORARY = "temporary"
    NOT_APPLICABLE = "not_applicable"


# --------------------------------------------------------------------------- core


class Evidence(BaseModel):
    """A pointer into the codebase supporting a finding.

    ``snippet`` is redacted at Finding-construction time when the owning rule's
    category is SECRETS or when ``redact`` is set.
    """

    file: str
    line: int | None = None
    end_line: int | None = None
    snippet: str = ""
    note: str = ""
    redact: bool = False


class FileEdit(BaseModel):
    """Whole-file replacement; the engine verifies the sha before writing."""

    path: str
    old_content_sha256: str
    new_content: str


class ValidationStep(BaseModel):
    name: str
    passed: bool
    skipped: bool = False
    detail: str = ""


class FixRecord(BaseModel):
    status: FixStatus
    patch_summary: str = ""
    original_snippet: str = ""
    repaired_snippet: str = ""
    commit_sha: str | None = None
    validation: list[ValidationStep] = Field(default_factory=list)
    repro_test: str | None = None
    residual_risk: str = ""


class SuppressionEntry(BaseModel):
    fingerprint: str
    rule_id: str
    reason: SuppressionReason
    author: str = ""
    created: datetime | None = None
    expires: datetime | None = None
    note: str = ""


class Finding(BaseModel):
    id: str
    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    why_it_matters: str
    evidence: list[Evidence] = Field(default_factory=list)
    file: str | None = None
    line: int | None = None
    autofix_safety: AutofixSafety
    fingerprint: str
    references: list[str] = Field(default_factory=list)
    recommended_followup: str = ""
    suppressed: bool = False
    suppression: SuppressionEntry | None = None
    #: Fingerprint present in ``.vibeguard/baseline.json`` — reported, never gated on.
    baselined: bool = False
    fix: FixRecord | None = None


class Patch(BaseModel):
    finding_id: str
    file_edits: list[FileEdit] = Field(default_factory=list)
    description: str = ""
    commit_message: str = ""


# ----------------------------------------------------------------------- discovery


class TechProfile(BaseModel):
    languages: dict[str, int] = Field(default_factory=dict)
    frameworks: list[str] = Field(default_factory=list)
    frontend: list[str] = Field(default_factory=list)
    backend: list[str] = Field(default_factory=list)
    databases: list[str] = Field(default_factory=list)
    orms: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    containers: list[str] = Field(default_factory=list)
    ci_cd: list[str] = Field(default_factory=list)
    iac: list[str] = Field(default_factory=list)
    test_frameworks: list[str] = Field(default_factory=list)
    caches: list[str] = Field(default_factory=list)
    brokers: list[str] = Field(default_factory=list)
    workers: list[str] = Field(default_factory=list)
    serverless: list[str] = Field(default_factory=list)
    realtime: list[str] = Field(default_factory=list)
    auth: list[str] = Field(default_factory=list)
    secret_mechanisms: list[str] = Field(default_factory=list)
    external_services: list[str] = Field(default_factory=list)
    manifest_files: list[str] = Field(default_factory=list)

    def all_technologies(self) -> set[str]:
        """Every detected technology token, lowercased — the rule applicability set."""
        tokens: set[str] = {name.lower() for name in self.languages}
        for field in (
            self.frameworks,
            self.frontend,
            self.backend,
            self.databases,
            self.orms,
            self.package_managers,
            self.containers,
            self.ci_cd,
            self.iac,
            self.test_frameworks,
            self.caches,
            self.brokers,
            self.workers,
            self.serverless,
            self.realtime,
            self.auth,
            self.secret_mechanisms,
            self.external_services,
        ):
            tokens.update(item.lower() for item in field)
        return tokens


class ArchNode(BaseModel):
    id: str
    kind: str
    label: str
    meta: dict[str, Any] = Field(default_factory=dict)


class ArchEdge(BaseModel):
    src: str
    dst: str
    kind: str


class ArchitectureGraph(BaseModel):
    nodes: list[ArchNode] = Field(default_factory=list)
    edges: list[ArchEdge] = Field(default_factory=list)


class ScaleProfile(BaseModel):
    scale: ScaleClass
    loc: int = 0
    service_count: int = 1
    has_sensitive_data: bool = False
    rationale: str = ""


# ---------------------------------------------------------------- git / reporting


class GitState(BaseModel):
    is_repo: bool = False
    head_sha: str | None = None
    branch: str | None = None
    dirty: bool = False
    dirty_paths: list[str] = Field(default_factory=list)


class RegressionDiff(BaseModel):
    new: list[str] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)
    regressed: list[str] = Field(default_factory=list)
    unchanged: int = 0


class CategoryScore(BaseModel):
    category: Category
    score: int
    applicable: bool
    finding_count: int


class ChecklistItem(BaseModel):
    """One master-checklist topic and its resolved status — INTERFACES.md §11."""

    topic_id: str
    section: str
    name: str
    category: Category
    status: ChecklistStatus
    detectors: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    fixes: list[str] = Field(default_factory=list)
    validation: str = ""
    note: str = ""


class ScanReport(BaseModel):
    schema_version: Literal["1"] = "1"
    repo: str
    scan_date: datetime
    vibeguard_version: str
    mode: str
    tech: TechProfile
    scale: ScaleProfile
    graph: ArchitectureGraph
    findings: list[Finding] = Field(default_factory=list)
    checklist: list[ChecklistItem] = Field(default_factory=list)
    scores_before: list[CategoryScore] = Field(default_factory=list)
    scores_after: list[CategoryScore] | None = None
    overall_before: int = 100
    overall_after: int | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    regression: RegressionDiff | None = None
    adapters_used: list[str] = Field(default_factory=list)
    validators_used: list[str] = Field(default_factory=list)
    #: The validation ladder as it ran over the untouched repository, before any fix.
    #: Failures here are excluded from post-fix verdicts (DECISIONS.md D21) and must
    #: stay visible, so the exclusions are auditable in every renderer.
    baseline_validation: list[ValidationStep] = Field(default_factory=list)
    ai_used: bool = False
    local_only: bool = True
    suppressions: list[SuppressionEntry] = Field(default_factory=list)
    #: Non-fatal problems worth surfacing in the report (expired suppressions,
    #: unreadable baseline files, …). Never silently swallowed.
    warnings: list[str] = Field(default_factory=list)


def __getattr__(name: str) -> Any:
    """Late-bound re-export of ScanContext.

    ``ScanContext`` is listed alongside the core models in INTERFACES.md §2 but is
    implemented in ``vibeguard.discovery.context`` (it depends on config + discovery
    types). This shim keeps ``from vibeguard.core.models import ScanContext`` valid
    without an import cycle. See docs/DECISIONS.md.
    """
    if name == "ScanContext":
        from vibeguard.discovery.context import ScanContext

        return ScanContext
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
