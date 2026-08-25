"""VG-DR-004 — incident, on-call, and postmortem readiness.

Advisory by construction: the absence of a runbook in the repository is evidence
about the repository, not proof that the team has no process.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.disaster_recovery._signals import find_markers, name_hits

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["IncidentReadinessRule"]

_DOC_NAME_HINTS = (
    "runbook",
    "playbook",
    "oncall",
    "on-call",
    "on_call",
    "incident",
    "postmortem",
    "post-mortem",
    "escalation",
    "disaster-recovery",
    "disaster_recovery",
)

_READINESS_RE = re.compile(
    r"pagerduty|opsgenie|victorops|alertmanager|route:\s*\n?\s*receiver|"
    r"on[- _]?call|escalation[ _-]?policy|incident[ _-]?(?:response|commander|template|"
    r"channel|severity)|post[- ]?mortem|blameless|runbook",
    re.IGNORECASE,
)


class IncidentReadinessRule(ProjectRule):
    """No runbook, on-call docs, incident template, or alert routing."""

    id: ClassVar[str] = "VG-DR-004"
    category: ClassVar[Category] = Category.DISASTER_RECOVERY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No incident, on-call, or postmortem readiness"
    description: ClassVar[str] = (
        "No runbook, on-call or escalation documentation, incident template, postmortem "
        "record, or alert-routing configuration is present in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "When production breaks at 3am, whoever is awake needs to know what to check, who "
        "to wake up, and how to roll back — and they need it written down, because nobody "
        "reasons well at 3am. Without it, outages last hours instead of minutes and the "
        "same failure recurs because nothing was ever written up afterwards."
    )
    references: ClassVar[list[str]] = [
        "https://sre.google/sre-book/managing-incidents/",
        "https://sre.google/sre-book/postmortem-culture/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "disaster-recovery.incident-readiness",
        "disaster-recovery.on-call-readiness",
        "disaster-recovery.postmortem-process",
        "disaster-recovery.disaster-recovery-plan",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Add a one-page `RUNBOOK.md` covering how to restart the service, where the logs "
        "and dashboards are, how to roll back a deploy, and who to contact — then wire "
        "your alerts to a real destination (PagerDuty, Opsgenie, or an Alertmanager "
        "receiver) so somebody is actually paged."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if name_hits(ctx, _DOC_NAME_HINTS, max_hits=1):
            return None
        if any(ctx.exists(path) for path in ("docs/runbooks", "runbooks", "postmortems")):
            return None
        if find_markers(ctx, _READINESS_RE, max_hits=1):
            return None
        return (
            "VibeGuard found no operational-readiness artefacts in this repository: no "
            "RUNBOOK.md or runbooks/ directory, no on-call or escalation documentation, "
            "no incident template, no postmortem directory, and no alert-routing "
            "configuration (PagerDuty, Opsgenie, Alertmanager). This says nothing about "
            "what lives in a wiki elsewhere — but anything not in the repository is not "
            "reachable from the terminal of whoever is on call.",
            "checked file names for runbook/on-call/incident/postmortem/escalation and "
            "file contents for pagerduty, opsgenie, and alertmanager routing",
        )


RULES: list[type[Rule]] = [IncidentReadinessRule]
