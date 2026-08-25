"""VG-OBS-003 / VG-OBS-007 — error tracking, metrics, and service-level objectives."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.observability._common import haystack, matched_tokens

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoErrorTrackingRule", "NoMetricsRule"]

_ERROR_TRACKING_TOKENS = (
    "sentry",
    "rollbar",
    "bugsnag",
    "honeybadger",
    "airbrake",
    "raygun",
    "datadog",
    "ddtrace",
    "dd-trace",
    "newrelic",
    "new_relic",
    "new-relic",
    "opentelemetry",
    "elastic-apm",
    "elasticapm",
    "appsignal",
    "glitchtip",
)


class NoErrorTrackingRule(ProjectRule):
    """Nothing collects unhandled exceptions from the running service."""

    id: ClassVar[str] = "VG-OBS-003"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No error tracking configured"
    description: ClassVar[str] = (
        "No error-tracking or APM integration (Sentry, Rollbar, Bugsnag, Datadog, New "
        "Relic, OpenTelemetry, …) was found in the project."
    )
    why_it_matters: ClassVar[str] = (
        "Without error tracking you find out about crashes when a user complains — if "
        "they bother. Exceptions land in a log file nobody reads, there is no stack "
        "trace with the request context attached, and there is no signal that a deploy "
        "just started breaking one endpoint in ten. Teams routinely discover such "
        "regressions days later, after the traffic has already been lost."
    )
    references: ClassVar[list[str]] = [
        "https://docs.sentry.io/product/sentry-basics/",
        "https://opentelemetry.io/docs/what-is-opentelemetry/",
    ]
    topics: ClassVar[set[str]] = {
        "observability.error-tracking",
        "observability.alerts",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Add one error-tracking SDK and initialise it at start-up (for example "
        "`sentry_sdk.init(dsn=os.environ[\"SENTRY_DSN\"], traces_sample_rate=0.1)`), "
        "then set an alert so a spike in new exceptions notifies a human."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            if matched_tokens(haystack(ctx), _ERROR_TRACKING_TOKENS):
                return None
        except Exception:  # pragma: no cover - defensive
            return None
        return (
            "No error-tracking or APM integration was detected in the dependencies or "
            "the application start-up code.",
            "searched manifests and source for sentry, rollbar, bugsnag, honeybadger, "
            "datadog, new relic, elastic-apm, and opentelemetry",
        )


_METRICS_TOKENS = (
    "prometheus_client",
    "prometheus-client",
    "prom-client",
    "prometheus",
    "statsd",
    "micrometer",
    "opentelemetry",
    "otel_meter",
    "metrics.counter",
    "/metrics",
    "datadog",
    "cloudwatch",
    "grafana",
)
_SLO_RE = re.compile(
    r"\b(?:slos?|slis?|error[ _-]budgets?|service[ -]level[ -]objectives?|burn[ _-]rate)\b"
)
_SLO_DOC_HINTS = ("slo", "sli", "objectives")


class NoMetricsRule(ProjectRule):
    """No metrics pipeline and no service-level objectives written down."""

    id: ClassVar[str] = "VG-OBS-007"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No metrics or service-level objectives defined"
    description: ClassVar[str] = (
        "No metrics client, `/metrics` endpoint, or SLO document was found, so there "
        "is no numeric definition of what \"working\" means for this service."
    )
    why_it_matters: ClassVar[str] = (
        "Logs tell you what happened to one request; metrics tell you whether the "
        "service as a whole is getting slower or failing more often. Without them, a "
        "gradual regression — latency creeping from 100ms to 3s over a week — is "
        "invisible until it becomes an outage, and without an SLO nobody can say "
        "whether the current error rate is acceptable or an emergency."
    )
    references: ClassVar[list[str]] = [
        "https://sre.google/sre-book/service-level-objectives/",
        "https://prometheus.io/docs/practices/instrumentation/",
    ]
    topics: ClassVar[set[str]] = {
        "observability.metrics",
        "observability.slis",
        "observability.slos",
        "observability.error-budgets",
        "observability.monitoring",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Expose request rate, error rate, and latency histograms on a `/metrics` "
        "endpoint (prometheus_client in Python, prom-client in Node), then write down "
        "one SLO — for example \"99% of requests under 500ms over 30 days\" — in "
        "`docs/slo.md` so alerts have something to measure against."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            text = haystack(ctx)
            if matched_tokens(text, _METRICS_TOKENS):
                return None
            if _SLO_RE.search(text):
                return None
            if self._has_slo_document(ctx):
                return None
        except Exception:  # pragma: no cover - defensive
            return None
        return (
            "No metrics client or `/metrics` endpoint was found, and no document "
            "defines SLIs, SLOs, or an error budget.",
            "searched for prometheus_client / prom-client / statsd / micrometer / "
            "OpenTelemetry metrics, a /metrics route, and slo|sli|error-budget docs",
        )

    @staticmethod
    def _has_slo_document(ctx: ScanContext) -> bool:
        for rel in ctx.files:
            name = PurePosixPath(rel).name.lower()
            if name.endswith((".md", ".yaml", ".yml")) and any(
                hint in name for hint in _SLO_DOC_HINTS
            ):
                return True
        return False
