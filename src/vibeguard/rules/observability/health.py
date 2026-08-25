"""VG-OBS-004 / VG-OBS-005 — health endpoints and request correlation."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import AutofixSafety, Category, Confidence, ScaleClass, Severity
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.observability._common import has_server, haystack, matched_tokens

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoCorrelationIdRule", "NoHealthCheckRule"]

log = logging.getLogger(__name__)

_HEALTH_ROUTE = re.compile(
    r"""(?ix)
    /(?:_?health(?:z|check|_check)?|readyz?|ready_check|livez?|liveness|ping|status)\b
  | \blivenessprobe\b
  | \breadinessprobe\b
  | \bhealthcheck\s*:
  | \bHEALTHCHECK\b
    """
)


class NoHealthCheckRule(ProjectRule):
    """A server with no endpoint an orchestrator or uptime monitor can poll."""

    id: ClassVar[str] = "VG-OBS-004"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No health-check endpoint"
    description: ClassVar[str] = (
        "A server framework is present but no route matching /health, /healthz, "
        "/ready, /live, /ping, or /status was found."
    )
    why_it_matters: ClassVar[str] = (
        "Load balancers, container orchestrators, and uptime monitors all decide "
        "whether an instance is alive by asking it. With nothing to ask, traffic keeps "
        "being routed to a process that is deadlocked or has lost its database "
        "connection, and a bad deploy rolls out to every instance because nothing "
        "reported it unhealthy. Users see errors long before anyone gets paged."
    )
    references: ClassVar[list[str]] = [
        "https://microservices.io/patterns/observability/health-check-api.html",
        "https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/",
    ]
    topics: ClassVar[set[str]] = {
        "observability.health-checks",
        "observability.liveness-checks",
        "observability.readiness-checks",
        "containers.health-checks",
    }
    #: Health probes matter once something is orchestrating the service; a single
    #: hobby process has nothing polling it.
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    recommended_followup: ClassVar[str] = (
        "Add a cheap `GET /healthz` that returns 200 without touching downstream "
        "services (liveness) and a `GET /readyz` that checks the database connection "
        "(readiness), then point your container's healthcheck or Kubernetes probes at "
        "them."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_server(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            if _HEALTH_ROUTE.search(haystack(ctx)):
                return None
        except Exception:  # pragma: no cover - defensive
            # Rule/repository boundary: a project we cannot read is a project we
            # cannot make a claim about, so stay silent — but say so in the log.
            log.debug("health-route search failed; skipping VG-OBS-004", exc_info=True)
            return None
        return (
            "A server framework is configured but no health, readiness, or liveness "
            "route was found anywhere in the project.",
            "searched routes and manifests for /health, /healthz, /ready, /readyz, "
            "/live, /livez, /_health, /ping, /status, HEALTHCHECK, and k8s probes",
        )


_CORRELATION_TOKENS = (
    "request-id",
    "request_id",
    "requestid",
    "x-request-id",
    "correlation-id",
    "correlation_id",
    "correlationid",
    "x-correlation-id",
    "traceparent",
    "trace-id",
    "trace_id",
    "opentelemetry",
    "otel",
    "cls-rtracer",
    "asgi-correlation-id",
    "express-request-id",
    "requestcontext",
    "b3-traceid",
)


class NoCorrelationIdRule(ProjectRule):
    """No request id threaded through logs and downstream calls."""

    id: ClassVar[str] = "VG-OBS-005"
    category: ClassVar[Category] = Category.OBSERVABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No request correlation IDs"
    description: ClassVar[str] = (
        "No request-id / correlation-id / traceparent handling was found, so log "
        "lines cannot be tied back to the request that produced them."
    )
    why_it_matters: ClassVar[str] = (
        "When a user reports \"it failed around 2pm\", a correlation id is what turns "
        "thousands of interleaved log lines into the twelve that belong to their "
        "request. Without one, debugging a concurrent service means guessing which "
        "lines go together, and a failure that crosses two services becomes almost "
        "impossible to reconstruct at all."
    )
    references: ClassVar[list[str]] = [
        "https://opentelemetry.io/docs/concepts/context-propagation/",
        "https://www.w3.org/TR/trace-context/",
    ]
    topics: ClassVar[set[str]] = {
        "observability.correlation-ids",
        "observability.request-ids",
        "observability.distributed-tracing",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL

    recommended_followup: ClassVar[str] = (
        "Add middleware that reads `X-Request-ID` (or generates a UUID4 when absent), "
        "stores it in a context variable, includes it in every log record, and "
        "forwards it as a header on outbound calls — or adopt OpenTelemetry, which "
        "does this via `traceparent`."
    )

    def applicable(self, ctx: ScanContext) -> bool:
        return super().applicable(ctx) and has_server(ctx)

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        try:
            if matched_tokens(haystack(ctx), _CORRELATION_TOKENS):
                return None
        except Exception:  # pragma: no cover - defensive
            # Broad by design: the rule/repository boundary. A scan must never
            # die on one unreadable input — but it must not go quiet either.
            log.debug("correlation-id search failed; skipping the check", exc_info=True)
            return None
        return (
            "No request-id, correlation-id, or traceparent handling was found in the "
            "server code, middleware, or dependencies.",
            "searched for request-id/correlation-id middleware, X-Request-ID header "
            "handling, W3C traceparent, and OpenTelemetry instrumentation",
        )
