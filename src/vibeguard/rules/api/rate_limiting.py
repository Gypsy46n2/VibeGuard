"""VG-API-003 — a public HTTP service with no rate limiting anywhere."""

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
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.api._http import repo_matches, serves_http

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoRateLimitingRule"]

_LIMITER = re.compile(
    r"flask[-_]limiter|slowapi|django[-_]ratelimit|djangorestframework.*throttl|"
    r"express-rate-limit|express-slow-down|rate-limiter-flexible|"
    r"@?fastify[-/]rate-limit|koa-ratelimit|"
    r"\bratelimit\b|\brate_limit\b|\brateLimit\b|\bRateLimit\b|"
    r"limit_req|limit_conn|"
    r"DEFAULT_THROTTLE_RATES|throttle_classes|"
    r"x-amazon-apigateway-integration|usagePlan|UsagePlan|"
    r"quota|throttling|throttlingBurstLimit",
    re.IGNORECASE,
)


class NoRateLimitingRule(ProjectRule):
    """Fires when routes are served but nothing in the repo limits request rate."""

    id: ClassVar[str] = "VG-API-003"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No rate limiting on a public HTTP service"
    description: ClassVar[str] = (
        "The application serves HTTP routes but no rate-limiting library, middleware, or "
        "gateway throttling configuration was found anywhere in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "Without a request-rate ceiling, one script can send thousands of requests a second "
        "and take the service down for everyone — no botnet required. It also removes the "
        "cost of guessing: login endpoints can be brute-forced, password-reset and SMS "
        "endpoints can be abused to run up your bill, and expensive queries can be replayed "
        "until the database falls over."
    )
    references: ClassVar[list[str]] = [
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "https://flask-limiter.readthedocs.io/en/stable/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "api.rate-limiting",
        "security.ddos-readiness",
        "security.waf-readiness",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED
    recommended_followup: ClassVar[str] = (
        "Add a limiter in front of every route — e.g. Flask-Limiter/SlowAPI in Python or "
        "`express-rate-limit` in Node — with a strict per-IP budget on authentication and "
        "any endpoint that sends mail, SMS, or money."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if not serves_http(ctx):
            return None
        if repo_matches(ctx, _LIMITER):
            return None
        return (
            "HTTP routes are served by "
            f"{', '.join(sorted(ctx.tech.backend))} but no rate limiter "
            "(flask-limiter, slowapi, django-ratelimit, express-rate-limit, "
            "@fastify/rate-limit, nginx limit_req, or API-gateway throttling) is configured.",
            "searched dependencies, middleware, and infrastructure config for any "
            "rate-limiting or throttling mechanism",
        )
