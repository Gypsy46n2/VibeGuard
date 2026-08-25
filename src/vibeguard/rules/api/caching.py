"""VG-API-008 / VG-API-009 — no cache layer, and no proxy in front of the app."""

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
from vibeguard.rules.api._http import handlers, repo_matches, serves_http

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoCachingStrategyRule", "NoReverseProxyRule"]

_MIN_READ_ROUTES = 2

_CACHE = re.compile(
    r"\bredis\b|memcache|flask[-_]caching|cachetools|django\.core\.cache|"
    r"Cache-Control|cache_control|s-maxage|max-age|stale-while-revalidate|"
    r"\bETag\b|etag|If-None-Match|Last-Modified|"
    r"lru_cache|functools\.cache|node-cache|@nestjs/cache|"
    r"cloudfront|cloudflare|fastly|akamai|CDN_URL|"
    r"revalidate|unstable_cache|cacheManifest",
    re.IGNORECASE,
)

_BINDS_PORT = re.compile(
    r"app\.run\s*\(|uvicorn\.run\s*\(|hypercorn\.run\s*\(|app\.listen\s*\(|"
    r"server\.listen\s*\(|fastify\.listen\s*\(|serve\s*\(\s*app|runserver"
)
_PROXY = re.compile(
    r"nginx|traefik|caddy|envoy|haproxy|"
    r"kind:\s*Ingress|ingressClassName|aws_lb|aws_alb|load_balancer|loadBalancer|"
    r"apigateway|api_gateway|AWS::ApiGateway|cloudfront|"
    r"kong|\bALB\b|elasticloadbalancing|service\.type:\s*LoadBalancer",
    re.IGNORECASE,
)


class NoCachingStrategyRule(ProjectRule):
    """Read-heavy routes with nothing caching their results."""

    id: ClassVar[str] = "VG-API-008"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No caching strategy"
    description: ClassVar[str] = (
        "The service exposes read-heavy HTTP routes but no cache layer was found: no "
        "redis/memcached, no in-process cache, no Cache-Control or ETag headers, and no CDN "
        "configuration."
    )
    why_it_matters: ClassVar[str] = (
        "Every read then costs a full database round trip, so latency and database load "
        "grow in lockstep with traffic and a modest spike is enough to saturate the "
        "connection pool. It is also pure waste: the same rarely-changing responses are "
        "recomputed thousands of times, which shows up directly on the database and "
        "egress bill."
    )
    references: ClassVar[list[str]] = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching",
        "https://redis.io/docs/latest/develop/use/patterns/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "api.caching",
        "performance.cache-efficiency",
        "cost.poor-caching",
        "network.edge-caching",
        "network.cache-invalidation",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.SMALL
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Pick one read route that dominates traffic and cache it end to end: send "
        "`Cache-Control` and an `ETag` on the response, and memoise the expensive query in "
        "Redis with an explicit TTL and an invalidation path on write."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if not serves_http(ctx):
            return None
        if ctx.tech.caches:
            return None
        reads = [h for h in handlers(ctx) if h.accepts("get")]
        if len(reads) < _MIN_READ_ROUTES:
            return None
        if repo_matches(ctx, _CACHE):
            return None
        return (
            f"{len(reads)} read (GET) route(s) are served with no cache layer, cache "
            "headers, or CDN configuration anywhere in the repository.",
            "searched for redis/memcached, flask-caching, cachetools, django cache, "
            "Cache-Control/ETag/stale-while-revalidate headers, and CDN config",
        )


class NoReverseProxyRule(ProjectRule):
    """The application process is the edge: no proxy, gateway, or load balancer."""

    id: ClassVar[str] = "VG-API-009"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No reverse proxy, gateway, or load-balancer readiness"
    description: ClassVar[str] = (
        "The application binds a port and serves traffic directly, and no nginx, traefik, "
        "caddy, envoy, ingress, ALB, or API-gateway configuration exists in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "With nothing in front of the app there is no place to terminate TLS, buffer slow "
        "clients, or spread load across more than one instance — so every deploy is a "
        "visible outage and one slow client can occupy a worker for minutes. It also means "
        "there is no single choke point to add rate limiting, request-size limits, or a WAF "
        "when you eventually need them under pressure."
    )
    references: ClassVar[list[str]] = [
        "https://docs.gunicorn.org/en/stable/deploy.html",
        "https://kubernetes.io/docs/concepts/services-networking/ingress/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "api.reverse-proxies",
        "api.api-gateways",
        "api.load-balancing-readiness",
        "network.reverse-proxies",
        "network.proxies",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Put a reverse proxy or managed load balancer in front of the app (nginx/Caddy, an "
        "ALB, or a Kubernetes Ingress), terminate TLS there, and let it buffer slow clients "
        "so the application process only ever handles fast, complete requests."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if not serves_http(ctx):
            return None
        binder = repo_matches(ctx, _BINDS_PORT)
        if not binder:
            return None
        if repo_matches(ctx, _PROXY):
            return None
        return (
            f"{binder} starts an HTTP listener directly and no reverse proxy, ingress, "
            "load balancer, or API gateway is configured anywhere in the repository.",
            "searched for nginx/traefik/caddy/envoy/haproxy config, Kubernetes Ingress, "
            "ALB/ELB definitions, and API-gateway declarations",
        )
