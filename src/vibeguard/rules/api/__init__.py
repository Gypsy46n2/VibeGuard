"""VibeGuard api rule pack — outbound-call hygiene and HTTP surface posture.

Covers the two ends of an HTTP boundary: calls this service makes (timeouts,
retries, connection posture) and the surface it exposes (rate limiting, versioning,
webhook verification, idempotency, caching, edge readiness, realtime transports).
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.api.caching import NoCachingStrategyRule, NoReverseProxyRule
from vibeguard.rules.api.rate_limiting import NoRateLimitingRule
from vibeguard.rules.api.realtime import RealtimeWithoutHeartbeatRule
from vibeguard.rules.api.retries import RetryWithoutBackoffRule
from vibeguard.rules.api.timeouts import HttpTimeoutJsRule, HttpTimeoutPythonRule
from vibeguard.rules.api.versioning import NoApiVersioningRule
from vibeguard.rules.api.webhooks import NoIdempotencyKeyRule, UnverifiedWebhookRule

RULES: list[type[Rule]] = [
    HttpTimeoutPythonRule,  # VG-API-001
    HttpTimeoutJsRule,  # VG-API-002
    NoRateLimitingRule,  # VG-API-003
    RetryWithoutBackoffRule,  # VG-API-004
    NoApiVersioningRule,  # VG-API-005
    UnverifiedWebhookRule,  # VG-API-006
    NoIdempotencyKeyRule,  # VG-API-007
    NoCachingStrategyRule,  # VG-API-008
    NoReverseProxyRule,  # VG-API-009
    RealtimeWithoutHeartbeatRule,  # VG-API-010
]

__all__ = [
    "RULES",
    "HttpTimeoutJsRule",
    "HttpTimeoutPythonRule",
    "NoApiVersioningRule",
    "NoCachingStrategyRule",
    "NoIdempotencyKeyRule",
    "NoRateLimitingRule",
    "NoReverseProxyRule",
    "RealtimeWithoutHeartbeatRule",
    "RetryWithoutBackoffRule",
    "UnverifiedWebhookRule",
]
