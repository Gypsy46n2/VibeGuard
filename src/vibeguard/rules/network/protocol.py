"""VG-NET-003 — multi-service deployment with no stated network posture."""

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
from vibeguard.rules.api._http import repo_matches

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoProtocolPostureRule"]

_MIN_SERVICES = 2

_PROTOCOL = re.compile(
    r"http2|http/2|http_2|h2c|grpc|gRPC|\.proto\b|protobuf|http3|quic|"
    r"listen\s+443\s+ssl\s+http2|ALPN",
    re.IGNORECASE,
)
_DISCOVERY = re.compile(
    r"\bconsul\b|coredns|dnsPolicy|dnsConfig|service_discovery|serviceDiscovery|"
    r"\beureka\b|resolver\s+|route53|aws_service_discovery|"
    r"kind:\s*Service\b|externalName|SRV\s+record",
    re.IGNORECASE,
)
_CONN_TIMEOUT = re.compile(
    r"connect_timeout|connectTimeout|proxy_connect_timeout|dial_timeout|dialTimeout|"
    r"connectionTimeout|timeoutSeconds|idle_timeout|idleTimeout|keepalive_timeout",
    re.IGNORECASE,
)


class NoProtocolPostureRule(ProjectRule):
    """A review prompt for the service-to-service network layer of a large system."""

    id: ClassVar[str] = "VG-NET-003"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.LOW
    title: ClassVar[str] = "Network protocol posture not established"
    description: ClassVar[str] = (
        "This is a review prompt rather than a detected defect: the deployment runs several "
        "services, but the repository states no protocol choice (HTTP/2 or gRPC), no "
        "DNS/service-discovery configuration, and no connection-level timeouts between "
        "services, so those decisions are currently implicit."
    )
    why_it_matters: ClassVar[str] = (
        "In a multi-service system the network is where the surprises live. Implicit "
        "defaults mean nobody has decided how long one service waits on another, how it "
        "finds it when an address changes, or whether connections are multiplexed — so the "
        "first DNS change or slow dependency produces an outage whose cause nobody can "
        "point at. Writing the posture down is cheap; discovering it during an incident is "
        "not."
    )
    references: ClassVar[list[str]] = [
        "https://grpc.io/docs/guides/performance/",
        "https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "network.dns",
        "network.tcp",
        "network.udp",
        "network.http2",
        "network.http3",
        "network.grpc",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.LARGE
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Write down the service-to-service contract: which protocol each hop uses (HTTP/1.1 "
        "keep-alive, HTTP/2, or gRPC), how services resolve each other, and explicit "
        "connect/read/idle timeouts — then encode those numbers in the proxy or client "
        "configuration rather than leaving them at library defaults."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if ctx.scale.service_count < _MIN_SERVICES:
            return None
        checks = (
            ("an HTTP/2 or gRPC protocol choice", _PROTOCOL),
            ("DNS / service-discovery configuration", _DISCOVERY),
            ("connection-level timeouts between services", _CONN_TIMEOUT),
        )
        missing = [label for label, pattern in checks if not repo_matches(ctx, pattern)]
        if len(missing) < 3:
            return None
        return (
            f"{ctx.scale.service_count} services are deployed and the repository declares "
            "none of: " + "; ".join(missing) + ".",
            "review prompt only — searched for HTTP/2, gRPC and .proto definitions, DNS / "
            "service-discovery config, and connect/idle timeout settings",
        )
