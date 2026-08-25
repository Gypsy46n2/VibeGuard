"""VG-NET-001 — static assets served by the app process with no CDN in front."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
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

__all__ = ["NoCdnForStaticAssetsRule"]

_STATIC_DIRS = {"static", "public", "assets", "dist", "build", "www", "wwwroot", "media"}
_ASSET_SUFFIXES = {
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".webp",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
}
_MIN_ASSETS = 3

_SELF_SERVED = re.compile(
    r"StaticFiles\s*\(|static_folder|send_from_directory\s*\(|send_file\s*\(|"
    r"express\.static\s*\(|serveStatic|fastify-static|@fastify/static|"
    r"STATIC_ROOT|STATICFILES_DIRS|whitenoise|url_for\s*\(\s*['\"]static['\"]"
)
_CDN = re.compile(
    r"cloudfront|cloudflare|fastly|akamai|bunnycdn|\bcdn\b|CDN_URL|assetPrefix|"
    r"vercel\.json|netlify\.toml|_headers|firebase\.json|"
    r"expires\s+\d+|Cache-Control|s-maxage|max-age=|"
    r"aws_cloudfront_distribution|AWS::CloudFront",
    re.IGNORECASE,
)


class NoCdnForStaticAssetsRule(ProjectRule):
    """A static-heavy frontend served straight out of the application process."""

    id: ClassVar[str] = "VG-NET-001"
    category: ClassVar[Category] = Category.RELIABILITY
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Static assets served without a CDN or edge caching"
    description: ClassVar[str] = (
        "The repository ships a static asset tree that the application process serves "
        "itself, and no CDN or edge-caching configuration was found."
    )
    why_it_matters: ClassVar[str] = (
        "Every page view then spends application workers and database-adjacent capacity "
        "shipping bytes that never change, and a traffic spike on the marketing page can "
        "starve the actual API. Users far from your single region wait for every image and "
        "bundle to cross an ocean, and you pay full origin egress for content an edge cache "
        "would have served for a fraction of the cost."
    )
    references: ClassVar[list[str]] = [
        "https://web.dev/articles/content-delivery-networks",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"network.cdn-configuration", "network.edge-caching"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.MEDIUM
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Put a CDN in front of the asset tree (CloudFront, Cloudflare, Fastly, or the "
        "hosting platform's edge), serve fingerprinted filenames with a long "
        "`Cache-Control: public, max-age=31536000, immutable`, and stop routing asset "
        "requests through the application process."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        assets = self._asset_paths(ctx)
        if len(assets) < _MIN_ASSETS and not ctx.tech.frontend:
            return None
        if not assets:
            return None
        if not repo_matches(ctx, _SELF_SERVED) and not ctx.tech.frontend:
            return None
        if repo_matches(ctx, _CDN):
            return None
        sample = ", ".join(assets[:4])
        return (
            f"{len(assets)} static asset(s) are served from the application process "
            f"(e.g. {sample}) with no CDN or edge-caching configuration in the repository.",
            "searched for cloudfront/cloudflare/fastly/akamai config, _headers, "
            "vercel.json, netlify.toml, and nginx expires/Cache-Control blocks",
        )

    @staticmethod
    def _asset_paths(ctx: ScanContext, limit: int = 200) -> list[str]:
        out: list[str] = []
        for rel in ctx.files:
            path = PurePosixPath(rel)
            if path.suffix.lower() not in _ASSET_SUFFIXES:
                continue
            if not any(part.lower() in _STATIC_DIRS for part in path.parts[:-1]):
                continue
            out.append(rel)
            if len(out) >= limit:
                break
        return out
